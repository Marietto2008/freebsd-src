/*-
 * Copyright (C) 2021-2022 Intel Corporation.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Derivato da projectacrn/acrn-hypervisor (hypervisor/arch/x86/guest/vept.c).
 * Intestazione e clausola 3 di ACRN conservate.
 *
 * Copyright (c) 2026 Marietto.
 *
 * Shadow EPT per il VMX annidato (D1=a, T2.7). Quando VMCS12 abilita EPT, la
 * EPT violation in L2 si risolve camminando EPT12 (in memoria dell'L1) per il
 * GPA di L2 -> L1-GPA + permessi, traducendo l'L1-GPA via EPT01
 * (pmap_extract) -> HPA, e installando una foglia shadow con permessi
 * EPT12 ∩ EPT01. Lo shadow EPTP (radice) diventa l'EPTP di VMCS02.
 *
 * ⚠⚠ NON COLLAUDATO SU HARDWARE. E' il codice a piu' alto rischio del
 * progetto: un errore qui corrompe in silenzio la memoria del guest annidato.
 * Va validato per primo con i test [ept] di kvm-unit-tests (T2.7 "Fatto
 * quando") e con un L1 reale. Limiti dichiarati: solo pagine 4K nello shadow
 * (le large page di EPT12 si rispecchiano a 4K per l'indirizzo in fault);
 * memtype WB per la RAM; il caso EPT01-miss (RAM non residente o MMIO, §6.7.4)
 * per ora si riflette all'L1 come EPT violation invece di fare vm_fault/MMIO.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>
#include <machine/vmm.h>
#include <dev/vmm/vmm_mem.h>
#include <machine/pte.h>

#include "vmx_cpufunc.h"
#include "vmx_controls.h"
#include "vmx.h"
#include "vmx_nested.h"

MALLOC_DEFINE(M_VMX_VEPT, "vmx_vept", "Intel VMX nested shadow EPT");

#define	EPT_RWX		(EPT_PG_READ | EPT_PG_WRITE | EPT_PG_EXECUTE)
#define	EPT_ADDR(e)	((e) & 0x000ffffffffff000ULL)
#define	EPT_IDX(gpa, lvl)	(((gpa) >> (12 + 9 * (lvl))) & 0x1ff)

/*
 * Diagnostica della shadow EPT (fase C, parere #25 di Astra). Domanda: quando
 * l'L1 fa INVEPT su una radice, quante delle tabelle EPT12 servite a
 * costruirne le traduzioni shadow sono DIVERSE dalla versione usata per
 * costruirle? SOLO misura: la radice si svuota comunque come prima (31b286d).
 *
 * Per radice: le tabelle EPT12 attraversate dai walk di vmx_vept_fault, con
 * la fotografia (4 KB) presa alla PRIMA traversata. La fotografia non si
 * aggiorna mai fino allo svuotamento della radice: un walk successivo che
 * trova la voce usata diversa dalla fotografia conta un "disallineamento
 * durante il walk" (il controesempio del parere #25 §3: aggiornarla
 * nasconderebbe la modifica a un INVEPT seguente). All'INVEPT si rilegge
 * ogni tabella e si confrontano le 512 voci: per livello e per tipo di
 * cambiamento. Spenta per difetto (hw.vmm.vmx.vept_diag).
 */
SYSCTL_DECL(_hw_vmm_vmx);
static int vept_diag = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_diag, CTLFLAG_RWTUN, &vept_diag, 0,
    "nested: diagnostica delle tabelle EPT12 all'INVEPT (0 = spenta)");

/*
 * veptdiag(vcpuid, eptp12, tabelle tracciate, tabelle cambiate, voci
 * cambiate, ns di scansione) e veptdiag2(vcpuid, voci cambiate per livello
 * (4 x 16 bit, livello 0 in basso), per tipo (6 x 10 bit: indirizzo,
 * permessi, page size, attributi, A/D, altro), disallineamenti durante i
 * walk, illeggibili | tetto superato << 32).
 */
SDT_PROVIDER_DECLARE(vmm);
SDT_PROBE_DEFINE6(vmm, vmx, nested, veptdiag, "int", "uint64_t", "int", "int",
    "int", "uint64_t");
SDT_PROBE_DEFINE5(vmm, vmx, nested, veptdiag2, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t");
/* veptdiag3(vcpuid, traduzioni shadow vive nella radice, cioe' le foglie
 * 4K che un B0 conserverebbe o un B1 dovrebbe giudicare) */
SDT_PROBE_DEFINE2(vmm, vmx, nested, veptdiag3, "int", "uint64_t");

/* Foglie presenti nel sottoalbero shadow (livello 0 = tabella di foglie). */
static uint64_t
vept_count_leaves(const uint64_t *tbl, int level)
{
	uint64_t n = 0;
	int i;

	for (i = 0; i < 512; i++) {
		if ((tbl[i] & EPT_RWX) == 0)
			continue;
		if (level == 0)
			n++;
		else
			n += vept_count_leaves((const uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(tbl[i])), level - 1);
	}
	return (n);
}

#define	VEPT_OBS_MAX	512		/* tabelle tracciate per radice */
#define	VEPT_OBS_HASH	1024		/* bucket (potenza di 2, > MAX) */

struct vept_obs_ent {
	uint64_t	gpa;		/* tabella EPT12 (GPA dell'L1); 0 = vuota */
	int		level;		/* 3 = PML4 ... 0 = PT */
	uint64_t	*snap;		/* 512 voci alla prima traversata */
	uint64_t	base;		/* C2: L2-GPA coperto dalla voce 0 */
	bool		ambiguous;	/* C2: raggiunta da piu' basi o livelli */
};

/* C2: intervallo L2-GPA [start, end) da invalidare in una B1 */
struct vept_rng {
	uint64_t	start, end;
};
#define	VEPT_RNG_MAX	8192

struct vept_obs {
	struct vept_obs_ent ent[VEPT_OBS_HASH];
	int		n;		/* tabelle tracciate */
	uint64_t	walk_mismatch;	/* voce usata != fotografia */
	bool		overflow;	/* tetto superato: misura incompleta */
	struct vept_rng	*rng;		/* C2: buffer degli intervalli */
};

static struct vept_obs *
vept_obs_get(struct vmx_nested *n, uint64_t *root)
{
	int i;

	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root == root) {
			if (n->vept_obs[i] == NULL)
				n->vept_obs[i] = malloc(sizeof(struct vept_obs),
				    M_VMX_VEPT, M_WAITOK | M_ZERO);
			return (n->vept_obs[i]);
		}
	return (NULL);
}

/* Svuota le osservazioni (le fotografie restano allocate e si riusano). */
static void
vept_obs_reset(struct vept_obs *o)
{
	int i;

	if (o == NULL)
		return;
	for (i = 0; i < VEPT_OBS_HASH; i++) {
		o->ent[i].gpa = 0;
		o->ent[i].ambiguous = false;
	}
	o->n = 0;
	o->walk_mismatch = 0;
	o->overflow = false;
}

static void
vept_obs_free(struct vept_obs *o)
{
	int i;

	if (o == NULL)
		return;
	for (i = 0; i < VEPT_OBS_HASH; i++)
		if (o->ent[i].snap != NULL)
			free(o->ent[i].snap, M_VMX_VEPT);
	if (o->rng != NULL)
		free(o->rng, M_VMX_VEPT);
	free(o, M_VMX_VEPT);
}

/*
 * Tabella EPT12 attraversata da un walk di vmx_vept_fault: prima volta,
 * fotografia; volte successive, confronto della sola voce usata (la
 * fotografia NON si aggiorna).
 */
static void
vept_obs_note(struct vept_obs *o, uint64_t gpa, int level, const uint64_t *page,
    int idx, uint64_t base)
{
	struct vept_obs_ent *e;
	uint32_t h;
	int i;

	if (o == NULL || gpa == 0)
		return;
	h = (uint32_t)((gpa >> 12) * 2654435761U);
	for (i = 0; i < VEPT_OBS_HASH; i++) {
		e = &o->ent[(h + i) & (VEPT_OBS_HASH - 1)];
		if (e->gpa == gpa) {
			if (e->snap[idx] != page[idx])
				o->walk_mismatch++;
			if (e->base != base || e->level != level)
				e->ambiguous = true;	/* C2: aliasing */
			return;
		}
		if (e->gpa == 0)
			break;
	}
	if (i == VEPT_OBS_HASH || o->n >= VEPT_OBS_MAX) {
		o->overflow = true;
		return;
	}
	if (e->snap == NULL)
		e->snap = malloc(PAGE_SIZE, M_VMX_VEPT, M_WAITOK);
	memcpy(e->snap, page, PAGE_SIZE);
	e->gpa = gpa;
	e->level = level;
	e->base = base;
	e->ambiguous = false;
	o->n++;
}

/*
 * C2 (parere #26 di Astra): simulazione di B1. Ogni voce EPT12 cambiata a
 * livello L di una tabella con base B invaliderebbe l'intervallo L2-GPA
 * [B + j * 2^(12+9L), + 2^(12+9L)); livello 3 = tutta la radice. Si contano
 * le foglie shadow vive che cadono negli intervalli (uniti), e i motivi per
 * cui una B1 dovrebbe invece svuotare tutto. La shadow ha solo foglie 4K
 * (vept_install): nessuna superpage shadow da spezzare.
 */
#define	VEPT_FB_AMBIG	0x01	/* tabella cambiata raggiunta da piu' basi */
#define	VEPT_FB_L3	0x02	/* voce di PML4 cambiata */
#define	VEPT_FB_OVERFL	0x04	/* tetto di tabelle superato */
#define	VEPT_FB_UNREAD	0x08	/* tabella illeggibile */
#define	VEPT_FB_WALK	0x10	/* disallineamento gia' visto nei walk */
#define	VEPT_FB_NRNG	0x20	/* troppi intervalli */

SDT_PROBE_DEFINE6(vmm, vmx, nested, veptdiag4, "int", "uint64_t", "uint64_t",
    "int", "int", "uint64_t");	/* vcpu, vive, colpite, intervalli, motivi, ns */

static int
vept_rng_cmp(const void *a, const void *b)
{
	const struct vept_rng *x = a, *y = b;

	return (x->start < y->start ? -1 : x->start > y->start);
}

/* Foglie vive del sottoalbero tbl (livello lvl, che copre da tb) dentro
 * [s, e). Si scende solo dove c'e' sovrapposizione. */
static uint64_t
vept_count_range(const uint64_t *tbl, int lvl, uint64_t tb, uint64_t s,
    uint64_t e)
{
	uint64_t span = 1ULL << (12 + 9 * lvl), lo, n = 0;
	int i, i0, i1;

	if (e <= tb)
		return (0);
	i0 = s > tb ? (int)((s - tb) / span) : 0;
	i1 = (int)MIN((e - tb + span - 1) / span, 512);
	for (i = i0; i < i1; i++) {
		if ((tbl[i] & EPT_RWX) == 0)
			continue;
		lo = tb + (uint64_t)i * span;
		if (lvl == 0)
			n++;
		else
			n += vept_count_range((const uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(tbl[i])), lvl - 1, lo, MAX(s, lo),
			    MIN(e, lo + span));
	}
	return (n);
}

/* All'INVEPT su una radice: confronta e riporta. Non cambia nulla. */
static void
vept_obs_scan(struct vmx_vcpu *vcpu, struct vept_obs *o, uint64_t eptp12,
    const uint64_t *root)
{
	struct vept_obs_ent *e;
	uint64_t *page, x, levels = 0, kinds = 0;
	uint64_t lv[4] = { 0 }, k[6] = { 0 };
	sbintime_t t0 = sbinuptime();
	void *cookie;
	int i, j, tch = 0, ech = 0, unread = 0, c;

	int nr = 0, fb = 0;
	uint64_t live, hit = 0, span;
	sbintime_t t1;

	if (o == NULL)
		return;
	if (o->rng == NULL)
		o->rng = malloc(VEPT_RNG_MAX * sizeof(struct vept_rng),
		    M_VMX_VEPT, M_WAITOK);
	if (o->overflow)
		fb |= VEPT_FB_OVERFL;
	if (o->walk_mismatch != 0)
		fb |= VEPT_FB_WALK;
	for (i = 0; i < VEPT_OBS_HASH; i++) {
		e = &o->ent[i];
		if (e->gpa == 0)
			continue;
		page = vm_gpa_hold(vcpu->vcpu, e->gpa, PAGE_SIZE, VM_PROT_READ,
		    &cookie);
		if (page == NULL) {
			unread++;
			fb |= VEPT_FB_UNREAD;
			continue;
		}
		c = 0;
		span = 1ULL << (12 + 9 * (e->level & 3));
		for (j = 0; j < 512; j++) {
			x = page[j] ^ e->snap[j];
			if (x == 0)
				continue;
			c++;
			/* C2: intervallo che B1 invaliderebbe */
			if (e->ambiguous)
				fb |= VEPT_FB_AMBIG;
			else if (e->level >= 3)
				fb |= VEPT_FB_L3;
			else if (nr >= VEPT_RNG_MAX)
				fb |= VEPT_FB_NRNG;
			else {
				o->rng[nr].start = e->base + (uint64_t)j * span;
				o->rng[nr].end = o->rng[nr].start + span;
				nr++;
			}
			if (x & 0x000ffffffffff000ULL)
				k[0]++;			/* indirizzo */
			else if (x & 0x407ULL)
				k[1]++;			/* R/W/X, X utente */
			else if (x & EPT_PG_PS)
				k[2]++;			/* page size */
			else if (x & 0x78ULL)
				k[3]++;			/* memtype, ignore PAT */
			else if (x & 0x300ULL)
				k[4]++;			/* accessed/dirty */
			else
				k[5]++;
		}
		vm_gpa_release(cookie);
		if (c != 0) {
			tch++;
			ech += c;
			lv[e->level & 3] += c;
		}
	}
	for (i = 0; i < 4; i++)
		levels |= MIN(lv[i], 0xffff) << (16 * i);
	for (i = 0; i < 6; i++)
		kinds |= MIN(k[i], 0x3ff) << (10 * i);
	SDT_PROBE6(vmm, vmx, nested, veptdiag, vcpu->vcpuid, eptp12, o->n, tch,
	    ech, (uint64_t)sbttons(sbinuptime() - t0));
	SDT_PROBE5(vmm, vmx, nested, veptdiag2, vcpu->vcpuid, levels, kinds,
	    o->walk_mismatch, (uint64_t)unread | ((uint64_t)o->overflow << 32));
	live = vept_count_leaves(root, 3);
	SDT_PROBE2(vmm, vmx, nested, veptdiag3, vcpu->vcpuid, live);
	/* C2: intervalli uniti, foglie vive colpite */
	t1 = sbinuptime();
	if (nr > 1) {
		qsort(o->rng, nr, sizeof(struct vept_rng), vept_rng_cmp);
		for (i = 0, j = 1; j < nr; j++) {
			if (o->rng[j].start <= o->rng[i].end) {
				if (o->rng[j].end > o->rng[i].end)
					o->rng[i].end = o->rng[j].end;
			} else
				o->rng[++i] = o->rng[j];
		}
		nr = i + 1;
	}
	for (i = 0; i < nr; i++)
		hit += vept_count_range(root, 3, 0, o->rng[i].start,
		    o->rng[i].end);
	SDT_PROBE6(vmm, vmx, nested, veptdiag4, vcpu->vcpuid, live, hit, nr,
	    fb, (uint64_t)sbttons(sbinuptime() - t1));
}


/*
 * Prepara la radice shadow per l'EPTP12 corrente: riprende quella gia' fatta
 * per lo stesso EPTP12, altrimenti ne alloca una VUOTA (o svuota la meno usata
 * di recente, oltre VEPT_NROOTS). PUO' DORMIRE (malloc/free):
 * va chiamata nello slow path PRIMA del VMPTRLD del VMCS02, perche' VMPTRLD
 * fa critical_enter (panic "malloc: called with spinlock or critical section
 * held", kvm-unit-tests 'EPT A/D disabled'). Con radice valida l'L2 entra e la
 * shadow si riempie a domanda in vmx_vept_fault; tornare un EPTP invalido
 * farebbe fallire ogni ingresso (uovo-e-gallina).
 */
static void vept_wipe(uint64_t *root);

void
vmx_vept_prepare(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t eptp12 = (c != NULL) ? vmcs12_read_field(c, VMCS_EPTP) : 0;
	struct vept_slot *s, *pick = NULL;
	int i;

	/*
	 * Radice gia' costruita per questo EPTP12 (cambio VTL di Hyper-V):
	 * la si riprende COSI' COM'E'. Le sue voci valgono finche' l'L1 non
	 * fa INVEPT, che le svuota tutte (vmx_vept_invept); il TLB della
	 * radice lo invalida vmx_run a ogni ingresso in L2.
	 */
	for (i = 0; i < VEPT_NROOTS; i++) {
		s = &n->vept_slot[i];
		if (s->root != NULL && s->eptp12 == eptp12) {
			pick = s;
			break;
		}
	}
	if (pick == NULL) {
		/* slot libero, altrimenti il meno usato di recente (svuotato) */
		for (i = 0; i < VEPT_NROOTS; i++) {
			s = &n->vept_slot[i];
			if (s->root == NULL) {
				pick = s;
				break;
			}
			if (pick == NULL || s->used < pick->used)
				pick = s;
		}
		if (pick->root == NULL)
			pick->root = malloc_aligned(PAGE_SIZE, PAGE_SIZE,
			    M_VMX_VEPT, M_WAITOK | M_ZERO);
		else {
			vept_wipe(pick->root);
			vept_obs_reset(n->vept_obs[pick - n->vept_slot]);
		}
		pick->eptp12 = eptp12;
	}
	pick->used = ++n->vept_tick;
	n->vept_root = pick->root;
	n->vept_eptp12 = eptp12;
}

/* Shadow EPTP (radice) da scrivere nel VMCS02: WB, 4 livelli. Non dorme:
 * la radice l'ha gia' preparata vmx_vept_prepare. */
uint64_t
vmx_vept_eptp(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;

	KASSERT(n->vept_root != NULL, ("%s: radice shadow non preparata",
	    __func__));
	/*
	 * Formato EPTP (SDM 24.6.11): bit 2:0 tipo di memoria (6 = WB), bit 5:3
	 * lunghezza del cammino - 1 (3). NON EPT_PG_MEMORY_TYPE, che e' per le
	 * voci foglia (bit 5:3): dava 0x38 = UC con cammino 8, EPTP non valido
	 * (INVEPT -> VM-instruction error 28, kvm-unit-tests EPT A/D disabled).
	 */
	return (vtophys(n->vept_root) | 6UL | (3UL << 3));
}

/* Svuota le sottotabelle della radice (non la radice) e la azzera. */
static void vept_free_level(uint64_t *tbl, int level);

/* Svuota una radice TENENDOLA, cosi' un EPTP gia' scritto nel VMCS02 resta
 * valido. */
static void
vept_wipe(uint64_t *root)
{
	int i;

	for (i = 0; i < 512; i++) {
		if ((root[i] & EPT_RWX) != 0 && (root[i] & EPT_PG_PS) == 0)
			vept_free_level((uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(root[i])), 2);
		root[i] = 0;
	}
}

/*
 * INVEPT dell'L1. All-context (tipo 2): svuota tutte le radici. Single-
 * context (tipo 1, parere #24 di Astra, come handle_invept di KVM): solo le
 * radici costruite per un EPTP12 con la stessa BASE FISICA (bit 51:12) di
 * quello del descrittore -- tutte, se piu' d'una -- perche' l'SDM associa le
 * traduzioni ai bit 51:12 e non agli attributi dell'EPTP. Le altre (l'altro
 * VTL, l'altra partizione) restano: prima si svuotavano tutte a ogni INVEPT
 * single-context di Hyper-V (~50/s), con ~150 000 EPT violation/s per
 * ricostruirle (fase A). Svuotare la radice intera basta: single-context non
 * e' single-address.
 * Il TLB per l'EPTP shadow lo invalida vmx_run a ogni rientro in L2 (INVEPT
 * single-context sulla radice corrente; le altre lo ricevono quando tornano
 * correnti), come prima. Le radici sono per vCPU (vmx_nested): nessuna
 * condivisione fra vCPU. Ritorna il numero di radici svuotate.
 */
#define	VEPT_EPTP_BASE	0x000ffffffffff000ULL	/* bit 51:12 */

int
vmx_vept_invept(struct vmx_vcpu *vcpu, uint64_t type, uint64_t eptp)
{
	struct vmx_nested *n = vcpu->nested;
	struct vept_slot *s;
	int i, wiped = 0;

	for (i = 0; i < VEPT_NROOTS; i++) {
		s = &n->vept_slot[i];
		if (s->root == NULL)
			continue;
		if (type == 1 && (s->eptp12 & VEPT_EPTP_BASE) !=
		    (eptp & VEPT_EPTP_BASE))
			continue;
		if (vept_diag)		/* fase C: solo misura, PRIMA di svuotare */
			vept_obs_scan(vcpu, n->vept_obs[i], s->eptp12,
			    s->root);
		vept_wipe(s->root);
		vept_obs_reset(n->vept_obs[i]);
		wiped++;
	}
	return (wiped);
}

/* Libera le tabelle shadow (ricorsiva sui livelli interni). */
static void
vept_free_level(uint64_t *tbl, int level)
{
	int i;

	if (level > 0) {
		for (i = 0; i < 512; i++) {
			if ((tbl[i] & EPT_RWX) != 0 && (tbl[i] & EPT_PG_PS) == 0) {
				uint64_t *sub =
				    (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(tbl[i]));
				vept_free_level(sub, level - 1);
			}
		}
	}
	free(tbl, M_VMX_VEPT);
}

void
vmx_vept_flush(struct vmx_nested *n)
{
	int i;

	for (i = 0; i < VEPT_NROOTS; i++) {
		if (n->vept_slot[i].root != NULL) {
			vept_free_level(n->vept_slot[i].root, 3);
			n->vept_slot[i].root = NULL;
		}
		n->vept_slot[i].eptp12 = 0;
		n->vept_slot[i].used = 0;
		vept_obs_free(n->vept_obs[i]);
		n->vept_obs[i] = NULL;
	}
	n->vept_root = NULL;
	n->vept_eptp12 = 0;
}

/*
 * Cammina EPT12 (in memoria dell'L1) per l2gpa. Ritorna VEPT_OK con l1gpa e
 * perm (R/W/X, intersezione dei livelli); VEPT_VIOL se una voce non e'
 * presente (perm = quelli accumulati fin li', per la qualificazione);
 * VEPT_MISCONF per una voce malformata (SDM 28.3.3.1: scrivibile senza essere
 * leggibile, o foglia con tipo di memoria riservato 2/3/7); -1 se una
 * tabella dell'L1 non e' leggibile.
 */
static int
ept12_translate(struct vmx_vcpu *vcpu, uint64_t eptp12, uint64_t l2gpa,
    uint64_t *l1gpa, uint64_t *perm, struct vept_obs *obs)
{
	uint64_t tbl_gpa, pte, acc, mt;
	uint64_t *page;
	void *cookie;
	int level, idx;

	tbl_gpa = EPT_ADDR(eptp12);
	acc = EPT_RWX;
	*perm = 0;
	for (level = 3; level >= 0; level--) {
		idx = EPT_IDX(l2gpa, level);
		page = vm_gpa_hold(vcpu->vcpu, tbl_gpa, PAGE_SIZE,
		    VM_PROT_READ, &cookie);
		if (page == NULL)
			return (-1);
		pte = page[idx];
		vept_obs_note(obs, tbl_gpa, level, page, idx, level >= 3 ? 0 :
		    l2gpa & ~((1ULL << (12 + 9 * (level + 1))) - 1));
		vm_gpa_release(cookie);
		if ((pte & EPT_RWX) == 0)
			return (VEPT_VIOL);		/* non presente */
		if ((pte & 0x3) == 0x2)
			return (VEPT_MISCONF);		/* W senza R */
		acc &= pte;				/* ∩ permessi R/W/X */
		if (level == 0 || (pte & EPT_PG_PS) != 0) {
			uint64_t mask = (1ULL << (12 + 9 * level)) - 1;

			mt = (pte >> 3) & 0x7;
			if (mt == 2 || mt == 3 || mt == 7)
				return (VEPT_MISCONF);	/* tipo riservato */
			*l1gpa = (EPT_ADDR(pte) & ~mask) | (l2gpa & mask);
			*perm = acc & EPT_RWX;
			return (VEPT_OK);
		}
		tbl_gpa = EPT_ADDR(pte);
	}
	return (VEPT_VIOL);
}

/* Installa una foglia shadow 4K: l2gpa -> hpa con permessi e memtype WB. */
static int
vept_install(struct vmx_nested *n, uint64_t l2gpa, uint64_t hpa, uint64_t perm,
    int mt)
{
	uint64_t *tbl = n->vept_root;
	int level, idx;

	for (level = 3; level > 0; level--) {
		idx = EPT_IDX(l2gpa, level);
		if ((tbl[idx] & EPT_RWX) == 0) {
			uint64_t *np = malloc_aligned(PAGE_SIZE, PAGE_SIZE,
			    M_VMX_VEPT, M_WAITOK | M_ZERO);
			tbl[idx] = vtophys(np) | EPT_RWX;
		}
		tbl = (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(tbl[idx]));
	}
	idx = EPT_IDX(l2gpa, 0);
	tbl[idx] = (hpa & ~0xfffULL) | (perm & EPT_RWX) |
	    EPT_PG_MEMORY_TYPE(mt) | EPT_PG_IGNORE_PAT;
	return (0);
}

/*
 * EPT violation mentre il vCPU e' in L2 (VMCS02 corrente, VMCS12 usa EPT).
 * Ritorna 0 se ha installato la shadow e si puo' rientrare in L2; 1 se
 * l'accesso va riflesso all'L1 (EPT12 nega o EPT01 non mappa).
 */
int
vmx_vept_fault(struct vmx_vcpu *vcpu, uint64_t l2gpa, uint64_t qual,
    uint64_t *l1gpa, uint64_t *perm)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t eptp12, hpa, access;
	void *p, *ck;
	int r;

	/*
	 * SLOW PATH (vCPU FROZEN, nessun VMCS caricato): qui si puo' dormire
	 * (vm_gpa_hold, malloc M_WAITOK). Esiti: VEPT_OK shadow installata,
	 * si riparte in L2; VEPT_VIOL / VEPT_MISCONF da riflettere all'L1;
	 * VEPT_MMIO l'L1 mappa l'L2 su un suo indirizzo che non e' RAM.
	 */
	if (c == NULL)
		return (VEPT_VIOL);
	eptp12 = vmcs12_read_field(c, VMCS_EPTP);
	if (n->vept_root == NULL || n->vept_eptp12 != eptp12)
		vmx_vept_prepare(vcpu);		/* allinea radice ed EPTP12 */

	r = ept12_translate(vcpu, eptp12, l2gpa, l1gpa, perm,
	    vept_diag ? vept_obs_get(n, n->vept_root) : NULL);
	if (r < 0)
		return (VEPT_VIOL);		/* tabella dell'L1 illeggibile */
	if (r != VEPT_OK)
		return (r);
	/*
	 * Tipo d'accesso (qualificazione: bit 0 R, 1 W, 2 X, stessi bit dei
	 * permessi EPT) contro i permessi dell'L1. Prima non si confrontava: si
	 * installava la voce coi permessi dell'L1, l'L2 rifaceva l'accesso,
	 * l'hardware rifaceva il fault e si girava a vuoto.
	 */
	access = qual & EPT_RWX;
	if ((access & ~*perm) != 0)
		return (VEPT_VIOL);
	/*
	 * Pagina host dell'L1-GPA: vm_gpa_hold la porta in memoria se serve
	 * (prima pmap_extract sull'EPT01 falliva per una pagina mai toccata
	 * dall'L1). La memoria del guest e' wired: non si sposta dopo il
	 * rilascio.
	 */
	p = vm_gpa_hold(vcpu->vcpu, *l1gpa & ~(uint64_t)PAGE_MASK, PAGE_SIZE,
	    VM_PROT_READ, &ck);
	if (p != NULL) {
		hpa = DMAP_TO_PHYS((vm_offset_t)p);
		vm_gpa_release(ck);
		vept_install(n, l2gpa, hpa, *perm, 6);	/* RAM: WB */
		return (VEPT_OK);
	}
	/* Non RAM. Se l'EPT01 mappa gia' l'L1-GPA (BAR di un dispositivo in
	 * passthrough) si usa la stessa pagina host, non cacheable. */
	hpa = pmap_extract(vcpu->vmx->pmap, *l1gpa);
	if (hpa != 0) {
		vept_install(n, l2gpa, hpa, *perm, 0);	/* MMIO: UC */
		return (VEPT_OK);
	}
	return (VEPT_MMIO);			/* dispositivo emulato dell'L1 */
}

/*
 * vmmops nested_gpa (vm_gla2gpa, ptp_hold): GPA dell'L2 -> GPA dell'L1, per
 * emulare un'istruzione dell'L2. Identita' fuori da un L2 o se il VMCS12 non
 * usa EPT (allora L2-GPA == L1-GPA).
 */
int
vmx_vept_l1gpa(struct vmx_vcpu *vcpu, uint64_t gpa, int prot, uint64_t *out)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t perm;

	*out = gpa;
	if (n == NULL || !n->in_l2 || (c = nested_current_cache(n)) == NULL ||
	    (vmcs12_proc2(c) &
	    PROCBASED2_ENABLE_EPT) == 0)
		return (0);
	if (ept12_translate(vcpu, vmcs12_read_field(c, VMCS_EPTP), gpa, out,
	    &perm, NULL) != VEPT_OK || (prot & ~perm & EPT_RWX) != 0)
		return (EFAULT);
	return (0);
}

/*
 * Sonda 9: voce foglia dello shadow EPT per l2gpa (0 se assente), per
 * confrontare la pagina host che vede l'hardware con quella attesa.
 */
uint64_t
vmx_vept_shadow_entry(struct vmx_vcpu *vcpu, uint64_t l2gpa)
{
	uint64_t *tbl = vcpu->nested->vept_root, e;
	int level;

	if (tbl == NULL)
		return (0);
	for (level = 3; level > 0; level--) {
		e = tbl[EPT_IDX(l2gpa, level)];
		if ((e & EPT_RWX) == 0)
			return (0);
		tbl = (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(e));
	}
	return (tbl[EPT_IDX(l2gpa, 0)]);
}
