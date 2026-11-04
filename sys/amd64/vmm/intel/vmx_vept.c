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
#include <sys/proc.h>
#include <sys/sdt.h>
#include <sys/sysctl.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <machine/clock.h>	/* tsc_freq (parere #41 §6) */
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

/*
 * B1 (parere #28 di Astra). Con hw.vmm.vmx.vept_keep=1 (letto alla creazione
 * del nested di ogni vCPU) un INVEPT non svuota piu' la radice: rilegge le
 * tabelle EPT12 tracciate, invalida nella shadow i soli intervalli L2-GPA
 * delle voci cambiate e aggiorna quelle voci delle fotografie. Ogni dubbio
 * (tabella ambigua, voce di PML4, tetto, tabella illeggibile o cambiata fra
 * le due passate, radice non conservabile) svuota la radice come prima.
 *
 * Contratto TLB (audit del parere #28 §2): la shadow si modifica SOLO nello
 * slow path (vmx_nested_exit, vCPU FROZEN). Dopo, vm_run riparte con un
 * vmx_run nuovo che, se in L2, fa INVEPT single-context dell'EPTP shadow
 * sulla CPU corrente PRIMA del primo ingresso; vmx_run gira tutto sotto il
 * critical_enter di vm_run, quindi niente migrazioni fra l'INVEPT e gli
 * ingressi. Su un'altra CPU dove il vCPU aveva girato restano traduzioni
 * vecchie della stessa radice, ma il vCPU ci rientra solo passando da un
 * altro vmx_run, cioe' da un altro INVEPT. Le radici sono per vCPU. Le
 * tabelle intermedie della shadow non si staccano mai in B1 (si azzerano le
 * foglie): si liberano solo allo svuotamento, come gia' prima di B1.
 */
static int vept_keep = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_keep, CTLFLAG_RWTUN, &vept_keep, 0,
    "nested: B1, conserva la shadow EPT all'INVEPT (letto alla creazione "
    "del vCPU nested)");
static int vept_verify_hpa = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_verify_hpa, CTLFLAG_RWTUN,
    &vept_verify_hpa, 0,
    "nested: B1, riverifica a campione le foglie conservate (0 = no)");

#define	VEPT_CTR(name, descr)						\
	static u_long name;						\
	SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, name, CTLFLAG_RD, &name, 0, descr)
VEPT_CTR(vept_keep_partial_invepts, "B1: INVEPT con la radice conservata");
VEPT_CTR(vept_keep_retained_leaves, "B1: foglie conservate (somma)");
VEPT_CTR(vept_keep_invalidated_leaves, "B1: foglie invalidate (somma)");
VEPT_CTR(vept_keep_full_fallbacks, "B1: INVEPT con svuotamento completo");
VEPT_CTR(vept_keep_scan_race_fallbacks,
    "B1: svuotamenti per tabella cambiata fra le due passate");
VEPT_CTR(vept_keep_shadow_flushes,
    "B1: INVEPT hardware dovuti a una shadow ridotta");
VEPT_CTR(vept_keep_walk_zaps, "B1: voci cambiate viste da un walk");
VEPT_CTR(vept_keep_verify_checked, "B1: foglie riverificate");
VEPT_CTR(vept_keep_verify_mismatch, "B1: foglie riverificate DISCORDANTI");
VEPT_CTR(vept_memgen_changes_detected,
    "B1: generazioni dei mapping cambiate viste da un vCPU");
VEPT_CTR(vept_ptp_write_retry_xlate,
    "H1: walk ripartiti, EPT12 della tabella non piu' valida (parere #110)");
VEPT_CTR(vept_ptp_write_retry_remap,
    "H1: walk ripartiti, tabella rimappata su un'altra pagina dell'L1");
VEPT_CTR(vept_h2_viol_final,
    "H2: EPT violation dell'emulatore sull'indirizzo finale (registrate)");
VEPT_CTR(vept_h2_viol_ptp,
    "H2: EPT violation dell'emulatore su una tabella dell'L2 (registrate)");
VEPT_CTR(vept_h2_misconf,
    "H2: EPT misconfiguration trovate dall'emulatore (registrate)");
VEPT_CTR(vept_h2_unread,
    "H2: tabella di EPT12 illeggibile nell'emulatore (registrata come violation)");
VEPT_CTR(vept_h2_already,
    "H2: violazione gia' registrata e non consegnata (deve essere 0)");
VEPT_CTR(vept_memgen_roots_invalidated,
    "B1: radici svuotate per generazione cambiata");
VEPT_CTR(vept_stale_root_enters,
    "B1: ingressi in L2 con una radice di generazione vecchia (deve essere 0)");
VEPT_CTR(vept_shadow_pages, "nested: pagine di tabelle shadow EPT allocate");
/*
 * Parere #29 di Astra, §3: foglie shadow perse, per motivo. Ogni foglia tolta
 * finisce in UNA sola voce. partial = intervalli cambiati di un INVEPT che
 * conserva la radice; walk = voce cambiata vista da un walk; race, alias,
 * capacity (tetto, troppi cambi, memoria), backing (MMIO/non wired), force
 * (walk non tracciato), other (PML4, illeggibile, verifica) = svuotamenti
 * completi di B1; memgen = generazione dei mapping; keep0 = INVEPT con
 * vept_keep=0; lru = slot ripreso per un altro EPTP12.
 */
VEPT_CTR(vept_leaves_zapped_partial, "B1: foglie tolte da INVEPT conservati");
VEPT_CTR(vept_leaves_zapped_walk, "B1: foglie tolte da voci cambiate nei walk");
VEPT_CTR(vept_leaves_zapped_race, "B1: foglie perse per corsa fra le passate");
VEPT_CTR(vept_leaves_zapped_alias, "B1: foglie perse per tabella ambigua");
VEPT_CTR(vept_leaves_zapped_capacity, "B1: foglie perse per tetti o memoria");
VEPT_CTR(vept_leaves_zapped_backing, "B1: foglie perse per MMIO o RAM non wired");
VEPT_CTR(vept_leaves_zapped_force, "B1: foglie perse per walk non tracciato");
VEPT_CTR(vept_leaves_zapped_walkfull,
    "B1: foglie perse per walk su tabella ambigua o PML4 cambiata");
VEPT_CTR(vept_keep_walk_wipes,
    "B1: radici svuotate subito da un walk (ambigua o PML4 cambiata)");
VEPT_CTR(vept_leaves_zapped_other, "B1: foglie perse per PML4, illeggibile, verifica");
VEPT_CTR(vept_leaves_zapped_memgen, "nested: foglie perse per generazione dei mapping");
VEPT_CTR(vept_leaves_zapped_keep0, "nested: foglie perse da INVEPT con vept_keep=0");
VEPT_CTR(vept_leaves_zapped_lru, "nested: foglie perse riprendendo uno slot");
/* Parere #29, §1: INVEPT dell'L1 e radici elaborate. Invariante:
 * roots_matched = roots_kept + roots_fallback. */
VEPT_CTR(vept_invept_single, "nested: INVEPT single-context dell'L1");
VEPT_CTR(vept_invept_all, "nested: INVEPT all-context dell'L1");
VEPT_CTR(vept_invept_roots_matched, "nested: radici colpite da un INVEPT");
VEPT_CTR(vept_invept_roots_kept, "nested: radici colpite e conservate (B1)");
VEPT_CTR(vept_invept_roots_fallback, "nested: radici colpite e svuotate");
VEPT_CTR(vept_invept_roots_unmatched, "nested: radici esistenti non colpite");
VEPT_CTR(vept_shadow_pages_high, "nested: massimo di vept_shadow_pages");

/*
 * veptkeep(vcpu, eptp12, foglie vive prima, foglie invalidate, intervalli |
 * voci cambiate << 32, motivi di svuotamento (16 bit) | tabelle tracciate
 * << 16 (16 bit) | ns << 32). Motivi 0 = radice conservata.
 */
SDT_PROBE_DEFINE6(vmm, vmx, nested, veptkeep, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
#define	VEPT_KEEP_A5(fb, ntr, t0)	((uint64_t)(fb) |		\
	(uint64_t)MIN((ntr), 0xffff) << 16 |				\
	(uint64_t)MIN(sbttons(sbinuptime() - (t0)), 0xffffffff) << 32)
/* veptmemgen(vcpu, generazione nuova, radici svuotate) */
SDT_PROBE_DEFINE3(vmm, vmx, nested, veptmemgen, "int", "uint64_t", "int");
/* veptverify(vcpu, l2gpa, foglia shadow, attesa: hpa | permessi, esito) */
SDT_PROBE_DEFINE5(vmm, vmx, nested, veptverify, "int", "uint64_t",
    "uint64_t", "uint64_t", "int");

bool
vmx_vept_keep_enabled(void)
{
	return (vept_keep != 0);
}

/* Pagina di tabella shadow (puo' dormire) e suo rilascio, con il conto. */
static uint64_t *
vept_page_alloc(void)
{
	u_long m;

	m = atomic_fetchadd_long(&vept_shadow_pages, 1) + 1;
	if (m > vept_shadow_pages_high)
		vept_shadow_pages_high = m;		/* indicativo */
	return (malloc_aligned(PAGE_SIZE, PAGE_SIZE, M_VMX_VEPT,
	    M_WAITOK | M_ZERO));
}

static void
vept_page_free(uint64_t *p)
{
	free(p, M_VMX_VEPT);
	atomic_subtract_long(&vept_shadow_pages, 1);
}

/*
 * B1: azzera le foglie shadow del sottoalbero tbl (livello lvl, che copre da
 * tb) dentro [s, e); le tabelle intermedie restano. Ritorna le foglie tolte.
 */
static uint64_t
vept_zap_range(uint64_t *tbl, int lvl, uint64_t tb, uint64_t s, uint64_t e)
{
	uint64_t span = 1ULL << (12 + 9 * lvl), lo, n = 0;
	int i, i0, i1;

	KASSERT(curthread->td_critnest == 0,
	    ("%s: shadow modificata in sezione critica", __func__));
	if (e <= tb)
		return (0);
	i0 = s > tb ? (int)((s - tb) / span) : 0;
	i1 = (int)MIN((e - tb + span - 1) / span, 512);
	for (i = i0; i < i1; i++) {
		if ((tbl[i] & EPT_RWX) == 0)
			continue;
		lo = tb + (uint64_t)i * span;
		if (lvl == 0) {
			tbl[i] = 0;
			n++;
		} else
			n += vept_zap_range((uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(tbl[i])), lvl - 1, lo, MAX(s, lo),
			    MIN(e, lo + span));
	}
	return (n);
}

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

#define	VEPT_OBS_MAX	2048		/* tabelle tracciate per radice (C2.1) */
#define	VEPT_OBS_HASH	4096		/* bucket (potenza di 2, > MAX) */

/*
 * C2.1 (parere #27 di Astra): memoria della diagnostica con conto e tetto
 * globali. Le fotografie si allocano una per tabella, quando serve, con
 * M_NOWAIT: se il tetto e' raggiunto o l'allocazione fallisce, la misura
 * della radice diventa incompleta (overflow), l'INVEPT non cambia.
 */
static int vept_diag_maxmb = 128;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_diag_maxmb, CTLFLAG_RWTUN,
    &vept_diag_maxmb, 0, "nested: tetto della memoria della diagnostica EPT12 (MB)");
static u_long vept_diag_mem, vept_diag_mem_high;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_diag_mem, CTLFLAG_RD,
    &vept_diag_mem, 0, "nested: memoria della diagnostica EPT12 (byte)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_diag_mem_high, CTLFLAG_RD,
    &vept_diag_mem_high, 0, "nested: massimo della memoria della diagnostica EPT12");
static u_long vept_diag_dist_ovf;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_diag_dist_ovf, CTLFLAG_RD,
    &vept_diag_dist_ovf, 0, "nested: tabelle distinte non registrate (insieme pieno)");

static void *
vept_diag_alloc(size_t sz)
{
	void *p;
	u_long m;

	if (atomic_fetchadd_long(&vept_diag_mem, sz) + sz >
	    (u_long)vept_diag_maxmb << 20) {
		atomic_subtract_long(&vept_diag_mem, sz);
		return (NULL);
	}
	p = malloc(sz, M_VMX_VEPT, M_NOWAIT | M_ZERO);
	if (p == NULL) {
		atomic_subtract_long(&vept_diag_mem, sz);
		return (NULL);
	}
	m = vept_diag_mem;
	if (m > vept_diag_mem_high)
		vept_diag_mem_high = m;		/* indicativo: senza CAS */
	return (p);
}

static void
vept_diag_free(void *p, size_t sz)
{
	if (p == NULL)
		return;
	free(p, M_VMX_VEPT);
	atomic_subtract_long(&vept_diag_mem, sz);
}

/*
 * C2.1: insieme CUMULATIVO delle tabelle EPT12 distinte di una radice (cioe'
 * di un EPTP12), che NON si azzera all'INVEPT: con B1 le radici vivranno a
 * lungo e le fotografie si accumuleranno. Chiave (GPA, livello, base L2-GPA),
 * ora dell'ultimo uso, epoca (= numero di svuotamenti della radice) in cui e'
 * stata vista l'ultima volta: una tabella che ricompare dopo uno svuotamento
 * e' un "riuso". Si azzera solo quando lo slot passa a un altro EPTP12.
 */
#define	VEPT_DIST_HASH	16384
struct vept_dent {
	uint64_t	gpa;		/* 0 = vuota */
	uint64_t	base;
	sbintime_t	last;
	uint32_t	epoch;
	int		level;
};
SDT_PROBE_DEFINE6(vmm, vmx, nested, veptdiag5, "int", "uint64_t", "uint64_t",
    "uint64_t", "uint64_t", "uint64_t");
/* veptdiag5(vcpu, eptp12, distinte in 1 s | 10 s << 21 | 60 s << 42,
 * distinte totali, riusi dopo uno svuotamento, tabelle tracciate ora) */

struct vept_obs_ent {
	uint64_t	gpa;		/* tabella EPT12 (GPA dell'L1); 0 = vuota */
	int		level;		/* 3 = PML4 ... 0 = PT */
	uint64_t	*snap;		/* 512 voci alla prima traversata */
	uint64_t	base;		/* C2: L2-GPA coperto dalla voce 0 */
	bool		ambiguous;	/* C2: raggiunta da piu' basi o livelli */
	int		chg_first;	/* B1: sue voci cambiate in obs->chg */
	int		chg_n;
};

/* B1: voce EPT12 cambiata, trovata dalla prima passata dell'INVEPT */
struct vept_chg {
	uint64_t	val;		/* valore letto */
	uint32_t	ent;		/* tabella: indice in obs->ent[] */
	uint32_t	j;		/* voce */
};

/* C2: intervallo L2-GPA [start, end) da invalidare in una B1 */
struct vept_rng {
	uint64_t	start, end;
};
#define	VEPT_RNG_MAX	8192

/* parere #39 §4: riferimento alla pagina di una tabella, dalla passata 1 alla 2 */
struct vept_pk {
	uint64_t	*page;
	void		*cookie;
};

struct vept_obs {
	struct vept_obs_ent ent[VEPT_OBS_HASH];
	int		n;		/* tabelle tracciate */
	uint64_t	walk_mismatch;	/* voce usata != fotografia */
	bool		overflow;	/* tetto superato: misura incompleta */
	struct vept_rng	*rng;		/* C2: buffer degli intervalli */
	struct vept_dent *dist;		/* C2.1: insieme cumulativo */
	uint32_t	epoch;		/* C2.1: svuotamenti della radice */
	uint64_t	dtotal, reuse;	/* C2.1 */
	sbintime_t	dreport;	/* C2.1: ultimo riepilogo */
	struct vmx_nested *nested;	/* B1: proprietario e slot della radice */
	int		slot;
	struct vept_chg	*chg;		/* B1: VEPT_RNG_MAX voci cambiate */
	struct vept_pk	*pk;		/* parere #39: riferimenti fra le passate */
	int		pk_live;	/* riferimenti tenuti ora */
};

static struct vept_obs *
vept_obs_get(struct vmx_nested *n, uint64_t *root)
{
	int i;

	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root == root) {
			if (n->vept_obs[i] == NULL &&
			    (n->vept_obs[i] = vept_diag_alloc(
			    sizeof(struct vept_obs))) != NULL) {
				n->vept_obs[i]->nested = n;
				n->vept_obs[i]->slot = i;
			}
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
	o->epoch++;		/* C2.1: l'insieme cumulativo resta */
	o->n = 0;
	o->walk_mismatch = 0;
	o->overflow = false;
}

/* C2.1: lo slot passa a un altro EPTP12: l'insieme cumulativo riparte. */
static void
vept_dist_clear(struct vept_obs *o)
{
	if (o == NULL || o->dist == NULL)
		return;
	memset(o->dist, 0, VEPT_DIST_HASH * sizeof(struct vept_dent));
	o->dtotal = o->reuse = 0;
}

static void
vept_obs_free(struct vept_obs *o)
{
	int i;

	if (o == NULL)
		return;
	for (i = 0; i < VEPT_OBS_HASH; i++)
		vept_diag_free(o->ent[i].snap, PAGE_SIZE);
	vept_diag_free(o->rng, VEPT_RNG_MAX * sizeof(struct vept_rng));
	vept_diag_free(o->chg, VEPT_RNG_MAX * sizeof(struct vept_chg));
	vept_diag_free(o->dist, VEPT_DIST_HASH * sizeof(struct vept_dent));
	KASSERT(o->pk_live == 0, ("%s: %d riferimenti EPT12 ancora tenuti",
	    __func__, o->pk_live));
	vept_diag_free(o->pk, VEPT_OBS_HASH * sizeof(struct vept_pk));
	vept_diag_free(o, sizeof(struct vept_obs));
}

/* C2.1: aggiorna l'insieme cumulativo delle tabelle distinte. */
static void
vept_dist_note(struct vept_obs *o, uint64_t gpa, int level, uint64_t base)
{
	struct vept_dent *d;
	uint32_t h;
	int i;

	if (o->dist == NULL && (o->dist = vept_diag_alloc(VEPT_DIST_HASH *
	    sizeof(struct vept_dent))) == NULL) {
		vept_diag_dist_ovf++;
		return;
	}
	h = (uint32_t)(((gpa >> 12) ^ (base >> 21) ^ (uint64_t)level) *
	    2654435761U);
	for (i = 0; i < 64; i++) {	/* sondaggio limitato */
		d = &o->dist[(h + i) & (VEPT_DIST_HASH - 1)];
		if (d->gpa == gpa && d->level == level && d->base == base) {
			if (d->epoch != o->epoch) {
				o->reuse++;	/* ricompare dopo uno svuotamento */
				d->epoch = o->epoch;
			}
			d->last = sbinuptime();
			return;
		}
		if (d->gpa == 0) {
			d->gpa = gpa;
			d->level = level;
			d->base = base;
			d->epoch = o->epoch;
			d->last = sbinuptime();
			o->dtotal++;
			return;
		}
	}
	vept_diag_dist_ovf++;
}

/* C2.1: al massimo una volta al secondo, tabelle distinte usate negli ultimi
 * 1, 10 e 60 secondi. */
static void
vept_dist_report(struct vmx_vcpu *vcpu, struct vept_obs *o, uint64_t eptp12)
{
	sbintime_t now = sbinuptime(), age;
	uint64_t d1 = 0, d10 = 0, d60 = 0;
	int i;

	if (o->dist == NULL || now - o->dreport < SBT_1S)
		return;
	o->dreport = now;
	for (i = 0; i < VEPT_DIST_HASH; i++) {
		if (o->dist[i].gpa == 0)
			continue;
		age = now - o->dist[i].last;
		if (age < SBT_1S)
			d1++;
		if (age < 10 * SBT_1S)
			d10++;
		if (age < 60 * SBT_1S)
			d60++;
	}
	SDT_PROBE6(vmm, vmx, nested, veptdiag5, vcpu->vcpuid, eptp12,
	    MIN(d1, 0x1fffff) | MIN(d10, 0x1fffff) << 21 |
	    MIN(d60, 0x1fffff) << 42, o->dtotal, o->reuse, o->n);
}

static void vept_walk_changed(struct vept_obs *o, struct vept_obs_ent *e,
    int idx, uint64_t val);

/*
 * Tabella EPT12 attraversata da un walk di vmx_vept_fault: prima volta,
 * fotografia; volte successive, confronto della sola voce usata. Senza B1 la
 * fotografia non si aggiorna; con B1 vept_walk_changed invalida le foglie
 * della voce vecchia e aggiorna quella sola voce.
 */
static void
vept_obs_note(struct vept_obs *o, uint64_t gpa, int level, const uint64_t *page,
    int idx, uint64_t pte, uint64_t base)
{
	struct vept_obs_ent *e;
	uint32_t h;
	int i;

	if (o == NULL || gpa == 0)
		return;
	if (vept_diag)
		vept_dist_note(o, gpa, level, base);
	h = (uint32_t)((gpa >> 12) * 2654435761U);
	for (i = 0; i < VEPT_OBS_HASH; i++) {
		e = &o->ent[(h + i) & (VEPT_OBS_HASH - 1)];
		if (e->gpa == gpa) {
			if (e->base != base || e->level != level)
				e->ambiguous = true;	/* C2: aliasing */
			if (e->snap[idx] != pte) {
				o->walk_mismatch++;
				if (o->nested != NULL && o->nested->vept_keep)
					vept_walk_changed(o, e, idx, pte);
			}
			return;
		}
		if (e->gpa == 0)
			break;
	}
	if (i == VEPT_OBS_HASH || o->n >= VEPT_OBS_MAX) {
		o->overflow = true;
		return;
	}
	if (e->snap == NULL && (e->snap = vept_diag_alloc(PAGE_SIZE)) == NULL) {
		o->overflow = true;		/* tetto di memoria: incompleta */
		return;
	}
	memcpy(e->snap, page, PAGE_SIZE);
	/* B1: la voce che il walk usa e' quella letta UNA volta dal walk;
	 * un altro LP dell'L1 puo' averla cambiata prima della copia */
	e->snap[idx] = pte;
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
#define	VEPT_FB_RACE	0x40	/* B1: tabella cambiata fra le due passate */
#define	VEPT_FB_NOKEEP	0x80	/* B1: radice non conservabile */
#define	VEPT_FB_NOMEM	0x100	/* B1: osservazioni o buffer non allocati */
#define	VEPT_FB_FORCE	0x200	/* B1: walk non tracciato (memoria, o 2 svuotamenti) */
#define	VEPT_FB_VERIFY	0x400	/* B1: verifica a campione discorde */

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
	if (o->rng == NULL &&
	    (o->rng = vept_diag_alloc(VEPT_RNG_MAX * sizeof(struct vept_rng))) ==
	    NULL)
		return;			/* tetto di memoria: niente misura */
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
	vept_dist_report(vcpu, o, eptp12);
}


/*
 * B1: un walk ha trovato la voce idx della tabella e diversa dalla fotografia
 * (il controesempio del parere #25 §3). Le foglie shadow costruite dalla voce
 * vecchia stanno tutte nel suo intervallo L2-GPA, perche' la tabella e'
 * raggiunta da una base sola: si azzerano PRIMA, poi si aggiorna quella sola
 * voce della fotografia, e il walk prosegue e installa la traduzione nuova.
 * Senza aggiornarla un A -> B -> A lascerebbe conservata una foglia fatta da
 * B. Tabella ambigua o voce di PML4: la shadow non e' piu' certificabile e si
 * svuota SUBITO (parere #29 §5), non al prossimo INVEPT dell'L1: wipe_now,
 * eseguito da vmx_vept_fault a walk finito (a meta' walk si perderebbero le
 * fotografie delle tabelle gia' annotate), prima di qualunque rientro in L2.
 */
static void
vept_walk_changed(struct vept_obs *o, struct vept_obs_ent *e, int idx,
    uint64_t val)
{
	struct vmx_nested *n = o->nested;
	struct vept_kslot *k = &n->vept_ks[o->slot];
	uint64_t span, st, z;

	if (e->ambiguous || e->level >= 3) {
		k->wipe_now = true;
		return;
	}
	span = 1ULL << (12 + 9 * e->level);
	st = e->base + (uint64_t)idx * span;
	z = vept_zap_range(n->vept_slot[o->slot].root, 3, 0, st, st + span);
	k->leaves -= z;
	if (z != 0) {
		n->vept_flush_pending = true;
		n->vept_flush_cause |= 2;	/* voci EPT12 cambiate (B1) */
	}
	e->snap[idx] = val;
	atomic_add_long(&vept_keep_walk_zaps, 1);
	atomic_add_long(&vept_keep_invalidated_leaves, z);
	atomic_add_long(&vept_leaves_zapped_walk, z);
}

static struct vept_obs_ent *
vept_obs_find(struct vept_obs *o, uint64_t gpa)
{
	struct vept_obs_ent *e;
	uint32_t h = (uint32_t)((gpa >> 12) * 2654435761U);
	int i;

	for (i = 0; i < VEPT_OBS_HASH; i++) {
		e = &o->ent[(h + i) & (VEPT_OBS_HASH - 1)];
		if (e->gpa == gpa)
			return (e);
		if (e->gpa == 0)
			break;
	}
	return (NULL);
}

/*
 * B1, verifica: lo stesso cammino di ept12_translate ma sulle FOTOGRAFIE,
 * cioe' su cio' che la conservazione assume. -1 se una tabella del cammino
 * non e' tracciata: una foglia che ne dipende non dovrebbe esistere.
 */
static int
vept_snap_translate(struct vept_obs *o, uint64_t eptp12, uint64_t l2gpa,
    uint64_t *l1gpa, uint64_t *perm)
{
	struct vept_obs_ent *e;
	uint64_t tbl_gpa = EPT_ADDR(eptp12), pte, acc = EPT_RWX, mask;
	int level;

	for (level = 3; level >= 0; level--) {
		if ((e = vept_obs_find(o, tbl_gpa)) == NULL)
			return (-1);
		pte = e->snap[EPT_IDX(l2gpa, level)];
		if ((pte & EPT_RWX) == 0)
			return (VEPT_VIOL);
		acc &= pte;
		if (level == 0 || (pte & EPT_PG_PS) != 0) {
			mask = (1ULL << (12 + 9 * level)) - 1;
			*l1gpa = (EPT_ADDR(pte) & ~mask) | (l2gpa & mask);
			*perm = acc & EPT_RWX;
			return (VEPT_OK);
		}
		tbl_gpa = EPT_ADDR(pte);
	}
	return (VEPT_VIOL);
}

/*
 * B1, hw.vmm.vmx.vept_verify_hpa: dopo un INVEPT che conserva la radice, fino
 * a VEPT_VERIFY_MAX foglie riconfrontate con il cammino sulle fotografie e con
 * l'HPA di vm_gpa_hold dell'L1-GPA (parere #28 §6). Ritorna le discordanze; il
 * chiamante allora svuota la radice.
 *
 * Parere #31 §2: i candidati non si cercano piu' percorrendo tutta la radice
 * (fino a 26 ms con ~628 k foglie) ma in un reservoir di VEPT_VS_N L2-GPA per
 * radice, campione uniforme delle foglie installate dall'ultimo svuotamento
 * (algoritmo R), azzerato a ogni svuotamento, quindi anche a ogni cambio della
 * generazione dei mapping. Solo indirizzi logici: a verifica si rifa' il
 * cammino dalla radice (profondita' 4) e una foglia non piu' presente si salta.
 * Costo O(K x D), non O(foglie vive). I candidati ruotano fra un INVEPT e
 * l'altro.
 */
#define	VEPT_VERIFY_MAX	64

static void vept_time_note(u_long *sum, u_long *max, sbintime_t from);
VEPT_CTR(vept_keep_verify_stale, "B1: candidati alla verifica senza foglia");
VEPT_CTR(vept_t_verify_ns, "B1: tempo della verifica HPA (ns)");
static u_long vept_t_verify_max_ns;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_t_verify_max_ns, CTLFLAG_RW,
    &vept_t_verify_max_ns, 0, "B1: massimo della verifica HPA (ns)");
/*
 * Prova del rilevatore (parere #31 §2), SOLO per i test: con
 * hw.vmm.vmx.vept_test_verify_corrupt=1 la verifica successiva confronta,
 * per il primo candidato, un HPA alterato di una pagina invece di quello
 * della foglia. La foglia vera non si tocca e l'L2 non gira mai con un
 * mapping sbagliato: la discordanza deve essere vista e la radice svuotata.
 */
static int vept_test_verify_corrupt = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_test_verify_corrupt, CTLFLAG_RW,
    &vept_test_verify_corrupt, 0,
    "nested: SOLO PROVE, una discordanza simulata nella prossima verifica HPA");
VEPT_CTR(vept_test_verify_injected, "B1: discordanze simulate nella verifica");

/* Reservoir dei candidati: chiamata per ogni foglia nuova (algoritmo R). */
static void
vept_vs_note(struct vept_kslot *k, uint64_t l2gpa)
{
	uint64_t x, r;

	k->vs_n++;
	if (k->vs_n <= VEPT_VS_N) {
		k->vs_gpa[k->vs_n - 1] = l2gpa;
		return;
	}
	x = k->vs_rng != 0 ? k->vs_rng :
	    0x9e3779b97f4a7c15ULL ^ (uint64_t)(uintptr_t)k;
	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	k->vs_rng = x;
	r = x % k->vs_n;
	if (r < VEPT_VS_N)
		k->vs_gpa[r] = l2gpa;
}

/* Voce foglia shadow per l2gpa nella radice, 0 se assente. */
static uint64_t
vept_leaf_get(uint64_t *tbl, uint64_t l2gpa)
{
	int level;

	for (level = 3; level > 0; level--) {
		if ((tbl[EPT_IDX(l2gpa, level)] & EPT_RWX) == 0)
			return (0);
		tbl = (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(
		    tbl[EPT_IDX(l2gpa, level)]));
	}
	return (tbl[EPT_IDX(l2gpa, 0)]);
}

static int
vept_verify(struct vmx_vcpu *vcpu, struct vept_obs *o, uint64_t eptp12,
    uint64_t *root, struct vept_kslot *k)
{
	uint64_t l2gpa, l1gpa, perm, exp, leaf, v;
	sbintime_t t0 = sbinuptime();
	int i, n, checked = 0, bad = 0, stale = 0, r;
	static int printed;
	void *p, *ck;

	n = (int)MIN(k->vs_n, VEPT_VS_N);
	for (i = 0; i < n && checked < VEPT_VERIFY_MAX; i++) {
		l2gpa = k->vs_gpa[(k->vs_start + i) % n];
		if (((leaf = vept_leaf_get(root, l2gpa)) & EPT_RWX) == 0) {
			stale++;
			continue;
		}
		checked++;
		r = vept_snap_translate(o, eptp12, l2gpa, &l1gpa, &perm);
		exp = 0;
		if (r == VEPT_OK && (p = vm_gpa_hold(vcpu->vcpu,
		    l1gpa & ~(uint64_t)PAGE_MASK, PAGE_SIZE, VM_PROT_READ,
		    &ck)) != NULL) {
			exp = DMAP_TO_PHYS((vm_offset_t)p) | (perm & EPT_RWX);
			vm_gpa_release(ck);
		}
		v = leaf & (EPT_ADDR(~0ULL) | EPT_RWX);
		if (vept_test_verify_corrupt != 0) {
			vept_test_verify_corrupt = 0;
			v ^= PAGE_SIZE;		/* HPA alterato, solo nel confronto */
			atomic_add_long(&vept_test_verify_injected, 1);
		}
		if (exp != 0 && v == exp)
			continue;
		bad++;
		SDT_PROBE5(vmm, vmx, nested, veptverify, vcpu->vcpuid, l2gpa, leaf,
		    exp, r);
		if (printed++ < 8)
			printf("nested: B1 verifica vcpu%d l2gpa %#lx foglia %#lx "
			    "attesa %#lx (r=%d)\n", vcpu->vcpuid, (u_long)l2gpa,
			    (u_long)leaf, (u_long)exp, r);
	}
	if (n > 0)
		k->vs_start = (k->vs_start + VEPT_VERIFY_MAX) % n;
	atomic_add_long(&vept_keep_verify_checked, checked);
	atomic_add_long(&vept_keep_verify_stale, stale);
	atomic_add_long(&vept_keep_verify_mismatch, bad);
	vept_time_note(&vept_t_verify_ns, &vept_t_verify_max_ns, t0);
	return (bad);
}

static void vept_root_wipe(struct vmx_nested *n, int i);

/*
 * B1, retry delle due passate (parere #29 §2). vept_scan_retries: tentativi
 * in piu' dopo una corsa, 0..VEPT_MAX_SCAN_RETRIES (0 = come 0d5bd14).
 * vept_scan_budget_us: oltre questo tempo dall'inizio dell'INVEPT non si
 * ritenta piu'.
 */
#define	VEPT_MAX_SCAN_RETRIES	2
static int vept_scan_retries = 1;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_scan_retries, CTLFLAG_RWTUN,
    &vept_scan_retries, 0,
    "nested: B1, nuovi tentativi delle due passate dopo una corsa (0..2)");
static int vept_scan_budget_us = 2000;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_scan_budget_us, CTLFLAG_RWTUN,
    &vept_scan_budget_us, 0,
    "nested: B1, oltre questi us dall'inizio dell'INVEPT niente retry");
VEPT_CTR(vept_scan_first_pass_ok, "B1: validazione riuscita al primo tentativo");
VEPT_CTR(vept_scan_retry_1_success, "B1: validazione riuscita al 1o retry");
VEPT_CTR(vept_scan_retry_2_success, "B1: validazione riuscita al 2o retry");
VEPT_CTR(vept_scan_retry_exhausted, "B1: svuotamento per corsa dopo i retry");
VEPT_CTR(vept_scan_retry_nonrace_fallback,
    "B1: svuotamento per altro motivo durante un retry");
VEPT_CTR(vept_scan_retry_budget_fallback,
    "B1: svuotamento per budget di tempo esaurito");
VEPT_CTR(vept_scan_retries_done, "B1: retry eseguiti");
VEPT_CTR(vept_scan_bytes_read, "B1: byte di EPT12 letti dalle due passate");
/*
 * Parere #30 §2: tempi per fase (somme in ns, massimi azzerabili) e, per
 * tentativo, tempo delle due passate e foglie conservate dai successi: le
 * foglie salvate dal retry n sono quelle che il retry n-1 avrebbe perso.
 * Il budget vept_scan_budget_us e' un tetto sul tempo TOTALE dall'inizio
 * dell'INVEPT, controllato prima di ogni nuovo tentativo: non si moltiplica
 * per i tentativi, ma non interrompe un tentativo gia' iniziato.
 */
VEPT_CTR(vept_t_scan_ns, "B1: tempo nelle due passate, tutti i tentativi (ns)");
VEPT_CTR(vept_t_partial_ns, "B1: tempo di invalidazione parziale e commit (ns)");
VEPT_CTR(vept_t_full_ns, "B1: tempo di svuotamento nei fallback (ns)");
VEPT_CTR(vept_t_attempt0_ns, "B1: tempo delle passate, primo tentativo (ns)");
VEPT_CTR(vept_t_attempt1_ns, "B1: tempo delle passate, 1o retry (ns)");
VEPT_CTR(vept_t_attempt2_ns, "B1: tempo delle passate, 2o retry (ns)");
VEPT_CTR(vept_retry_1_leaves_saved, "B1: foglie conservate da successi al 1o retry");
VEPT_CTR(vept_retry_2_leaves_saved, "B1: foglie conservate da successi al 2o retry");
VEPT_CTR(vept_retry_1_leaves_invalidated,
    "B1: foglie invalidate dai successi al 1o retry");
VEPT_CTR(vept_retry_2_leaves_invalidated,
    "B1: foglie invalidate dai successi al 2o retry");
static u_long vept_t_scan_max_ns, vept_t_partial_max_ns, vept_t_full_max_ns;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_t_scan_max_ns, CTLFLAG_RW,
    &vept_t_scan_max_ns, 0, "B1: massimo delle due passate (ns)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_t_partial_max_ns, CTLFLAG_RW,
    &vept_t_partial_max_ns, 0, "B1: massimo dell'invalidazione parziale (ns)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_t_full_max_ns, CTLFLAG_RW,
    &vept_t_full_max_ns, 0, "B1: massimo dello svuotamento (ns)");

static void
vept_time_note(u_long *sum, u_long *max, sbintime_t from)
{
	u_long ns = (u_long)sbttons(sbinuptime() - from);

	atomic_add_long(sum, ns);
	if (max != NULL && ns > *max)
		*max = ns;			/* indicativo: senza CAS */
}
static u_long vept_scan_max_ns;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vept_scan_max_ns, CTLFLAG_RW,
    &vept_scan_max_ns, 0, "B1: durata massima di un INVEPT (ns, 0 per azzerare)");

static void
vept_scan_note_ns(sbintime_t t0)
{
	u_long ns = (u_long)sbttons(sbinuptime() - t0);

	if (ns > vept_scan_max_ns)
		vept_scan_max_ns = ns;		/* indicativo: senza CAS */
}

/*
 * Prova deterministica della corsa (parere #29 §7), SOLO per i test:
 * hw.vmm.vmx.vept_test_race = 1 una volta, 2 a ogni tentativo. Fra la prima
 * e la seconda passata L0 fa cio' che farebbe un altro LP dell'L1: inverte
 * il bit W di una voce EPT12 di livello 0 invariata, scrivibile e con una
 * foglia shadow viva. La seconda passata deve vedere la corsa; il retry deve
 * incorporare la modifica (foglia invalidata, le altre conservate).
 */
static int vept_test_race = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_test_race, CTLFLAG_RW,
    &vept_test_race, 0,
    "nested: SOLO PROVE, scrittura EPT12 fra le passate (1 una volta, 2 sempre)");
VEPT_CTR(vept_test_race_injected, "B1: scritture iniettate fra le passate");

/*
 * Parere #39 §5, §6.2, §7: contatori del percorso EPT02 (fault, walk EPT12) e
 * degli hold delle tabelle EPT12, contati per vCPU in vmx_nested.st_vept[]
 * (niente variabili condivise nel percorso caldo) e versati qui dallo slow path
 * (nested_stats_flush). Bilancio: vst_h_release == somma degli hold contati -
 * vst_h_null.
 */
CTASSERT(VST_N <= nitems(((struct vmx_nested *)0)->st_vept));
static u_long vept_st_tot[VST_N];
static u_long vept_st_pk_peak;
#define	VST_SYSCTL(i, name, descr)					\
	SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, name, CTLFLAG_RD,		\
	    &vept_st_tot[i], 0, descr)
VST_SYSCTL(VST_FAULT, vst_fault, "EPT02: fault arrivati a vmx_vept_fault");
VST_SYSCTL(VST_F_RAM, vst_f_ram, "EPT02: foglie RAM installate");
VST_SYSCTL(VST_F_MMIO, vst_f_mmio, "EPT02: foglie MMIO (BAR) installate");
VST_SYSCTL(VST_F_VIOL_MISSING, vst_f_viol_missing, "EPT02: EPT12 non mappa (riflessa)");
VST_SYSCTL(VST_F_VIOL_PERM, vst_f_viol_perm, "EPT02: EPT12 nega l'accesso (riflessa)");
VST_SYSCTL(VST_F_MISCONF, vst_f_misconf, "EPT02: EPT12 malformata (riflessa)");
VST_SYSCTL(VST_F_EMUL, vst_f_emul, "EPT02: MMIO dell'L1, emulazione");
VST_SYSCTL(VST_F_UNREAD, vst_f_unread, "EPT02: tabella EPT12 illeggibile");
VST_SYSCTL(VST_F_REINSTALL, vst_f_reinstall, "EPT02: foglia gia' presente riscritta");
VST_SYSCTL(VST_WALK, vst_walk, "EPT12: walk (fault ed emulazione)");
VST_SYSCTL(VST_WALK_D1, vst_walk_d1, "EPT12: walk fermati al 1o livello");
VST_SYSCTL(VST_WALK_D2, vst_walk_d2, "EPT12: walk fermati al 2o livello");
VST_SYSCTL(VST_WALK_D3, vst_walk_d3, "EPT12: walk fermati al 3o livello");
VST_SYSCTL(VST_WALK_D4, vst_walk_d4, "EPT12: walk fino al 4o livello");
VST_SYSCTL(VST_H_WALK3, vst_h_walk3, "hold EPT12 del walk, livello 3 (PML4)");
VST_SYSCTL(VST_H_WALK2, vst_h_walk2, "hold EPT12 del walk, livello 2");
VST_SYSCTL(VST_H_WALK1, vst_h_walk1, "hold EPT12 del walk, livello 1");
VST_SYSCTL(VST_H_WALK0, vst_h_walk0, "hold EPT12 del walk, livello 0");
VST_SYSCTL(VST_H_L1PAGE, vst_h_l1page, "hold della pagina dell'L1-GPA (fault)");
VST_SYSCTL(VST_H_SCAN1, vst_h_scan1, "hold della passata 1 di B1");
VST_SYSCTL(VST_H_SCAN2, vst_h_scan2, "hold della passata 2 di B1");
VST_SYSCTL(VST_H_SCAN2_REUSE, vst_h_scan2_reuse,
    "passata 2 di B1: riferimento della passata 1 riusato (hold evitati)");
VST_SYSCTL(VST_H_NULL, vst_h_null, "hold contati falliti (NULL)");
VST_SYSCTL(VST_H_RELEASE, vst_h_release, "rilasci contati");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vst_pk_peak, CTLFLAG_RD, &vept_st_pk_peak, 0,
    "B1: massimo di riferimenti tenuti fra le passate da un gestore");
VST_SYSCTL(VST_T_EXIT_L1, vst_t_exit_l1, "vmx_run: cicli a interrupt disabilitati dopo un'uscita dall'L1");
VST_SYSCTL(VST_T_EXIT_L1_N, vst_t_exit_l1_n, "vmx_run: uscite dall'L1 misurate");
VST_SYSCTL(VST_T_EXIT_L2, vst_t_exit_l2, "vmx_run: cicli a interrupt disabilitati dopo un'uscita dall'L2");
VST_SYSCTL(VST_T_EXIT_L2_N, vst_t_exit_l2_n, "vmx_run: uscite dall'L2 misurate");
VST_SYSCTL(VST_T_ENT_L1, vst_t_ent_l1, "vmx_run: cicli a interrupt disabilitati prima di entrare in L1");
VST_SYSCTL(VST_T_ENT_L1_N, vst_t_ent_l1_n, "vmx_run: ingressi in L1 misurati");
VST_SYSCTL(VST_T_ENT_L2, vst_t_ent_l2, "vmx_run: cicli a interrupt disabilitati prima di entrare in L2");
VST_SYSCTL(VST_T_ENT_L2_N, vst_t_ent_l2_n, "vmx_run: ingressi in L2 misurati");
VST_SYSCTL(VST_T_EXIT_B0, vst_t_exit_b0, "tratto d'uscita < 1 us");
VST_SYSCTL(VST_T_EXIT_B1, vst_t_exit_b1, "tratto d'uscita 1-5 us");
VST_SYSCTL(VST_T_EXIT_B2, vst_t_exit_b2, "tratto d'uscita 5-20 us");
VST_SYSCTL(VST_T_EXIT_B3, vst_t_exit_b3, "tratto d'uscita >= 20 us");
VST_SYSCTL(VST_T_ENT_B0, vst_t_ent_b0, "tratto d'ingresso < 1 us");
VST_SYSCTL(VST_T_ENT_B1, vst_t_ent_b1, "tratto d'ingresso 1-5 us");
VST_SYSCTL(VST_T_ENT_B2, vst_t_ent_b2, "tratto d'ingresso 5-20 us");
VST_SYSCTL(VST_T_ENT_B3, vst_t_ent_b3, "tratto d'ingresso >= 20 us");
VST_SYSCTL(VST_T_RDTSC, vst_t_rdtsc, "cicli di due rdtsc di fila (campione 1/256)");
VST_SYSCTL(VST_T_RDTSC_N, vst_t_rdtsc_n, "campioni di vst_t_rdtsc");
static u_long vept_st_tmax[4];
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vst_tmax_exit_l1, CTLFLAG_RD, &vept_st_tmax[0], 0,
    "vmx_run: massimo del tratto d'uscita dall'L1 (cicli)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vst_tmax_exit_l2, CTLFLAG_RD, &vept_st_tmax[1], 0,
    "vmx_run: massimo del tratto d'uscita dall'L2 (cicli)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vst_tmax_ent_l1, CTLFLAG_RD, &vept_st_tmax[2], 0,
    "vmx_run: massimo del tratto d'ingresso in L1 (cicli)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, vst_tmax_ent_l2, CTLFLAG_RD, &vept_st_tmax[3], 0,
    "vmx_run: massimo del tratto d'ingresso in L2 (cicli)");

/*
 * Parere #41 §6: un tratto di vmx_run a interrupt disabilitati, per vCPU (gira con
 * gli interrupt spenti, sul vCPU stesso: niente atomiche). base = somma, base+1 =
 * conteggio; bucket0 = prima delle quattro classi; imax = indice del massimo.
 */
static uint64_t vst_cicli_us;		/* cicli TSC per microsecondo, al primo uso */

void
vst_tratto(struct vmx_nested *n, int base, int bucket0, int imax, uint64_t c)
{
	uint64_t f = vst_cicli_us;

	if (__predict_false(f == 0))
		f = vst_cicli_us = MAX(tsc_freq / 1000000, 1);
	n->st_vept[base] += c;
	n->st_vept[base + 1]++;
	n->st_vept[bucket0 + (c < f ? 0 : c < 5 * f ? 1 : c < 20 * f ? 2 : 3)]++;
	if (c > n->st_tmax[imax])
		n->st_tmax[imax] = c;
}

void
vept_stats_flush(struct vmx_nested *n)
{
	u_long p;
	int i;

	for (i = 0; i < VST_N; i++) {
		if (n->st_vept[i] != 0) {
			atomic_add_long(&vept_st_tot[i], n->st_vept[i]);
			n->st_vept[i] = 0;
		}
	}
	while ((p = vept_st_pk_peak) < n->st_vept_pk_peak &&
	    !atomic_cmpset_long(&vept_st_pk_peak, p, n->st_vept_pk_peak))
		;
	for (i = 0; i < 4; i++) {
		while ((p = vept_st_tmax[i]) < n->st_tmax[i] &&
		    !atomic_cmpset_long(&vept_st_tmax[i], p, n->st_tmax[i]))
			;
	}
}

/* Hold e rilascio CONTATI (i soli siti del parere #39): vedi il bilancio sopra. */
static uint64_t *
vept_hold(struct vmx_vcpu *vcpu, uint64_t gpa, void **cookie, int site)
{
	uint64_t *p;

	p = vm_gpa_hold(vcpu->vcpu, gpa, PAGE_SIZE, VM_PROT_READ, cookie);
	vcpu->nested->st_vept[site]++;
	if (p == NULL)
		vcpu->nested->st_vept[VST_H_NULL]++;
	return (p);
}

static void
vept_rel(struct vmx_vcpu *vcpu, void *cookie)
{
	vm_gpa_release(cookie);
	vcpu->nested->st_vept[VST_H_RELEASE]++;
}

/*
 * Parere #39 §4: con vept_scan_hold_keep=1 la passata 1 di B1 conserva il
 * riferimento alla pagina di ogni tabella e la passata 2 lo riusa invece di
 * rifare l'hold. Le passate restano DUE, complete e distinte, e la seconda
 * RILEGGE le voci (atomic_load_64 sulla pagina): si risparmia solo l'hold. La
 * pagina e' la stessa che darebbe un nuovo hold: il GPA della tabella (e->gpa)
 * cambia solo nei walk dello stesso vCPU, che non girano durante il gestore, e
 * il mapping GPA->HPA cambia solo con tutti i vCPU IDLE (generazione dei
 * mapping). Tutti i riferimenti si rilasciano alla fine di OGNI tentativo,
 * anche su corsa, budget o errore; un retry li riprende da capo. Se il buffer
 * dei riferimenti non si alloca, il gestore lavora come con 0.
 */
static int vept_scan_hold_keep = 0;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, vept_scan_hold_keep, CTLFLAG_RWTUN,
    &vept_scan_hold_keep, 0,
    "nested: B1, la passata 2 riusa il riferimento della 1 (0 = no)");

/* rilascia i riferimenti tenuti dalla passata 1 e non ancora consumati */
static void
vept_pk_release(struct vmx_vcpu *vcpu, struct vept_obs *o)
{
	int t;

	for (t = 0; t < VEPT_OBS_HASH; t++) {
		if (o->pk[t].cookie != NULL) {
			vept_rel(vcpu, o->pk[t].cookie);
			o->pk[t].cookie = NULL;
			o->pk[t].page = NULL;
		}
	}
	o->pk_live = 0;
}

static bool
vept_leaf_present(uint64_t *tbl, uint64_t l2gpa)
{
	int level;

	for (level = 3; level > 0; level--) {
		if ((tbl[EPT_IDX(l2gpa, level)] & EPT_RWX) == 0)
			return (false);
		tbl = (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(
		    tbl[EPT_IDX(l2gpa, level)]));
	}
	return ((tbl[EPT_IDX(l2gpa, 0)] & EPT_RWX) != 0);
}

static void
vept_test_race_inject(struct vmx_vcpu *vcpu, struct vept_obs_ent *e, int j)
{
	uint64_t *page;
	void *ck;

	page = vm_gpa_hold(vcpu->vcpu, e->gpa, PAGE_SIZE,
	    VM_PROT_READ | VM_PROT_WRITE, &ck);
	if (page == NULL)
		return;
	if (atomic_load_64(&page[j]) & EPT_PG_WRITE)
		atomic_clear_64(&page[j], EPT_PG_WRITE);
	else
		atomic_set_64(&page[j], EPT_PG_WRITE);
	vm_gpa_release(ck);
	atomic_add_long(&vept_test_race_injected, 1);
	if (vept_test_race == 1)
		vept_test_race = 0;
}

/*
 * B1: INVEPT dell'L1 che colpisce la radice dello slot i. Ritorna true se la
 * radice e' stata conservata, false se svuotata.
 *  1. prima passata: per ogni tabella tracciata, le voci diverse dalla
 *     fotografia; ognuna da' un intervallo L2-GPA (2^(12+9L) alla base della
 *     tabella) e va nella lista dei cambi, col valore letto;
 *  2. seconda passata: si rileggono TUTTE le tabelle tracciate, anche quelle
 *     trovate invariate, e devono valere fotografia + cambi; se no un altro
 *     LP dell'L1 sta scrivendo mentre si legge (parere #28 §3: rilevatore
 *     conservativo, non una prova di atomicita'): si rifanno 1 e 2 fino a
 *     vept_scan_retries volte, poi si svuota tutto;
 *  3. intervalli ordinati e uniti, foglie shadow azzerate, INVEPT hw dovuto;
 *  4. solo allora, nelle fotografie, le sole voci cambiate.
 * Una scrittura dopo la seconda passata la vedra' il prossimo INVEPT, che
 * l'L1 deve comunque fare per renderla visibile.
 */
static bool
vept_keep_invept(struct vmx_vcpu *vcpu, int i)
{
	struct vmx_nested *n = vcpu->nested;
	struct vept_slot *s = &n->vept_slot[i];
	struct vept_kslot *k = &n->vept_ks[i];
	struct vept_obs *o = n->vept_obs[i];
	struct vept_obs_ent *e;
	uint64_t *page, span, expect, v, live = k->leaves, inval = 0, bytes = 0;
	sbintime_t t0 = sbinuptime(), ts, ta, tp;
	void *cookie;
	int fb = 0, nr = 0, nc = 0, t, j, c, m, ntr = 0;
	int attempt = 0, retries, inj_t, inj_j;
	bool keep_ref = false;		/* parere #39 §4 */

	KASSERT(curthread->td_critnest == 0,
	    ("%s: shadow modificata in sezione critica", __func__));
	if (k->nokeep)
		fb |= VEPT_FB_NOKEEP;
	if (k->force_full)
		fb |= VEPT_FB_FORCE;
	if (o == NULL)
		fb |= VEPT_FB_NOMEM;
	else {
		ntr = o->n;
		if (o->overflow)
			fb |= VEPT_FB_OVERFL;
		if (o->rng == NULL)
			o->rng = vept_diag_alloc(VEPT_RNG_MAX *
			    sizeof(struct vept_rng));
		if (o->chg == NULL)
			o->chg = vept_diag_alloc(VEPT_RNG_MAX *
			    sizeof(struct vept_chg));
		if (o->rng == NULL || o->chg == NULL)
			fb |= VEPT_FB_NOMEM;
	}
	if (fb != 0)
		goto full;

	/*
	 * 1 + 2, ripetute al massimo vept_scan_retries volte se la seconda
	 * passata trova una corsa (parere #29 §2). Ogni tentativo riparte dalle
	 * fotografie PERSISTENTI, che nessun tentativo modifica: snapshot A,
	 * prima lettura B, seconda C -> il tentativo dopo trova A -> C, non
	 * B -> C. Shadow e fotografie si toccano solo dopo una validazione
	 * riuscita. Oltre il budget di tempo, svuotamento.
	 */
	retries = MIN(MAX(vept_scan_retries, 0), VEPT_MAX_SCAN_RETRIES);
	/* parere #39 §4: deciso una volta per gestore, uguale per ogni tentativo */
	keep_ref = vept_scan_hold_keep != 0;
	if (keep_ref && o->pk == NULL &&
	    (o->pk = vept_diag_alloc(VEPT_OBS_HASH * sizeof(struct vept_pk))) == NULL)
		keep_ref = false;
	KASSERT(o->pk == NULL || o->pk_live == 0,
	    ("%s: riferimenti EPT12 rimasti da un gestore precedente", __func__));
	ts = sbinuptime();
	for (attempt = 0;; attempt++) {
		ta = sbinuptime();
		nc = 0;
		inj_t = -1;
		inj_j = 0;
		/* 1. voci cambiate */
		for (t = 0; t < VEPT_OBS_HASH && fb == 0; t++) {
			e = &o->ent[t];
			e->chg_first = nc;
			e->chg_n = 0;
			if (e->gpa == 0)
				continue;
			page = vept_hold(vcpu, e->gpa, &cookie, VST_H_SCAN1);
			if (page == NULL) {
				fb |= VEPT_FB_UNREAD;
				break;
			}
			bytes += PAGE_SIZE;
			span = 1ULL << (12 + 9 * (e->level & 3));
			for (j = 0; j < 512; j++) {
				v = atomic_load_64(&page[j]);
				if (v == e->snap[j]) {
					if (vept_test_race != 0 && inj_t < 0 &&
					    e->level == 0 && !e->ambiguous &&
					    (v & EPT_PG_WRITE) != 0 &&
					    vept_leaf_present(s->root, e->base +
					    (uint64_t)j * PAGE_SIZE)) {
						inj_t = t;
						inj_j = j;
					}
					continue;
				}
				if (e->ambiguous)
					fb |= VEPT_FB_AMBIG;
				else if (e->level >= 3)
					fb |= VEPT_FB_L3;
				else if (nc >= VEPT_RNG_MAX)
					fb |= VEPT_FB_NRNG;
				if (fb != 0)
					break;
				o->chg[nc].val = v;
				o->chg[nc].ent = t;
				o->chg[nc].j = j;
				o->rng[nc].start = e->base + (uint64_t)j * span;
				o->rng[nc].end = o->rng[nc].start + span;
				nc++;
			}
			if (keep_ref) {
				/* il riferimento passa alla passata 2 (o al rilascio) */
				o->pk[t].page = page;
				o->pk[t].cookie = cookie;
				if (++o->pk_live > (int)n->st_vept_pk_peak)
					n->st_vept_pk_peak = o->pk_live;
			} else
				vept_rel(vcpu, cookie);
			e->chg_n = nc - e->chg_first;
		}
		if (fb != 0) {
			if (keep_ref)
				vept_pk_release(vcpu, o);	/* niente passata 2 */
			break;
		}

		/* prova del parere #29 §7: un "altro LP" scrive fra le passate */
		if (inj_t >= 0)
			vept_test_race_inject(vcpu, &o->ent[inj_t], inj_j);

		/* 2. rilettura di tutte le tabelle (le voci si RILEGGONO sempre) */
		for (t = 0; t < VEPT_OBS_HASH && fb == 0; t++) {
			e = &o->ent[t];
			if (e->gpa == 0)
				continue;
			if (keep_ref && o->pk[t].cookie != NULL) {
				page = o->pk[t].page;
				cookie = o->pk[t].cookie;
				o->pk[t].page = NULL;
				o->pk[t].cookie = NULL;
				o->pk_live--;
				n->st_vept[VST_H_SCAN2_REUSE]++;
			} else
				page = vept_hold(vcpu, e->gpa, &cookie, VST_H_SCAN2);
			if (page == NULL) {
				fb |= VEPT_FB_UNREAD;
				break;
			}
			bytes += PAGE_SIZE;
			c = e->chg_first;
			m = c + e->chg_n;
			for (j = 0; j < 512; j++) {
				expect = (c < m && o->chg[c].j == (uint32_t)j) ?
				    o->chg[c++].val : e->snap[j];
				if (atomic_load_64(&page[j]) != expect) {
					fb |= VEPT_FB_RACE;
					break;
				}
			}
			vept_rel(vcpu, cookie);
		}
		/* fine del tentativo: i riferimenti non consumati (corsa a meta'
		 * passata 2, tabella illeggibile) si rilasciano QUI, sempre */
		if (keep_ref)
			vept_pk_release(vcpu, o);
		vept_time_note(attempt == 0 ? &vept_t_attempt0_ns :
		    attempt == 1 ? &vept_t_attempt1_ns : &vept_t_attempt2_ns,
		    NULL, ta);
		if (fb != VEPT_FB_RACE || attempt >= retries)
			break;
		if (sbttons(sbinuptime() - t0) > (int64_t)vept_scan_budget_us *
		    1000) {
			atomic_add_long(&vept_scan_retry_budget_fallback, 1);
			break;
		}
		atomic_add_long(&vept_scan_retries_done, 1);
		fb = 0;			/* nuova transazione dalle fotografie */
	}
	atomic_add_long(&vept_scan_bytes_read, bytes);
	vept_time_note(&vept_t_scan_ns, &vept_t_scan_max_ns, ts);
	tp = sbinuptime();
	if (fb != 0) {
		if (fb == VEPT_FB_RACE && attempt > 0)
			atomic_add_long(&vept_scan_retry_exhausted, 1);
		else if (attempt > 0)
			atomic_add_long(&vept_scan_retry_nonrace_fallback, 1);
		goto full;
	}
	atomic_add_long(attempt == 0 ? &vept_scan_first_pass_ok :
	    attempt == 1 ? &vept_scan_retry_1_success :
	    &vept_scan_retry_2_success, 1);

	/* 3. intervalli uniti, foglie azzerate */
	nr = nc;
	if (nr > 1) {
		qsort(o->rng, nr, sizeof(struct vept_rng), vept_rng_cmp);
		for (c = 0, j = 1; j < nr; j++) {
			if (o->rng[j].start <= o->rng[c].end) {
				if (o->rng[j].end > o->rng[c].end)
					o->rng[c].end = o->rng[j].end;
			} else
				o->rng[++c] = o->rng[j];
		}
		nr = c + 1;
	}
	for (j = 0; j < nr; j++)
		inval += vept_zap_range(s->root, 3, 0, o->rng[j].start,
		    o->rng[j].end);
	k->leaves -= inval;
	if (inval != 0) {
		n->vept_flush_pending = true;
		n->vept_flush_cause |= 1;	/* INVEPT di L1 */
	}

	/* 4. fotografie: solo le voci cambiate, dopo le invalidazioni */
	for (c = 0; c < nc; c++)
		o->ent[o->chg[c].ent].snap[o->chg[c].j] = o->chg[c].val;

	if (vept_verify_hpa && vept_verify(vcpu, o, s->eptp12, s->root, k) != 0) {
		fb |= VEPT_FB_VERIFY;
		goto full;
	}
	vept_time_note(&vept_t_partial_ns, &vept_t_partial_max_ns, tp);
	if (attempt == 1) {
		atomic_add_long(&vept_retry_1_leaves_saved, k->leaves);
		atomic_add_long(&vept_retry_1_leaves_invalidated, inval);
	} else if (attempt == 2) {
		atomic_add_long(&vept_retry_2_leaves_saved, k->leaves);
		atomic_add_long(&vept_retry_2_leaves_invalidated, inval);
	}
	atomic_add_long(&vept_keep_partial_invepts, 1);
	atomic_add_long(&vept_keep_retained_leaves, k->leaves);
	atomic_add_long(&vept_keep_invalidated_leaves, inval);
	atomic_add_long(&vept_leaves_zapped_partial, inval);
	SDT_PROBE6(vmm, vmx, nested, veptkeep, vcpu->vcpuid, s->eptp12, live,
	    inval, (uint64_t)nr | (uint64_t)nc << 32, VEPT_KEEP_A5(0, ntr, t0));
	vept_scan_note_ns(t0);
	return (true);

full:
	atomic_add_long(&vept_keep_full_fallbacks, 1);
	if (fb & VEPT_FB_RACE)
		atomic_add_long(&vept_keep_scan_race_fallbacks, 1);
	atomic_add_long(&vept_keep_invalidated_leaves, live);
	atomic_add_long((fb & VEPT_FB_RACE) ? &vept_leaves_zapped_race :
	    (fb & VEPT_FB_AMBIG) ? &vept_leaves_zapped_alias :
	    (fb & (VEPT_FB_OVERFL | VEPT_FB_NRNG | VEPT_FB_NOMEM)) ?
	    &vept_leaves_zapped_capacity :
	    (fb & VEPT_FB_NOKEEP) ? &vept_leaves_zapped_backing :
	    (fb & VEPT_FB_FORCE) ? &vept_leaves_zapped_force :
	    &vept_leaves_zapped_other, live);
	SDT_PROBE6(vmm, vmx, nested, veptkeep, vcpu->vcpuid, s->eptp12, live,
	    live, (uint64_t)nr | (uint64_t)nc << 32, VEPT_KEEP_A5(fb, ntr, t0));
	tp = sbinuptime();
	vept_root_wipe(n, i);
	vept_time_note(&vept_t_full_ns, &vept_t_full_max_ns, tp);
	vept_scan_note_ns(t0);
	return (false);
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

	if (n->vept_keep)
		vmx_vept_memgen_sync(vcpu);	/* prima di riusare una radice */
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
			pick->root = vept_page_alloc();
		else {
			atomic_add_long(&vept_leaves_zapped_lru,
			    n->vept_ks[pick - n->vept_slot].leaves);
			vept_root_wipe(n, pick - n->vept_slot);
			vept_dist_clear(n->vept_obs[pick - n->vept_slot]);
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

/* Svuota la radice dello slot i e le sue osservazioni (l'insieme cumulativo
 * della diagnostica resta: si azzera solo se lo slot cambia EPTP12). */
static void
vept_root_wipe(struct vmx_nested *n, int i)
{
	vept_wipe(n->vept_slot[i].root);
	vept_obs_reset(n->vept_obs[i]);
	n->vept_ks[i].leaves = 0;
	n->vept_ks[i].nokeep = false;
	n->vept_ks[i].force_full = false;
	n->vept_ks[i].wipe_now = false;
	n->vept_ks[i].vs_n = 0;		/* reservoir della verifica */
	n->vept_ks[i].vs_start = 0;
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
vmx_vept_invept(struct vmx_vcpu *vcpu, uint64_t type, uint64_t eptp, int *kept)
{
	struct vmx_nested *n = vcpu->nested;
	struct vept_slot *s;
	int i, wiped = 0;

	*kept = 0;
	atomic_add_long(type == 1 ? &vept_invept_single : &vept_invept_all, 1);
	for (i = 0; i < VEPT_NROOTS; i++) {
		s = &n->vept_slot[i];
		if (s->root == NULL)
			continue;
		if (type == 1 && (s->eptp12 & VEPT_EPTP_BASE) !=
		    (eptp & VEPT_EPTP_BASE)) {
			atomic_add_long(&vept_invept_roots_unmatched, 1);
			continue;
		}
		atomic_add_long(&vept_invept_roots_matched, 1);
		if (vept_diag)		/* fase C: solo misura, PRIMA di svuotare */
			vept_obs_scan(vcpu, n->vept_obs[i], s->eptp12,
			    s->root);
		if (n->vept_keep) {	/* B1: conservata o svuotata */
			if (!vept_keep_invept(vcpu, i)) {
				wiped++;
				atomic_add_long(&vept_invept_roots_fallback, 1);
			} else {
				(*kept)++;
				atomic_add_long(&vept_invept_roots_kept, 1);
			}
			continue;
		}
		atomic_add_long(&vept_leaves_zapped_keep0, n->vept_ks[i].leaves);
		atomic_add_long(&vept_invept_roots_fallback, 1);
		vept_root_wipe(n, i);
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
	vept_page_free(tbl);
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
		memset(&n->vept_ks[i], 0, sizeof(n->vept_ks[i]));
	}
	n->vept_flush_pending = false;
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
	vcpu->nested->st_vept[VST_WALK]++;
	for (level = 3; level >= 0; level--) {
		idx = EPT_IDX(l2gpa, level);
		page = vept_hold(vcpu, tbl_gpa, &cookie, VST_H_WALK3 + (3 - level));
		if (page == NULL)
			return (-1);
		/* parere #39 §5: profondita' = tabelle lette, contata all'ultima */
		if (level == 0)
			vcpu->nested->st_vept[VST_WALK_D4]++;
		/* una sola lettura: la memoria dell'L1 puo' cambiare sotto */
		pte = atomic_load_64(&page[idx]);
		vept_obs_note(obs, tbl_gpa, level, page, idx, pte, level >= 3 ?
		    0 : l2gpa & ~((1ULL << (12 + 9 * (level + 1))) - 1));
		vept_rel(vcpu, cookie);
		if (level > 0 && ((pte & EPT_RWX) == 0 || (pte & 0x3) == 0x2 ||
		    (pte & EPT_PG_PS) != 0))
			vcpu->nested->st_vept[VST_WALK_D1 + (3 - level)]++;
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
vept_install(struct vmx_nested *n, struct vept_kslot *k, uint64_t l2gpa,
    uint64_t hpa, uint64_t perm, int mt)
{
	uint64_t *tbl = n->vept_root;
	int level, idx;

	for (level = 3; level > 0; level--) {
		idx = EPT_IDX(l2gpa, level);
		if ((tbl[idx] & EPT_RWX) == 0) {
			uint64_t *np = vept_page_alloc();
			tbl[idx] = vtophys(np) | EPT_RWX;
		}
		tbl = (uint64_t *)PHYS_TO_DMAP(EPT_ADDR(tbl[idx]));
	}
	idx = EPT_IDX(l2gpa, 0);
	if ((tbl[idx] & EPT_RWX) == 0) {
		k->leaves++;
		if (vept_verify_hpa)
			vept_vs_note(k, l2gpa);	/* candidati della verifica */
	} else
		n->st_vept[VST_F_REINSTALL]++;	/* parere #39 §5 */
	tbl[idx] = (hpa & ~0xfffULL) | (perm & EPT_RWX) |
	    EPT_PG_MEMORY_TYPE(mt) | EPT_PG_IGNORE_PAT;
	return (0);
}

/* Slot della radice corrente (vept_root non NULL). */
static int
vept_cur_slot(struct vmx_nested *n)
{
	int i;

	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root == n->vept_root)
			return (i);
	panic("%s: radice corrente %p senza slot", __func__, n->vept_root);
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
	struct vept_kslot *k;
	struct vept_obs *obs = NULL;
	uint64_t eptp12, hpa, access;
	void *p, *ck;
	int r;

	/*
	 * SLOW PATH (vCPU FROZEN, nessun VMCS caricato): qui si puo' dormire
	 * (vm_gpa_hold, malloc M_WAITOK). Esiti: VEPT_OK shadow installata,
	 * si riparte in L2; VEPT_VIOL / VEPT_MISCONF da riflettere all'L1;
	 * VEPT_MMIO l'L1 mappa l'L2 su un suo indirizzo che non e' RAM.
	 */
	n->st_vept[VST_FAULT]++;		/* parere #39 §5 */
	if (c == NULL)
		return (VEPT_VIOL);
	eptp12 = vmcs12_read_field(c, VMCS_EPTP);
	if (n->vept_root == NULL || n->vept_eptp12 != eptp12)
		vmx_vept_prepare(vcpu);		/* allinea radice ed EPTP12 */
	k = &n->vept_ks[vept_cur_slot(n)];

	/* B1: un walk non tracciato rende la radice non conservabile fino al
	 * prossimo svuotamento */
	if (vept_diag || n->vept_keep) {
		obs = vept_obs_get(n, n->vept_root);
		if (obs == NULL && n->vept_keep)
			k->force_full = true;
	}
	r = ept12_translate(vcpu, eptp12, l2gpa, l1gpa, perm, obs);
	if (k->wipe_now) {
		/*
		 * B1: il walk ha visto cambiata una voce di una tabella ambigua o
		 * di PML4. Radice svuotata ORA e walk rifatto sulla radice vuota
		 * (le sue tabelle si fotografano di nuovo). Se capita ancora
		 * (tabella cambiata fra due visite dello stesso walk) si svuota di
		 * nuovo e il walk resta non tracciato: force_full.
		 */
		atomic_add_long(&vept_keep_walk_wipes, 1);
		atomic_add_long(&vept_leaves_zapped_walkfull, k->leaves);
		vept_root_wipe(n, vept_cur_slot(n));
		r = ept12_translate(vcpu, eptp12, l2gpa, l1gpa, perm, obs);
		if (k->wipe_now) {
			atomic_add_long(&vept_keep_walk_wipes, 1);
			atomic_add_long(&vept_leaves_zapped_walkfull, k->leaves);
			vept_root_wipe(n, vept_cur_slot(n));
			k->force_full = true;
		}
	}
	if (r < 0) {
		n->st_vept[VST_F_UNREAD]++;
		return (VEPT_VIOL);		/* tabella dell'L1 illeggibile */
	}
	if (r != VEPT_OK) {
		n->st_vept[r == VEPT_MISCONF ? VST_F_MISCONF : VST_F_VIOL_MISSING]++;
		return (r);
	}
	/*
	 * Tipo d'accesso (qualificazione: bit 0 R, 1 W, 2 X, stessi bit dei
	 * permessi EPT) contro i permessi dell'L1. Prima non si confrontava: si
	 * installava la voce coi permessi dell'L1, l'L2 rifaceva l'accesso,
	 * l'hardware rifaceva il fault e si girava a vuoto.
	 */
	access = qual & EPT_RWX;
	if ((access & ~*perm) != 0) {
		n->st_vept[VST_F_VIOL_PERM]++;
		return (VEPT_VIOL);
	}
	/*
	 * Pagina host dell'L1-GPA: vm_gpa_hold la porta in memoria se serve
	 * (prima pmap_extract sull'EPT01 falliva per una pagina mai toccata
	 * dall'L1). La memoria del guest e' wired: non si sposta dopo il
	 * rilascio.
	 */
	p = vept_hold(vcpu, *l1gpa & ~(uint64_t)PAGE_MASK, &ck, VST_H_L1PAGE);
	if (p != NULL) {
		hpa = DMAP_TO_PHYS((vm_offset_t)p);
		vept_rel(vcpu, ck);
		n->st_vept[VST_F_RAM]++;
		/* B1: si conservano solo foglie di RAM wired (GPA -> HPA fisso
		 * finche' il mapping esiste: generazione dei mapping) */
		if (n->vept_keep && !vm_mem_wired(vcpu->vmx->vm,
		    *l1gpa & ~(uint64_t)PAGE_MASK))
			k->nokeep = true;
		vept_install(n, k, l2gpa, hpa, *perm, 6);	/* RAM: WB */
		return (VEPT_OK);
	}
	/* Non RAM. Se l'EPT01 mappa gia' l'L1-GPA (BAR di un dispositivo in
	 * passthrough) si usa la stessa pagina host, non cacheable. */
	hpa = pmap_extract(vcpu->vmx->pmap, *l1gpa);
	if (hpa != 0) {
		k->nokeep = true;		/* B1: MMIO mai conservata */
		n->st_vept[VST_F_MMIO]++;
		vept_install(n, k, l2gpa, hpa, *perm, 0);	/* MMIO: UC */
		return (VEPT_OK);
	}
	n->st_vept[VST_F_EMUL]++;
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
 * vmmops nested_gpa per l'emulatore (ptp_hold, traduzione finale di
 * _vm_gla2gpa). H2 (AUDIT-PTP-HOLD, parere #119): prima un EFAULT qui
 * diventava un errore di vm_run e uccideva la VM, scatenabile dall'L2 con una
 * PTE verso un suo GPA che l'L1 non mappa. Il walk hardware avrebbe dato
 * all'L1 una EPT violation (o misconfiguration): con VM_NGPA_RECORD la si
 * registra in emu_viol, come vmx_vept_ptp_write per H1, e si ritorna
 * EJUSTRETURN; la consegna e' la stessa (vmx_run -> slow path ->
 * nested_ept_emul_reflect), prima di qualunque nuovo ingresso in L2.
 * Semantica identica al percorso hardware (vmx_vept_fault): tabella
 * dell'L1 illeggibile = violation; voce malformata = misconfiguration
 * (motivo 49, qualificazione 0). Qualificazione della violation (SDM, Exit
 * Qualification for EPT Violations): bit 0-2 tipo d'accesso (fetch = solo
 * bit 2; una voce di tabella dell'L2 si LEGGE: bit 0, con EPTP12[6]=0 gli A/D
 * di EPT non sono esposti), bit 3-5 permessi dell'L1 (0 se non presente), bit
 * 7 indirizzo lineare valido, bit 8 = 1 solo per l'indirizzo finale, e solo
 * allora i bit 9-11 (informazioni avanzate, capacita' passata all'L1 da
 * nested_msrs_init). Senza VM_NGPA_RECORD (vm_gla2gpa_nofault) resta EFAULT.
 */
/*
 * Permessi EPT che l'accesso richiede davvero (puro: il banco userland lo
 * estrae dal sorgente). Un fetch (vmm_fetch_instruction chiede READ|EXECUTE)
 * vuole solo X, come il walk hardware: chiedere anche R darebbe all'L1 una
 * violation FALSA su una pagina eseguibile senza R, e un ciclo (l'hardware
 * esegue, l'emulatore nega). Un dato vuole R e/o W come chiesto; la voce di
 * una tabella dell'L2 si legge.
 */
static uint64_t
vept_emul_need(int prot, int flags)
{
	if ((flags & VM_NGPA_FINAL) == 0)
		return (EPT_PG_READ);
	if (prot & VM_PROT_EXECUTE)
		return (EPT_PG_EXECUTE);
	return (((prot & VM_PROT_READ) ? EPT_PG_READ : 0) |
	    ((prot & VM_PROT_WRITE) ? EPT_PG_WRITE : 0));
}

/* Qualificazione della violation dell'emulatore (vedi sotto); pura: il banco
 * userland la estrae dal sorgente. Bit 0-2 = l'accesso richiesto. */
static uint64_t
vept_emul_qual(int prot, int flags, uint64_t perm)
{
	uint64_t need, qual;

	need = vept_emul_need(prot, flags);
	qual = ((need & EPT_PG_READ) ? EPT_VIOLATION_DATA_READ : 0) |
	    ((need & EPT_PG_WRITE) ? EPT_VIOLATION_DATA_WRITE : 0) |
	    ((need & EPT_PG_EXECUTE) ? EPT_VIOLATION_INST_FETCH : 0);
	qual |= ((perm & EPT_RWX) << 3) | EPT_VIOLATION_GLA_VALID;
	if (flags & VM_NGPA_FINAL) {
		qual |= EPT_VIOLATION_XLAT_VALID;
		if (flags & VM_NGPA_LA_US)
			qual |= 1UL << 9;
		if (flags & VM_NGPA_LA_RW)
			qual |= 1UL << 10;
		if (flags & VM_NGPA_LA_XD)
			qual |= 1UL << 11;
	}
	return (qual);
}

int
vmx_vept_l1gpa_emul(struct vmx_vcpu *vcpu, uint64_t gpa, int prot,
    uint64_t gla, int flags, uint64_t *out)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t perm;
	int r;

	*out = gpa;
	if (n == NULL || !n->in_l2 || (c = nested_current_cache(n)) == NULL ||
	    (vmcs12_proc2(c) & PROCBASED2_ENABLE_EPT) == 0)
		return (0);
	r = ept12_translate(vcpu, vmcs12_read_field(c, VMCS_EPTP), gpa, out,
	    &perm, NULL);
	if (r == VEPT_OK && (vept_emul_need(prot, flags) & ~perm) == 0)
		return (0);
	if ((flags & VM_NGPA_RECORD) == 0)
		return (EFAULT);
	/* una sola causa: la prima in ordine di programma (il chiamante si
	 * ferma al primo fault, quindi qui non si arriva con una pendente) */
	if (n->emu_viol) {
		atomic_add_long(&vept_h2_already, 1);
		return (EJUSTRETURN);
	}
	n->emu_viol_gpa = gpa;
	n->emu_viol_gla = gla;
	n->emu_viol_vmcs12 = n->current_vmcs12;
	if (r == VEPT_MISCONF) {
		n->emu_viol_reason = EXIT_REASON_EPT_MISCONFIG;
		n->emu_viol_qual = 0;
		atomic_add_long(&vept_h2_misconf, 1);
	} else {
		if (r < 0) {
			atomic_add_long(&vept_h2_unread, 1);
			perm = 0;
		} else if (r != VEPT_OK)
			perm = 0;		/* non presente: permessi 0 */
		atomic_add_long((flags & VM_NGPA_FINAL) ? &vept_h2_viol_final :
		    &vept_h2_viol_ptp, 1);
		n->emu_viol_reason = EXIT_REASON_EPT_FAULT;
		n->emu_viol_qual = vept_emul_qual(prot, flags, perm);
	}
	n->emu_viol = true;
	return (EJUSTRETURN);
}

/*
 * vmmops nested_ptp_write (sessione 1d, parere di Astra sul caso H): prima che
 * l'emulatore di L0 scriva A/D nella voce di tabella dell'L2 al GPA 'ptegpa'.
 * Il walk hardware fa lo stesso aggiornamento come accesso in SCRITTURA alla
 * pagina di tabelle (con EPTP12[6]=0 gli A/D di EPT non c'entrano): se l'EPT
 * dell'L1 non concede W, l'L1 vede una EPT violation (casi H/H_D della 1d,
 * qualificazione RD|WR|permessi|GLA valido, bit 8 = 0, GPA = la voce). Qui la
 * si registra soltanto: la riflette lo slow path (nested_ept_emul_reflect),
 * prima di qualunque nuovo ingresso in L2. Fuori da un L2 con EPT (anche
 * quando L0 emula un'istruzione dell'L1) non c'e' nulla da controllare.
 */
int
vmx_vept_ptp_write(struct vmx_vcpu *vcpu, uint64_t ptegpa, uint64_t l1held,
    uint64_t gla, bool *denied)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t l1gpa, perm;

	*denied = false;
	if (n == NULL || !n->in_l2 || (c = nested_current_cache(n)) == NULL ||
	    (vmcs12_proc2(c) & PROCBASED2_ENABLE_EPT) == 0)
		return (0);
	/*
	 * La pagina e' appena stata letta con R (ptp_hold). VEPT_VIOL (non
	 * presente), VEPT_MISCONF o tabella dell'L1 illeggibile (<0) qui vogliono
	 * dire che l'L1 ha cambiato EPT12 nel frattempo: il walk riparte dalla
	 * radice (EAGAIN). Nessuna di queste diventa una violazione qui (parere
	 * #109 §3: solo "W negato con traduzione valida"), e nessuna diventa un
	 * errore fatale nuovo (§4): al giro dopo decide ptp_hold, come prima.
	 */
	if (ept12_translate(vcpu, vmcs12_read_field(c, VMCS_EPTP), ptegpa,
	    &l1gpa, &perm, NULL) != VEPT_OK) {
		atomic_add_long(&vept_ptp_write_retry_xlate, 1);
		return (EAGAIN);
	}
	/*
	 * Parere #110 §2: il permesso vale per la pagina in cui si scrive. Il
	 * cmpset scrivera' nella pagina tenuta da ptp_hold (L1-GPA 'l1held');
	 * se ora EPT12 manda la stessa GPA dell'L2 su un'altra pagina dell'L1,
	 * ne' il permesso vecchio ne' quello nuovo autorizzano a scrivere nella
	 * pagina tenuta: niente scrittura, niente violazione, il walk riparte.
	 * Basta l'L1-GPA: la memoria dell'L1 cambia mappa (L1-GPA -> HPA) solo
	 * con tutti i vCPU IDLE (vmx_vept_memgen_sync), mai con questo vCPU
	 * FROZEN nell'emulazione; quindi stesso L1-GPA = stessa pagina host.
	 * EPTP12 e' lo stesso di ptp_hold: lo cambia solo l'L1 con VMWRITE e
	 * VMRESUME su questo vCPU, che durante l'emulazione non gira.
	 */
	if ((l1gpa & ~(uint64_t)PAGE_MASK) != (l1held & ~(uint64_t)PAGE_MASK)) {
		atomic_add_long(&vept_ptp_write_retry_remap, 1);
		return (EAGAIN);
	}
	if ((perm & EPT_PG_WRITE) != 0)
		return (0);
	*denied = true;
	n->emu_viol = true;
	n->emu_viol_reason = EXIT_REASON_EPT_FAULT;
	n->emu_viol_gpa = ptegpa;
	n->emu_viol_gla = gla;
	n->emu_viol_vmcs12 = n->current_vmcs12;
	n->emu_viol_qual = EPT_VIOLATION_DATA_READ | EPT_VIOLATION_DATA_WRITE |
	    ((perm & EPT_RWX) << 3) | EPT_VIOLATION_GLA_VALID;
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

/*
 * WSL2-FreeBSD 003, diagpf2: walk dell'indirizzo lineare gla dell'L2 (CR3
 * cr3, paginazione a 4 livelli) visto in due modi, per ogni tabella e per la
 * pagina finale: (a) come lo vede l'L1, cioe' EPT12 letto VIVO + pagina host
 * di vm_gpa_hold; (b) come lo vede l'hardware, cioe' la foglia dell'EPT02
 * ombra della radice corrente. La PTE si legge da entrambe le pagine host.
 * Si segue il cammino (a). Solo dallo slow path (vm_gpa_hold puo' dormire),
 * con la radice ombra gia' allineata all'EPTP12 del VMCS12 (vmx_vept_prepare).
 */
void
vmx_vept_diag_walk(struct vmx_vcpu *vcpu, uint64_t eptp12, uint64_t cr3,
    uint64_t gla, const char *tag)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t tgpa, l1, perm, sh, exp, pte_e, pte_s, *p, m;
	void *ck;
	int lvl, r, idx;

	tgpa = cr3 & 0x000ffffffffff000ULL;
	for (lvl = 3; lvl >= -1; lvl--) {
		idx = lvl >= 0 ? (int)((gla >> (12 + 9 * lvl)) & 0x1ff) : 0;
		l1 = perm = 0;
		r = ept12_translate(vcpu, eptp12, tgpa, &l1, &perm, NULL);
		sh = n->vept_root != NULL ? vept_leaf_get(n->vept_root, tgpa) : 0;
		exp = pte_e = pte_s = 0;
		if (r == VEPT_OK && (p = vm_gpa_hold(vcpu->vcpu,
		    l1 & ~(uint64_t)PAGE_MASK, PAGE_SIZE, VM_PROT_READ,
		    &ck)) != NULL) {
			exp = DMAP_TO_PHYS((vm_offset_t)p);
			if (lvl >= 0)
				pte_e = atomic_load_64(&p[idx]);
			vm_gpa_release(ck);
		}
		if ((sh & EPT_RWX) != 0 && lvl >= 0)
			pte_s = atomic_load_64(&((uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(sh)))[idx]);
		printf("nested_diag_pfinj   %s %s l2gpa=%#lx | EPT12 viva r=%d "
		    "l1gpa=%#lx perm=%#lx hpa=%#lx | ombra=%#lx%s | pte vera=%#lx "
		    "ombra=%#lx%s\n", tag, lvl >= 0 ? (lvl == 3 ? "PML4" :
		    lvl == 2 ? "PDPT" : lvl == 1 ? "PD  " : "PT  ") : "PAG ",
		    (u_long)tgpa, r, (u_long)l1, (u_long)perm, (u_long)exp,
		    (u_long)sh, ((sh & EPT_RWX) != 0 && EPT_ADDR(sh) != exp) ?
		    " <-- HPA DIVERSO" : ((sh & EPT_RWX) == 0 ? " (assente)" : ""),
		    (u_long)pte_e, (u_long)pte_s, ((sh & EPT_RWX) != 0 &&
		    lvl >= 0 && pte_s != pte_e) ? " <-- PTE DIVERSA" : "");
		if (lvl < 0 || r != VEPT_OK || (pte_e & 1) == 0)
			return;
		if (lvl > 0 && (pte_e & 0x80) != 0) {
			m = (1ULL << (12 + 9 * lvl)) - 1;
			tgpa = ((pte_e & 0x000ffffffffff000ULL & ~m) |
			    (gla & m)) & ~(uint64_t)PAGE_MASK;
			lvl = 0;		/* prossimo giro: la pagina finale */
			continue;
		}
		tgpa = pte_e & 0x000ffffffffff000ULL;
	}
}

/*
 * B1, generazione dei mapping di L0 (parere #28 §4, §6). Una foglia shadow
 * contiene l'HPA preso da vm_gpa_hold: con la radice conservata a lungo, un
 * mapping tolto o rifatto la renderebbe falsa. La generazione cambia solo con
 * tutti i vCPU IDLE (ioctl con LOCK_ALL_VCPUS), quindi mai durante uno slow
 * path o un vmx_run: basta confrontarla all'inizio dello slow path, in
 * vmx_vept_prepare e in vmx_run prima di ogni ingresso in L2.
 */
void
vmx_vept_memgen_sync(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t g = vm_memmap_generation(vcpu->vmx->vm);
	int i, inv = 0;

	for (i = 0; i < VEPT_NROOTS; i++) {
		if (n->vept_ks[i].memgen == g)
			continue;
		if (n->vept_slot[i].root != NULL) {
			atomic_add_long(&vept_leaves_zapped_memgen,
			    n->vept_ks[i].leaves);
			vept_root_wipe(n, i);
			inv++;
		}
		n->vept_ks[i].memgen = g;
	}
	if (inv != 0) {
		atomic_add_long(&vept_memgen_changes_detected, 1);
		atomic_add_long(&vept_memgen_roots_invalidated, inv);
		SDT_PROBE3(vmm, vmx, nested, veptmemgen, vcpu->vcpuid, g, inv);
	}
}

/* La radice corrente e' di una generazione vecchia? Non dorme. */
bool
vmx_vept_memgen_stale(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	int i;

	if (n->vept_root == NULL)
		return (false);
	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root == n->vept_root)
			return (n->vept_ks[i].memgen !=
			    vm_memmap_generation(vcpu->vmx->vm));
	return (false);
}

/* Slot della radice corrente, o -1 (parere #53 §8, strumentazione): come
 * vept_cur_slot ma senza panic, per il percorso caldo di vmx_run. */
int
vmx_vept_cur_slot(struct vmx_nested *n)
{
	int i;

	if (n->vept_root == NULL)
		return (-1);
	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root == n->vept_root)
			return (i);
	return (-1);
}

/* vmx_run ha appena fatto INVEPT dell'EPTP shadow su questa CPU. */
void
vmx_vept_hw_flushed(struct vmx_vcpu *vcpu)
{
	if (vcpu->nested->vept_flush_pending) {
		vcpu->nested->vept_flush_pending = false;
		atomic_add_long(&vept_keep_shadow_flushes, 1);
	}
}

/* Subito prima di un ingresso in L2 con la shadow: l'invariante, contato. */
void
vmx_vept_enter_check(struct vmx_vcpu *vcpu)
{
	if (vmx_vept_memgen_stale(vcpu))
		atomic_add_long(&vept_stale_root_enters, 1);
}
