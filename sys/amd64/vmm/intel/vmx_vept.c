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
		else
			vept_wipe(pick->root);
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
 * INVEPT dell'L1: svuota TUTTE le radici (single-context compreso: non si
 * legge il descrittore, e svuotarne di piu' e' sempre lecito). Il TLB per
 * l'EPTP shadow lo invalida vmx_run a ogni rientro in L2 (INVEPT
 * single-context sulla radice corrente; le altre lo ricevono quando
 * tornano correnti).
 */
void
vmx_vept_invept(struct vmx_nested *n)
{
	int i;

	for (i = 0; i < VEPT_NROOTS; i++)
		if (n->vept_slot[i].root != NULL)
			vept_wipe(n->vept_slot[i].root);
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
    uint64_t *l1gpa, uint64_t *perm)
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

	r = ept12_translate(vcpu, eptp12, l2gpa, l1gpa, perm);
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
	    &perm) != VEPT_OK || (prot & ~perm & EPT_RWX) != 0)
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
