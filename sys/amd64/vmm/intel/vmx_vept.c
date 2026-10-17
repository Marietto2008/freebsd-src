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
#include "vmx.h"
#include "vmx_nested.h"

MALLOC_DEFINE(M_VMX_VEPT, "vmx_vept", "Intel VMX nested shadow EPT");

#define	EPT_RWX		(EPT_PG_READ | EPT_PG_WRITE | EPT_PG_EXECUTE)
#define	EPT_ADDR(e)	((e) & 0x000ffffffffff000ULL)
#define	EPT_IDX(gpa, lvl)	(((gpa) >> (12 + 9 * (lvl))) & 0x1ff)

/*
 * Prepara la radice shadow per l'EPTP12 corrente: la alloca VUOTA se manca, la
 * svuota (tenendola) se l'L1 ha cambiato EPT. PUO' DORMIRE (malloc/free):
 * va chiamata nello slow path PRIMA del VMPTRLD del VMCS02, perche' VMPTRLD
 * fa critical_enter (panic "malloc: called with spinlock or critical section
 * held", kvm-unit-tests 'EPT A/D disabled'). Con radice valida l'L2 entra e la
 * shadow si riempie a domanda in vmx_vept_fault; tornare un EPTP invalido
 * farebbe fallire ogni ingresso (uovo-e-gallina).
 */
void
vmx_vept_prepare(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t eptp12 = (c != NULL) ? vmcs12_read_field(c, VMCS_EPTP) : 0;

	if (n->vept_root == NULL) {
		n->vept_root = malloc_aligned(PAGE_SIZE, PAGE_SIZE,
		    M_VMX_VEPT, M_WAITOK | M_ZERO);
		n->vept_eptp12 = eptp12;
	} else if (n->vept_eptp12 != eptp12) {
		/* l'L1 ha cambiato EPT: la shadow rispecchia quello vecchio */
		vmx_vept_invept(n);
		n->vept_eptp12 = eptp12;
	}
}

/* Shadow EPTP (radice) da scrivere nel VMCS02: WB, 4 livelli. Non dorme:
 * la radice l'ha gia' preparata vmx_vept_prepare. */
uint64_t
vmx_vept_eptp(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;

	KASSERT(n->vept_root != NULL, ("%s: radice shadow non preparata",
	    __func__));
	return (vtophys(n->vept_root) | EPT_PG_MEMORY_TYPE(6) | (3UL << 3));
}

/* Svuota le sottotabelle della radice (non la radice) e la azzera. */
static void vept_free_level(uint64_t *tbl, int level);

/*
 * INVEPT dell'L1, o EPT12 cambiato: svuota la shadow TENENDO la radice, cosi'
 * l'EPTP gia' scritto nel VMCS02 resta valido. Il TLB per l'EPTP shadow lo
 * invalida vmx_run a ogni rientro in L2 (INVEPT single-context).
 */
void
vmx_vept_invept(struct vmx_nested *n)
{
	uint64_t *root = n->vept_root;
	int i;

	if (root == NULL)
		return;
	for (i = 0; i < 512; i++) {
		if ((root[i] & EPT_RWX) != 0 && (root[i] & EPT_PG_PS) == 0)
			vept_free_level((uint64_t *)PHYS_TO_DMAP(
			    EPT_ADDR(root[i])), 2);
		root[i] = 0;
	}
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
	if (n->vept_root != NULL) {
		vept_free_level(n->vept_root, 3);
		n->vept_root = NULL;
		n->vept_eptp12 = 0;
	}
}

/* Cammina EPT12 (in memoria dell'L1) per l2gpa. Ritorna 0 con l1gpa e
 * perm; 1 se EPT12 nega (violation da riflettere); -1 su errore d'accesso. */
static int
ept12_translate(struct vmx_vcpu *vcpu, uint64_t eptp12, uint64_t l2gpa,
    uint64_t *l1gpa, uint64_t *perm)
{
	uint64_t tbl_gpa, pte, acc;
	uint64_t *page;
	void *cookie;
	int level, idx;

	tbl_gpa = EPT_ADDR(eptp12);
	acc = EPT_RWX;
	for (level = 3; level >= 0; level--) {
		idx = EPT_IDX(l2gpa, level);
		page = vm_gpa_hold(vcpu->vcpu, tbl_gpa, PAGE_SIZE,
		    VM_PROT_READ, &cookie);
		if (page == NULL)
			return (-1);
		pte = page[idx];
		vm_gpa_release(cookie);
		if ((pte & EPT_RWX) == 0)
			return (1);			/* non presente */
		acc &= pte;				/* ∩ permessi R/W/X */
		if (level == 0 || (pte & EPT_PG_PS) != 0) {
			uint64_t mask = (1ULL << (12 + 9 * level)) - 1;
			*l1gpa = (EPT_ADDR(pte) & ~mask) | (l2gpa & mask);
			*perm = acc & EPT_RWX;
			return (0);
		}
		tbl_gpa = EPT_ADDR(pte);
	}
	return (1);
}

/* Installa una foglia shadow 4K: l2gpa -> hpa con permessi e memtype WB. */
static int
vept_install(struct vmx_nested *n, uint64_t l2gpa, uint64_t hpa, uint64_t perm)
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
	    EPT_PG_MEMORY_TYPE(6) | EPT_PG_IGNORE_PAT;
	return (0);
}

/*
 * EPT violation mentre il vCPU e' in L2 (VMCS02 corrente, VMCS12 usa EPT).
 * Ritorna 0 se ha installato la shadow e si puo' rientrare in L2; 1 se
 * l'accesso va riflesso all'L1 (EPT12 nega o EPT01 non mappa).
 */
int
vmx_vept_fault(struct vmx_vcpu *vcpu, uint64_t l2gpa)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	uint64_t eptp12, l1gpa, perm, hpa;
	void *p, *ck;
	int r;

	/*
	 * SLOW PATH (vCPU FROZEN, fuori dal critical_enter di vm_run): qui si
	 * puo' dormire (vm_gpa_hold, malloc M_WAITOK). Prima era chiamata dal
	 * percorso veloce (nested_l2_exit dentro vmx_run): vietato.
	 */
	if (c == NULL)
		return (1);
	eptp12 = vmcs12_read_field(c, VMCS_EPTP);
	if (n->vept_root == NULL || n->vept_eptp12 != eptp12)
		vmx_vept_prepare(vcpu);	/* allinea radice ed EPTP12 */

	r = ept12_translate(vcpu, eptp12, l2gpa, &l1gpa, &perm);
	if (r != 0)
		return (1);			/* EPT12 nega -> violation all'L1 */
	/*
	 * Pagina host dell'L1-GPA: vm_gpa_hold la porta in memoria se serve
	 * (prima pmap_extract sull'EPT01 falliva per una pagina mai toccata
	 * dall'L1 e la violation finiva, a torto, all'L1). La memoria del guest
	 * e' wired: la pagina non si sposta dopo il rilascio.
	 */
	p = vm_gpa_hold(vcpu->vcpu, l1gpa & ~(uint64_t)PAGE_MASK, PAGE_SIZE,
	    VM_PROT_READ, &ck);
	if (p == NULL)
		return (1);			/* non RAM (MMIO dell'L1): all'L1 */
	hpa = DMAP_TO_PHYS((vm_offset_t)p);
	vm_gpa_release(ck);
	vept_install(n, l2gpa, hpa, perm);
	return (0);				/* rientra in L2 */
}
