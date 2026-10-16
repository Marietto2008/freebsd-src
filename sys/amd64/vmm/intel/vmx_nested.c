/*-
 * Copyright (C) 2021-2022 Intel Corporation.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Derivato da projectacrn/acrn-hypervisor (hypervisor/arch/x86/guest:
 * nested.c). Intestazione e clausola 3 di ACRN conservate.
 *
 * Copyright (c) 2026 Marietto.
 *
 * VMX annidato per vmm (piano nested v2). T1.3: ciclo di vita dello stato
 * nested per vCPU (alloc su 0->1 della capability, free a 1->0 e al cleanup
 * del vCPU), piu' i contatori vmm_stat e le probe SDT che i task successivi
 * sparano. Nessuna logica di esecuzione annidata ancora: quella arriva da
 * T1.7 in poi.
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/sdt.h>

#include <machine/vmm.h>
#include <machine/cpufunc.h>
#include <machine/specialreg.h>
#include <machine/md_var.h>

#include "vmx.h"
#include "vmx_nested.h"
#include "vmm_stat.h"

MALLOC_DEFINE(M_VMX_NESTED, "vmx_nested", "Intel VMX nested virtualization");

/*
 * Probe SDT del nested. Non si sparano ancora (lo faranno T1.7+); definirle
 * qui le rende visibili da subito a dtrace: vmm:vmx:nested:*.
 */
SDT_PROVIDER_DECLARE(vmm);
SDT_PROBE_DEFINE1(vmm, vmx, nested, enter_l2, "struct vmx_vcpu *");
SDT_PROBE_DEFINE1(vmm, vmx, nested, reflect, "struct vmx_vcpu *");
SDT_PROBE_DEFINE2(vmm, vmx, nested, synth_exit, "struct vmx_vcpu *", "int");
SDT_PROBE_DEFINE1(vmm, vmx, nested, slowpath, "struct vmx_vcpu *");
SDT_PROBE_DEFINE2(vmm, vmx, nested, shadow_fill, "struct vmx_vcpu *", "uint64_t");
SDT_PROBE_DEFINE2(vmm, vmx, nested, vmfail, "struct vmx_vcpu *", "int");
SDT_PROBE_DEFINE1(vmm, vmx, nested, init_latched, "struct vmx_vcpu *");

/* Contatori per vCPU (bhyvectl --get-stats). */
VMM_STAT_INTEL(VMX_NESTED_L2_ENTRIES, "ingressi in L2");
VMM_STAT_INTEL(VMX_NESTED_REFLECTIONS, "exit riflesse all'L1");
VMM_STAT_INTEL(VMX_NESTED_SYNTH_EXITS, "exit sintetiche verso l'L1");
VMM_STAT_INTEL(VMX_NESTED_SLOWPATH, "exit nested gestite nello slow path");
VMM_STAT_INTEL(VMX_NESTED_VMFAIL, "VMfail restituiti all'L1");

/*
 * Alloca lo stato nested del vCPU. Idempotente: se gia' presente, no-op.
 * Chiamata dal passaggio 0->1 della capability VM_CAP_NESTED_VIRT, in
 * contesto di processo (ioctl), quindi M_WAITOK e' ammesso.
 */
/*
 * Calcola i valori delle MSR di capability VMX esposti all'L1 (D4=C, set A
 * misurato dall'host), con le esclusioni di §6.3 e i must-be-1 di D4.b.
 * Derivati dalle MSR dell'host; il set esatto lo conferma test_vmx_caps di
 * kvm-unit-tests sull'hardware (T1.4 "Fatto quando").  I bit potrebbero
 * essere rifiniti dopo quel test: vedi docs/nested/T1.4.md.
 */
static void
vmx_nested_init_msrs(struct vmx_nested *n)
{
	uint64_t basic, misc, proc2, eptcap;
	uint64_t *m = n->vmx_msr;

	/* IA32_VMX_BASIC: revisione dell'host, dimensione 4096, memtype WB,
	 * bit 54 (report INS/OUTS) e 55 (true controls). */
	basic = rdmsr(MSR_VMX_BASIC);
	m[0x480 - 0x480] = (basic & 0x7fffffffULL) | (4096ULL << 32) |
	    (6ULL << 50) | (1ULL << 54) | (1ULL << 55);

	/* pin-based (legacy e true): host + ext-int(0) e NMI(3) exiting
	 * must-be-1 nelle allowed-0 (D4.b). */
	m[0x481 - 0x480] = rdmsr(MSR_VMX_PINBASED_CTLS)      | 0x9ULL;
	m[0x48d - 0x480] = rdmsr(MSR_VMX_TRUE_PINBASED_CTLS) | 0x9ULL;

	/* proc-based primary, exit, entry: come l'host. */
	m[0x482 - 0x480] = rdmsr(MSR_VMX_PROCBASED_CTLS);
	m[0x48e - 0x480] = rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS);
	m[0x483 - 0x480] = rdmsr(MSR_VMX_EXIT_CTLS);
	m[0x48f - 0x480] = rdmsr(MSR_VMX_TRUE_EXIT_CTLS);
	m[0x484 - 0x480] = rdmsr(MSR_VMX_ENTRY_CTLS);
	m[0x490 - 0x480] = rdmsr(MSR_VMX_TRUE_ENTRY_CTLS);

	/* MISC: host senza PT (14), SMBASE (15), VMXOFF-unblock-SMI (28) e il
	 * rate del preemption timer (0-4). bit 29 (VMWRITE-any) resta: F0=SI. */
	misc = rdmsr(IA32_VMX_MISC);
	m[0x485 - 0x480] = misc & ~(0x1fULL | (1ULL << 14) | (1ULL << 15) |
	    (1ULL << 28));

	/* CR0/CR4 fixed e VMCS_ENUM: dall'host. */
	m[0x486 - 0x480] = rdmsr(MSR_VMX_CR0_FIXED0);
	m[0x487 - 0x480] = rdmsr(MSR_VMX_CR0_FIXED1);
	m[0x488 - 0x480] = rdmsr(MSR_VMX_CR4_FIXED0);
	m[0x489 - 0x480] = rdmsr(MSR_VMX_CR4_FIXED1);
	m[0x48a - 0x480] = rdmsr(IA32_VMX_VMCS_ENUM);

	/* proc-based2: host MENO le feature escluse (§6.3), togliendole dalle
	 * allowed-1 (dword alto). Restano EPT, VPID, unrestricted, RDTSCP,
	 * INVPCID, WBINVD, DESC_TABLE, RDRAND/RDSEED, PAUSE_LOOP. */
	proc2 = rdmsr(MSR_VMX_PROCBASED_CTLS2);
	{
		uint64_t exc =
		    (1ULL << 0)  | /* virtualize APIC accesses */
		    (1ULL << 4)  | /* virtualize x2APIC */
		    (1ULL << 8)  | /* APIC register virtualization */
		    (1ULL << 9)  | /* virtual-interrupt delivery */
		    (1ULL << 13) | /* VMFUNC */
		    (1ULL << 14) | /* VMCS shadowing (per l'L1) */
		    (1ULL << 15) | /* ENCLS exiting */
		    (1ULL << 17) | /* PML */
		    (1ULL << 18) | /* EPT-violation #VE */
		    (1ULL << 20) | /* XSAVES/XRSTORS */
		    (1ULL << 22) | /* mode-based execute control */
		    (1ULL << 23) | /* sub-page write permissions */
		    (1ULL << 24) | /* Intel PT uses guest phys */
		    (1ULL << 25) | /* TSC scaling */
		    (1ULL << 28);  /* ENCLV exiting */
		m[0x48b - 0x480] = proc2 & ~(exc << 32);
	}

	/* EPT/VPID cap: host senza EPT A/D (21) e page-walk a 5 livelli (7). */
	eptcap = rdmsr(MSR_VMX_EPT_VPID_CAP);
	m[0x48c - 0x480] = eptcap & ~((1ULL << 21) | (1ULL << 7));

	/* IA32_FEATURE_CONTROL: LOCK + VMX outside SMX (niente SMX). */
	n->feature_control = IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN;
}

int
vmx_nested_init(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n;
	int i;

	if (vcpu->nested != NULL)
		return (0);

	n = malloc(sizeof(*n), M_VMX_NESTED, M_WAITOK | M_ZERO);
	n->current_vmcs12 = VMCS12_GPA_NONE;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++)
		n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
	vmx_nested_init_msrs(n);
	/*
	 * msr_bitmap e le pagine VMCS02 restano NULL: le allocano pigramente
	 * T6.3 (bitmap fusa) e T1.8 (VMCS02 al VMPTRLD del VMCS12).
	 */
	vcpu->nested = n;
	return (0);
}

/*
 * Libera lo stato nested. Idempotente. Chiamata a 1->0 della capability e
 * da vmx_vcpu_cleanup.
 */
void
vmx_nested_free(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n;
	int i;

	n = vcpu->nested;
	if (n == NULL)
		return;

	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs02 != NULL)
			free(n->cache[i].vmcs02, M_VMX_NESTED);
	}
	if (n->msr_bitmap != NULL)
		free(n->msr_bitmap, M_VMX_NESTED);
	free(n, M_VMX_NESTED);
	vcpu->nested = NULL;
}

/*
 * Slow path del nested (op vmmops_nested_exit). Chiamato da vm_run quando
 * vmx_exit_process segna VM_EXITCODE_NESTED, col vCPU FROZEN. Ancora nessuna
 * istruzione VMX gestita qui (arrivano da T1.7/T1.8): per ora si rientra.
 */
int
vmx_nested_exit(void *vcpui)
{
	struct vmx_vcpu *vcpu = vcpui;

	SDT_PROBE1(vmm, vmx, nested, slowpath, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_SLOWPATH, 1);
	return (0);
}
