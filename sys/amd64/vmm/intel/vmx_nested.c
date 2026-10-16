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
