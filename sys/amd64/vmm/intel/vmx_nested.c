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
#include <machine/psl.h>
#include <machine/specialreg.h>
#include <machine/md_var.h>

#include <vm/vm.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <machine/vmparam.h>
#include "vmx_cpufunc.h"
#include "vmx.h"
#include "vmx_nested.h"
#include "vmm_stat.h"
#include <dev/vmm/vmm_mem.h>

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

/* --- Esito di un'istruzione VMX nel RFLAGS dell'L1 (SDM 31.2) --- */
void
nested_vmx_result(struct vmx_vcpu *vcpu, int errnum)
{
	uint64_t rflags;

	rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	if (errnum != VMXR_SUCCEED) {		/* VMfailValid(errnum) */
		rflags |= PSL_Z;
		vmcs_write(VMCS_INSTRUCTION_ERROR, errnum);
	}
	vmcs_write(VMCS_GUEST_RFLAGS, rflags);
}

void
nested_vmfail_invalid(struct vmx_vcpu *vcpu)
{
	uint64_t rflags;

	rflags = vmcs_read(VMCS_GUEST_RFLAGS);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	rflags |= PSL_C;			/* VMfailInvalid */
	vmcs_write(VMCS_GUEST_RFLAGS, rflags);
}

static void
nested_advance_rip(void)
{
	vmcs_write(VMCS_GUEST_RIP, vmcs_read(VMCS_GUEST_RIP) +
	    vmcs_read(VMCS_EXIT_INSTRUCTION_LENGTH));
}

/*
 * Decodifica l'operando di memoria di un'istruzione VMX (SDM: campo
 * VM-exit instruction-information + exit qualification) e lo traduce nel
 * GPA dell'L1. Ritorna 0 e *gpa, oppure -1 se e' stata iniettata
 * un'eccezione (#GP/#PF) nell'L1. Il formato dei bit coincide con quello
 * gia' usato da inout_str_* e con KVM/SDM: addrsize 9:7, seg 17:15,
 * index 21:18 (invalido se bit 22), base 26:23 (invalido se bit 27).
 */
static int
nested_operand_gpa(struct vmx_vcpu *vcpu, int prot, uint64_t *gpa)
{
	struct vm_guest_paging paging;
	struct seg_desc desc;
	uint64_t qual, offset, gla;
	uint32_t info;
	enum vm_reg_name seg;
	int scaling, addrsize, fault, error;

	qual = vmcs_read(VMCS_EXIT_QUALIFICATION);
	info = (uint32_t)vmcs_read(VMCS_EXIT_INSTRUCTION_INFO);

	scaling = info & 0x3;
	switch ((info >> 7) & 0x7) {
	case 0: addrsize = 2; break;
	case 1: addrsize = 4; break;
	default: addrsize = 8; break;
	}
	seg = vm_segment_name((info >> 15) & 0x7);

	offset = qual;				/* displacement */
	if (((info >> 27) & 0x1) == 0)		/* BaseReg valido */
		offset += vmx_get_guest_reg(vcpu, (info >> 23) & 0xf);
	if (((info >> 22) & 0x1) == 0)		/* IndexReg valido */
		offset += vmx_get_guest_reg(vcpu, (info >> 18) & 0xf) << scaling;

	error = vmx_getdesc(vcpu, seg, &desc);
	if (error != 0)
		return (-1);
	vmx_paging_info(&paging);
	if (vie_calculate_gla(vmx_cpu_mode(), seg, &desc, offset, 8, addrsize,
	    prot, &gla) != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (-1);
	}
	if (vm_gla2gpa(vcpu->vcpu, &paging, gla, prot, gpa, &fault) != 0 || fault)
		return (-1);			/* #PF iniettato da vm_gla2gpa */
	return (0);
}

/* Legge gli 8 byte (puntatore VMCS/regione) all'operando. -1 = fallito. */
static int
nested_read_operand_u64(struct vmx_vcpu *vcpu, uint64_t *out)
{
	uint64_t gpa, *p;
	void *cookie;

	if (nested_operand_gpa(vcpu, VM_PROT_READ, &gpa) != 0)
		return (-1);			/* eccezione gia' iniettata */
	p = vm_gpa_hold(vcpu->vcpu, gpa, sizeof(uint64_t), VM_PROT_READ, &cookie);
	if (p == NULL) {
		nested_vmfail_invalid(vcpu);
		return (-1);
	}
	*out = *p;
	vm_gpa_release(cookie);
	return (0);
}

static int
nested_vmxon(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t ptr;

	if (n->vmxon) {
		nested_vmx_result(vcpu, VMXERR_VMXON_IN_VMX_ROOT);
		goto done;
	}
	if (nested_read_operand_u64(vcpu, &ptr) != 0)
		return (0);
	/*
	 * Controlli SDM completi (CR0/CR4 fixed, CPL, revisione e
	 * allineamento della VMXON region): limite v1, vedi deviazioni.md.
	 */
	n->vmxon_ptr = ptr;
	n->vmxon = true;
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip();
	return (0);
}

static int
nested_vmxoff(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	int i;

	n->vmxon = false;
	n->current_vmcs12 = VMCS12_GPA_NONE;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
		n->cache[i].launched = 0;
	}
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip();
	return (0);
}

static int
nested_vmclear(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t vmcs12;
	int i;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	if (nested_read_operand_u64(vcpu, &vmcs12) != 0)
		return (0);
	if ((vmcs12 & PAGE_MASK) != 0 || vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		goto done;
	}
	if (vmcs12 == n->current_vmcs12)
		n->current_vmcs12 = VMCS12_GPA_NONE;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs12_gpa == vmcs12) {
			n->cache[i].vmcs12_gpa = VMCS12_GPA_NONE;
			n->cache[i].launched = 0;
			break;
		}
	}
	/* SDM: VMCLEAR azzera il launch-state anche nel VMCS12 in memoria.
	 * Scrittura in guest memory: T1.8/T2. */
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip();
	return (0);
}

static int
nested_vmptrld(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t vmcs12;
	int i, slot;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	if (nested_read_operand_u64(vcpu, &vmcs12) != 0)
		return (0);
	if ((vmcs12 & PAGE_MASK) != 0 || vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		goto done;
	}
	/* (Verifica della revisione del VMCS12: T1.8.) */
	slot = -1;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs12_gpa == vmcs12)
			break;
		if (slot < 0 && n->cache[i].vmcs12_gpa == VMCS12_GPA_NONE)
			slot = i;
	}
	if (i == VMX_NESTED_MAX_VMCS12) {	/* non in cache: creane una voce */
		if (slot < 0)
			slot = 0;		/* evizione semplice (v1) */
		n->cache[slot].vmcs12_gpa = vmcs12;
		n->cache[slot].launched = 0;
		n->cache[slot].host_dirty = true;
		n->cache[slot].control_dirty = true;
	}
	n->current_vmcs12 = vmcs12;
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip();
	return (0);
}

static int
nested_vmptrst(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t gpa, *p;
	void *cookie;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	if (nested_operand_gpa(vcpu, VM_PROT_WRITE, &gpa) != 0)
		return (0);
	p = vm_gpa_hold(vcpu->vcpu, gpa, sizeof(uint64_t), VM_PROT_WRITE, &cookie);
	if (p == NULL) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	*p = n->current_vmcs12;			/* VMCS12_GPA_NONE se nessuno */
	vm_gpa_release(cookie);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip();
	return (0);
}

/*
 * Slow path del nested (op vmmops_nested_exit): dispatch sull'istruzione VMX
 * che ha causato l'uscita, col vCPU FROZEN. VMLAUNCH/VMRESUME (T2.4),
 * VMREAD/VMWRITE (T1.8) e VMCALL non sono ancora qui: per ora #UD.
 */
int
vmx_nested_exit(void *vcpui)
{
	struct vmx_vcpu *vcpu = vcpui;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	uint32_t reason = vmexit->u.vmx.exit_reason & 0xffff;

	SDT_PROBE1(vmm, vmx, nested, slowpath, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_SLOWPATH, 1);

	switch (reason) {
	case EXIT_REASON_VMXON:		return (nested_vmxon(vcpu));
	case EXIT_REASON_VMXOFF:	return (nested_vmxoff(vcpu));
	case EXIT_REASON_VMCLEAR:	return (nested_vmclear(vcpu));
	case EXIT_REASON_VMPTRLD:	return (nested_vmptrld(vcpu));
	case EXIT_REASON_VMPTRST:	return (nested_vmptrst(vcpu));
	default:
		vm_inject_ud(vcpu->vcpu);
		return (0);
	}
}
