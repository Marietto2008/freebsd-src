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
#include "vmx_controls.h"
#include "vmx.h"
#include "vmx_msr.h"
#include "vmx_nested.h"
#include "vmm_stat.h"
#include "vmm_host.h"
#include "io/vlapic.h"
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
	/* Pin-based ESPOSTO GREZZO, come sul ferro nudo (0x7F00000016 sul 9900K:
	 * ext-int/NMI NON forzati, preemption timer presente). Hyper-V accetta
	 * questo; se forzo ext-int/NMI (allowed-0 bit 0,3) li rifiuta e scarta
	 * anche il preemption timer (evt 46: allowed 0x3F0000001E vs 0x7F0000001F).
	 * Il forzamento per la sicurezza di L0 NON serve qui: lo rimette la
	 * composizione del VMCS02 (nested_compose_vmcs02: pin |= EXTINT|NMI). */
	m[0x481 - 0x480] = rdmsr(MSR_VMX_PINBASED_CTLS);
	m[0x48d - 0x480] = rdmsr(MSR_VMX_TRUE_PINBASED_CTLS);

	/* proc-based primary, exit, entry: come l'host. */
	m[0x482 - 0x480] = rdmsr(MSR_VMX_PROCBASED_CTLS);
	m[0x48e - 0x480] = rdmsr(MSR_VMX_TRUE_PROCBASED_CTLS);
	m[0x483 - 0x480] = rdmsr(MSR_VMX_EXIT_CTLS);
	m[0x48f - 0x480] = rdmsr(MSR_VMX_TRUE_EXIT_CTLS);
	m[0x484 - 0x480] = rdmsr(MSR_VMX_ENTRY_CTLS);
	m[0x490 - 0x480] = rdmsr(MSR_VMX_TRUE_ENTRY_CTLS);

	/* MISC: host senza PT (14), SMBASE (15), VMXOFF-unblock-SMI (28).
	 * TENGO il rate del preemption timer (bit 0-4): se lo azzero, Hyper-V
	 * vede il timer annunciato ma con rate invalido e lo esclude dall'allowed
	 * del pin-based (evt 46 su 0x48D). bit 29 (VMWRITE-any) resta: F0=SI. */
	misc = rdmsr(IA32_VMX_MISC);
	m[0x485 - 0x480] = misc & ~((1ULL << 14) | (1ULL << 15) | (1ULL << 28));

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
	n->vpid2 = vpid_alloc(vcpu->vcpuid);	/* VPID distinto L2 (T2.8) */
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
	vmx_vept_flush(n);
	if (n->vpid2 != 0)
		vpid_free(n->vpid2);
	if (n->msr_bitmap != NULL)
		free(n->msr_bitmap, M_VMX_NESTED);
	free(n, M_VMX_NESTED);
	vcpu->nested = NULL;
}

/* --- Esito di un'istruzione VMX nel RFLAGS dell'L1 (SDM 31.2) --- */
static int vmcs12_write_field(struct vmcs12_cache *c, uint32_t enc,
    uint64_t val);	/* definito piu' sotto, usato da nested_vmx_result */

/*
 * Nota: questi girano nel slow path (vcpu FROZEN), dove il VMCS01 NON e'
 * caricato. Lo stato guest (RFLAGS, RIP) si tocca via l'API registri, che a
 * vcpu non-running carica il VMCS da sola; i campi d'uscita vengono dai valori
 * catturati in vmx_exit_process (vcpu->nested->exit_*).
 */
void
nested_vmx_result(struct vmx_vcpu *vcpu, int errnum)
{
	uint64_t rflags;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, &rflags);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	if (errnum != VMXR_SUCCEED) {		/* VMfailValid(errnum) */
		struct vmcs12_cache *c = nested_current_cache(vcpu->nested);
		rflags |= PSL_Z;
		if (c != NULL)			/* L1 lo legge via VMREAD 0x4400 */
			vmcs12_write_field(c, VMCS_INSTRUCTION_ERROR, errnum);
	}
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, rflags);
}

void
nested_vmfail_invalid(struct vmx_vcpu *vcpu)
{
	uint64_t rflags;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, &rflags);
	rflags &= ~(PSL_C | PSL_PF | PSL_AF | PSL_Z | PSL_N | PSL_V);
	rflags |= PSL_C;			/* VMfailInvalid */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, rflags);
}

static void
nested_advance_rip(struct vmx_vcpu *vcpu)
{
	uint64_t rip;

	vm_get_register(vcpu->vcpu, VM_REG_GUEST_RIP, &rip);
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    rip + vcpu->nested->exit_insn_length);
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

	qual = vcpu->nested->exit_qual;		/* catturati col VMCS corrente */
	info = (uint32_t)vcpu->nested->exit_insn_info;

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

	error = vmx_getdesc(vcpu, seg, &desc);	/* sicuro: VMPTRLD a vcpu frozen */
	if (error != 0)
		return (-1);
	paging = vcpu->nested->exit_paging;	/* catturato col VMCS corrente */
	if (vie_calculate_gla(paging.cpu_mode, seg, &desc, offset, 8, addrsize,
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
	nested_advance_rip(vcpu);
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
	nested_advance_rip(vcpu);
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
	nested_advance_rip(vcpu);
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
	nested_advance_rip(vcpu);
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
	nested_advance_rip(vcpu);
	return (0);
}

/* --- store software dei campi VMCS12 (T1.8) --- */
struct vmcs12_cache *
nested_current_cache(struct vmx_nested *n)
{
	int i;

	if (n->current_vmcs12 == VMCS12_GPA_NONE)
		return (NULL);
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++)
		if (n->cache[i].vmcs12_gpa == n->current_vmcs12)
			return (&n->cache[i]);
	return (NULL);
}

uint64_t
vmcs12_read_field(struct vmcs12_cache *c, uint32_t enc)
{
	int i;

	for (i = 0; i < c->nfields; i++)
		if (c->fields[i].enc == enc)
			return (c->fields[i].val);
	return (0);
}

static int
vmcs12_write_field(struct vmcs12_cache *c, uint32_t enc, uint64_t val)
{
	int i;

	for (i = 0; i < c->nfields; i++)
		if (c->fields[i].enc == enc) {
			c->fields[i].val = val;
			return (0);
		}
	if (c->nfields >= VMCS12_NFIELDS)
		return (-1);
	c->fields[c->nfields].enc = enc;
	c->fields[c->nfields].val = val;
	c->nfields++;
	return (0);
}

/*
 * VMREAD/VMWRITE dell'L1. Tutte le istruzioni escono (nessuno shadowing
 * hardware ancora: §6.2 e' un'ottimizzazione rimandata a T2) e si gestiscono
 * in software sullo store del VMCS12 corrente. Decode dell'operando: campo
 * in reg2 (bit 31:28), valore/dest in reg1 (bit 6:3) se registro (bit 10),
 * altrimenti operando di memoria (SDM/KVM).
 */
static int
nested_vmread(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t val, gpa, *p;
	uint32_t info, field;
	void *cookie;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) { nested_vmfail_invalid(vcpu); goto done; }

	info = (uint32_t)vcpu->nested->exit_insn_info; /* catturato */
	field = (uint32_t)vmx_get_guest_reg(vcpu, (info >> 28) & 0xf);
	val = vmcs12_read_field(c, field);

	if ((info >> 10) & 0x1) {
		vmx_set_guest_reg(vcpu, (info >> 3) & 0xf, val);
	} else {
		if (nested_operand_gpa(vcpu, VM_PROT_WRITE, &gpa) != 0)
			return (0);
		p = vm_gpa_hold(vcpu->vcpu, gpa, sizeof(uint64_t),
		    VM_PROT_WRITE, &cookie);
		if (p == NULL) { nested_vmfail_invalid(vcpu); goto done; }
		*p = val;
		vm_gpa_release(cookie);
	}
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}

static int
nested_vmwrite(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	uint64_t val, gpa, *p;
	uint32_t info, field;
	void *cookie;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) { nested_vmfail_invalid(vcpu); goto done; }

	info = (uint32_t)vcpu->nested->exit_insn_info; /* catturato */
	field = (uint32_t)vmx_get_guest_reg(vcpu, (info >> 28) & 0xf);

	if ((info >> 10) & 0x1) {
		val = vmx_get_guest_reg(vcpu, (info >> 3) & 0xf);
	} else {
		if (nested_operand_gpa(vcpu, VM_PROT_READ, &gpa) != 0)
			return (0);
		p = vm_gpa_hold(vcpu->vcpu, gpa, sizeof(uint64_t),
		    VM_PROT_READ, &cookie);
		if (p == NULL) { nested_vmfail_invalid(vcpu); goto done; }
		val = *p;
		vm_gpa_release(cookie);
	}
	/* F0: VMWRITE su ogni campo (MISC bit 29) = SI -> niente rifiuto RO. */
	if (vmcs12_write_field(c, field, val) != 0) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	c->control_dirty = true;
	c->host_dirty = true;
	nested_vmx_result(vcpu, VMXR_SUCCEED);
done:
	nested_advance_rip(vcpu);
	return (0);
}


/*
 * L1 -> L2: VMLAUNCH (is_resume=false) / VMRESUME (is_resume=true), §6.6.
 * Prepara e compone VMCS02, lo rende corrente e lascia che vm_run (dopo il
 * goto restart) ci entri. Su fallimento ripristina VMCS01 e riflette un
 * VMfail all'L1 (in bring-up, piu' sicuro di sospendere la VM). Ritorna
 * sempre 0: l'esito e' nel RFLAGS dell'L1 (fallimento) o nell'ingresso in L2.
 */
static int
nested_vmlaunch(struct vmx_vcpu *vcpu, bool is_resume)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c;
	struct vmcs *vmcs02;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	int error;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	c = nested_current_cache(n);
	if (c == NULL) {
		nested_vmfail_invalid(vcpu);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* launch state: VMLAUNCH vuole clear, VMRESUME vuole launched */
	if (is_resume && !c->launched) {
		nested_vmx_result(vcpu, VMXERR_VMRESUME_NONLAUNCHED_VMCS);
		nested_advance_rip(vcpu);
		return (0);
	}
	if (!is_resume && c->launched) {
		nested_vmx_result(vcpu, VMXERR_VMLAUNCH_NONCLEAR_VMCS);
		nested_advance_rip(vcpu);
		return (0);
	}
	/*
	 * Controlli su controlli/host-state di VMCS12 in software (VMfailValid
	 * 7/8): limite v1, rimandati. Lo stato guest lo verifica l'hardware.
	 */

	/* host-state fisso del VMCS02 (lascia nessun VMCS corrente) */
	if ((error = vmx_nested_vmcs02_setup(c)) != 0) {
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	vmcs02 = (struct vmcs *)c->vmcs02;

	VMPTRLD(vmcs02);
	nested_compose_vmcs02(vcpu);
	/* host-state PER-CPU + HOST_CR3 (dipendono dalla CPU d'ingresso) */
	vmwrite(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmwrite(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmwrite(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vmwrite(VMCS_HOST_CR3, rcr3());

	/* controllo di sicurezza OBBLIGATORIO (unico chiamante, §3/§6.3) */
	error = nested_vmcs02_check(vcpu);
	if (error != 0) {
		VMCLEAR(vmcs02);
		VMPTRLD(vcpu->vmcs01);		/* torna corrente l'L1 */
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	VMCLEAR(vmcs02);			/* vmx_run lo ricarichera' */

	/*
	 * Commuta al VMCS02: vmx_run, dopo il goto restart di vm_run, fara'
	 * VMPTRLD(vcpu->vmcs) ed entrera' in L2. Il RIP dell'L2 e' nel
	 * GUEST_RIP di VMCS02 (copiato in compose).
	 */
	vcpu->vmcs = vmcs02;
	n->in_l2 = true;
	c->launched = 1;			/* dopo VMLAUNCH il VMCS12 e' launched */
	vmexit->inst_length = 0;
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_L2_ENTRIES, 1);
	return (0);
}


/* Attributi "host load" standard dei segmenti all'uscita verso l'L1 (SDM
 * "Loading Host State"): CS code R/A, dati RW/A, TR busy-TSS. */
#define	NESTED_AR_CODE	0x0000a09b	/* P,S,DPL0,exec/read,accessed,L/D,G */
#define	NESTED_AR_DATA	0x0000c093	/* P,S,DPL0,read/write,accessed,G */
#define	NESTED_AR_TR	0x0000008b	/* P,busy 32/64 TSS */

static void
nested_load_seg(uint32_t sel_enc, uint32_t base_enc, uint32_t lim_enc,
    uint32_t ar_enc, uint16_t sel, uint64_t base, uint32_t lim, uint32_t ar)
{
	vmwrite(sel_enc, sel);
	vmwrite(base_enc, base);
	vmwrite(lim_enc, lim);
	vmwrite(ar_enc, ar);
}

/*
 * L2 -> L1 (riflessione, §6.6). Il VMCS02 e' corrente. Salva le info d'uscita
 * e lo stato di L2 nello store VMCS12, poi carica lo stato host di VMCS12 nel
 * guest di VMCS01 (l'L1 riprende al suo "host RIP"). Al ritorno VMCS01 e'
 * corrente, in_l2=0. vmexit->rip = host RIP di VMCS12.
 * ⚠ Gli attributi di segmento e i dettagli di "Loading Host State" seguono
 * l'SDM a memoria: da validare su hardware (un AR errato fa triple-fault
 * l'L1 alla ripresa; lo rileva kut-f2a).
 */
static void
nested_reflect_to_l1(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	struct vmcs *vmcs02 = vcpu->vmcs;
	uint64_t efer, pat, hrip, hrsp, hcr0, hcr3, hcr4;
	uint32_t i;
	/* stato di L2 da ricopiare in VMCS12 cosi' l'L1 lo rilegge con VMREAD */
	static const uint32_t l2state[] = {
		VMCS_GUEST_RIP, VMCS_GUEST_RSP, VMCS_GUEST_RFLAGS,
		VMCS_GUEST_CR0, VMCS_GUEST_CR3, VMCS_GUEST_CR4,
		VMCS_GUEST_IA32_EFER,
		VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_SS_SELECTOR,
		VMCS_GUEST_INTERRUPTIBILITY, VMCS_GUEST_ACTIVITY,
	};

	if (c == NULL)
		return;
	/* 1-2. info d'uscita + stato di L2 -> store VMCS12 */
	vmcs12_write_field(c, VMCS_EXIT_REASON,
	    vmexit->u.vmx.exit_reason);
	vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
	    vmcs_read(VMCS_EXIT_QUALIFICATION));
	vmcs12_write_field(c, VMCS_EXIT_INTR_INFO,
	    vmcs_read(VMCS_EXIT_INTR_INFO));
	vmcs12_write_field(c, VMCS_EXIT_INTR_ERRCODE,
	    vmcs_read(VMCS_EXIT_INTR_ERRCODE));
	vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_LENGTH,
	    vmcs_read(VMCS_EXIT_INSTRUCTION_LENGTH));
	vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_INFO,
	    vmcs_read(VMCS_EXIT_INSTRUCTION_INFO));
	for (i = 0; i < nitems(l2state); i++)
		vmcs12_write_field(c, l2state[i], vmcs_read(l2state[i]));
	/* [v2] IA-32e mode guest degli entry controls di VMCS12 = EFER.LMA di L2 */
	efer = vmcs_read(VMCS_GUEST_IA32_EFER);

	/* 3. se VMCS12 non usa VPID, flush del VPID02 (§6.6) */
	if ((vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) &
	    PROCBASED2_ENABLE_VPID) == 0) {
		struct invvpid_desc d;
		bzero(&d, sizeof(d));
		d.vpid = n->vpid2;
		invvpid(INVVPID_TYPE_SINGLE_CONTEXT, d);
	}
	/* 4. commuta a VMCS01 */
	VMCLEAR(vmcs02);
	VMPTRLD(vcpu->vmcs01);
	vcpu->vmcs = vcpu->vmcs01;

	/* 6. Loading Host State: host di VMCS12 -> guest di VMCS01 */
	hcr0 = (vmcs12_read_field(c, VMCS_HOST_CR0) | cr0_ones_mask) &
	    ~cr0_zeros_mask;
	hcr4 = (vmcs12_read_field(c, VMCS_HOST_CR4) | cr4_ones_mask) &
	    ~cr4_zeros_mask;
	hcr3 = vmcs12_read_field(c, VMCS_HOST_CR3);
	hrip = vmcs12_read_field(c, VMCS_HOST_RIP);
	hrsp = vmcs12_read_field(c, VMCS_HOST_RSP);
	vmwrite(VMCS_GUEST_CR0, hcr0);
	vmwrite(VMCS_GUEST_CR3, hcr3);
	vmwrite(VMCS_GUEST_CR4, hcr4);
	vmwrite(VMCS_GUEST_RIP, hrip);
	vmwrite(VMCS_GUEST_RSP, hrsp);
	vmwrite(VMCS_GUEST_RFLAGS, 0x2);		/* bit 1 fisso */
	vmwrite(VMCS_GUEST_DR7, 0x400);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);
	vmwrite(VMCS_GUEST_INTERRUPTIBILITY, 0);
	vmwrite(VMCS_GUEST_ACTIVITY, 0);		/* active */
	vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
	/* SYSENTER */
	vmwrite(VMCS_GUEST_IA32_SYSENTER_CS,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_CS));
	vmwrite(VMCS_GUEST_IA32_SYSENTER_ESP,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_ESP));
	vmwrite(VMCS_GUEST_IA32_SYSENTER_EIP,
	    vmcs12_read_field(c, VMCS_HOST_IA32_SYSENTER_EIP));
	/* EFER/PAT secondo gli exit controls di VMCS12 */
	efer = vmcs12_read_field(c, VMCS_HOST_IA32_EFER);
	pat = vmcs12_read_field(c, VMCS_HOST_IA32_PAT);
	vmwrite(VMCS_GUEST_IA32_EFER, efer);
	vmwrite(VMCS_GUEST_IA32_PAT, pat);
	/* segmenti host: selettori da VMCS12, basi/limiti/attributi standard */
	nested_load_seg(VMCS_GUEST_CS_SELECTOR, VMCS_GUEST_CS_BASE,
	    VMCS_GUEST_CS_LIMIT, VMCS_GUEST_CS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_CS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_CODE);
	nested_load_seg(VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_SS_BASE,
	    VMCS_GUEST_SS_LIMIT, VMCS_GUEST_SS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_SS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_DS_SELECTOR, VMCS_GUEST_DS_BASE,
	    VMCS_GUEST_DS_LIMIT, VMCS_GUEST_DS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_DS_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_ES_BASE,
	    VMCS_GUEST_ES_LIMIT, VMCS_GUEST_ES_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_ES_SELECTOR), 0, 0xfffff,
	    NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_FS_BASE,
	    VMCS_GUEST_FS_LIMIT, VMCS_GUEST_FS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_FS_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_FS_BASE), 0xfffff, NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_GS_SELECTOR, VMCS_GUEST_GS_BASE,
	    VMCS_GUEST_GS_LIMIT, VMCS_GUEST_GS_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_GS_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_GS_BASE), 0xfffff, NESTED_AR_DATA);
	nested_load_seg(VMCS_GUEST_TR_SELECTOR, VMCS_GUEST_TR_BASE,
	    VMCS_GUEST_TR_LIMIT, VMCS_GUEST_TR_ACCESS_RIGHTS,
	    vmcs12_read_field(c, VMCS_HOST_TR_SELECTOR),
	    vmcs12_read_field(c, VMCS_HOST_TR_BASE), 0x67, NESTED_AR_TR);
	vmwrite(VMCS_GUEST_GDTR_BASE, vmcs12_read_field(c, VMCS_HOST_GDTR_BASE));
	vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_IDTR_BASE, vmcs12_read_field(c, VMCS_HOST_IDTR_BASE));
	vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_FS_BASE, vmcs12_read_field(c, VMCS_HOST_FS_BASE));
	vmwrite(VMCS_GUEST_GS_BASE, vmcs12_read_field(c, VMCS_HOST_GS_BASE));

	n->in_l2 = false;
	vmexit->rip = hrip;
	vmexit->inst_length = 0;
	vm_exit_intinfo(vcpu->vcpu, 0);
	SDT_PROBE1(vmm, vmx, nested, reflect, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_REFLECTIONS, 1);
}

/* Legge un bit in una bitmap in memoria dell'L1 (I/O o MSR). true se
 * impostato o se la pagina non e' accessibile (conservativo: riflette). */
static bool
nested_bitmap_bit(struct vmx_vcpu *vcpu, uint64_t bmgpa, uint32_t bit)
{
	uint8_t *b;
	void *cookie;
	bool set;

	b = vm_gpa_hold(vcpu->vcpu, bmgpa + (bit >> 3), 1, VM_PROT_READ,
	    &cookie);
	if (b == NULL)
		return (true);
	set = (*b >> (bit & 7)) & 1;
	vm_gpa_release(cookie);
	return (set);
}

/*
 * Instradamento delle uscite mentre il vCPU e' in L2 (§6.4). Chiamata
 * all'inizio di vmx_exit_process. Ritorna true se l'uscita e' stata gestita
 * qui (riflessa all'L1): il chiamante deve restituire HANDLED senza toccare i
 * rami dell'L1. ext-int/NMI restano all'L0 (ritorna false: il flusso normale
 * li gestisce e si rientra in L2, con VMCS02 ancora corrente).
 */
bool
nested_l2_exit(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	uint32_t reason = vmexit->u.vmx.exit_reason & 0xffff;

	switch (reason) {
	case EXIT_REASON_EXT_INTR:
		/* interrupt fisico per l'host: lo gestisce l'L0, si rientra in L2 */
		return (false);
	case EXIT_REASON_EXCEPTION:
		/* NMI (intr_type NMI) all'L0; le altre eccezioni si riflettono
		 * se nella exception bitmap di VMCS12 (semplificato: riflette). */
		if (((uint32_t)vmcs_read(VMCS_EXIT_INTR_INFO) & 0x700) ==
		    (2 << 8))	/* type 2 = NMI */
			return (false);
		break;			/* eccezione non-NMI -> riflette */
	case EXIT_REASON_INOUT: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12;
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if (p12 & PROCBASED_IO_EXITING) break;	/* uncond -> riflette */
		if (p12 & PROCBASED_IO_BITMAPS) {
			uint16_t port = (vmcs_read(VMCS_EXIT_QUALIFICATION) >>
			    16) & 0xffff;
			uint64_t bm = (port < 0x8000) ?
			    vmcs12_read_field(cc, VMCS_IO_BITMAP_A) :
			    vmcs12_read_field(cc, VMCS_IO_BITMAP_B);
			if (nested_bitmap_bit(vcpu, bm, port & 0x7fff))
				break;			/* L1 intercetta -> riflette */
		}
		return (false);			/* L0 gestisce con i registri di L2 */
	}
	case EXIT_REASON_RDMSR:
	case EXIT_REASON_WRMSR: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12, msr, base, bit;
		bool wr = (reason == EXIT_REASON_WRMSR);
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if ((p12 & PROCBASED_MSR_BITMAPS) == 0) break; /* tutte -> riflette */
		msr = (uint32_t)vmx_get_guest_reg(vcpu, VM_REG_GUEST_RCX);
		if (msr < 0x2000) { base = wr ? 2048 : 0; bit = msr; }
		else if (msr >= 0xc0000000 && msr < 0xc0002000)
			{ base = wr ? 3072 : 1024; bit = msr - 0xc0000000; }
		else break;			/* fuori range -> riflette */
		if (nested_bitmap_bit(vcpu,
		    vmcs12_read_field(cc, VMCS_MSR_BITMAP) + base, bit))
			break;			/* L1 intercetta -> riflette */
		return (false);			/* L0 gestisce con i registri di L2 */
	}
	case EXIT_REASON_MWAIT:
	case EXIT_REASON_MONITOR: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t p12, flag;
		if (cc == NULL) break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		flag = (reason == EXIT_REASON_MWAIT) ? PROCBASED_MWAIT_EXITING :
		    PROCBASED_MONITOR_EXITING;
		if (p12 & flag) break;		/* L1 intercetta -> riflette */
		vm_inject_ud(vcpu->vcpu);	/* non intercettato -> #UD in L2 */
		return (false);
	}
	case EXIT_REASON_EPT_FAULT:
	case EXIT_REASON_EPT_MISCONFIG: {
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		if (cc != NULL && (vmcs12_read_field(cc,
		    VMCS_SEC_PROC_BASED_CTLS) & PROCBASED2_ENABLE_EPT)) {
			if (vmx_vept_fault(vcpu) == 0)
				return (false);	/* shadow installata, rientra in L2 */
			nested_reflect_to_l1(vcpu, vmexit);
			return (true);
		}
		/* VMCS12 senza EPT: L2-GPA == L1-GPA, gestione L0 normale */
		return (false);
	}
	default:
		break;
	}
	/* ogni break qui sopra significa: rifletti all'L1 */
	nested_reflect_to_l1(vcpu, vmexit);
	return (true);
}

static int
nested_invvpid(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct invvpid_desc d;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	/* flush delle mappature VPID02 di L2 (semplificato: single-context) */
	bzero(&d, sizeof(d));
	d.vpid = n->vpid2;
	invvpid(INVVPID_TYPE_SINGLE_CONTEXT, d);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
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
	case EXIT_REASON_VMREAD:	return (nested_vmread(vcpu));
	case EXIT_REASON_VMWRITE:	return (nested_vmwrite(vcpu));
	case EXIT_REASON_VMLAUNCH:	return (nested_vmlaunch(vcpu, false));
	case EXIT_REASON_VMRESUME:	return (nested_vmlaunch(vcpu, true));
	case EXIT_REASON_INVVPID:	return (nested_invvpid(vcpu));
	default:
		vm_inject_ud(vcpu->vcpu);
		return (0);
	}
}

/*
 * Prepara la pagina VMCS02 di una voce di cache (T2.2): alloca se serve,
 * scrive la revision ID, VMCLEAR, poi l'host-state FISSO via vmcs_init_host()
 * sulla pagina resa corrente. I campi host PER-CPU (TR/GDTR/GS base) e
 * HOST_CR3 li scrive il chiamante all'ingresso in L2 (T2.4). Al ritorno non
 * resta nessun VMCS corrente: il chiamante ricarica cio' che gli serve.
 */
int
vmx_nested_vmcs02_setup(struct vmcs12_cache *c)
{
	struct vmcs *v;
	int error;

	if (c->vmcs02 == NULL)
		c->vmcs02 = malloc_aligned(sizeof(struct vmcs), PAGE_SIZE,
		    M_VMX_NESTED, M_WAITOK | M_ZERO);
	v = (struct vmcs *)c->vmcs02;
	v->identifier = vmx_revision();
	if ((error = vmclear(v)) != 0)
		return (error);
	VMPTRLD(v);
	error = vmcs_init_host();
	VMCLEAR(v);
	return (error);
}

/* adjust_ctl: rende un controllo valido sull'hardware (must-be-1 nel dword
 * basso, allowed-1 nell'alto della MSR di capability). Come KVM/ACRN. */
static uint32_t
nested_adjust_ctl(uint32_t desired, u_int msr)
{
	uint64_t cap = rdmsr(msr);
	return ((desired | (uint32_t)cap) & (uint32_t)(cap >> 32));
}

/*
 * Compone VMCS02 da VMCS12 (§6.3). Il VMCS02 deve essere GIA' corrente
 * (VMPTRLD dal chiamante, T2.4). Legge VMCS12 dallo store software; scrive
 * VMCS02 con vmwrite. La corrispondenza riga-per-riga con §6.3 e' in
 * docs/nested/T2.3.md (da rivedere).
 */
int
nested_compose_vmcs02(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmx_vcpu *x = vcpu;
	struct vmcs12_cache *c;
	uint32_t pin, proc, proc2, exitc, entryc, excbmp;
	uint64_t g_cr0, g_cr4, m12cr0, m12cr4;
	int i;
	/* guest-state copiato esplicitamente (niente shadowing hw: §6.2 -> T2) */
	static const uint32_t gstate[] = {
		VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_CS_SELECTOR,
		VMCS_GUEST_SS_SELECTOR, VMCS_GUEST_DS_SELECTOR,
		VMCS_GUEST_FS_SELECTOR, VMCS_GUEST_GS_SELECTOR,
		VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_TR_SELECTOR,
		VMCS_GUEST_ES_LIMIT, VMCS_GUEST_CS_LIMIT, VMCS_GUEST_SS_LIMIT,
		VMCS_GUEST_DS_LIMIT, VMCS_GUEST_FS_LIMIT, VMCS_GUEST_GS_LIMIT,
		VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_TR_LIMIT,
		VMCS_GUEST_GDTR_LIMIT, VMCS_GUEST_IDTR_LIMIT,
		VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_GUEST_CS_ACCESS_RIGHTS,
		VMCS_GUEST_SS_ACCESS_RIGHTS, VMCS_GUEST_DS_ACCESS_RIGHTS,
		VMCS_GUEST_FS_ACCESS_RIGHTS, VMCS_GUEST_GS_ACCESS_RIGHTS,
		VMCS_GUEST_LDTR_ACCESS_RIGHTS, VMCS_GUEST_TR_ACCESS_RIGHTS,
		VMCS_GUEST_ES_BASE, VMCS_GUEST_CS_BASE, VMCS_GUEST_SS_BASE,
		VMCS_GUEST_DS_BASE, VMCS_GUEST_FS_BASE, VMCS_GUEST_GS_BASE,
		VMCS_GUEST_LDTR_BASE, VMCS_GUEST_TR_BASE,
		VMCS_GUEST_GDTR_BASE, VMCS_GUEST_IDTR_BASE,
		VMCS_GUEST_CR3, VMCS_GUEST_DR7, VMCS_GUEST_RSP, VMCS_GUEST_RIP,
		VMCS_GUEST_RFLAGS, VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
		VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_ESP,
		VMCS_GUEST_IA32_SYSENTER_EIP, VMCS_GUEST_IA32_DEBUGCTL,
		VMCS_GUEST_IA32_PAT, VMCS_GUEST_IA32_EFER,
		VMCS_GUEST_INTERRUPTIBILITY, VMCS_GUEST_ACTIVITY,
	};

	c = nested_current_cache(n);
	if (c == NULL)
		return (EINVAL);

	/* --- Pin-based: VMCS12 U {ext-int, NMI exiting}; preempt/posted = 0 --- */
	pin = (uint32_t)vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
	pin |= PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING;
	pin = nested_adjust_ctl(pin, MSR_VMX_TRUE_PINBASED_CTLS);
	pin &= ~(PINBASED_PREMPTION_TIMER | PINBASED_POSTED_INTERRUPT);
	vmwrite(VMCS_PIN_BASED_CTLS, pin);

	/* --- Primary proc: VMCS12 U requisiti L0; I/O bitmaps=0, TPR shadow=0;
	 *     HLT = SOLO VMCS12 (non si eredita da VMCS01) --- */
	proc = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	proc |= PROCBASED_IO_EXITING | PROCBASED_MSR_BITMAPS |
	    PROCBASED_MWAIT_EXITING | PROCBASED_MONITOR_EXITING |
	    PROCBASED_SECONDARY_CONTROLS | PROCBASED_CR8_LOAD_EXITING |
	    PROCBASED_CR8_STORE_EXITING;
	proc = nested_adjust_ctl(proc, MSR_VMX_TRUE_PROCBASED_CTLS);
	proc &= ~(PROCBASED_IO_BITMAPS | PROCBASED_USE_TPR_SHADOW);
	/* T2.6: se l'L1 ha un evento pendente per se', accendi il window-exiting
	 * cosi' l'L2 esce presto e la finestra viene riflessa all'L1 (§6.5). */
	{
		int vec;
		struct vlapic *vl = vm_lapic(x->vcpu);
		if (vlapic_pending_intr(vl, &vec))
			proc |= PROCBASED_INT_WINDOW_EXITING;
		if (vm_nmi_pending(x->vcpu))
			proc |= PROCBASED_NMI_WINDOW_EXITING;
	}
	vmwrite(VMCS_PRI_PROC_BASED_CTLS, proc);

	/* --- Secondary proc: EPT=1, VPID=1, shadowing=0, APIC-virt=0 --- */
	proc2 = (uint32_t)vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS);
	proc2 |= PROCBASED2_ENABLE_EPT | PROCBASED2_ENABLE_VPID;
	proc2 = nested_adjust_ctl(proc2, MSR_VMX_PROCBASED_CTLS2);
	proc2 &= ~(PROCBASED2_VMCS_SHADOWING |
	    PROCBASED2_VIRTUALIZE_APIC_ACCESSES |
	    PROCBASED2_VIRTUALIZE_X2APIC_MODE |
	    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY);
	vmwrite(VMCS_SEC_PROC_BASED_CTLS, proc2);

	/* --- Exit controls: quelli dell'L0 --- */
	exitc = nested_adjust_ctl(exit_ctls, MSR_VMX_TRUE_EXIT_CTLS);
	vmwrite(VMCS_EXIT_CTLS, exitc);

	/* --- Entry controls: IA-32e mode guest = VMCS12; load EFER/PAT/dbg=1 --- */
	entryc = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_CTLS) &
	    VM_ENTRY_GUEST_LMA;
	entryc |= VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_LOAD_PAT |
	    VM_ENTRY_LOAD_EFER;
	entryc = nested_adjust_ctl(entryc, MSR_VMX_TRUE_ENTRY_CTLS);
	entryc &= ~(VM_ENTRY_INTO_SMM | VM_ENTRY_DEACTIVATE_DUAL_MONITOR);
	vmwrite(VMCS_ENTRY_CTLS, entryc);

	/* --- Exception bitmap: VMCS12 U bitmap dell'L0 (#MC, vec30, #DB) --- */
	excbmp = (uint32_t)vmcs12_read_field(c, VMCS_EXCEPTION_BITMAP) |
	    x->cap.exc_bitmap;
	vmwrite(VMCS_EXCEPTION_BITMAP, excbmp);
	vmwrite(VMCS_PF_ERROR_MASK, vmcs12_read_field(c, VMCS_PF_ERROR_MASK));
	vmwrite(VMCS_PF_ERROR_MATCH, vmcs12_read_field(c, VMCS_PF_ERROR_MATCH));

	/* --- CR0/CR4: maschere (mask12), read-shadow (VMCS12), guest con i bit
	 *     fixed dell'host applicati --- */
	m12cr0 = vmcs12_read_field(c, VMCS_CR0_MASK);
	m12cr4 = vmcs12_read_field(c, VMCS_CR4_MASK);
	vmwrite(VMCS_CR0_MASK, m12cr0);
	vmwrite(VMCS_CR4_MASK, m12cr4);
	vmwrite(VMCS_CR0_SHADOW, vmcs12_read_field(c, VMCS_CR0_SHADOW));
	vmwrite(VMCS_CR4_SHADOW, vmcs12_read_field(c, VMCS_CR4_SHADOW));
	g_cr0 = (vmcs12_read_field(c, VMCS_GUEST_CR0) | cr0_ones_mask) &
	    ~cr0_zeros_mask;
	g_cr4 = (vmcs12_read_field(c, VMCS_GUEST_CR4) | cr4_ones_mask) &
	    ~cr4_zeros_mask;
	vmwrite(VMCS_GUEST_CR0, g_cr0);
	vmwrite(VMCS_GUEST_CR4, g_cr4);

	/* --- resto del guest-state copiato esplicitamente --- */
	for (i = 0; i < (int)nitems(gstate); i++)
		vmwrite(gstate[i], vmcs12_read_field(c, gstate[i]));

	/* --- EPTP, VPID, MSR bitmap, TSC offset, liste MSR, link pointer --- */
	/* EPTP: shadow EPT se VMCS12 usa EPT (T2.7), altrimenti EPTP01. */
	if (vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) &
	    PROCBASED2_ENABLE_EPT)
		vmwrite(VMCS_EPTP, vmx_vept_eptp(vcpu));
	else
		vmwrite(VMCS_EPTP, x->vmx->eptp);
	/* VPID02 distinto per l2 (T2.8), per non aliasare la TLB con l1 */
	vmwrite(VMCS_VPID, n->vpid2);
	/* MSR bitmap: quello dell'L0 (intercetta cio' che serve a L0); la
	 * fusione con quello dell'L1 e' T6.3. */
	vmwrite(VMCS_MSR_BITMAP, vtophys(x->vmx->msr_bitmap));
	/* TSC offset: quello di VMCS12 (l'offset dell'L0 si somma in T2). */
	vmwrite(VMCS_TSC_OFFSET, vmcs12_read_field(c, VMCS_TSC_OFFSET));
	/* liste MSR a 0 (applicate in software nello slow path, §6.3). */
	vmwrite(VMCS_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VMCS_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_LINK_POINTER, ~0UL);

	/* entry interruption info: VMCS12 (prima entry dopo VMLAUNCH/VMRESUME). */
	vmwrite(VMCS_ENTRY_INTR_INFO, vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO));

	c->control_dirty = false;
	SDT_PROBE1(vmm, vmx, nested, enter_l2, vcpu);
	return (0);
}

/*
 * Controllo di sicurezza OBBLIGATORIO prima di ogni VMLAUNCH/VMRESUME su
 * VMCS02 (§3). Unico chiamante: subito prima di vmx_enter_guest (T2.4). Il
 * VMCS02 deve essere corrente. Ritorna 0 se e' sicuro entrare.
 */
int
nested_vmcs02_check(struct vmx_vcpu *vcpu)
{
	uint32_t pin, proc, proc2;
	uint64_t link;

	pin   = (uint32_t)vmcs_read(VMCS_PIN_BASED_CTLS);
	proc  = (uint32_t)vmcs_read(VMCS_PRI_PROC_BASED_CTLS);
	proc2 = (uint32_t)vmcs_read(VMCS_SEC_PROC_BASED_CTLS);
	link  = vmcs_read(VMCS_LINK_POINTER);

	/* requisiti dell'L0 presenti */
	if ((pin & (PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING)) !=
	    (PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING))
		return (EINVAL);
	if ((proc & PROCBASED_SECONDARY_CONTROLS) == 0)
		return (EINVAL);
	/* I/O incondizionato e NIENTE I/O bitmaps */
	if ((proc & PROCBASED_IO_EXITING) == 0 ||
	    (proc & PROCBASED_IO_BITMAPS) != 0)
		return (EINVAL);
	/* HLT NON ereditato da VMCS01: non deve essere forzato dall'L0 qui.
	 * (Se c'e', deve venire da VMCS12; non lo possiamo distinguere a
	 * posteriori, quindi e' solo un promemoria per la review.) */
	/* shadowing spento, EPT acceso, link pointer ~0 */
	if ((proc2 & PROCBASED2_VMCS_SHADOWING) != 0)
		return (EINVAL);
	if ((proc2 & PROCBASED2_ENABLE_EPT) == 0)
		return (EINVAL);
	if (link != ~0UL)
		return (EINVAL);
	return (0);
}
