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
#include <sys/proc.h>
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

static void	nested_bitmaps_unmap(struct vmcs12_cache *c);
static void	nested_msr_list_unmap(struct nested_msr_list *l);
static int	nested_bitmaps_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c);
static void	nested_msr_list_exit(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c, bool store);
static uint32_t	nested_msr_list_entry(struct vmx_vcpu *vcpu,
		    struct vmcs12_cache *c);
static void	nested_reflect_to_l1(struct vmx_vcpu *vcpu,
		    struct vm_exit *vmexit);

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
		nested_bitmaps_unmap(&n->cache[i]);
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
	if (errnum != VMXR_SUCCEED) {
		/* SDM VMfail: VMfailValid(errnum) se c'e' un VMCS corrente,
		 * altrimenti VMfailInvalid (non c'e' dove scrivere l'errore). */
		struct vmcs12_cache *c = nested_current_cache(vcpu->nested);
		if (c != NULL) {		/* L1 lo legge via VMREAD 0x4400 */
			rflags |= PSL_Z;
			vmcs12_write_field(c, VMCS_INSTRUCTION_ERROR, errnum);
		} else
			rflags |= PSL_C;
	}
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RFLAGS, rflags);
}

/*
 * Sonda: stampa host-state, controlli e campi d'uscita del VMCS CORRENTE
 * (vmread grezzo: chiamarla solo con un VMCS caricato). Con
 * hw.vmm.vmx.nested_probe=1..3, vedi vmx.c.
 */
void
nested_probe_dump(const char *tag)
{
	static const struct { uint32_t enc; const char *nm; } f[] = {
		{ VMCS_HOST_CR0, "H_CR0" }, { VMCS_HOST_CR3, "H_CR3" },
		{ VMCS_HOST_CR4, "H_CR4" }, { VMCS_HOST_RSP, "H_RSP" },
		{ VMCS_HOST_RIP, "H_RIP" }, { VMCS_HOST_CS_SELECTOR, "H_CS" },
		{ VMCS_HOST_SS_SELECTOR, "H_SS" }, { VMCS_HOST_DS_SELECTOR, "H_DS" },
		{ VMCS_HOST_ES_SELECTOR, "H_ES" }, { VMCS_HOST_FS_SELECTOR, "H_FS" },
		{ VMCS_HOST_GS_SELECTOR, "H_GS" }, { VMCS_HOST_TR_SELECTOR, "H_TR" },
		{ VMCS_HOST_FS_BASE, "H_FSB" }, { VMCS_HOST_GS_BASE, "H_GSB" },
		{ VMCS_HOST_TR_BASE, "H_TRB" }, { VMCS_HOST_GDTR_BASE, "H_GDTRB" },
		{ VMCS_HOST_IDTR_BASE, "H_IDTRB" },
		{ VMCS_HOST_IA32_SYSENTER_CS, "H_SECS" },
		{ VMCS_HOST_IA32_SYSENTER_ESP, "H_SESP" },
		{ VMCS_HOST_IA32_SYSENTER_EIP, "H_SEIP" },
		{ VMCS_HOST_IA32_EFER, "H_EFER" }, { VMCS_HOST_IA32_PAT, "H_PAT" },
		{ VMCS_HOST_IA32_PERF_GLOBAL_CTRL, "H_PGC" },
		{ VMCS_PIN_BASED_CTLS, "PIN" }, { VMCS_PRI_PROC_BASED_CTLS, "PROC" },
		{ VMCS_SEC_PROC_BASED_CTLS, "PROC2" }, { VMCS_EXIT_CTLS, "EXIT" },
		{ VMCS_ENTRY_CTLS, "ENTRY" }, { VMCS_EPTP, "EPTP" },
		{ VMCS_VPID, "VPID" }, { VMCS_LINK_POINTER, "LINK" },
		{ VMCS_MSR_BITMAP, "MSRBM" },
		{ VMCS_EXIT_MSR_LOAD_COUNT, "XMLC" },
		{ VMCS_EXIT_MSR_STORE_COUNT, "XMSC" },
		{ VMCS_ENTRY_MSR_LOAD_COUNT, "NMLC" },
		{ VMCS_GUEST_RIP, "G_RIP" }, { VMCS_GUEST_RSP, "G_RSP" },
		{ VMCS_GUEST_RFLAGS, "G_RFL" }, { VMCS_GUEST_CR0, "G_CR0" },
		{ VMCS_GUEST_CR3, "G_CR3" }, { VMCS_GUEST_CR4, "G_CR4" },
		{ VMCS_GUEST_IA32_EFER, "G_EFER" },
		{ VMCS_GUEST_CS_SELECTOR, "G_CS" },
		{ VMCS_GUEST_CS_ACCESS_RIGHTS, "G_CSAR" },
		{ VMCS_GUEST_TR_ACCESS_RIGHTS, "G_TRAR" },
		{ VMCS_GUEST_ACTIVITY, "G_ACT" },
		{ VMCS_GUEST_INTERRUPTIBILITY, "G_INTR" },
		{ VMCS_ENTRY_INTR_INFO, "N_INTINFO" },
		{ VMCS_EXIT_REASON, "X_REASON" },
		{ VMCS_EXIT_QUALIFICATION, "X_QUAL" },
		{ VMCS_EXIT_INTR_INFO, "X_INTINFO" },
		{ VMCS_IDT_VECTORING_INFO, "X_IDTVEC" },
	};
	uint64_t v;
	int i;

	for (i = 0; i < (int)nitems(f); i++) {
		if (i % 6 == 0)
			printf("%snested_probe %s:", i ? "\n" : "", tag);
		if (vmread(f[i].enc, &v) == 0)
			printf(" %s=%#lx", f[i].nm, v);
		else
			printf(" %s=ERR", f[i].nm);
	}
	printf("\n");
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
/* indirizzo canonico a 48 bit (LA57 non esposto all'L1) */
static bool
nested_canonical(uint64_t a)
{
	return ((int64_t)(a << 16) >> 16) == (int64_t)a;
}

static int
nested_operand_gpa_at(struct vmx_vcpu *vcpu, int prot, uint64_t add,
    uint64_t *gpa);

static int
nested_operand_gpa(struct vmx_vcpu *vcpu, int prot, uint64_t *gpa)
{
	return (nested_operand_gpa_at(vcpu, prot, 0, gpa));
}

/* Come sopra, per gli 8 byte a 'add' byte dall'inizio dell'operando
 * (descrittori di INVVPID/INVEPT: 16 byte, letti in due meta'). */
static int
nested_operand_gpa_at(struct vmx_vcpu *vcpu, int prot, uint64_t add,
    uint64_t *gpa)
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

	offset = qual + add;			/* displacement */
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
		/* SDM: riferimento via SS -> #SS(0), altrimenti #GP(0) */
		if (seg == VM_REG_GUEST_SS)
			vm_inject_ss(vcpu->vcpu, 0);
		else
			vm_inject_gp(vcpu->vcpu);
		return (-1);
	}
	/*
	 * In modo 64 bit vie_calculate_gla non rifiuta un indirizzo non
	 * canonico: lo farebbe vm_gla2gpa, ma sempre con #GP. Via SS l'SDM
	 * vuole #SS(0) (kvm-unit-tests invvpid_test_ss).
	 */
	if (paging.cpu_mode == CPU_MODE_64BIT && !nested_canonical(gla)) {
		if (seg == VM_REG_GUEST_SS)
			vm_inject_ss(vcpu->vcpu, 0);
		else
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

/*
 * CR0/CR4 come li vede l'L1: i bit posseduti da L0 (maschera) vengono dal
 * read-shadow. Serve perche' bhyve forza bit come CR0.NE e CR4.VMXE nel
 * registro reale del guest. vm_get_register con VMCS_IDENT fa
 * VMPTRLD/VMCLEAR da se': sicuro anche nello slow path.
 */
static uint64_t
nested_guest_cr(struct vmx_vcpu *vcpu, int reg, uint32_t mask_enc,
    uint32_t shadow_enc)
{
	uint64_t v, m, s;

	vm_get_register(vcpu->vcpu, reg, &v);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(mask_enc), &m);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(shadow_enc), &s);
	return ((v & ~m) | (s & m));
}

static bool
nested_fixed_ok(uint64_t val, uint64_t fixed0, uint64_t fixed1)
{
	return ((val & fixed0) == fixed0 && (val & ~fixed1) == 0);
}

static int
nested_vmxon(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t ptr, cr0, cr4;
	uint32_t *p, rev;
	void *cookie;

	/*
	 * In VMX non-root VMXON esce SEMPRE verso L0, prima dei controlli
	 * dell'SDM: li rifacciamo qui, nell'ordine dell'SDM (come KVM
	 * handle_vmxon). Verificati da kvm-unit-tests test_vmxon.
	 */
	cr0 = nested_guest_cr(vcpu, VM_REG_GUEST_CR0, VMCS_CR0_MASK,
	    VMCS_CR0_SHADOW);
	cr4 = nested_guest_cr(vcpu, VM_REG_GUEST_CR4, VMCS_CR4_MASK,
	    VMCS_CR4_SHADOW);
	if ((cr4 & CR4_VMXE) == 0) {		/* precede la VM exit: #UD */
		vm_inject_ud(vcpu->vcpu);
		return (0);
	}
	if (n->exit_paging.cpl != 0) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if (n->vmxon) {
		nested_vmx_result(vcpu, VMXERR_VMXON_IN_VMX_ROOT);
		goto done;
	}
	if (!nested_fixed_ok(cr0, n->vmx_msr[0x486 - 0x480],
	    n->vmx_msr[0x487 - 0x480]) ||
	    !nested_fixed_ok(cr4, n->vmx_msr[0x488 - 0x480],
	    n->vmx_msr[0x489 - 0x480])) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if ((n->feature_control & (IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN)) != (IA32_FEATURE_CONTROL_LOCK |
	    IA32_FEATURE_CONTROL_VMX_EN)) {
		vm_inject_gp(vcpu->vcpu);
		return (0);
	}
	if (nested_read_operand_u64(vcpu, &ptr) != 0)
		return (0);
	/* VMXON region: allineata a 4K, entro MAXPHYADDR, revisione giusta. */
	if ((ptr & PAGE_MASK) != 0 || (ptr >> cpu_maxphyaddr) != 0) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	p = vm_gpa_hold(vcpu->vcpu, ptr, sizeof(*p), VM_PROT_READ, &cookie);
	if (p == NULL) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
	rev = *p;
	vm_gpa_release(cookie);
	if (rev != (uint32_t)(n->vmx_msr[0] & 0x7fffffff)) {
		nested_vmfail_invalid(vcpu);
		goto done;
	}
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
		nested_bitmaps_unmap(&n->cache[i]);
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
	if ((vmcs12 & PAGE_MASK) != 0 || (vmcs12 >> cpu_maxphyaddr) != 0) {
		nested_vmx_result(vcpu, VMXERR_VMCLEAR_INVALID_ADDRESS);
		goto done;
	}
	if (vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMCLEAR_VMXON_POINTER);
		goto done;
	}
	if (vmcs12 == n->current_vmcs12)
		n->current_vmcs12 = VMCS12_GPA_NONE;
	for (i = 0; i < VMX_NESTED_MAX_VMCS12; i++) {
		if (n->cache[i].vmcs12_gpa == vmcs12) {
			nested_bitmaps_unmap(&n->cache[i]);
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
	if ((vmcs12 & PAGE_MASK) != 0 || (vmcs12 >> cpu_maxphyaddr) != 0) {
		nested_vmx_result(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
		goto done;
	}
	if (vmcs12 == n->vmxon_ptr) {
		nested_vmx_result(vcpu, VMXERR_VMPTRLD_VMXON_POINTER);
		goto done;
	}
	/*
	 * Revisione del VMCS12 (primi 31 bit) = quella esposta in
	 * IA32_VMX_BASIC; il bit 31 (shadow-VMCS indicator) e' ammesso solo
	 * se l'L1 ha il VMCS shadowing, che NON gli esponiamo -> errore.
	 */
	{
		uint32_t *p, rev;
		void *cookie;

		p = vm_gpa_hold(vcpu->vcpu, vmcs12, sizeof(*p), VM_PROT_READ,
		    &cookie);
		if (p == NULL) {
			nested_vmx_result(vcpu, VMXERR_VMPTRLD_INVALID_ADDRESS);
			goto done;
		}
		rev = *p;
		vm_gpa_release(cookie);
		if (rev != (uint32_t)(n->vmx_msr[0] & 0x7fffffff)) {
			nested_vmx_result(vcpu,
			    VMXERR_VMPTRLD_INCORRECT_REVISION);
			goto done;
		}
	}
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
		nested_bitmaps_unmap(&n->cache[slot]);	/* evizione */
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
 * Encoding VMCS dell'L1. All'L1 esponiamo la stessa CPU (VMCS_ENUM compreso):
 * un campo e' supportato se e solo se un VMREAD reale di quell'encoding
 * riesce (vm_get_register con VMCS_IDENT fa VMPTRLD/VMCLEAR da se').
 * Prima lo store accettava QUALUNQUE encoding (kvm-unit-tests: MAX_INDEX
 * 0x1ff invece di 0x17).
 */
static bool
nested_field_ok(struct vmx_vcpu *vcpu, uint32_t field)
{
	uint64_t tmp;

	if ((field & 0xffff8000) != 0)		/* bit 31:15 riservati */
		return (false);
	return (vm_get_register(vcpu->vcpu, VMCS_IDENT(field), &tmp) == 0);
}

/* Larghezza del campo (bit 14:13): 0=16, 1=64, 2=32, 3=naturale. */
#define	NESTED_FIELD_WIDTH(f)	(((f) >> 13) & 3)
/* Accesso HIGH (bit 0) di un campo a 64 bit = meta' alta dello stesso campo. */
#define	NESTED_FIELD_HIGH(f)	(NESTED_FIELD_WIDTH(f) == 1 && ((f) & 1) != 0)

static uint64_t
nested_field_mask(uint32_t field)
{
	switch (NESTED_FIELD_WIDTH(field)) {
	case 0:	return (0xffffULL);
	case 2:	return (0xffffffffULL);
	default: return (~0ULL);
	}
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
	if (!nested_field_ok(vcpu, field)) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	if (NESTED_FIELD_HIGH(field))
		val = vmcs12_read_field(c, field & ~1U) >> 32;
	else
		val = vmcs12_read_field(c, field) & nested_field_mask(field);

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
	if (!nested_field_ok(vcpu, field)) {
		nested_vmx_result(vcpu, VMXERR_UNSUPPORTED_VMCS_COMPONENT);
		goto done;
	}
	if (NESTED_FIELD_HIGH(field)) {		/* scrive la meta' alta */
		field &= ~1U;
		val = (vmcs12_read_field(c, field) & 0xffffffffULL) |
		    (val << 32);
	} else
		val &= nested_field_mask(field);
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
/*
 * Controlli SDM 26.2.1 (campi di controllo, VMfailValid 7) e 26.2.2-26.2.4
 * (stato host e dimensione dello spazio d'indirizzi, VMfailValid 8) sul
 * VMCS12, contro le capacita' VMX ESPOSTE all'L1 (n->vmx_msr). Prima erano
 * "rimandati": la composizione aggiunge di suo i bit obbligatori e nascondeva
 * gli errori dell'L1 (kvm-unit-tests vmx_controls_test,
 * vmx_host_state_area_test). Slow path: puo' leggere la memoria dell'L1
 * (VTPR della pagina virtual-APIC). 0 se tutto valido.
 */
static bool
nested_pa_ok(uint64_t pa, uint64_t align)
{
	return ((pa & (align - 1)) == 0 && (pa >> cpu_maxphyaddr) == 0);
}

static bool
nested_ctl_ok(uint32_t val, uint64_t msr)
{
	return ((val & (uint32_t)msr) == (uint32_t)msr &&
	    (val & ~(uint32_t)(msr >> 32)) == 0);
}

static bool
nested_msr_area_ok(struct vmcs12_cache *c, uint32_t addr_f, uint32_t cnt_f)
{
	uint64_t a = vmcs12_read_field(c, addr_f);
	uint64_t n = vmcs12_read_field(c, cnt_f);

	if (n == 0)
		return (true);
	return ((a & 0xf) == 0 && ((a + n * 16 - 1) >> cpu_maxphyaddr) == 0);
}

static int
nested_check_vmentry(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t *m = n->vmx_msr;
	bool tru = (m[0] >> 55) & 1;
	uint32_t pin, proc, proc2, exitc, entryc, info;
	uint64_t misc = m[0x485 - 0x480], cap = m[0x48c - 0x480];
	uint64_t v, l1efer = 0;
	bool hostlm;
	int i;

	pin = (uint32_t)vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
	proc = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	proc2 = (proc & PROCBASED_SECONDARY_CONTROLS) ?
	    (uint32_t)vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) : 0;
	exitc = (uint32_t)vmcs12_read_field(c, VMCS_EXIT_CTLS);
	entryc = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_CTLS);

	/* --- 26.2.1.1 controlli d'esecuzione --- */
	if (!nested_ctl_ok(pin, m[(tru ? 0x48d : 0x481) - 0x480]) ||
	    !nested_ctl_ok(proc, m[(tru ? 0x48e : 0x482) - 0x480]) ||
	    ((proc & PROCBASED_SECONDARY_CONTROLS) &&
	    !nested_ctl_ok(proc2, m[0x48b - 0x480])))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (vmcs12_read_field(c, VMCS_CR3_TARGET_COUNT) > ((misc >> 16) & 0x1ff))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc & PROCBASED_IO_BITMAPS) &&
	    (!nested_pa_ok(vmcs12_read_field(c, VMCS_IO_BITMAP_A), PAGE_SIZE) ||
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_IO_BITMAP_B), PAGE_SIZE)))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc & PROCBASED_MSR_BITMAPS) &&
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_MSR_BITMAP), PAGE_SIZE))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (proc & PROCBASED_USE_TPR_SHADOW) {
		uint64_t va = vmcs12_read_field(c, VMCS_VIRTUAL_APIC);
		uint32_t thr = (uint32_t)vmcs12_read_field(c, VMCS_TPR_THRESHOLD);

		if (!nested_pa_ok(va, PAGE_SIZE))
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if ((proc2 & PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY) == 0) {
			if ((thr & ~0xfU) != 0)
				return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
			if ((proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) == 0) {
				uint8_t *pg;
				void *ck;
				uint8_t vtpr;

				pg = vm_gpa_hold(vcpu->vcpu, va, PAGE_SIZE,
				    VM_PROT_READ, &ck);
				if (pg == NULL)
					return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
				vtpr = pg[0x80];
				vm_gpa_release(ck);
				if ((thr & 0xf) > (uint32_t)(vtpr >> 4))
					return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
			}
		}
	} else if (proc2 & (PROCBASED2_VIRTUALIZE_X2APIC_MODE |
	    PROCBASED2_APIC_REGISTER_VIRTUALIZATION |
	    PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_NMI_EXITING) == 0 && (pin & PINBASED_VIRTUAL_NMI))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_VIRTUAL_NMI) == 0 &&
	    (proc & PROCBASED_NMI_WINDOW_EXITING))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES) &&
	    !nested_pa_ok(vmcs12_read_field(c, VMCS_APIC_ACCESS), PAGE_SIZE))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUALIZE_X2APIC_MODE) &&
	    (proc2 & PROCBASED2_VIRTUALIZE_APIC_ACCESSES))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_VIRTUAL_INTERRUPT_DELIVERY) &&
	    (pin & PINBASED_EXTINT_EXITING) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((proc2 & PROCBASED2_ENABLE_VPID) &&
	    (vmcs12_read_field(c, VMCS_VPID) & 0xffff) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (proc2 & PROCBASED2_ENABLE_EPT) {
		uint64_t e = vmcs12_read_field(c, VMCS_EPTP);
		uint64_t mt = e & 7;

		if (!((mt == 0 && (cap & (1ULL << 8))) ||
		    (mt == 6 && (cap & (1ULL << 14)))) ||
		    ((e >> 3) & 7) != 3 ||
		    ((e & (1ULL << 6)) && (cap & (1ULL << 21)) == 0) ||
		    (e & 0xf80) != 0 || (e >> cpu_maxphyaddr) != 0)
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	}
	if ((proc2 & PROCBASED2_UNRESTRICTED_GUEST) &&
	    (proc2 & PROCBASED2_ENABLE_EPT) == 0)
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.1.2 controlli d'uscita --- */
	if (!nested_ctl_ok(exitc, m[(tru ? 0x48f : 0x483) - 0x480]))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if ((pin & PINBASED_PREMPTION_TIMER) == 0 &&
	    (exitc & VM_EXIT_SAVE_PREEMPTION_TIMER))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	if (!nested_msr_area_ok(c, VMCS_EXIT_MSR_STORE,
	    VMCS_EXIT_MSR_STORE_COUNT) ||
	    !nested_msr_area_ok(c, VMCS_EXIT_MSR_LOAD, VMCS_EXIT_MSR_LOAD_COUNT))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.1.3 controlli d'ingresso --- */
	if (!nested_ctl_ok(entryc, m[(tru ? 0x490 : 0x484) - 0x480]) ||
	    (entryc & (VM_ENTRY_INTO_SMM | VM_ENTRY_DEACTIVATE_DUAL_MONITOR)))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
	info = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO);
	if (info & VMCS_INTR_VALID) {
		uint32_t type = (info >> 8) & 7, vec = info & 0xff;
		bool pe = (vmcs12_read_field(c, VMCS_GUEST_CR0) & CR0_PE) != 0;
		bool ec, want;

		if (type == 1 ||
		    (type == 7 && (vec != 0 ||
		    ((m[(tru ? 0x48e : 0x482) - 0x480] >> 32) &
		    PROCBASED_MTF) == 0)) ||
		    (type == 2 && vec != 2) || (type == 3 && vec > 31))
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		ec = (info & (1U << 11)) != 0;
		want = type == 3 && (pe ||
		    (proc2 & PROCBASED2_UNRESTRICTED_GUEST) == 0) &&
		    (vec == 8 || (vec >= 10 && vec <= 14) || vec == 17 ||
		    vec == 21);
		if (ec != want || (info & 0x7ffff000U) != 0)
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if (ec && (vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR) >>
		    16) != 0)
			return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		if (type >= 4 && type <= 6) {
			v = vmcs12_read_field(c, VMCS_ENTRY_INST_LENGTH);
			if (v > 15 || (v == 0 && (misc & (1ULL << 30)) == 0))
				return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		}
	}
	if (!nested_msr_area_ok(c, VMCS_ENTRY_MSR_LOAD,
	    VMCS_ENTRY_MSR_LOAD_COUNT))
		return (VMXERR_ENTRY_INVALID_CONTROL_FIELD);

	/* --- 26.2.2 stato host --- */
	if (!nested_fixed_ok(vmcs12_read_field(c, VMCS_HOST_CR0),
	    m[0x486 - 0x480], m[0x487 - 0x480]) ||
	    !nested_fixed_ok(vmcs12_read_field(c, VMCS_HOST_CR4),
	    m[0x488 - 0x480], m[0x489 - 0x480]) ||
	    (vmcs12_read_field(c, VMCS_HOST_CR3) >> cpu_maxphyaddr) != 0 ||
	    !nested_canonical(vmcs12_read_field(c,
	    VMCS_HOST_IA32_SYSENTER_ESP)) ||
	    !nested_canonical(vmcs12_read_field(c,
	    VMCS_HOST_IA32_SYSENTER_EIP)))
		return (VMXERR_ENTRY_INVALID_HOST_STATE);
	if (exitc & VM_EXIT_LOAD_PAT) {
		v = vmcs12_read_field(c, VMCS_HOST_IA32_PAT);
		for (i = 0; i < 8; i++) {
			uint8_t t = (v >> (i * 8)) & 0xff;

			if (t == 2 || t == 3 || t > 7)
				return (VMXERR_ENTRY_INVALID_HOST_STATE);
		}
	}
	hostlm = (exitc & VM_EXIT_HOST_LMA) != 0;
	if (exitc & VM_EXIT_LOAD_EFER) {
		v = vmcs12_read_field(c, VMCS_HOST_IA32_EFER);
		if ((v & ~(EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE)) != 0 ||
		    ((v & EFER_LMA) != 0) != hostlm ||
		    ((v & EFER_LME) != 0) != hostlm)
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	{
		static const uint32_t sel[] = {
			VMCS_HOST_ES_SELECTOR, VMCS_HOST_CS_SELECTOR,
			VMCS_HOST_SS_SELECTOR, VMCS_HOST_DS_SELECTOR,
			VMCS_HOST_FS_SELECTOR, VMCS_HOST_GS_SELECTOR,
			VMCS_HOST_TR_SELECTOR,
		};
		for (i = 0; i < (int)nitems(sel); i++)
			if (vmcs12_read_field(c, sel[i]) & 0x7)	/* RPL, TI */
				return (VMXERR_ENTRY_INVALID_HOST_STATE);
		if (vmcs12_read_field(c, VMCS_HOST_CS_SELECTOR) == 0 ||
		    vmcs12_read_field(c, VMCS_HOST_TR_SELECTOR) == 0 ||
		    (!hostlm && vmcs12_read_field(c, VMCS_HOST_SS_SELECTOR) == 0))
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	if (!nested_canonical(vmcs12_read_field(c, VMCS_HOST_FS_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_GS_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_GDTR_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_IDTR_BASE)) ||
	    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_TR_BASE)))
		return (VMXERR_ENTRY_INVALID_HOST_STATE);

	/* --- 26.2.4 dimensione dello spazio d'indirizzi --- */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_EFER, &l1efer);
	if (((l1efer & EFER_LMA) != 0) != hostlm)
		return (VMXERR_ENTRY_INVALID_HOST_STATE);
	if (hostlm) {
		if ((vmcs12_read_field(c, VMCS_HOST_CR4) & CR4_PAE) == 0 ||
		    !nested_canonical(vmcs12_read_field(c, VMCS_HOST_RIP)))
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	} else {
		if ((entryc & VM_ENTRY_GUEST_LMA) ||
		    (vmcs12_read_field(c, VMCS_HOST_CR4) & CR4_PCIDE) ||
		    (vmcs12_read_field(c, VMCS_HOST_RIP) >> 32) != 0)
			return (VMXERR_ENTRY_INVALID_HOST_STATE);
	}
	return (0);
}

/*
 * PAE senza EPT nel VMCS12: la CPU vera, al VM-entry, legge i 4 PDPTE dalla
 * memoria di CR3 e ne verifica i bit riservati (SDM 26.3.1.6). Il VMCS02 usa
 * sempre EPT (quella di L0), quindi la CPU li prenderebbe dai campi PDPTE del
 * VMCS: li si legge qui (slow path, PRIMA del VMPTRLD: vm_gpa_hold puo'
 * dormire) e la composizione li scrive. Prima si copiavano i campi PDPTE del
 * VMCS12, senza senso in questo caso (kvm-unit-tests vmx_pae_test, che poi si
 * bloccava). Riservati: bit 2:1, 8:5, da MAXPHYADDR a 62, e 63 senza EFER.NX.
 */
static void
nested_load_pdptes(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct vmx_nested *n = vcpu->nested;
	uint64_t cr0, cr4, efer, cr3, *p, rsvd;
	void *ck;
	int i;

	n->pdpte_mem = n->pdpte_bad = false;
	cr0 = vmcs12_read_field(c, VMCS_GUEST_CR0);
	cr4 = vmcs12_read_field(c, VMCS_GUEST_CR4);
	if ((vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
	    PROCBASED_SECONDARY_CONTROLS) != 0 &&
	    (vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) &
	    PROCBASED2_ENABLE_EPT) != 0)
		return;				/* con EPT12: dal VMCS12 */
	if ((cr0 & CR0_PG) == 0 || (cr4 & CR4_PAE) == 0 ||
	    (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_GUEST_LMA) != 0)
		return;				/* non e' paging PAE */
	efer = vmcs12_read_field(c, VMCS_GUEST_IA32_EFER);
	cr3 = vmcs12_read_field(c, VMCS_GUEST_CR3) & 0xffffffe0UL;
	rsvd = 0x1e6ULL | (((1ULL << 63) - 1) & ~((1ULL << cpu_maxphyaddr) - 1));
	if ((efer & EFER_NXE) == 0)
		rsvd |= 1ULL << 63;
	p = vm_gpa_hold(vcpu->vcpu, cr3, 4 * sizeof(uint64_t), VM_PROT_READ,
	    &ck);
	if (p == NULL) {
		n->pdpte_bad = true;
		return;
	}
	for (i = 0; i < 4; i++) {
		n->pdpte[i] = p[i];
		if ((p[i] & 1) != 0 && (p[i] & rsvd) != 0)
			n->pdpte_bad = true;
	}
	vm_gpa_release(ck);
	n->pdpte_mem = true;
}

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
	/* SDM 26.1: VMLAUNCH/VMRESUME nell'ombra di un MOV SS -> VMfail 26,
	 * prima del controllo sul launch state (vmentry_movss_shadow_test) */
	{
		uint64_t gi = 0;

		vm_get_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_GUEST_INTERRUPTIBILITY), &gi);
		if (gi & VMCS_INTERRUPTIBILITY_MOVSS_BLOCKING) {
			nested_vmx_result(vcpu, VMXERR_ENTRY_MOV_SS_BLOCKING);
			nested_advance_rip(vcpu);
			return (0);
		}
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
	/* controlli SDM su controlli e stato host del VMCS12 (VMfail 7 / 8);
	 * lo stato guest lo verifica l'hardware sul VMCS02 */
	if ((error = nested_check_vmentry(vcpu, c)) != 0) {
		nested_vmx_result(vcpu, error);
		nested_advance_rip(vcpu);
		return (0);
	}

	/* Bitmap I/O e MSR dell'L1: mappate qui (slow path, si puo' dormire),
	 * lette dal percorso veloce. Non mappabili -> controllo non valido. */
	if (nested_bitmaps_map(vcpu, c) != 0) {
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}

	/* DR7/DEBUGCTL dell'L1, letti ORA (VMCS01 ancora vcpu->vmcs; dopo il
	 * VMPTRLD del VMCS02 vm_get_register lo scaricherebbe): se l'L1 non
	 * chiede load debug controls, l'L2 li eredita (compose). */
	vm_get_register(vcpu->vcpu, VM_REG_GUEST_DR7, &n->l1_dr7);
	vm_get_register(vcpu->vcpu, VMCS_IDENT(VMCS_GUEST_IA32_DEBUGCTL),
	    &n->l1_debugctl);
	/* TSC dell'L1 = TSC host + offset del VMCS01 (se usato): l'L2 vede
	 * quello dell'L1 + l'offset del VMCS12. Si legge ORA, come DR7. */
	{
		uint64_t p01 = 0, o01 = 0;

		vm_get_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_PRI_PROC_BASED_CTLS), &p01);
		if (p01 & PROCBASED_TSC_OFFSET)
			vm_get_register(vcpu->vcpu,
			    VMCS_IDENT(VMCS_TSC_OFFSET), &o01);
		n->l1_tsc_offset = o01;
	}

	/* host-state fisso del VMCS02 (lascia nessun VMCS corrente) */
	if ((error = vmx_nested_vmcs02_setup(c)) != 0) {
		nested_vmx_result(vcpu, VMXERR_ENTRY_INVALID_CONTROL_FIELD);
		nested_advance_rip(vcpu);
		return (0);
	}
	vmcs02 = (struct vmcs *)c->vmcs02;

	nested_load_pdptes(vcpu, c);		/* puo' dormire: prima del VMPTRLD */

	/* Shadow EPT: radice preparata QUI, dove si puo' dormire. Da VMPTRLD
	 * in poi si e' in sezione critica (niente malloc ne' vm_gpa_hold). */
	if (vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) &
	    PROCBASED2_ENABLE_EPT)
		vmx_vept_prepare(vcpu);

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
	/*
	 * Lista "carica all'ingresso" del VMCS12 (dopo lo stato guest, SDM
	 * 26.4). Prima le liste MSR erano azzerate e mai applicate. Un elemento
	 * non caricabile (es. FS_BASE, vietato) e' un VM-entry fallito: uscita
	 * verso l'L1 con motivo 34 + bit 31 e qualificazione = indice 1-based.
	 */
	{
		/* PDPTE non validi: stato guest non valido (33), qualificazione 2,
		 * PRIMA delle liste MSR (SDM: i controlli di stato vengono prima) */
		uint32_t fail = n->pdpte_bad ? 2 : nested_msr_list_entry(vcpu, c);
		uint32_t why = n->pdpte_bad ? EXIT_REASON_INVAL_VMCS :
		    EXIT_REASON_INVAL_MSR;

		if (fail != 0) {
			vcpu->vmcs = vmcs02;	/* la riflessione usa il corrente */
			n->in_l2 = true;
			vmexit->u.vmx.exit_reason = why | 0x80000000;
			n->synth = true;
			n->synth_intr_info = 0;
			n->synth_qual = fail;
			n->slow_reflect = true;
			nested_reflect_to_l1(vcpu, vmexit);
			n->synth = false;
			n->slow_reflect = false;
			n->synth_qual = 0;
			/* slow path: nessun VMCS lasciato attivo sulla CPU, e
			 * nextrip allineato all'host RIP dell'L1 (vm_run l'aveva
			 * gia' calcolato sul RIP del VMLAUNCH) */
			VMCLEAR(vcpu->vmcs01);
			vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP, vmexit->rip);
			return (0);
		}
	}

	if (__predict_false(vmx_nested_probe == 1)) {
		/* sonda 1: host-state VMCS02 contro VMCS01, poi VMfail (no L2) */
		nested_probe_dump("VMCS02");
		VMCLEAR(vmcs02);
		VMPTRLD(vcpu->vmcs01);
		nested_probe_dump("VMCS01");
		VMCLEAR(vcpu->vmcs01);
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
	/*
	 * I campi host per-CPU (TR/GDTR/GS base) li scrive solo
	 * vmx_set_pcpu_defaults, e solo se lastcpu != curcpu: col vCPU sulla
	 * stessa CPU il VMCS02 restava con basi a 0 -> alla prima uscita da
	 * L2 l'host caricava GDT/TSS/GS nulli -> triple fault, reset
	 * istantaneo della macchina (kvm-unit-tests F2a). lastcpu vale per
	 * VMCS: NOCPU forza la riscrittura nel VMCS02 al prossimo vmx_run.
	 */
	vcpu->state.lastcpu = NOCPU;
	n->in_l2 = true;
	/* launched solo se l'ingresso RIESCE (SDM): un VM-entry fallito lascia
	 * il VMCS clear. Si segna ora e si annulla nella riflessione se il
	 * primo ingresso fallisce (n->launching). */
	if (!is_resume)
		n->launching = true;
	c->launched = 1;			/* dopo VMLAUNCH il VMCS12 e' launched */
	/*
	 * vm_run ha GIA' calcolato nextrip = RIP dell'L1 + lunghezza del
	 * VMLAUNCH, prima di chiamare questo slow path, e vmx_run lo scrive
	 * nel GUEST_RIP del VMCS corrente: senza questo, l'L2 partiva
	 * dall'istruzione dell'L1 dopo il VMLAUNCH (kvm-unit-tests F2a:
	 * "VM-Fail on vmlaunch: unexpected flags 2", stampato DA L2).
	 * vm_set_register(RIP) scrive nel VMCS02 (ora vcpu->vmcs) e allinea
	 * nextrip al punto d'ingresso di L2.
	 */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP,
	    vmcs12_read_field(c, VMCS_GUEST_RIP));
	/*
	 * vmx_inject_interrupts azzera il blocco STI/MOV-SS se il RIP
	 * d'ingresso differisce da state.nextrip (l'ultima uscita, dell'L1):
	 * al VMLAUNCH/VMRESUME il RIP cambia SEMPRE, e cancellava il blocco
	 * chiesto dall'L1 nel VMCS12 (kvm-unit-tests vmx_intr_window_test,
	 * 'blocking by STI / MOV-SS'). Il riferimento diventa il RIP dell'L2.
	 */
	vcpu->state.nextrip = vmcs12_read_field(c, VMCS_GUEST_RIP);
	/* Load PAT all'ingresso: il PAT virtuale del vCPU diventa quello
	 * dell'L2 (kvm-unit-tests 'control field PAT': l'L2 lo rilegge con
	 * RDMSR, che bhyve serve da guest_msrs). */
	if (vmcs12_read_field(c, VMCS_ENTRY_CTLS) & VM_ENTRY_LOAD_PAT)
		vcpu->guest_msrs[IDX_MSR_PAT] =
		    vmcs12_read_field(c, VMCS_GUEST_IA32_PAT);
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
	uint64_t efer, hrip, hrsp, hcr0, hcr3, hcr4;
	uint32_t i;
	/* stato di L2 da ricopiare in VMCS12 cosi' l'L1 lo rilegge con VMREAD */
	/*
	 * SDM 28.3: all'uscita si salva TUTTO lo stato guest. Prima solo 11
	 * campi: l'L1 rileggeva segmenti, GDTR/IDTR, SYSENTER, LDTR, PDPTE
	 * dell'L2 come li aveva scritti lui (kvm-unit-tests vmx_ldtr_test,
	 * vmx_mtf_pdpte_test); Hyper-V li usa per emulare la partizione root.
	 * PAT, DR7 e DEBUGCTL solo coi rispettivi save controls (piu' sotto).
	 */
	static const uint32_t l2state[] = {
		VMCS_GUEST_RIP, VMCS_GUEST_RSP, VMCS_GUEST_RFLAGS,
		VMCS_GUEST_CR0, VMCS_GUEST_CR3, VMCS_GUEST_CR4,
		VMCS_GUEST_IA32_EFER,
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
		VMCS_GUEST_PENDING_DBG_EXCEPTIONS,
		VMCS_GUEST_IA32_SYSENTER_CS, VMCS_GUEST_IA32_SYSENTER_ESP,
		VMCS_GUEST_IA32_SYSENTER_EIP,
		VMCS_GUEST_PDPTE0, VMCS_GUEST_PDPTE1,
		VMCS_GUEST_PDPTE2, VMCS_GUEST_PDPTE3,
		VMCS_GUEST_INTERRUPTIBILITY, VMCS_GUEST_ACTIVITY,
	};

	if (c == NULL)
		return;
	/*
	 * Motivo d'uscita COMPLETO: vmx_run lo prende con vmcs_exit_reason(),
	 * che tiene solo i bit 15:0 e scarta il bit 31 (VM-entry fallito).
	 * L'L1 vedeva un VM-entry fallito del VMCS02 (motivo 33, CR3 con bit
	 * riservati) come un'uscita normale e saltava un'istruzione
	 * (kvm-unit-tests vmx_pse_test / vmx_pae_test). Le uscite sintetiche o
	 * dello slow path hanno gia' il motivo impostato da chi le genera.
	 */
	if (!vcpu->nested->synth && !vcpu->nested->slow_reflect)
		vmexit->u.vmx.exit_reason =
		    (uint32_t)vmcs_read(VMCS_EXIT_REASON);
	/*
	 * VM-entry fallito sul VMLAUNCH: il VMCS12 resta clear (SDM 26.7/26.8).
	 * Prima restava launched e ogni VMLAUNCH successivo rispondeva VMfail 4
	 * invece di valutare i controlli (kvm-unit-tests vmx_controls_test /
	 * vmx_host_state_area_test: 1411 + 537 fallimenti in gran parte a
	 * catena).
	 */
	if ((vmexit->u.vmx.exit_reason & 0x80000000) != 0 &&
	    vcpu->nested->launching)
		c->launched = 0;
	vcpu->nested->launching = false;
	if (__predict_false(vmx_nested_probe == 6)) {
		/* sonda 6: traccia le uscite riflesse all'L1 (non ferma nulla) */
		static int traced6;
		if (traced6 < 64) {
			traced6++;
			printf("nested_probe REFLECT#%d reason=%#x qual=%#lx "
			    "l2rip=%#lx l2cr3=%#lx synth=%d slow=%d\n", traced6,
			    vmexit->u.vmx.exit_reason,
			    (u_long)(vcpu->nested->synth ? vcpu->nested->synth_qual :
			    vmcs_read(VMCS_EXIT_QUALIFICATION)),
			    (u_long)vmcs_read(VMCS_GUEST_RIP),
			    (u_long)vmcs_read(VMCS_GUEST_CR3),
			    vcpu->nested->synth, vcpu->nested->slow_reflect);
		}
	}
	/* 1-2. info d'uscita + stato di L2 -> store VMCS12 */
	vmcs12_write_field(c, VMCS_EXIT_REASON,
	    vmexit->u.vmx.exit_reason);
	if (vcpu->nested->synth) {
		/* uscita sintetica: nessun dato hardware */
		vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
		    vcpu->nested->synth_qual);
		vmcs12_write_field(c, VMCS_EXIT_INTR_INFO,
		    vcpu->nested->synth_intr_info);
		vmcs12_write_field(c, VMCS_EXIT_INTR_ERRCODE, 0);
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_LENGTH, 0);
		vmcs12_write_field(c, VMCS_EXIT_INSTRUCTION_INFO, 0);
	} else {
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
		/* EPT violation/misconfig: il GPA (e il lineare) che l'L1 deve
		 * conoscere per gestirla. */
		vmcs12_write_field(c, VMCS_GUEST_PHYSICAL_ADDRESS,
		    vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS));
		vmcs12_write_field(c, VMCS_GUEST_LINEAR_ADDRESS,
		    vmcs_read(VMCS_GUEST_LINEAR_ADDRESS));
	}
	/*
	 * SDM: ogni VM exit azzera il bit valid del VM-entry
	 * interruption-information. Senza, ogni VMRESUME successivo
	 * re-iniettava l'evento in L2 (kvm-unit-tests 'Inject an event to a
	 * halted guest': #GP in L2 a rip 0xa). L'IDT-vectoring info dice
	 * all'L1 se l'uscita ha interrotto la consegna di un evento.
	 */
	vmcs12_write_field(c, VMCS_ENTRY_INTR_INFO,
	    vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO) & ~VMCS_INTR_VALID);
	vmcs12_write_field(c, VMCS_IDT_VECTORING_INFO, vcpu->nested->synth ?
	    0 : vmcs_read(VMCS_IDT_VECTORING_INFO));
	vmcs12_write_field(c, VMCS_IDT_VECTORING_ERROR, vcpu->nested->synth ?
	    0 : vmcs_read(VMCS_IDT_VECTORING_ERROR));
	for (i = 0; i < nitems(l2state); i++)
		vmcs12_write_field(c, l2state[i], vmcs_read(l2state[i]));
	/*
	 * PAT: bhyve lo virtualizza in guest_msrs[IDX_MSR_PAT] (il PAT
	 * hardware resta quello dell'host, per l'L1 come per l'L2): e' "il PAT
	 * corrente del vCPU". Save PAT copia quello che l'L2 ha in uso.
	 */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PAT)
		vmcs12_write_field(c, VMCS_GUEST_IA32_PAT,
		    vcpu->guest_msrs[IDX_MSR_PAT]);
	/* Save preemption timer: il residuo (salvato dal VMCS02) all'L1. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PREEMPTION_TIMER)
		vmcs12_write_field(c, VMCS_PREEMPTION_TIMER_VALUE,
		    vmcs_read(VMCS_PREEMPTION_TIMER_VALUE));
	/* Save debug controls: DR7/DEBUGCTL dell'L2 nel VMCS12, solo se chiesto. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_DEBUG_CONTROLS) {
		vmcs12_write_field(c, VMCS_GUEST_DR7,
		    vmcs_read(VMCS_GUEST_DR7));
		vmcs12_write_field(c, VMCS_GUEST_IA32_DEBUGCTL,
		    vmcs_read(VMCS_GUEST_IA32_DEBUGCTL));
	}
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
	/* Lista "salva all'uscita": MSR dell'L2, col VMCS02 ancora corrente
	 * (EFER, SYSENTER...). Non su un VM-entry fallito (SDM 27.8). */
	if ((vmexit->u.vmx.exit_reason & 0x80000000) == 0)
		nested_msr_list_exit(vcpu, c, true);

	/* 4. commuta a VMCS01 */
	VMCLEAR(vmcs02);
	VMPTRLD(vcpu->vmcs01);
	vcpu->vmcs = vcpu->vmcs01;
	/* Il VMCS01 riparte su QUESTA CPU, ma il vCPU puo' essere migrato
	 * mentre era in L2 (la riscrittura e' finita nel VMCS02): riscrivo i
	 * campi host per-CPU qui, ora che il VMCS01 e' corrente. */
	vmcs_write(VMCS_HOST_TR_BASE, vmm_get_host_trbase());
	vmcs_write(VMCS_HOST_GDTR_BASE, vmm_get_host_gdtrbase());
	vmcs_write(VMCS_HOST_GS_BASE, vmm_get_host_gsbase());
	vcpu->state.lastcpu = curcpu;

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
	vmwrite(VMCS_GUEST_IA32_EFER, efer);
	/* SDM "Loading Host State": all'uscita DR7 = 0x400, DEBUGCTL = 0. */
	vmwrite(VMCS_GUEST_DR7, 0x400);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);
	/* Load PAT all'uscita: il PAT virtuale dell'L1 diventa HOST_PAT. */
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_LOAD_PAT)
		vcpu->guest_msrs[IDX_MSR_PAT] =
		    vmcs12_read_field(c, VMCS_HOST_IA32_PAT);
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
	/* SDM 28.5.2: all'uscita LDTR = 0, inutilizzabile (prima restava
	 * quella dell'L2: kvm-unit-tests vmx_ldtr_test) */
	nested_load_seg(VMCS_GUEST_LDTR_SELECTOR, VMCS_GUEST_LDTR_BASE,
	    VMCS_GUEST_LDTR_LIMIT, VMCS_GUEST_LDTR_ACCESS_RIGHTS, 0, 0, 0,
	    0x10000);
	vmwrite(VMCS_GUEST_GDTR_BASE, vmcs12_read_field(c, VMCS_HOST_GDTR_BASE));
	vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_IDTR_BASE, vmcs12_read_field(c, VMCS_HOST_IDTR_BASE));
	vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_FS_BASE, vmcs12_read_field(c, VMCS_HOST_FS_BASE));
	vmwrite(VMCS_GUEST_GS_BASE, vmcs12_read_field(c, VMCS_HOST_GS_BASE));

	/* TSC dell'L1 cambiato da una lista d'ingresso: nel VMCS01 ora */
	if (n->l1_tsc_dirty) {
		vmx_set_tsc_offset(vcpu, n->l1_tsc_offset);
		n->l1_tsc_dirty = false;
	}
	/* Lista "carica all'uscita": MSR dell'L1, dopo lo stato host (SDM). */
	n->msr_phase = 2;
	nested_msr_list_exit(vcpu, c, false);
	n->msr_phase = 0;

	n->in_l2 = false;
	vmexit->rip = hrip;
	vmexit->inst_length = 0;
	vm_exit_intinfo(vcpu->vcpu, 0);
	if (__predict_false(vmx_nested_probe == 3)) {
		/* sonda 3: riflessione completata, VMCS01 pronto per l'L1 */
		nested_probe_dump("REFLECT-VMCS01");
		vm_suspend(vcpu->vmx->vm, VM_SUSPEND_POWEROFF);
	}
	SDT_PROBE1(vmm, vmx, nested, reflect, vcpu);
	vmm_stat_incr(vcpu->vcpu, VMX_NESTED_REFLECTIONS, 1);
}

/*
 * Eventi dell'L1 mentre il vCPU e' in L2 (come vmx_check_nested_events di
 * KVM). Chiamata da vmx_run PRIMA di ogni ingresso in L2, col VMCS02
 * corrente. Se l'L1 ha un interrupt pendente e il suo VMCS12 chiede
 * l'uscita sugli interrupt esterni, l'hardware vero uscirebbe verso l'L1
 * con motivo EXTERNAL_INTERRUPT, qualunque sia l'IF di L2: si fa
 * un'uscita SINTETICA. Prima l'interrupt veniva iniettato in L2
 * (kvm-unit-tests 'interrupt': "intercepted interrupt while running
 * guest", poi exit reason 7 non richiesta). Con "acknowledge interrupt on
 * exit" il vettore e' accettato dall'APIC e va nelle info d'uscita;
 * senza, resta pendente e l'L1 lo prende riabilitando gli interrupt.
 * Ritorna true se l'uscita e' stata fatta: vmx_run deve uscire
 * (VM_EXITCODE_NESTED + restart_only, come dopo una riflessione).
 */
bool
nested_check_events(struct vmx_vcpu *vcpu, struct vm_exit *vmexit)
{
	struct vmx_nested *n = vcpu->nested;
	struct vmcs12_cache *c = nested_current_cache(n);
	struct vlapic *vl = vm_lapic(vcpu->vcpu);
	int vec;

	if (c == NULL || !n->in_l2)
		return (false);
	if ((vmcs12_read_field(c, VMCS_PIN_BASED_CTLS) &
	    PINBASED_EXTINT_EXITING) == 0)
		return (false);
	if (!vlapic_pending_intr(vl, &vec))
		return (false);

	n->synth_intr_info = 0;
	n->synth_qual = 0;
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) &
	    VM_EXIT_ACKNOWLEDGE_INTERRUPT) {
		vlapic_intr_accepted(vl, vec);
		n->synth_intr_info = vec | VMCS_INTR_T_HWINTR | VMCS_INTR_VALID;
	}
	if (__predict_false(vmx_nested_probe == 5)) {
		/* sonda 5: traccia le uscite sintetiche (non ferma nulla) */
		static int traced;
		if (traced < 32) {
			traced++;
			printf("nested_probe EXTINT#%d vec=%d info=%#x "
			    "pin12=%#lx exit12=%#lx l2rip=%#lx entryinfo12=%#lx\n",
			    traced, vec, n->synth_intr_info,
			    vmcs12_read_field(c, VMCS_PIN_BASED_CTLS),
			    vmcs12_read_field(c, VMCS_EXIT_CTLS),
			    vmcs_read(VMCS_GUEST_RIP),
			    vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO));
		}
	}
	vmexit->u.vmx.exit_reason = EXIT_REASON_EXT_INTR;
	n->synth = true;
	nested_reflect_to_l1(vcpu, vmexit);
	n->synth = false;
	n->restart_only = true;
	vmexit->exitcode = VM_EXITCODE_NESTED;
	return (true);
}

/*
 * Bitmap I/O e MSR dell'L1. Il percorso veloce (vmx_exit_process, sotto il
 * critical_enter di vm_run) non puo' chiamare vm_gpa_hold, che puo' dormire:
 * lo faceva qui (panic "vm_gpa_hold: invalid vcpu state 2", kvm-unit-tests
 * 'control field PAT', RDMSR di L2). Come KVM, le pagine si mappano una volta
 * al VMLAUNCH/VMRESUME, nello slow path, e restano tenute finche' la voce del
 * VMCS12 esiste.
 */
static void
nested_bitmaps_unmap(struct vmcs12_cache *c)
{
	if (c->ck_io_a != NULL)
		vm_gpa_release(c->ck_io_a);
	if (c->ck_io_b != NULL)
		vm_gpa_release(c->ck_io_b);
	if (c->ck_msr != NULL)
		vm_gpa_release(c->ck_msr);
	nested_msr_list_unmap(&c->ml_st);
	nested_msr_list_unmap(&c->ml_ld);
	nested_msr_list_unmap(&c->ml_en);
	c->bm_io_a = c->bm_io_b = c->bm_msr = NULL;
	c->ck_io_a = c->ck_io_b = c->ck_msr = NULL;
}

/*
 * Mappa una lista MSR del VMCS12 (SDM 24.7.2): indirizzo allineato a 16, al
 * massimo 512 elementi, pagina per pagina (prima una sola pagina: le liste
 * da 512 voci di atomic_switch_max_msrs_test facevano fallire il VMLAUNCH).
 * 0 ok o lista vuota; -1 non valida.
 */
static int
nested_msr_list_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c,
    uint32_t addr_f, uint32_t cnt_f, int prot, struct nested_msr_list *l)
{
	uint64_t gpa = vmcs12_read_field(c, addr_f);
	uint64_t cnt = vmcs12_read_field(c, cnt_f);
	uint64_t first, last, pg;
	int i;

	bzero(l, sizeof(*l));
	if (cnt == 0)
		return (0);
	if ((gpa & 0xf) != 0 || cnt > 512)
		return (-1);
	first = trunc_page(gpa);
	last = trunc_page(gpa + cnt * sizeof(struct msr_entry) - 1);
	for (pg = first, i = 0; pg <= last; pg += PAGE_SIZE, i++) {
		l->pg[i] = vm_gpa_hold(vcpu->vcpu, pg, PAGE_SIZE, prot,
		    &l->ck[i]);
		if (l->pg[i] == NULL) {
			nested_msr_list_unmap(l);
			return (-1);
		}
	}
	l->gpa = gpa;
	l->n = (uint32_t)cnt;
	return (0);
}

static void
nested_msr_list_unmap(struct nested_msr_list *l)
{
	int i;

	for (i = 0; i < 3; i++)
		if (l->ck[i] != NULL)
			vm_gpa_release(l->ck[i]);
	bzero(l, sizeof(*l));
}

/* voce i della lista (gia' mappata) */
static struct msr_entry *
nested_msr_ent(struct nested_msr_list *l, uint32_t i)
{
	uint64_t off = (l->gpa & PAGE_MASK) + (uint64_t)i * sizeof(struct msr_entry);

	return ((struct msr_entry *)(l->pg[off >> PAGE_SHIFT] +
	    (off & PAGE_MASK)));
}

/*
 * Legge/scrive un MSR "come lo vede il vCPU" per le liste MSR del nested.
 * live = true dentro vmx_run (uscita da L2): LSTAR, CSTAR, STAR, SF_MASK e
 * KGSBASE del guest sono nei registri hardware (vmx_msr_guest_enter);
 * live = false nello slow path (ingresso): sono in guest_msrs[]. PAT e
 * TSC_AUX stanno sempre in guest_msrs[] (PAT e' virtuale; TSC_AUX e'
 * commutato solo attorno al VM-entry). EFER, SYSENTER e DEBUGCTL vivono
 * nel VMCS CORRENTE. 0 ok; EINVAL MSR non gestito (per le liste di
 * caricamento: non ammesso).
 */
static int
nested_msr_rw(struct vmx_vcpu *vcpu, uint32_t idx, uint64_t *val, bool wr,
    bool live)
{
	int g = -1;
	uint32_t f = 0;

	switch (idx) {
	case MSR_LSTAR:		g = IDX_MSR_LSTAR; break;
	case MSR_CSTAR:		g = IDX_MSR_CSTAR; break;
	case MSR_STAR:		g = IDX_MSR_STAR; break;
	case MSR_SF_MASK:	g = IDX_MSR_SF_MASK; break;
	case MSR_KGSBASE:	g = IDX_MSR_KGSBASE; break;
	case MSR_PAT:		g = IDX_MSR_PAT; live = false; break;
	case MSR_TSC_AUX:	g = IDX_MSR_TSC_AUX; live = false; break;
	case MSR_EFER:		f = VMCS_GUEST_IA32_EFER; break;
	case MSR_SYSENTER_CS_MSR: f = VMCS_GUEST_IA32_SYSENTER_CS; break;
	case MSR_SYSENTER_ESP_MSR: f = VMCS_GUEST_IA32_SYSENTER_ESP; break;
	case MSR_SYSENTER_EIP_MSR: f = VMCS_GUEST_IA32_SYSENTER_EIP; break;
	case MSR_DEBUGCTLMSR:	f = VMCS_GUEST_IA32_DEBUGCTL; break;
	case MSR_TSC:
		/*
		 * Le liste MSR lavorano nel tempo dell'L1 (SDM: il valore NON
		 * subisce l'offset del VMCS12): TSC host + offset dell'L0 per
		 * l'L1. Prima si usava l'offset del VMCS02 (L0 + L1->L2): il
		 * valore salvato era piu' alto dell'offset dell'L2
		 * (vmx_store_tsc_test, rdtsc_vmexit_diff_test,
		 * vmx_preemption_timer_expiry_test). In scrittura non ammesso.
		 */
		if (wr) {
			/*
			 * Scrivere IA32_TSC = WRMSR dell'L1: cambia l'offset che
			 * L0 da' all'L1 (come vmx_wrmsr). Nella lista d'ingresso
			 * il VMCS corrente e' il VMCS02: si ricalcola il suo
			 * offset e il VMCS01 si aggiorna all'uscita; nella lista
			 * load d'uscita il VMCS01 e' gia' corrente.
			 */
			struct vmx_nested *nn = vcpu->nested;
			struct vmcs12_cache *cc = nested_current_cache(nn);
			uint64_t off;

			nn->l1_tsc_offset = *val - rdtsc();
			if (nn->msr_phase == 2) {
				vmx_set_tsc_offset(vcpu, nn->l1_tsc_offset);
				nn->l1_tsc_dirty = false;
				return (0);
			}
			off = nn->l1_tsc_offset;
			if (cc != NULL && (vmcs12_read_field(cc,
			    VMCS_PRI_PROC_BASED_CTLS) & PROCBASED_TSC_OFFSET))
				off += vmcs12_read_field(cc, VMCS_TSC_OFFSET);
			vmwrite(VMCS_TSC_OFFSET, off);
			vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    vmcs_read(VMCS_PRI_PROC_BASED_CTLS) |
			    PROCBASED_TSC_OFFSET);
			nn->l1_tsc_dirty = true;
			return (0);
		}
		/* all'istante dell'uscita hardware (per una sintetica: ora) */
		*val = (vcpu->nested->synth ? rdtsc() : vcpu->nested->exit_tsc) +
		    vcpu->nested->l1_tsc_offset;
		return (0);
	default:
		return (EINVAL);	/* FS/GS_BASE, x2APIC, SMM...: vietati */
	}
	if (g >= 0) {
		if (live) {
			if (wr)
				wrmsr(idx, *val);
			else
				*val = rdmsr(idx);
		} else {
			if (wr)
				vcpu->guest_msrs[g] = *val;
			else
				*val = vcpu->guest_msrs[g];
		}
	} else {
		if (wr)
			vmwrite(f, idx == MSR_DEBUGCTLMSR ? (*val & 0x3) : *val);
		else
			*val = vmcs_read(f);
	}
	return (0);
}

/*
 * Lista "carica all'ingresso" del VMCS12 (slow path, VMCS02 corrente, dopo
 * lo stato guest come da SDM). 0 ok; altrimenti indice 1-based
 * dell'elemento non caricabile (VM-entry fallita, motivo 34).
 */
static uint32_t
nested_msr_list_entry(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	struct nested_msr_list *ml = &c->ml_en;	/* da nested_bitmaps_map */
	struct msr_entry *e;
	uint64_t v;
	uint32_t i, fail = 0;

	vcpu->nested->msr_phase = 1;
	for (i = 0; i < ml->n && fail == 0; i++) {
		e = nested_msr_ent(ml, i);
		v = e->val;
		if (e->reserved != 0 ||
		    nested_msr_rw(vcpu, e->index, &v, true, false) != 0)
			fail = i + 1;
	}
	vcpu->nested->msr_phase = 0;
	return (fail);
}

/*
 * Liste d'uscita (percorso veloce, pagine gia' mappate): store = salva gli
 * MSR dell'L2 (VMCS02 corrente, prima della commutazione); load = carica
 * quelli dell'L1 (VMCS01 corrente, dopo lo stato host). Un elemento non
 * gestito si salta: sull'hardware sarebbe un VMX abort.
 */
static void
nested_msr_list_exit(struct vmx_vcpu *vcpu, struct vmcs12_cache *c,
    bool store)
{
	struct nested_msr_list *ml = store ? &c->ml_st : &c->ml_ld;
	struct msr_entry *l;
	uint32_t i, n = ml->n;
	bool live = !vcpu->nested->slow_reflect;
	uint64_t v;

	for (i = 0; i < n; i++) {
		l = nested_msr_ent(ml, i);
		if (l->reserved != 0)
			continue;
		if (store) {
			if (nested_msr_rw(vcpu, l->index, &v, false, live) == 0)
				l->val = v;
		} else {
			v = l->val;
			(void)nested_msr_rw(vcpu, l->index, &v, true, live);
		}
	}
}

/* Slow path (vCPU FROZEN). 0 se ok; -1 se una bitmap richiesta dall'L1 non
 * e' mappabile (indirizzo non allineato o fuori dalla memoria del guest). */
static int
nested_bitmaps_map(struct vmx_vcpu *vcpu, struct vmcs12_cache *c)
{
	uint32_t p12;
	uint64_t gpa;

	nested_bitmaps_unmap(c);
	p12 = (uint32_t)vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS);
	if (p12 & PROCBASED_IO_BITMAPS) {
		gpa = vmcs12_read_field(c, VMCS_IO_BITMAP_A);
		if ((gpa & PAGE_MASK) != 0 || (c->bm_io_a = vm_gpa_hold(
		    vcpu->vcpu, gpa, PAGE_SIZE, VM_PROT_READ, &c->ck_io_a)) ==
		    NULL)
			goto fail;
		gpa = vmcs12_read_field(c, VMCS_IO_BITMAP_B);
		if ((gpa & PAGE_MASK) != 0 || (c->bm_io_b = vm_gpa_hold(
		    vcpu->vcpu, gpa, PAGE_SIZE, VM_PROT_READ, &c->ck_io_b)) ==
		    NULL)
			goto fail;
	}
	if (p12 & PROCBASED_MSR_BITMAPS) {
		gpa = vmcs12_read_field(c, VMCS_MSR_BITMAP);
		if ((gpa & PAGE_MASK) != 0 || (c->bm_msr = vm_gpa_hold(
		    vcpu->vcpu, gpa, PAGE_SIZE, VM_PROT_READ, &c->ck_msr)) ==
		    NULL)
			goto fail;
	}
	/* liste MSR d'uscita: usate dalla riflessione, nel percorso veloce */
	if (nested_msr_list_map(vcpu, c, VMCS_EXIT_MSR_STORE,
	    VMCS_EXIT_MSR_STORE_COUNT, VM_PROT_READ | VM_PROT_WRITE,
	    &c->ml_st) != 0 ||
	    nested_msr_list_map(vcpu, c, VMCS_EXIT_MSR_LOAD,
	    VMCS_EXIT_MSR_LOAD_COUNT, VM_PROT_READ,
	    &c->ml_ld) != 0 ||
	    nested_msr_list_map(vcpu, c, VMCS_ENTRY_MSR_LOAD,
	    VMCS_ENTRY_MSR_LOAD_COUNT, VM_PROT_READ,
	    &c->ml_en) != 0)
		goto fail;
	return (0);
fail:
	nested_bitmaps_unmap(c);
	return (-1);
}

/* Percorso veloce: bit di una bitmap gia' mappata. true se impostato o se la
 * bitmap non e' mappata (conservativo: riflette all'L1). */
static bool
nested_bitmap_bit(const uint8_t *bm, uint32_t bit)
{
	if (bm == NULL)
		return (true);
	return ((bm[bit >> 3] >> (bit & 7)) & 1);
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

	/* un'uscita normale da L2 = l'ingresso e' riuscito: VMCS12 launched */
	if ((vmcs_read(VMCS_EXIT_REASON) & 0x80000000) == 0)
		vcpu->nested->launching = false;

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
		if (p12 & PROCBASED_IO_BITMAPS) {
			/*
			 * SDM: con le bitmap l'I/O "incondizionato" e' ignorato.
			 * Esce se UNA qualunque delle porte toccate (1, 2 o 4
			 * byte) ha il bit, o se l'accesso sfora oltre 0xffff.
			 */
			uint64_t q = vmcs_read(VMCS_EXIT_QUALIFICATION);
			uint32_t port = (q >> 16) & 0xffff, size = (q & 7) + 1;
			uint32_t p;
			bool hit = false;

			if (port + size - 1 > 0xffff)
				break;			/* wrap -> riflette */
			for (p = port; p < port + size && !hit; p++)
				hit = nested_bitmap_bit(p < 0x8000 ?
				    cc->bm_io_a : cc->bm_io_b, p & 0x7fff);
			if (hit)
				break;			/* L1 intercetta -> riflette */
			return (false);		/* L0 gestisce con i reg. di L2 */
		}
		if (p12 & PROCBASED_IO_EXITING) break;	/* uncond -> riflette */
		return (false);			/* L0 gestisce con i registri di L2 */
	}
	case EXIT_REASON_INTR_WINDOW:
	case EXIT_REASON_NMI_WINDOW: {
		/*
		 * L0 apre queste finestre per iniettare eventi in L2: all'L1
		 * solo se il SUO VMCS12 le chiede. Prima si riflettevano
		 * sempre (kvm-unit-tests 'interrupt': "Unknown exit reason
		 * 0x7" nell'L1). Altrimenti la gestisce il flusso normale
		 * (chiude la finestra, inietta, si rientra in L2).
		 */
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint32_t flag = (reason == EXIT_REASON_INTR_WINDOW) ?
		    PROCBASED_INT_WINDOW_EXITING : PROCBASED_NMI_WINDOW_EXITING;

		if (cc != NULL && (vmcs12_read_field(cc,
		    VMCS_PRI_PROC_BASED_CTLS) & flag))
			break;			/* L1 la chiede -> riflette */
		return (false);
	}
	case EXIT_REASON_CR_ACCESS: {
		/*
		 * CR8 (TPR): L0 forza le uscite su CR8 nel VMCS02; si riflette
		 * all'L1 solo se il SUO VMCS12 le chiede, altrimenti L0 emula
		 * sul TPR del vCPU, che e' cio' che l'L2 vedrebbe sul ferro.
		 * Gli altri CR (0, 3, 4): riflessi come prima.
		 */
		struct vmcs12_cache *cc = nested_current_cache(vcpu->nested);
		uint64_t q = vmcs_read(VMCS_EXIT_QUALIFICATION);
		uint32_t cr = q & 0xf, type = (q >> 4) & 3, p12;

		if (cc == NULL || cr != 8 || type > 1)
			break;
		p12 = (uint32_t)vmcs12_read_field(cc, VMCS_PRI_PROC_BASED_CTLS);
		if (p12 & (type == 0 ? PROCBASED_CR8_LOAD_EXITING :
		    PROCBASED_CR8_STORE_EXITING))
			break;			/* L1 intercetta -> riflette */
		return (false);			/* L0 emula sul TPR */
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
		if (nested_bitmap_bit(cc->bm_msr == NULL ? NULL :
		    cc->bm_msr + base, bit))
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
			if (reason == EXIT_REASON_EPT_MISCONFIG)
				break;		/* -> riflette all'L1 */
			/*
			 * Violation con shadow EPT: si risolve nello SLOW PATH.
			 * Qui (dentro vmx_run, sotto critical_enter) non si puo'
			 * dormire, e vmx_vept_fault ne ha bisogno (vm_gpa_hold
			 * sulle tabelle dell'L1, malloc). Si cattura il GPA, si
			 * esce da vmx_run RESTANDO in L2 (vmx.c vede ept_pending)
			 * e si riesegue l'istruzione (inst_length 0).
			 */
			vcpu->nested->ept_gpa =
			    vmcs_read(VMCS_GUEST_PHYSICAL_ADDRESS);
			vcpu->nested->ept_qual = vmcs_read(VMCS_EXIT_QUALIFICATION);
			vcpu->nested->ept_pending = true;
			vmexit->inst_length = 0;
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
	uint32_t info = (uint32_t)n->exit_insn_info;
	uint64_t type, cap = n->vmx_msr[0x48c - 0x480], q[2], gpa, *p;
	void *ck;
	int i;

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	/*
	 * Emulazione completa (prima: flush e VMsucceed qualunque operando;
	 * kvm-unit-tests invvpid_test, 897 fallimenti). Descrittore di 16
	 * byte in memoria: VPID nei bit 15:0, bit 63:16 riservati, poi
	 * l'indirizzo lineare. Tipo nel registro (bit 31:28 di insn_info).
	 */
	type = vmx_get_guest_reg(vcpu, (info >> 28) & 0xf);
	for (i = 0; i < 2; i++) {
		if (nested_operand_gpa_at(vcpu, VM_PROT_READ, i * 8, &gpa) != 0)
			return (0);		/* #PF/#GP/#SS gia' iniettata */
		p = vm_gpa_hold(vcpu->vcpu, gpa, sizeof(uint64_t),
		    VM_PROT_READ, &ck);
		if (p == NULL) {
			nested_vmfail_invalid(vcpu);
			return (0);
		}
		q[i] = *p;
		vm_gpa_release(ck);
	}
	/* tipi annunciati nell'EPT/VPID cap: bit 40 + tipo (0..3) */
	if (type > 3 || (cap & (1ULL << (40 + type))) == 0 ||
	    (q[0] >> 16) != 0 ||				/* riservati */
	    (type != 2 && (q[0] & 0xffff) == 0) ||		/* VPID 0 */
	    (type == 0 && !nested_canonical(q[1]))) {		/* indirizzo */
		nested_vmx_result(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		nested_advance_rip(vcpu);
		return (0);
	}
	/* tutti i VPID dell'L1 condividono il VPID02 dell'L2: qualunque tipo
	 * e' soddisfatto (per eccesso) da un flush single-context di vpid2 */
	bzero(&d, sizeof(d));
	d.vpid = n->vpid2;
	invvpid(INVVPID_TYPE_SINGLE_CONTEXT, d);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

/*
 * INVEPT dell'L1 (prima non instradata: finiva in userland). Si svuota la
 * shadow EPT per intero, qualunque sia il tipo (single-context o all-context
 * sono entrambi soddisfatti da un flush completo); il TLB dell'EPTP shadow lo
 * invalida vmx_run al prossimo ingresso in L2. Tipo non annunciato nell'EPT
 * cap esposto all'L1 (bit 25 single, 26 all) -> VMfail 28.
 */
static int
nested_invept(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	uint32_t info = (uint32_t)n->exit_insn_info;
	uint64_t type, cap = n->vmx_msr[0x48c - 0x480];

	if (!n->vmxon) { vm_inject_ud(vcpu->vcpu); return (0); }
	type = vmx_get_guest_reg(vcpu, (info >> 28) & 0xf);
	if (!((type == 1 && (cap & (1ULL << 25))) ||
	    (type == 2 && (cap & (1ULL << 26))))) {
		nested_vmx_result(vcpu, VMXERR_INVALID_OPERAND_TO_INVEPT_INVVPID);
		nested_advance_rip(vcpu);
		return (0);
	}
	vmx_vept_invept(n);
	nested_vmx_result(vcpu, VMXR_SUCCEED);
	nested_advance_rip(vcpu);
	return (0);
}

/*
 * EPT violation di L2 con shadow EPT, nello slow path (vedi nested_l2_exit).
 *  - VEPT_OK: shadow installata, si riparte in L2 sulla stessa istruzione;
 *  - VEPT_MMIO: l'L2 tocca un dispositivo emulato dell'L1 -> emulazione
 *    normale di bhyve sul GPA dell'L1 (vm_run: VM_EXITCODE_INST_EMUL);
 *  - VEPT_VIOL / VEPT_MISCONF: riflessa all'L1 (motivo 48 o 49). Per la
 *    violation i bit 5:3 della qualificazione sono i permessi dell'EPT
 *    dell'L1, non quelli della shadow. Il VMCS02 conserva i campi d'uscita
 *    anche dopo VMCLEAR/VMPTRLD.
 */
static int
nested_ept_slow(struct vmx_vcpu *vcpu)
{
	struct vmx_nested *n = vcpu->nested;
	struct vm_exit *vmexit = vm_exitinfo(vcpu->vcpu);
	struct vmcs12_cache *c;
	uint64_t l1gpa = 0, perm = 0;
	int r;

	r = vmx_vept_fault(vcpu, n->ept_gpa, n->ept_qual, &l1gpa, &perm);
	if (r == VEPT_OK)
		return (0);
	if (r == VEPT_MMIO && (n->ept_qual & 0x3) != 0 &&
	    (n->ept_qual & 0x180) == 0x180) {
		/* lettura/scrittura dati da un indirizzo lineare (come
		 * ept_emulation_fault per l'L1) */
		vmexit->u.inst_emul = n->ept_emul.u.inst_emul;
		vmexit->u.inst_emul.gpa = l1gpa;
		vmexit->exitcode = VM_EXITCODE_INST_EMUL;
		vmexit->inst_length = 0;
		return (0);
	}
	VMPTRLD(vcpu->vmcs);			/* il VMCS02 */
	vmexit->u.vmx.exit_reason = (r == VEPT_MISCONF) ?
	    EXIT_REASON_EPT_MISCONFIG : EXIT_REASON_EPT_FAULT;
	n->slow_reflect = true;
	nested_reflect_to_l1(vcpu, vmexit);
	n->slow_reflect = false;
	c = nested_current_cache(n);
	if (c != NULL)
		vmcs12_write_field(c, VMCS_EXIT_QUALIFICATION,
		    (r == VEPT_MISCONF) ? 0 :
		    ((n->ept_qual & ~0x38ULL) | ((perm & 0x7) << 3)));
	VMCLEAR(vcpu->vmcs01);			/* niente VMCS attivo nello slow path */
	vm_set_register(vcpu->vcpu, VM_REG_GUEST_RIP, vmexit->rip);
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

	/* Uscita di L2 gia' riflessa all'L1 in vmx_exit_process: qui va solo
	 * fatto ripartire vmx_run. Il motivo d'uscita e' di L2 (es. VMCALL):
	 * passarlo allo switch sotto inietterebbe un #UD nell'L1. */
	if (vcpu->nested != NULL && vcpu->nested->restart_only) {
		vcpu->nested->restart_only = false;
		return (0);
	}
	/* EPT violation di L2 con shadow EPT, rimandata qui dal percorso veloce */
	if (vcpu->nested != NULL && vcpu->nested->ept_pending) {
		vcpu->nested->ept_pending = false;
		return (nested_ept_slow(vcpu));
	}

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
	case EXIT_REASON_INVEPT:	return (nested_invept(vcpu));
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
		/* con EPT e paging PAE la CPU prende i PDPTE da qui */
		VMCS_GUEST_PDPTE0, VMCS_GUEST_PDPTE1,
		VMCS_GUEST_PDPTE2, VMCS_GUEST_PDPTE3,
	};

	c = nested_current_cache(n);
	if (c == NULL)
		return (EINVAL);

	/* --- Pin-based: VMCS12 U {ext-int, NMI exiting}; posted = 0;
	 *     preemption timer SOLO se l'L1 lo chiede --- */
	pin = (uint32_t)vmcs12_read_field(c, VMCS_PIN_BASED_CTLS);
	pin |= PINBASED_EXTINT_EXITING | PINBASED_NMI_EXITING;
	pin = nested_adjust_ctl(pin, MSR_VMX_TRUE_PINBASED_CTLS);
	pin &= ~PINBASED_POSTED_INTERRUPT;
	/*
	 * Timer di preemption dell'L1 (prima spento sempre: kvm-unit-tests
	 * 'preemption timer' girava all'infinito aspettando l'uscita 52). Conta
	 * alla frequenza vera: all'L1 esponiamo il rate di IA32_VMX_MISC
	 * dell'host. Il valore iniziale e' quello del VMCS12.
	 */
	if ((vmcs12_read_field(c, VMCS_PIN_BASED_CTLS) &
	    PINBASED_PREMPTION_TIMER) == 0)
		pin &= ~PINBASED_PREMPTION_TIMER;
	else
		vmwrite(VMCS_PREEMPTION_TIMER_VALUE,
		    vmcs12_read_field(c, VMCS_PREEMPTION_TIMER_VALUE));
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
	/*
	 * PAT. bhyve non tocca mai il PAT reale (l'L1 gira col PAT dell'host),
	 * quindi exit_ctls non ha LOAD_PAT. Ma qui l'ingresso in L2 lo caricava
	 * SEMPRE dal VMCS12: senza LOAD_PAT all'uscita l'host restava col PAT
	 * dell'L2 (kvm-unit-tests 'null': GUEST_PAT mai scritto = 0 = tutto
	 * UC) -> host lentissimo, "congelato", USB giu'. Ora:
	 *  - all'uscita il PAT dell'host si RICARICA sempre (HOST_IA32_PAT e'
	 *    quello giusto, vmcs_init_host);
	 *  - all'ingresso si carica il PAT dell'L2 solo se l'L1 lo chiede;
	 *  - si salva il PAT dell'L2 all'uscita solo se l'L1 lo chiede.
	 */
	exitc = exit_ctls | VM_EXIT_LOAD_PAT;
	if (vmcs12_read_field(c, VMCS_EXIT_CTLS) & VM_EXIT_SAVE_PAT)
		exitc |= VM_EXIT_SAVE_PAT;
	/*
	 * Col timer di preemption attivo il valore residuo si salva SEMPRE: per
	 * l'L1 le uscite gestite da L0 non esistono, quindi al rientro in L2 il
	 * conto alla rovescia deve riprendere da dove era. All'L1 lo si passa
	 * solo se lo chiede (riflessione).
	 */
	exitc &= ~VM_EXIT_SAVE_PREEMPTION_TIMER;
	if (pin & PINBASED_PREMPTION_TIMER)
		exitc |= VM_EXIT_SAVE_PREEMPTION_TIMER;
	exitc = nested_adjust_ctl(exitc, MSR_VMX_TRUE_EXIT_CTLS);
	vmwrite(VMCS_EXIT_CTLS, exitc);

	/* --- Entry controls: IA-32e mode guest = VMCS12; load EFER/dbg=1.
	 *     Mai load PAT: il PAT dell'L2 e' virtuale come quello dell'L1
	 *     (guest_msrs[IDX_MSR_PAT], impostato in nested_vmlaunch) --- */
	entryc = (uint32_t)vmcs12_read_field(c, VMCS_ENTRY_CTLS) &
	    VM_ENTRY_GUEST_LMA;
	entryc |= VM_ENTRY_LOAD_DEBUG_CONTROLS | VM_ENTRY_LOAD_EFER;
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
	if (n->pdpte_mem) {			/* PAE senza EPT12: dalla memoria */
		vmwrite(VMCS_GUEST_PDPTE0, n->pdpte[0]);
		vmwrite(VMCS_GUEST_PDPTE1, n->pdpte[1]);
		vmwrite(VMCS_GUEST_PDPTE2, n->pdpte[2]);
		vmwrite(VMCS_GUEST_PDPTE3, n->pdpte[3]);
	}
	/* Senza load debug controls nel VMCS12, DR7/DEBUGCTL dell'L2 sono quelli
	 * che l'L1 aveva (kvm-unit-tests 'debug controls'). */
	if ((vmcs12_read_field(c, VMCS_ENTRY_CTLS) &
	    VM_ENTRY_LOAD_DEBUG_CONTROLS) == 0) {
		vmwrite(VMCS_GUEST_DR7, n->l1_dr7);
		vmwrite(VMCS_GUEST_IA32_DEBUGCTL, n->l1_debugctl);
	}

	/* --- EPTP, VPID, MSR bitmap, TSC offset, liste MSR, link pointer --- */
	/* EPTP: shadow EPT se VMCS12 usa EPT (T2.7), altrimenti EPTP01. */
	if (vmcs12_read_field(c, VMCS_SEC_PROC_BASED_CTLS) &
	    PROCBASED2_ENABLE_EPT)
		vmwrite(VMCS_EPTP, vmx_vept_eptp(vcpu));
	else
		vmwrite(VMCS_EPTP, x->vmx->eptp);
	/* VPID02 distinto per l2 (T2.8), per non aliasare la TLB con l1 */
	vmwrite(VMCS_VPID, n->vpid2);
	/* HOST_RSP: nel VMCS01 lo scrive vmx_init UNA volta (&vcpu->ctx, lo
	 * stack su cui vmx_exit_guest salva i registri del guest);
	 * vmcs_init_host non lo tocca, quindi nel VMCS02 valeva 0 -> alla
	 * prima uscita da L2 l'host ripartiva con RSP=0 -> triple fault. */
	vmwrite(VMCS_HOST_RSP, (u_long)&x->ctx);
	/* MSR bitmap: quello dell'L0 (intercetta cio' che serve a L0); la
	 * fusione con quello dell'L1 e' T6.3. */
	vmwrite(VMCS_MSR_BITMAP, vtophys(x->vmx->msr_bitmap));
	/*
	 * TSC offset = quello dell'L0 per l'L1 + quello dell'L1 per l'L2 (se
	 * l'L1 lo usa). Prima solo il secondo: l'L2 vedeva il TSC dell'host,
	 * non quello dell'L1 (kvm-unit-tests rdtsc_vmexit_diff_test). Il
	 * controllo TSC offsetting va acceso se l'offset non e' nullo.
	 */
	{
		uint64_t off = n->l1_tsc_offset;

		if (vmcs12_read_field(c, VMCS_PRI_PROC_BASED_CTLS) &
		    PROCBASED_TSC_OFFSET)
			off += vmcs12_read_field(c, VMCS_TSC_OFFSET);
		vmwrite(VMCS_TSC_OFFSET, off);
		if (off != 0)
			vmwrite(VMCS_PRI_PROC_BASED_CTLS,
			    vmcs_read(VMCS_PRI_PROC_BASED_CTLS) |
			    PROCBASED_TSC_OFFSET);
	}
	/* liste MSR a 0 (applicate in software nello slow path, §6.3). */
	vmwrite(VMCS_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VMCS_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_LINK_POINTER, ~0UL);

	/* Evento da iniettare in L2 richiesto dall'L1 (VMCS12): info, codice
	 * d'errore e lunghezza istruzione (interrupt/eccezioni software). Il
	 * bit valid lo azzera la riflessione a ogni uscita, come l'hardware. */
	vmwrite(VMCS_ENTRY_INTR_INFO, vmcs12_read_field(c, VMCS_ENTRY_INTR_INFO));
	vmwrite(VMCS_ENTRY_EXCEPTION_ERROR,
	    vmcs12_read_field(c, VMCS_ENTRY_EXCEPTION_ERROR));
	vmwrite(VMCS_ENTRY_INST_LENGTH,
	    vmcs12_read_field(c, VMCS_ENTRY_INST_LENGTH));

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
