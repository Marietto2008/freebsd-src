/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2011 NetApp, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/sysctl.h>

#include <machine/clock.h>
#include <machine/cpufunc.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/specialreg.h>
#include <machine/vmm.h>

#include "vmx.h"
#include "vmx_msr.h"
#include "vmx_nested.h"
#include "x86.h"

/*
 * claude 16/11/2026, prova (b): sincronizzazione delle scritture IA32_TSC dell'ospite. NON e' parita' con KVM
 * (diagnosi 055 par. 3.1): KVM applica alla lettera le WRMSR IA32_TSC dell'OSPITE (adjust_tsc_offset_guest, aggiorna
 * IA32_TSC_ADJUST); kvm_synchronize_tsc con la regola di 1 s vale solo per le scritture dell'host e alla creazione del
 * vCPU, e le liste MSR annidate passano dal percorso dell'ospite. Qui e' una deviazione VOLUTA dalla semantica
 * dell'hardware: le differenze sotto 1 s fra i vCPU si perdono (nessun sistema reale le chiede).
 * bhyve trasforma una WRMSR IA32_TSC in offset = valore - rdtsc() all'istante dell'EMULAZIONE: ogni vCPU eredita la
 * propria latenza d'uscita come sfasamento permanente. Quando l'ospite sincronizza i TSC dei suoi processori (Windows/
 * Hyper-V all'avvio) i vCPU restano sfasati: misurato il 15/11 un vCPU ~1.580 cicli indietro agli altri sette (entro 80);
 * un VP dell'L2 che vi passa vede il TSC tornare indietro, e il timecounter Hyper-V-TSC a 32 bit dell'L2 fa delta ~ 2^32
 * -> sbinuptime +429,5 s -> nanosleep di 2 ms che dormono 429,5 s (claude-lag). Regola (diagnosi 055 par. 3.2, a due
 * candidati): una scrittura il cui offset dista meno di 1 s (tsc_freq cicli) dall'offset comune della VM riceve l'offset
 * comune; altrimenti, se dista meno di 1 s da 0 (l'offset di nascita dei vCPU), riceve 0 e il comune torna 0; altrimenti
 * e' una scelta nuova dell'ospite e diventa l'offset comune (evento «new», stampato: e' un punto in cui uno sfasamento
 * puo' nascere). Chiude «l'ultima scrittura lontana vince»: un vCPU che torna vicino al valore di prima non apre un
 * comune nuovo con dentro la propria latenza. hw.vmm.vmx.tsc_sync=0 torna al comportamento di prima (offset per vCPU).
 */
SYSCTL_DECL(_hw_vmm_vmx);
static int vmx_tsc_sync_on = 1;
SYSCTL_INT(_hw_vmm_vmx, OID_AUTO, tsc_sync, CTLFLAG_RWTUN, &vmx_tsc_sync_on, 0,
    "Scritture IA32_TSC entro 1 s dall'offset comune della VM (o da 0) lo ricevono; deviazione voluta, NON come KVM");
static u_long vmx_tsc_sync_matched, vmx_tsc_sync_new, vmx_tsc_sync_maxcorr, vmx_tsc_sync_zero;
static u_int vmx_tsc_sync_stampe;
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, tsc_sync_zero, CTLFLAG_RD, &vmx_tsc_sync_zero, 0,
    "Scritture IA32_TSC lontane dal comune ma entro 1 s da 0: ricevono 0 e il comune torna 0 (diagnosi 055 par. 3.2)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, tsc_sync_matched, CTLFLAG_RD, &vmx_tsc_sync_matched, 0,
    "Scritture IA32_TSC ricondotte all'offset comune della VM");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, tsc_sync_new, CTLFLAG_RD, &vmx_tsc_sync_new, 0,
    "Scritture IA32_TSC oltre 1 s dall'offset comune: diventano il nuovo offset comune (l'offset comune nasce a 0)");
SYSCTL_ULONG(_hw_vmm_vmx, OID_AUTO, tsc_sync_maxcorr, CTLFLAG_RD, &vmx_tsc_sync_maxcorr, 0,
    "Correzione massima applicata da tsc_sync, in cicli (lo sfasamento che ci sarebbe stato)");

uint64_t
vmx_tsc_sync(struct vmx_vcpu *vcpu, uint64_t offset)
{
	struct vmx *vmx = vcpu->vmx;
	uint64_t ret, corr, corr0, prima;
	bool nuovo = false;

	if (!vmx_tsc_sync_on)
		return (offset);
	mtx_lock_spin(&vmx->tsc_sync_mtx);
	prima = vmx->tsc_sync_off;
	corr = offset - vmx->tsc_sync_off;
	if ((int64_t)corr < 0)
		corr = -corr;
	corr0 = ((int64_t)offset < 0) ? -offset : offset;
	if (vmx->tsc_sync_valid && corr < tsc_freq) {
		ret = vmx->tsc_sync_off;
		vmx_tsc_sync_matched++;
		if (corr > vmx_tsc_sync_maxcorr)
			vmx_tsc_sync_maxcorr = corr;
	} else if (corr0 < tsc_freq) {
		/* secondo candidato: l'offset di nascita dei vCPU */
		vmx->tsc_sync_off = 0;
		vmx->tsc_sync_valid = true;
		ret = 0;
		vmx_tsc_sync_zero++;
		if (corr0 > vmx_tsc_sync_maxcorr)
			vmx_tsc_sync_maxcorr = corr0;
	} else {
		vmx->tsc_sync_off = offset;
		vmx->tsc_sync_valid = true;
		ret = offset;
		vmx_tsc_sync_new++;
		nuovo = true;
	}
	mtx_unlock_spin(&vmx->tsc_sync_mtx);
	if (nuovo && atomic_fetchadd_int(&vmx_tsc_sync_stampe, 1) < 16)
		printf("vmx_tsc_sync: vcpu%d offset nuovo %#lx (comune prima %#lx): nuovo offset comune della VM\n",
		    vcpu->vcpuid, (u_long)offset, (u_long)prima);
	return (ret);
}

static bool
vmx_ctl_allows_one_setting(uint64_t msr_val, int bitpos)
{

	return ((msr_val & (1UL << (bitpos + 32))) != 0);
}

static bool
vmx_ctl_allows_zero_setting(uint64_t msr_val, int bitpos)
{

	return ((msr_val & (1UL << bitpos)) == 0);
}

uint32_t
vmx_revision(void)
{

	return (rdmsr(MSR_VMX_BASIC) & 0xffffffff);
}

/*
 * Generate a bitmask to be used for the VMCS execution control fields.
 *
 * The caller specifies what bits should be set to one in 'ones_mask'
 * and what bits should be set to zero in 'zeros_mask'. The don't-care
 * bits are set to the default value. The default values are obtained
 * based on "Algorithm 3" in Section 27.5.1 "Algorithms for Determining
 * VMX Capabilities".
 *
 * Returns zero on success and non-zero on error.
 */
int
vmx_set_ctlreg(int ctl_reg, int true_ctl_reg, uint32_t ones_mask,
	       uint32_t zeros_mask, uint32_t *retval)
{
	int i;
	uint64_t val, trueval;
	bool true_ctls_avail, one_allowed, zero_allowed;

	/* We cannot ask the same bit to be set to both '1' and '0' */
	if ((ones_mask ^ zeros_mask) != (ones_mask | zeros_mask))
		return (EINVAL);

	true_ctls_avail = (rdmsr(MSR_VMX_BASIC) & (1UL << 55)) != 0;

	val = rdmsr(ctl_reg);
	if (true_ctls_avail)
		trueval = rdmsr(true_ctl_reg);		/* step c */
	else
		trueval = val;				/* step a */

	for (i = 0; i < 32; i++) {
		one_allowed = vmx_ctl_allows_one_setting(trueval, i);
		zero_allowed = vmx_ctl_allows_zero_setting(trueval, i);

		KASSERT(one_allowed || zero_allowed,
			("invalid zero/one setting for bit %d of ctl 0x%0x, "
			 "truectl 0x%0x\n", i, ctl_reg, true_ctl_reg));

		if (zero_allowed && !one_allowed) {		/* b(i),c(i) */
			if (ones_mask & (1 << i))
				return (EINVAL);
			*retval &= ~(1 << i);
		} else if (one_allowed && !zero_allowed) {	/* b(i),c(i) */
			if (zeros_mask & (1 << i))
				return (EINVAL);
			*retval |= 1 << i;
		} else {
			if (zeros_mask & (1 << i))	/* b(ii),c(ii) */
				*retval &= ~(1 << i);
			else if (ones_mask & (1 << i)) /* b(ii), c(ii) */
				*retval |= 1 << i;
			else if (!true_ctls_avail)
				*retval &= ~(1 << i);	/* b(iii) */
			else if (vmx_ctl_allows_zero_setting(val, i))/* c(iii)*/
				*retval &= ~(1 << i);
			else if (vmx_ctl_allows_one_setting(val, i)) /* c(iv) */
				*retval |= 1 << i;
			else {
				panic("vmx_set_ctlreg: unable to determine "
				      "correct value of ctl bit %d for msr "
				      "0x%0x and true msr 0x%0x", i, ctl_reg,
				      true_ctl_reg);
			}
		}
	}

	return (0);
}

void
msr_bitmap_initialize(char *bitmap)
{

	memset(bitmap, 0xff, PAGE_SIZE);
}

int
msr_bitmap_change_access(char *bitmap, u_int msr, int access)
{
	int byte, bit;

	if (msr <= 0x00001FFF)
		byte = msr / 8;
	else if (msr >= 0xC0000000 && msr <= 0xC0001FFF)
		byte = 1024 + (msr - 0xC0000000) / 8;
	else
		return (EINVAL);

	bit = msr & 0x7;

	if (access & MSR_BITMAP_ACCESS_READ)
		bitmap[byte] &= ~(1 << bit);
	else
		bitmap[byte] |= 1 << bit;

	byte += 2048;
	if (access & MSR_BITMAP_ACCESS_WRITE)
		bitmap[byte] &= ~(1 << bit);
	else
		bitmap[byte] |= 1 << bit;

	return (0);
}

static uint64_t misc_enable;
static uint64_t platform_info;
static uint64_t turbo_ratio_limit;
static uint64_t host_msrs[GUEST_MSR_NUM];

static bool
nehalem_cpu(void)
{
	u_int family, model;

	/*
	 * The family:model numbers belonging to the Nehalem microarchitecture
	 * are documented in Section 35.5, Intel SDM dated Feb 2014.
	 */
	family = CPUID_TO_FAMILY(cpu_id);
	model = CPUID_TO_MODEL(cpu_id);
	if (family == 0x6) {
		switch (model) {
		case 0x1A:
		case 0x1E:
		case 0x1F:
		case 0x2E:
			return (true);
		default:
			break;
		}
	}
	return (false);
}

static bool
westmere_cpu(void)
{
	u_int family, model;

	/*
	 * The family:model numbers belonging to the Westmere microarchitecture
	 * are documented in Section 35.6, Intel SDM dated Feb 2014.
	 */
	family = CPUID_TO_FAMILY(cpu_id);
	model = CPUID_TO_MODEL(cpu_id);
	if (family == 0x6) {
		switch (model) {
		case 0x25:
		case 0x2C:
			return (true);
		default:
			break;
		}
	}
	return (false);
}

static bool
pat_valid(uint64_t val)
{
	int i, pa;

	/*
	 * From Intel SDM: Table "Memory Types That Can Be Encoded With PAT"
	 *
	 * Extract PA0 through PA7 and validate that each one encodes a
	 * valid memory type.
	 */
	for (i = 0; i < 8; i++) {
		pa = (val >> (i * 8)) & 0xff;
		if (pa == 2 || pa == 3 || pa >= 8)
			return (false);
	}
	return (true);
}

void
vmx_msr_init(void)
{
	uint64_t bus_freq, ratio;
	int i;

	/*
	 * It is safe to cache the values of the following MSRs because
	 * they don't change based on curcpu, curproc or curthread.
	 */
	host_msrs[IDX_MSR_LSTAR] = rdmsr(MSR_LSTAR);
	host_msrs[IDX_MSR_CSTAR] = rdmsr(MSR_CSTAR);
	host_msrs[IDX_MSR_STAR] = rdmsr(MSR_STAR);
	host_msrs[IDX_MSR_SF_MASK] = rdmsr(MSR_SF_MASK);

	/*
	 * Initialize emulated MSRs
	 */
	misc_enable = rdmsr(MSR_IA32_MISC_ENABLE);
	/*
	 * Set mandatory bits
	 *  11:   branch trace disabled
	 *  12:   PEBS unavailable
	 * Clear unsupported features
	 *  16:   SpeedStep enable
	 *  18:   enable MONITOR FSM
	 */
	misc_enable |= (1 << 12) | (1 << 11);
	misc_enable &= ~((1 << 18) | (1 << 16));

	if (nehalem_cpu() || westmere_cpu())
		bus_freq = 133330000;		/* 133Mhz */
	else
		bus_freq = 100000000;		/* 100Mhz */

	/*
	 * XXXtime
	 * The ratio should really be based on the virtual TSC frequency as
	 * opposed to the host TSC.
	 */
	ratio = (tsc_freq / bus_freq) & 0xff;

	/*
	 * The register definition is based on the micro-architecture
	 * but the following bits are always the same:
	 * [15:8]  Maximum Non-Turbo Ratio
	 * [28]    Programmable Ratio Limit for Turbo Mode
	 * [29]    Programmable TDC-TDP Limit for Turbo Mode
	 * [47:40] Maximum Efficiency Ratio
	 *
	 * The other bits can be safely set to 0 on all
	 * micro-architectures up to Haswell.
	 */
	platform_info = (ratio << 8) | (ratio << 40);

	/*
	 * The number of valid bits in the MSR_TURBO_RATIO_LIMITx register is
	 * dependent on the maximum cores per package supported by the micro-
	 * architecture. For e.g., Westmere supports 6 cores per package and
	 * uses the low 48 bits. Sandybridge support 8 cores per package and
	 * uses up all 64 bits.
	 *
	 * However, the unused bits are reserved so we pretend that all bits
	 * in this MSR are valid.
	 */
	for (i = 0; i < 8; i++)
		turbo_ratio_limit = (turbo_ratio_limit << 8) | ratio;
}

void
vmx_msr_guest_init(struct vmx *vmx, struct vmx_vcpu *vcpu)
{
	/*
	 * The permissions bitmap is shared between all vcpus so initialize it
	 * once when initializing the vBSP.
	 */
	if (vcpu->vcpuid == 0) {
		guest_msr_rw(vmx, MSR_LSTAR);
		guest_msr_rw(vmx, MSR_CSTAR);
		guest_msr_rw(vmx, MSR_STAR);
		guest_msr_rw(vmx, MSR_SF_MASK);
		guest_msr_rw(vmx, MSR_KGSBASE);
	}

	/*
	 * Initialize guest IA32_PAT MSR with default value after reset.
	 */
	vcpu->guest_msrs[IDX_MSR_PAT] = PAT_VALUE(0, PAT_WRITE_BACK) |
	    PAT_VALUE(1, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(2, PAT_UNCACHED)		|
	    PAT_VALUE(3, PAT_UNCACHEABLE)	|
	    PAT_VALUE(4, PAT_WRITE_BACK)	|
	    PAT_VALUE(5, PAT_WRITE_THROUGH)	|
	    PAT_VALUE(6, PAT_UNCACHED)		|
	    PAT_VALUE(7, PAT_UNCACHEABLE);

	return;
}

void
vmx_msr_guest_enter(struct vmx_vcpu *vcpu)
{

	/* Save host MSRs (in particular, KGSBASE) and restore guest MSRs */
	update_pcb_bases(curpcb);
	wrmsr(MSR_LSTAR, vcpu->guest_msrs[IDX_MSR_LSTAR]);
	wrmsr(MSR_CSTAR, vcpu->guest_msrs[IDX_MSR_CSTAR]);
	wrmsr(MSR_STAR, vcpu->guest_msrs[IDX_MSR_STAR]);
	wrmsr(MSR_SF_MASK, vcpu->guest_msrs[IDX_MSR_SF_MASK]);
	wrmsr(MSR_KGSBASE, vcpu->guest_msrs[IDX_MSR_KGSBASE]);
}

void
vmx_msr_guest_enter_tsc_aux(struct vmx *vmx, struct vmx_vcpu *vcpu)
{
	uint64_t guest_tsc_aux = vcpu->guest_msrs[IDX_MSR_TSC_AUX];
	uint32_t host_aux = cpu_auxmsr();

	if (vmx_have_msr_tsc_aux && guest_tsc_aux != host_aux)
		wrmsr(MSR_TSC_AUX, guest_tsc_aux);
}

void
vmx_msr_guest_exit(struct vmx_vcpu *vcpu)
{

	/* Save guest MSRs */
	vcpu->guest_msrs[IDX_MSR_LSTAR] = rdmsr(MSR_LSTAR);
	vcpu->guest_msrs[IDX_MSR_CSTAR] = rdmsr(MSR_CSTAR);
	vcpu->guest_msrs[IDX_MSR_STAR] = rdmsr(MSR_STAR);
	vcpu->guest_msrs[IDX_MSR_SF_MASK] = rdmsr(MSR_SF_MASK);
	vcpu->guest_msrs[IDX_MSR_KGSBASE] = rdmsr(MSR_KGSBASE);

	/* Restore host MSRs */
	wrmsr(MSR_LSTAR, host_msrs[IDX_MSR_LSTAR]);
	wrmsr(MSR_CSTAR, host_msrs[IDX_MSR_CSTAR]);
	wrmsr(MSR_STAR, host_msrs[IDX_MSR_STAR]);
	wrmsr(MSR_SF_MASK, host_msrs[IDX_MSR_SF_MASK]);

	/* MSR_KGSBASE will be restored on the way back to userspace */
}

void
vmx_msr_guest_exit_tsc_aux(struct vmx *vmx, struct vmx_vcpu *vcpu)
{
	uint64_t guest_tsc_aux = vcpu->guest_msrs[IDX_MSR_TSC_AUX];
	uint32_t host_aux = cpu_auxmsr();

	if (vmx_have_msr_tsc_aux && guest_tsc_aux != host_aux)
		/*
		 * Note that it is not necessary to save the guest value
		 * here; vcpu->guest_msrs[IDX_MSR_TSC_AUX] always
		 * contains the current value since it is updated whenever
		 * the guest writes to it (which is expected to be very
		 * rare).
		 */
		wrmsr(MSR_TSC_AUX, host_aux);
}

int
vmx_rdmsr(struct vmx_vcpu *vcpu, u_int num, uint64_t *val, bool *retu)
{
	int error;

	error = 0;

	switch (num) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
		*val = 0;
		break;
	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1:
		if (vm_rdmtrr(&vcpu->mtrr, num, val) != 0) {
			vm_inject_gp(vcpu->vcpu);
		}
		break;
	case MSR_IA32_MISC_ENABLE:
		*val = misc_enable;
		break;
	case MSR_PLATFORM_INFO:
		*val = platform_info;
		break;
	case MSR_TURBO_RATIO_LIMIT:
	case MSR_TURBO_RATIO_LIMIT1:
		*val = turbo_ratio_limit;
		break;
	case MSR_PAT:
		*val = vcpu->guest_msrs[IDX_MSR_PAT];
		break;
	case MSR_DEBUGCTLMSR:
		/*
		 * Il DEBUGCTL del guest vive nel VMCS (GUEST_IA32_DEBUGCTL, con
		 * load/save debug controls). Prima non era gestito: il RDMSR
		 * finiva in userland e QEMU rispondeva da una sua cache
		 * scollegata dal VMCS (kvm-unit-tests 'debug controls').
		 */
		error = vm_get_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_GUEST_IA32_DEBUGCTL), val);
		break;
	case MSR_IA32_FEATURE_CONTROL:
		if (vcpu->nested != NULL)
			*val = vcpu->nested->feature_control;
		else
			error = EINVAL;	/* nested off: come prima, a userland */
		break;
	case MSR_VMX_BASIC ... MSR_VMX_BASIC + 0x10:	/* 0x480..0x490 */
		if (vcpu->nested != NULL)
			*val = vcpu->nested->vmx_msr[num - MSR_VMX_BASIC];
		else
			error = EINVAL;
		break;
	case MSR_VMX_BASIC + 0x11:			/* 0x491 VMFUNC: non esposto */
		if (vcpu->nested != NULL)
			vm_inject_gp(vcpu->vcpu);
		else
			error = EINVAL;
		break;
	default:
		error = EINVAL;
		break;
	}
	return (error);
}

int
vmx_wrmsr(struct vmx_vcpu *vcpu, u_int num, uint64_t val, bool *retu)
{
	uint64_t changed;
	int error;

	error = 0;

	switch (num) {
	case MSR_MCG_CAP:
	case MSR_MCG_STATUS:
		break;		/* ignore writes */
	case MSR_MTRRcap:
	case MSR_MTRRdefType:
	case MSR_MTRR4kBase ... MSR_MTRR4kBase + 7:
	case MSR_MTRR16kBase ... MSR_MTRR16kBase + 1:
	case MSR_MTRR64kBase:
	case MSR_MTRRVarBase ... MSR_MTRRVarBase + (VMM_MTRR_VAR_MAX * 2) - 1:
		if (vm_wrmtrr(&vcpu->mtrr, num, val) != 0) {
			vm_inject_gp(vcpu->vcpu);
		}
		break;
	case MSR_IA32_MISC_ENABLE:
		changed = val ^ misc_enable;
		/*
		 * If the host has disabled the NX feature then the guest
		 * also cannot use it. However, a Linux guest will try to
		 * enable the NX feature by writing to the MISC_ENABLE MSR.
		 *
		 * This can be safely ignored because the memory management
		 * code looks at CPUID.80000001H:EDX.NX to check if the
		 * functionality is actually enabled.
		 */
		changed &= ~(1UL << 34);

		/*
		 * Punt to userspace if any other bits are being modified.
		 */
		if (changed)
			error = EINVAL;

		break;
	case MSR_PAT:
		if (pat_valid(val))
			vcpu->guest_msrs[IDX_MSR_PAT] = val;
		else
			vm_inject_gp(vcpu->vcpu);
		break;
	case MSR_TSC:
		/* claude 16/11: offset comune della VM se e' una sincronizzazione (vmx_tsc_sync) */
		error = vmx_set_tsc_offset(vcpu, vmx_tsc_sync(vcpu, val - rdtsc()));
		break;
	case MSR_TSC_AUX:
		if (vmx_have_msr_tsc_aux)
			/*
			 * vmx_msr_guest_enter_tsc_aux() will apply this
			 * value when it is called immediately before guest
			 * entry.
			 */
			vcpu->guest_msrs[IDX_MSR_TSC_AUX] = val;
		else
			vm_inject_gp(vcpu->vcpu);
		break;
	case MSR_DEBUGCTLMSR:
		/*
		 * Solo LBR (bit 0) e BTF (bit 1): BTS/trace e simili farebbero
		 * scrivere la CPU in aree (IA32_DS_AREA) non commutate tra guest
		 * e host. Gli altri bit si ignorano.
		 */
		error = vm_set_register(vcpu->vcpu,
		    VMCS_IDENT(VMCS_GUEST_IA32_DEBUGCTL), val & 0x3);
		break;
	case MSR_IA32_FEATURE_CONTROL:
		if (vcpu->nested != NULL) {
			/*
			 * L'MSR si presenta gia' bloccato (LOCK|VMX_EN) perche'
			 * edk2-bhyve non lo scrive. SeaBIOS/OVMF sotto QEMU invece
			 * lo riscrivono SEMPRE all'avvio (fw_cfg
			 * etc/msr_feature_control = LOCKED|VMXON_OUTSIDE_SMX
			 * [+LMCE/SGX]): un #GP li', senza IDT, e' un triple fault
			 * nel BIOS (kvm-unit-tests F1 non partiva). Accetto la
			 * riscrittura che conferma lo stato; i bit che non
			 * emuliamo (SMX, LMCE, SGX) si ignorano. Togliere LOCK o
			 * VMX_EN, o bit ignoti -> #GP come sull'hardware.
			 */
			uint64_t keep = IA32_FEATURE_CONTROL_LOCK |
			    IA32_FEATURE_CONTROL_VMX_EN;
			uint64_t ign = IA32_FEATURE_CONTROL_SMX_EN |
			    IA32_FEATURE_CONTROL_LMCE_EN |
			    (1UL << 17) | (1UL << 18);	/* SGX_LC, SGX */
			if ((val & keep) != keep || (val & ~(keep | ign)) != 0)
				vm_inject_gp(vcpu->vcpu);
			/* altrimenti: conferma idempotente, valore invariato */
		} else
			error = EINVAL;
		break;
	case MSR_VMX_BASIC ... MSR_VMX_BASIC + 0x11:	/* MSR VMX: sola lettura */
		if (vcpu->nested != NULL)
			vm_inject_gp(vcpu->vcpu);
		else
			error = EINVAL;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}
