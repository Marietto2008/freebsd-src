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
#include <sys/smp.h>

#include <x86/specialreg.h>
#include <x86/apicreg.h>

#include <dev/vmm/vmm_ktr.h>

#include <machine/vmm.h>
#include "vmm_lapic.h"
#include "vlapic.h"

/*
 * Some MSI message definitions
 */
#define	MSI_X86_ADDR_MASK	0xfff00000
#define	MSI_X86_ADDR_BASE	0xfee00000
#define	MSI_X86_ADDR_RH		0x00000008	/* Redirection Hint */
#define	MSI_X86_ADDR_LOG	0x00000004	/* Destination Mode */

int
lapic_get_state(struct vcpu *vcpu, struct vm_lapic_state *lapic_state)
{
    struct LAPIC *klapic = vlapic_page(vm_lapic(vcpu));
    #define COPY_FIELD(name, index) lapic_state->fields[index].data = klapic->name;

    #define RANGE_COPY_FIELD(name, index, i) COPY_FIELD(name##i, index##i);


    COPY_FIELD(id, LAPIC_ID);
    COPY_FIELD(version, LAPIC_VERSION);
    COPY_FIELD(tpr, LAPIC_TPR);
    COPY_FIELD(apr, LAPIC_APR);
    COPY_FIELD(ppr, LAPIC_PPR);
    COPY_FIELD(eoi, LAPIC_EOI);
    COPY_FIELD(ldr, LAPIC_LDR);
    COPY_FIELD(dfr, LAPIC_DFR);
    COPY_FIELD(svr, LAPIC_SVR);

    // Manually unroll isr tmr irr
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 0);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 1);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 2);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 3);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 4);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 5);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 6);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 7);

    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 0);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 1);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 2);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 3);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 4);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 5);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 6);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 7);

    RANGE_COPY_FIELD(irr, LAPIC_IRR, 0);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 1);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 2);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 3);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 4);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 5);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 6);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 7);

    COPY_FIELD(esr, LAPIC_ESR);
    COPY_FIELD(lvt_cmci, LAPIC_LVT_CMCI);
    COPY_FIELD(icr_lo, LAPIC_ICR_LO);
    COPY_FIELD(icr_hi, LAPIC_ICR_HI);
    COPY_FIELD(lvt_timer, LAPIC_LVT_TIMER);
    COPY_FIELD(lvt_thermal, LAPIC_LVT_THERMAL);
    COPY_FIELD(lvt_pcint, LAPIC_LVT_PCINT);
    COPY_FIELD(lvt_lint0, LAPIC_LVT_LINT0);
    COPY_FIELD(lvt_lint1, LAPIC_LVT_LINT1);
    COPY_FIELD(lvt_error, LAPIC_LVT_ERROR);
    COPY_FIELD(icr_timer, LAPIC_ICR_TIMER);
    COPY_FIELD(ccr_timer, LAPIC_CCR_TIMER);
    COPY_FIELD(dcr_timer, LAPIC_DCR_TIMER);

    #undef COPY_FIELD
    #undef RANGE_COPY_FIELD
    return 0;
}

int
lapic_set_state(struct vcpu *vcpu, struct vm_lapic_state *lapic_state)
{
    struct LAPIC *klapic = vlapic_page(vm_lapic(vcpu));
    #define COPY_FIELD(name, index) \
        klapic->name = lapic_state->fields[index].data;

    #define RANGE_COPY_FIELD(name, index, i) COPY_FIELD(name##i, index##i);


    COPY_FIELD(id, LAPIC_ID);
    COPY_FIELD(version, LAPIC_VERSION);
    COPY_FIELD(tpr, LAPIC_TPR);
    COPY_FIELD(apr, LAPIC_APR);
    COPY_FIELD(ppr, LAPIC_PPR);
    COPY_FIELD(eoi, LAPIC_EOI);
    COPY_FIELD(ldr, LAPIC_LDR);
    COPY_FIELD(dfr, LAPIC_DFR);
    COPY_FIELD(svr, LAPIC_SVR);

    // Manually unroll isr tmr irr
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 0);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 1);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 2);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 3);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 4);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 5);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 6);
    RANGE_COPY_FIELD(isr, LAPIC_ISR, 7);

    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 0);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 1);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 2);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 3);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 4);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 5);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 6);
    RANGE_COPY_FIELD(tmr, LAPIC_TMR, 7);

    RANGE_COPY_FIELD(irr, LAPIC_IRR, 0);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 1);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 2);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 3);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 4);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 5);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 6);
    RANGE_COPY_FIELD(irr, LAPIC_IRR, 7);

    COPY_FIELD(esr, LAPIC_ESR);
    COPY_FIELD(lvt_cmci, LAPIC_LVT_CMCI);
    COPY_FIELD(icr_lo, LAPIC_ICR_LO);
    COPY_FIELD(icr_hi, LAPIC_ICR_HI);
    COPY_FIELD(lvt_timer, LAPIC_LVT_TIMER);
    COPY_FIELD(lvt_thermal, LAPIC_LVT_THERMAL);
    COPY_FIELD(lvt_pcint, LAPIC_LVT_PCINT);
    COPY_FIELD(lvt_lint0, LAPIC_LVT_LINT0);
    COPY_FIELD(lvt_lint1, LAPIC_LVT_LINT1);
    COPY_FIELD(lvt_error, LAPIC_LVT_ERROR);
    COPY_FIELD(icr_timer, LAPIC_ICR_TIMER);
    COPY_FIELD(ccr_timer, LAPIC_CCR_TIMER);
    COPY_FIELD(dcr_timer, LAPIC_DCR_TIMER);

    #undef COPY_FIELD
    #undef RANGE_COPY_FIELD
    return 0;
}

int
lapic_set_intr(struct vcpu *vcpu, int vector, bool level)
{
	struct vlapic *vlapic;

	/*
	 * According to section "Maskable Hardware Interrupts" in Intel SDM
	 * vectors 16 through 255 can be delivered through the local APIC.
	 */
	if (vector < 16 || vector > 255)
		return (EINVAL);

	vlapic = vm_lapic(vcpu);
	if (vlapic_set_intr_ready(vlapic, vector, level)) {
		/*
		 * Ensure IRR write is globally visible before kicking
		 * the vcpu thread which will read it in vmx_inject_interrupts.
		 */
		mb();
		vcpu_notify_event(vcpu, true);
	}
	return (0);
}

int
lapic_clear_irr(struct vcpu *vcpu, struct vm_lapic_clear_irr *ci)
{
	struct LAPIC *lapic;
	uint32_t *irrptr;
	int i;

	lapic = vlapic_page(vm_lapic(vcpu));
	if (lapic == NULL)
		return (EINVAL);

	irrptr = &lapic->irr0;
	for (i = 0; i < 8; i++) {
		if (ci->irr_mask[i] != 0)
			atomic_clear_int(&irrptr[i * 4], ci->irr_mask[i]);
	}
	return (0);
}

int
lapic_set_local_intr(struct vm *vm, struct vcpu *vcpu, int vector)
{
	struct vlapic *vlapic;
	cpuset_t dmask;
	int cpu, error;

	if (vcpu == NULL) {
		error = 0;
		dmask = vm_active_cpus(vm);
		CPU_FOREACH_ISSET(cpu, &dmask) {
			vlapic = vm_lapic(vm_vcpu(vm, cpu));
			error = vlapic_trigger_lvt(vlapic, vector);
			if (error)
				break;
		}
	} else {
		vlapic = vm_lapic(vcpu);
		error = vlapic_trigger_lvt(vlapic, vector);
	}

	return (error);
}

int
lapic_intr_msi(struct vm *vm, uint64_t addr, uint64_t msg)
{
	int delmode, vec;
	uint32_t dest;
	bool phys;

	VM_CTR2(vm, "lapic MSI addr: %#lx msg: %#lx", addr, msg);

	if ((addr & MSI_X86_ADDR_MASK) != MSI_X86_ADDR_BASE) {
		VM_CTR1(vm, "lapic MSI invalid addr %#lx", addr);
		return (-1);
	}

	/*
	 * Extract the x86-specific fields from the MSI addr/msg
	 * params according to the Intel Arch spec, Vol3 Ch 10.
	 *
	 * The PCI specification does not support level triggered
	 * MSI/MSI-X so ignore trigger level in 'msg'.
	 *
	 * The 'dest' is interpreted as a logical APIC ID if both
	 * the Redirection Hint and Destination Mode are '1' and
	 * physical otherwise.
	 */
	dest = (addr >> 12) & 0xff;
	/*
	 * Extended Destination ID support uses bits 5-11 of the address:
	 * http://david.woodhou.se/ExtDestId.pdf
	 */
	dest |= ((addr >> 5) & 0x7f) << 8;
	phys = ((addr & (MSI_X86_ADDR_RH | MSI_X86_ADDR_LOG)) !=
	    (MSI_X86_ADDR_RH | MSI_X86_ADDR_LOG));
	delmode = msg & APIC_DELMODE_MASK;
	vec = msg & 0xff;

	vlapic_deliver_intr(vm, LAPIC_TRIG_EDGE, dest, phys, delmode, vec);
	return (0);
}

static bool
x2apic_msr(u_int msr)
{
	return (msr >= 0x800 && msr <= 0xBFF);
}

static u_int
x2apic_msr_to_regoff(u_int msr)
{

	return ((msr - 0x800) << 4);
}

bool
lapic_msr(u_int msr)
{

	return (x2apic_msr(msr) || msr == MSR_APICBASE);
}

int
lapic_rdmsr(struct vcpu *vcpu, u_int msr, uint64_t *rval, bool *retu)
{
	int error;
	u_int offset;
	struct vlapic *vlapic;

	vlapic = vm_lapic(vcpu);

	if (msr == MSR_APICBASE) {
		*rval = vlapic_get_apicbase(vlapic);
		error = 0;
	} else {
		offset = x2apic_msr_to_regoff(msr);
		error = vlapic_read(vlapic, 0, offset, rval, retu);
	}

	return (error);
}

int
lapic_wrmsr(struct vcpu *vcpu, u_int msr, uint64_t val, bool *retu)
{
	int error;
	u_int offset;
	struct vlapic *vlapic;

	vlapic = vm_lapic(vcpu);

	if (msr == MSR_APICBASE) {
		error = vlapic_set_apicbase(vlapic, val);
	} else {
		offset = x2apic_msr_to_regoff(msr);
		error = vlapic_write(vlapic, 0, offset, val, retu);
	}

	return (error);
}

int
lapic_mmio_write(struct vcpu *vcpu, uint64_t gpa, uint64_t wval, int size,
		 void *arg)
{
	int error;
	uint64_t off;
	struct vlapic *vlapic;

	off = gpa - DEFAULT_APIC_BASE;

	/*
	 * Memory mapped local apic accesses must be 4 bytes wide and
	 * aligned on a 16-byte boundary.
	 */
	if (size != 4 || off & 0xf)
		return (EINVAL);

	vlapic = vm_lapic(vcpu);
	error = vlapic_write(vlapic, 1, off, wval, arg);
	return (error);
}

int
lapic_mmio_read(struct vcpu *vcpu, uint64_t gpa, uint64_t *rval, int size,
		void *arg)
{
	int error;
	uint64_t off;
	struct vlapic *vlapic;

	off = gpa - DEFAULT_APIC_BASE;

	/*
	 * Memory mapped local apic accesses should be aligned on a
	 * 16-byte boundary.  They are also suggested to be 4 bytes
	 * wide, alas not all OSes follow suggestions.
	 */
	off &= ~3;
	if (off & 0xf)
		return (EINVAL);

	vlapic = vm_lapic(vcpu);
	error = vlapic_read(vlapic, 1, off, rval, arg);
	return (error);
}
