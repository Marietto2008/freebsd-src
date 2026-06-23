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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/_iovec.h>

#include <machine/specialreg.h>
#include <machine/psl.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>
#include <machine/vmm_snapshot.h>
#include <machine/vmm_instruction_emul.h>

#include <string.h>
#include <assert.h>

#include "vmmapi.h"
#include "internal.h"

const char *vm_capstrmap[] = {
	[VM_CAP_HALT_EXIT]  = "hlt_exit",
	[VM_CAP_MTRAP_EXIT] = "mtrap_exit",
	[VM_CAP_PAUSE_EXIT] = "pause_exit",
	[VM_CAP_UNRESTRICTED_GUEST] = "unrestricted_guest",
	[VM_CAP_ENABLE_INVPCID] = "enable_invpcid",
	[VM_CAP_BPT_EXIT] = "bpt_exit",
	[VM_CAP_RDPID] = "rdpid",
	[VM_CAP_RDTSCP] = "rdtscp",
	[VM_CAP_IPI_EXIT] = "ipi_exit",
	[VM_CAP_MASK_HWINTR] = "mask_hwintr",
	[VM_CAP_RFLAGS_TF] = "rflags_tf",
	[VM_CAP_MAX] = NULL,
};

#define	VM_MD_IOCTLS			\
	VM_SET_SEGMENT_DESCRIPTOR,	\
	VM_GET_SEGMENT_DESCRIPTOR,	\
	VM_SET_KERNEMU_DEV,		\
	VM_GET_KERNEMU_DEV,		\
    VM_SET_FLAGS,	 \
    VM_GET_FLAGS,    \
    VM_LAPIC_SET_STATE, \
    VM_LAPIC_GET_STATE, \
	VM_LAPIC_IRQ,			\
	VM_LAPIC_LOCAL_IRQ,		\
	VM_LAPIC_MSI,			\
	VM_IOAPIC_ASSERT_IRQ,		\
	VM_IOAPIC_DEASSERT_IRQ,		\
	VM_IOAPIC_PULSE_IRQ,		\
	VM_IOAPIC_PINCOUNT,		\
	VM_ISA_ASSERT_IRQ,		\
	VM_ISA_DEASSERT_IRQ,		\
	VM_ISA_PULSE_IRQ,		\
	VM_ISA_SET_IRQ_TRIGGER,		\
	VM_INJECT_NMI,			\
	VM_SET_X2APIC_STATE,		\
	VM_GET_X2APIC_STATE,		\
	VM_GET_HPET_CAPABILITIES,	\
	VM_RTC_WRITE,			\
	VM_RTC_READ,			\
	VM_RTC_SETTIME,			\
	VM_RTC_GETTIME,			\
	VM_GET_GPA_PMAP,		\
	VM_GLA2GPA,			\
	VM_SET_INTINFO,			\
	VM_GET_INTINFO,			\
	VM_RESTART_INSTRUCTION,		\
	VM_SNAPSHOT_REQ,		\
	VM_RESTORE_TIME

const cap_ioctl_t vm_ioctl_cmds[] = {
	VM_COMMON_IOCTLS,
	VM_PPT_IOCTLS,
	VM_MD_IOCTLS,
};
size_t vm_ioctl_ncmds = nitems(vm_ioctl_cmds);

int
vm_set_flags(struct vmctx *ctx,
    int flags)
{
	return (ioctl(ctx->fd, VM_SET_FLAGS, &flags));
}

int
vm_get_flags(struct vmctx *ctx,
    int *flags)
{
	return (ioctl(ctx->fd, VM_GET_FLAGS, &flags));
}

static int
mem_read(struct vcpu *vcpu __unused, uint64_t gpa, uint64_t *rval, int size, void *arg)
{
	qmem_callback_t mem_callback = arg;
	uint8_t temp_data[sizeof(uint64_t)] = {0};

	struct vm_qmem mem_args = {
		.gpa = gpa,
		.write = false,
		.size = size,
		.data = temp_data
	};

	mem_callback(&mem_args);

	*rval = 0; // Clear it first
	memcpy(rval, temp_data, size); // Copy only the 'size' bytes read

	return 0;
}

static int
mem_write(struct vcpu *vcpu __unused, uint64_t gpa, uint64_t wval, int size, void *arg)
{
	qmem_callback_t mem_callback = arg;

	uint8_t temp_data[sizeof(uint64_t)] = {};
    memcpy(temp_data, &wval, sizeof(uint64_t));

	struct vm_qmem mem_args = {
		.gpa = gpa,
		.write = true,
		.size = size,
        .data = temp_data
	};
    mem_callback(&mem_args);
    return 0;
}

int
vm_assist_qmem(struct vcpu* vcpu, qmem_callback_t mem_callback, struct vm_exit* vmexit)
{
	struct vie *vie;
	int cs_d;
	enum vm_cpu_mode mode;

	vie = &vmexit->u.inst_emul.vie;
	if (!vie->decoded) {
		/*
		 * Attempt to decode in userspace as a fallback.  This allows
		 * updating instruction decode in bhyve without rebooting the
		 * kernel (rapid prototyping), albeit with much slower
		 * emulation.
		 */
		vie_restart(vie);
		mode = vmexit->u.inst_emul.paging.cpu_mode;
		cs_d = vmexit->u.inst_emul.cs_d;
		if (vmm_decode_instruction(mode, cs_d, vie) != 0)
			goto fail;
		if (vm_set_register(vcpu, VM_REG_GUEST_RIP,
		    vmexit->rip + vie->num_processed) != 0)
			goto fail;
	}
	return (vmm_emulate_instruction(vcpu, vmexit->u.inst_emul.gpa, vie, &vmexit->u.inst_emul.paging, mem_read,
                                    mem_write, mem_callback));
fail:
    return -1;
}

int
vm_assist_qio(struct vcpu* vcpu, qio_callback_t io_callback, struct vm_exit* vmexit)
{
	int addrsize, bytes, in, port, prot, rep;
	uint32_t eax, val;
	int error, fault, retval;
	enum vm_reg_name idxreg;
	uint64_t gla, index, iterations, count;
	struct vm_inout_str *vis;
	struct iovec iov[2];
    struct vm_qio io_args;

	bytes = vmexit->u.inout.bytes;
	in = vmexit->u.inout.in;
	port = vmexit->u.inout.port;

    // Less than max ports
	assert(port < (1 << 16));
	assert(bytes == 1 || bytes == 2 || bytes == 4);

	retval = 0;
	if (vmexit->u.inout.string) {
		vis = &vmexit->u.inout_str;
		rep = vis->inout.rep;
		addrsize = vis->addrsize;
		prot = in ? PROT_WRITE : PROT_READ;
		assert(addrsize == 2 || addrsize == 4 || addrsize == 8);

		/* Index register */
		idxreg = in ? VM_REG_GUEST_RDI : VM_REG_GUEST_RSI;

        /* Masks bits under full register size. Ex addrsize == 4 bytes: 0xFFFFFFFF */
		index = vis->index & vie_size2mask(addrsize);

		/* Count register */
		count = vis->count & vie_size2mask(addrsize);

		/* Limit number of back-to-back in/out emulations to 16 */
		iterations = MIN(count, 16);
		while (iterations > 0) {
			assert(retval == 0);
			if (vie_calculate_gla(vis->paging.cpu_mode,
			    vis->seg_name, &vis->seg_desc, index, bytes,
			    addrsize, prot, &gla)) {
				vm_inject_gp(vcpu);
				break;
			}

			error = vm_copy_setup(vcpu, &vis->paging, gla,
			    bytes, prot, iov, nitems(iov), &fault);
			if (error) {
				retval = -1;  /* Unrecoverable error */
				break;
			} else if (fault) {
				retval = 0;  /* Resume guest to handle fault */
				break;
			}

			if (vie_alignment_check(vis->paging.cpl, bytes,
			    vis->cr0, vis->rflags, gla)) {
				vm_inject_ac(vcpu, 0);
				break;
			}

			val = 0;
			if (!in)
				vm_copyin(iov, &val, bytes);

			io_args.port = port;
			io_args.in = in;
			io_args.size = bytes;
            io_args.data = (uint8_t*)&val;
			retval = io_callback(&io_args);

			if (in)
				vm_copyout(&val, iov, bytes);

			/* Update index */
			if (vis->rflags & PSL_D)
				index -= bytes;
			else
				index += bytes;

			count--;
			iterations--;
		}

		/* Update index register */
		error = vie_update_register(vcpu, idxreg, index, addrsize);
		assert(error == 0);

		/*
		 * Update count register only if the instruction had a repeat
		 * prefix.
		 */
		if (rep) {
			error = vie_update_register(vcpu, VM_REG_GUEST_RCX,
			    count, addrsize);
			assert(error == 0);
		}

		/* Restart the instruction if more iterations remain */
		if (retval == 0 && count != 0) {
			error = vm_restart_instruction(vcpu);
			assert(error == 0);
		}
	} else {
		eax = vmexit->u.inout.eax;
		val = eax & vie_size2mask(bytes);
        io_args.port = port;
        io_args.in = in;
        io_args.size = bytes;
        io_args.data = (uint8_t*)&val;
        retval = io_callback(&io_args);
		if (retval == 0 && in) {
			eax &= ~vie_size2mask(bytes);
			eax |= val & vie_size2mask(bytes);
			error = vm_set_register(vcpu, VM_REG_GUEST_RAX,
			    eax);
			assert(error == 0);
		}
	}
	return (retval);
}

int
vm_set_desc(struct vcpu *vcpu, int reg,
	    uint64_t base, uint32_t limit, uint32_t access)
{
	int error;
	struct vm_seg_desc vmsegdesc;

	bzero(&vmsegdesc, sizeof(vmsegdesc));
	vmsegdesc.regnum = reg;
	vmsegdesc.desc.base = base;
	vmsegdesc.desc.limit = limit;
	vmsegdesc.desc.access = access;

	error = vcpu_ioctl(vcpu, VM_SET_SEGMENT_DESCRIPTOR, &vmsegdesc);
	return (error);
}

int
vm_get_desc(struct vcpu *vcpu, int reg, uint64_t *base, uint32_t *limit,
    uint32_t *access)
{
	int error;
	struct vm_seg_desc vmsegdesc;

	bzero(&vmsegdesc, sizeof(vmsegdesc));
	vmsegdesc.regnum = reg;

	error = vcpu_ioctl(vcpu, VM_GET_SEGMENT_DESCRIPTOR, &vmsegdesc);
	if (error == 0) {
		*base = vmsegdesc.desc.base;
		*limit = vmsegdesc.desc.limit;
		*access = vmsegdesc.desc.access;
	}
	return (error);
}

int
vm_get_seg_desc(struct vcpu *vcpu, int reg, struct seg_desc *seg_desc)
{
	int error;

	error = vm_get_desc(vcpu, reg, &seg_desc->base, &seg_desc->limit,
	    &seg_desc->access);
	return (error);
}

int
vm_lapic_set_state(struct vcpu *vcpu, struct vm_lapic_state* apic_page)
{
	return (vcpu_ioctl(vcpu, VM_LAPIC_SET_STATE, apic_page));
}

int
vm_lapic_get_state(struct vcpu *vcpu, struct vm_lapic_state* apic_page)
{
	return (vcpu_ioctl(vcpu, VM_LAPIC_GET_STATE, apic_page));
}


int
vm_lapic_irq(struct vcpu *vcpu, int vector)
{
	struct vm_lapic_irq vmirq;

	bzero(&vmirq, sizeof(vmirq));
	vmirq.vector = vector;

	return (vcpu_ioctl(vcpu, VM_LAPIC_IRQ, &vmirq));
}

int
vm_lapic_local_irq(struct vcpu *vcpu, int vector)
{
	struct vm_lapic_irq vmirq;

	bzero(&vmirq, sizeof(vmirq));
	vmirq.vector = vector;

	return (vcpu_ioctl(vcpu, VM_LAPIC_LOCAL_IRQ, &vmirq));
}

int
vm_lapic_msi(struct vmctx *ctx, uint64_t addr, uint64_t msg)
{
	struct vm_lapic_msi vmmsi;

	bzero(&vmmsi, sizeof(vmmsi));
	vmmsi.addr = addr;
	vmmsi.msg = msg;

	return (ioctl(ctx->fd, VM_LAPIC_MSI, &vmmsi));
}

int
vm_raise_msi(struct vmctx *ctx, uint64_t addr, uint64_t msg,
    int bus __unused, int slot __unused, int func __unused)
{
	return (vm_lapic_msi(ctx, addr, msg));
}

int
vm_apicid2vcpu(struct vmctx *ctx __unused, int apicid)
{
	/*
	 * The apic id associated with the 'vcpu' has the same numerical value
	 * as the 'vcpu' itself.
	 */
	return (apicid);
}

int
vm_ioapic_assert_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_ASSERT_IRQ, &ioapic_irq));
}

int
vm_ioapic_deassert_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_DEASSERT_IRQ, &ioapic_irq));
}

int
vm_ioapic_pulse_irq(struct vmctx *ctx, int irq)
{
	struct vm_ioapic_irq ioapic_irq;

	bzero(&ioapic_irq, sizeof(struct vm_ioapic_irq));
	ioapic_irq.irq = irq;

	return (ioctl(ctx->fd, VM_IOAPIC_PULSE_IRQ, &ioapic_irq));
}

int
vm_ioapic_pincount(struct vmctx *ctx, int *pincount)
{

	return (ioctl(ctx->fd, VM_IOAPIC_PINCOUNT, pincount));
}

int
vm_isa_assert_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_ASSERT_IRQ, &isa_irq));
}

int
vm_isa_deassert_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_DEASSERT_IRQ, &isa_irq));
}

int
vm_isa_pulse_irq(struct vmctx *ctx, int atpic_irq, int ioapic_irq)
{
	struct vm_isa_irq isa_irq;

	bzero(&isa_irq, sizeof(struct vm_isa_irq));
	isa_irq.atpic_irq = atpic_irq;
	isa_irq.ioapic_irq = ioapic_irq;

	return (ioctl(ctx->fd, VM_ISA_PULSE_IRQ, &isa_irq));
}

int
vm_isa_set_irq_trigger(struct vmctx *ctx, int atpic_irq,
    enum vm_intr_trigger trigger)
{
	struct vm_isa_irq_trigger isa_irq_trigger;

	bzero(&isa_irq_trigger, sizeof(struct vm_isa_irq_trigger));
	isa_irq_trigger.atpic_irq = atpic_irq;
	isa_irq_trigger.trigger = trigger;

	return (ioctl(ctx->fd, VM_ISA_SET_IRQ_TRIGGER, &isa_irq_trigger));
}

int
vm_inject_nmi(struct vcpu *vcpu)
{
	struct vm_nmi vmnmi;

	bzero(&vmnmi, sizeof(vmnmi));

	return (vcpu_ioctl(vcpu, VM_INJECT_NMI, &vmnmi));
}

int
vm_inject_exception(struct vcpu *vcpu, int vector, int errcode_valid,
    uint32_t errcode, int restart_instruction)
{
	struct vm_exception exc;

	exc.vector = vector;
	exc.error_code = errcode;
	exc.error_code_valid = errcode_valid;
	exc.restart_instruction = restart_instruction;

	return (vcpu_ioctl(vcpu, VM_INJECT_EXCEPTION, &exc));
}

int
vm_readwrite_kernemu_device(struct vcpu *vcpu, vm_paddr_t gpa,
    bool write, int size, uint64_t *value)
{
	struct vm_readwrite_kernemu_device irp = {
		.access_width = fls(size) - 1,
		.gpa = gpa,
		.value = write ? *value : ~0ul,
	};
	long cmd = (write ? VM_SET_KERNEMU_DEV : VM_GET_KERNEMU_DEV);
	int rc;

	rc = vcpu_ioctl(vcpu, cmd, &irp);
	if (rc == 0 && !write)
		*value = irp.value;
	return (rc);
}

int
vm_get_x2apic_state(struct vcpu *vcpu, enum x2apic_state *state)
{
	int error;
	struct vm_x2apic x2apic;

	bzero(&x2apic, sizeof(x2apic));

	error = vcpu_ioctl(vcpu, VM_GET_X2APIC_STATE, &x2apic);
	*state = x2apic.state;
	return (error);
}

int
vm_set_x2apic_state(struct vcpu *vcpu, enum x2apic_state state)
{
	int error;
	struct vm_x2apic x2apic;

	bzero(&x2apic, sizeof(x2apic));
	x2apic.state = state;

	error = vcpu_ioctl(vcpu, VM_SET_X2APIC_STATE, &x2apic);

	return (error);
}

int
vm_get_hpet_capabilities(struct vmctx *ctx, uint32_t *capabilities)
{
	int error;
	struct vm_hpet_cap cap;

	bzero(&cap, sizeof(struct vm_hpet_cap));
	error = ioctl(ctx->fd, VM_GET_HPET_CAPABILITIES, &cap);
	if (capabilities != NULL)
		*capabilities = cap.capabilities;
	return (error);
}

int
vm_rtc_write(struct vmctx *ctx, int offset, uint8_t value)
{
	struct vm_rtc_data rtcdata;
	int error;

	bzero(&rtcdata, sizeof(struct vm_rtc_data));
	rtcdata.offset = offset;
	rtcdata.value = value;
	error = ioctl(ctx->fd, VM_RTC_WRITE, &rtcdata);
	return (error);
}

int
vm_rtc_read(struct vmctx *ctx, int offset, uint8_t *retval)
{
	struct vm_rtc_data rtcdata;
	int error;

	bzero(&rtcdata, sizeof(struct vm_rtc_data));
	rtcdata.offset = offset;
	error = ioctl(ctx->fd, VM_RTC_READ, &rtcdata);
	if (error == 0)
		*retval = rtcdata.value;
	return (error);
}

int
vm_rtc_settime(struct vmctx *ctx, time_t secs)
{
	struct vm_rtc_time rtctime;
	int error;

	bzero(&rtctime, sizeof(struct vm_rtc_time));
	rtctime.secs = secs;
	error = ioctl(ctx->fd, VM_RTC_SETTIME, &rtctime);
	return (error);
}

int
vm_rtc_gettime(struct vmctx *ctx, time_t *secs)
{
	struct vm_rtc_time rtctime;
	int error;

	bzero(&rtctime, sizeof(struct vm_rtc_time));
	error = ioctl(ctx->fd, VM_RTC_GETTIME, &rtctime);
	if (error == 0)
		*secs = rtctime.secs;
	return (error);
}

/*
 * From Intel Vol 3a:
 * Table 9-1. IA-32 Processor States Following Power-up, Reset or INIT
 */
int
vcpu_reset(struct vcpu *vcpu)
{
	int error;
	uint64_t rflags, rip, cr0, cr4, zero, desc_base, rdx;
	uint32_t desc_access, desc_limit;
	uint16_t sel;

	zero = 0;

	rflags = 0x2;
	error = vm_set_register(vcpu, VM_REG_GUEST_RFLAGS, rflags);
	if (error)
		goto done;

	rip = 0xfff0;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RIP, rip)) != 0)
		goto done;

	/*
	 * According to Intels Software Developer Manual CR0 should be
	 * initialized with CR0_ET | CR0_NW | CR0_CD but that crashes some
	 * guests like Windows.
	 */
	cr0 = CR0_NE;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_CR0, cr0)) != 0)
		goto done;

	if ((error = vm_set_register(vcpu, VM_REG_GUEST_CR2, zero)) != 0)
		goto done;

	if ((error = vm_set_register(vcpu, VM_REG_GUEST_CR3, zero)) != 0)
		goto done;

	cr4 = 0;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_CR4, cr4)) != 0)
		goto done;

	/*
	 * CS: present, r/w, accessed, 16-bit, byte granularity, usable
	 */
	desc_base = 0xffff0000;
	desc_limit = 0xffff;
	desc_access = 0x0093;
	error = vm_set_desc(vcpu, VM_REG_GUEST_CS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0xf000;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_CS, sel)) != 0)
		goto done;

	/*
	 * SS,DS,ES,FS,GS: present, r/w, accessed, 16-bit, byte granularity
	 */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x0093;
	error = vm_set_desc(vcpu, VM_REG_GUEST_SS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vcpu, VM_REG_GUEST_DS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vcpu, VM_REG_GUEST_ES,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vcpu, VM_REG_GUEST_FS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	error = vm_set_desc(vcpu, VM_REG_GUEST_GS,
			    desc_base, desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_SS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_DS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_ES, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_FS, sel)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_GS, sel)) != 0)
		goto done;

	if ((error = vm_set_register(vcpu, VM_REG_GUEST_EFER, zero)) != 0)
		goto done;

	/* General purpose registers */
	rdx = 0xf00;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RAX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RBX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RCX, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RDX, rdx)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RSI, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RDI, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RBP, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_RSP, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R8, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R9, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R10, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R11, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R12, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R13, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R14, zero)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_R15, zero)) != 0)
		goto done;

	/* GDTR, IDTR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0;
	error = vm_set_desc(vcpu, VM_REG_GUEST_GDTR,
			    desc_base, desc_limit, desc_access);
	if (error != 0)
		goto done;

	error = vm_set_desc(vcpu, VM_REG_GUEST_IDTR,
			    desc_base, desc_limit, desc_access);
	if (error != 0)
		goto done;

	/* TR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x0000008b;
	error = vm_set_desc(vcpu, VM_REG_GUEST_TR, 0, 0, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_TR, sel)) != 0)
		goto done;

	/* LDTR */
	desc_base = 0;
	desc_limit = 0xffff;
	desc_access = 0x00000082;
	error = vm_set_desc(vcpu, VM_REG_GUEST_LDTR, desc_base,
			    desc_limit, desc_access);
	if (error)
		goto done;

	sel = 0;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_LDTR, 0)) != 0)
		goto done;

	if ((error = vm_set_register(vcpu, VM_REG_GUEST_DR6,
		 0xffff0ff0)) != 0)
		goto done;
	if ((error = vm_set_register(vcpu, VM_REG_GUEST_DR7, 0x400)) !=
	    0)
		goto done;

	if ((error = vm_set_register(vcpu, VM_REG_GUEST_INTR_SHADOW,
		 zero)) != 0)
		goto done;

	error = 0;
done:
	return (error);
}

void
vm_inject_fault(struct vcpu *vcpu, int vector, int errcode_valid,
    int errcode)
{
	int error, restart_instruction;

	restart_instruction = 1;

	error = vm_inject_exception(vcpu, vector, errcode_valid, errcode,
	    restart_instruction);
	assert(error == 0);
}
