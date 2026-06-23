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
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/bus.h>
#include <sys/pciio.h>
#include <sys/rman.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <dev/pci/pcivar.h>
#include <dev/pci/pcireg.h>

#include <machine/resource.h>
#include <machine/vmm.h>
#include <machine/vmm_dev.h>

#include <dev/vmm/vmm_ktr.h>

#include "vmm_lapic.h"

#include "iommu.h"
#include "ppt.h"
#include "ppt_uio.h"

/* uppt: userspace ppt character device */
#include <sys/conf.h>
#include <sys/event.h>
#include <sys/mutex.h>
#include <sys/selinfo.h>
#include <machine/vm.h>

/* XXX locking */

#define	MAX_MSIMSGS	32

/*
 * If the MSI-X table is located in the middle of a BAR then that MMIO
 * region gets split into two segments - one segment above the MSI-X table
 * and the other segment below the MSI-X table - with a hole in place of
 * the MSI-X table so accesses to it can be trapped and emulated.
 *
 * So, allocate a MMIO segment for each BAR register + 1 additional segment.
 */
#define	MAX_MMIOSEGS	((PCIR_MAX_BAR_0 + 1) + 1)

MALLOC_DEFINE(M_PPTMSIX, "pptmsix", "Passthru MSI-X resources");

/* --- uppt state structs --- */
struct uppt_irq_state {
	struct mtx	lock;
	int		pending;	/* count of pending interrupts */
	struct selinfo	sel;		/* for kqueue EVFILT_READ */
};

struct uppt_cdev_state {
	struct cdev		*cdev;
	struct uppt_irq_state	 irq;
	int			 unit;
};
/* --- end uppt state structs --- */

struct pptintr_arg {				/* pptintr(pptintr_arg) */
	struct pptdev	*pptdev;
	uint64_t	addr;
	uint64_t	msg_data;
};

struct pptseg {
	vm_paddr_t	gpa;
	size_t		len;
	int		wired;
};

struct pptdev {
	device_t	dev;
	struct vm	*vm;			/* owner of this device */
	TAILQ_ENTRY(pptdev)	next;
	struct pptseg mmio[MAX_MMIOSEGS];
	struct {
		int	num_msgs;		/* guest state */

		int	startrid;		/* host state */
		struct resource *res[MAX_MSIMSGS];
		void	*cookie[MAX_MSIMSGS];
		struct pptintr_arg arg[MAX_MSIMSGS];
	} msi;

	struct {
		int num_msgs;
		int startrid;
		int msix_table_rid;
		int msix_pba_rid;
		struct resource *msix_table_res;
		struct resource *msix_pba_res;
		struct resource **res;
		void **cookie;
		struct pptintr_arg *arg;
	} msix;

	struct uppt_cdev_state	*uppt_cdev;	/* /dev/pptN userspace interface */
};

SYSCTL_DECL(_hw_vmm);
SYSCTL_NODE(_hw_vmm, OID_AUTO, ppt, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "bhyve passthru devices");

static int num_pptdevs;
SYSCTL_INT(_hw_vmm_ppt, OID_AUTO, devices, CTLFLAG_RD, &num_pptdevs, 0,
    "number of pci passthru devices");

/* Debug counters for MSI interrupt tracing — safe to read via sysctl */
static u_long ppt_intr_count;
static u_long ppt_intr_last_addr;
static u_long ppt_intr_last_data;
static u_long ppt_intr_novm;
static u_long ppt_msi_setup_count;
static u_long ppt_msi_teardown_count;

SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, intr_count, CTLFLAG_RD,
    &ppt_intr_count, 0, "total pptintr calls");
SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, intr_last_addr, CTLFLAG_RD,
    &ppt_intr_last_addr, 0, "last MSI addr");
SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, intr_last_data, CTLFLAG_RD,
    &ppt_intr_last_data, 0, "last MSI data");
SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, intr_novm, CTLFLAG_RD,
    &ppt_intr_novm, 0, "pptintr with NULL vm");
SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, msi_setup_count, CTLFLAG_RD,
    &ppt_msi_setup_count, 0, "MSI setup calls");
SYSCTL_ULONG(_hw_vmm_ppt, OID_AUTO, msi_teardown_count, CTLFLAG_RD,
    &ppt_msi_teardown_count, 0, "MSI teardown calls");

static TAILQ_HEAD(, pptdev) pptdev_list = TAILQ_HEAD_INITIALIZER(pptdev_list);

/* uppt unit counter: assigned in ppt_attach order */
static int uppt_unit_counter;

/* forward declaration: ppt_pci_reset is defined later in this file */
static void ppt_pci_reset(device_t dev);

/* --- uppt character device implementation --- */

static int
uppt_open(struct cdev *cdev, int flags, int fmt, struct thread *td)
{
	/* always allow open; operations check vm state individually */
	return (0);
}

static int
uppt_ioctl(struct cdev *cdev, u_long cmd, caddr_t data,
    int flags, struct thread *td)
{
	struct pptdev *ppt = cdev->si_drv1;
	device_t dev = ppt->dev;
	int error = 0;

	switch (cmd) {
	case UPPT_GET_BAR_INFO: {
		struct uppt_bar_info *bi = (struct uppt_bar_info *)data;
		int bar = bi->bar;
		uint32_t lo, hi, probe, probe_hi;
		uint64_t base, size;

		if (bar < 0 || bar > 5)
			return (EINVAL);

		lo = pci_read_config(dev, PCIR_BAR(bar), 4);
		if (lo == 0 || lo == 0xFFFFFFFF)
			return (ENOENT);

		bi->is_mmio     = !(lo & PCIM_BAR_IO_SPACE);
		bi->is_64bit    = bi->is_mmio &&
		    ((lo & PCIM_BAR_MEM_TYPE) == PCIM_BAR_MEM_64);
		bi->is_prefetch = bi->is_mmio && !!(lo & PCIM_BAR_MEM_PREFETCH);

		if (bi->is_mmio) {
			base = lo & ~0xFULL;
			hi = 0;
			if (bi->is_64bit && bar < 5) {
				hi = pci_read_config(dev, PCIR_BAR(bar + 1), 4);
				base |= ((uint64_t)hi << 32);
			}
		} else {
			base = lo & ~0x3ULL;
		}
		bi->phys_addr = base;

		/*
		 * BAR size probe: safe only when device is not in a VM
		 * (MEMEN/PORTEN already disabled by ppt_attach).
		 */
		if (ppt->vm == NULL) {
			pci_write_config(dev, PCIR_BAR(bar), 0xFFFFFFFF, 4);
			probe = pci_read_config(dev, PCIR_BAR(bar), 4);
			pci_write_config(dev, PCIR_BAR(bar), lo, 4);

			if (bi->is_64bit && bar < 5) {
				pci_write_config(dev, PCIR_BAR(bar + 1),
				    0xFFFFFFFF, 4);
				probe_hi = pci_read_config(dev,
				    PCIR_BAR(bar + 1), 4);
				pci_write_config(dev, PCIR_BAR(bar + 1),
				    hi, 4);
				size = ~((((uint64_t)probe_hi << 32) |
				    (probe & ~0xFULL))) + 1;
			} else if (bi->is_mmio) {
				size = ~(probe & ~0xFULL) + 1;
			} else {
				size = (~(probe & ~0x3ULL) + 1) & 0xFFFF;
			}
			bi->size = size;
		} else {
			/* device in VM: can't safely probe size */
			bi->size = 0;
		}
		break;
	}

	case UPPT_RESET_DEVICE:
		/* refuse reset while device is assigned to a VM */
		if (ppt->vm != NULL)
			return (EBUSY);
		ppt_pci_reset(dev);
		break;

	default:
		error = ENOTTY;
		break;
	}
	return (error);
}

/*
 * uppt_mmap: map a BAR MMIO region into userspace.
 *
 * The mmap() offset must be the BAR physical address (from UPPT_GET_BAR_INFO).
 * The device must not be assigned to a VM (ppt->vm == NULL).
 *
 * Called once per PAGE_SIZE chunk; offset increments by PAGE_SIZE per call.
 */
static int
uppt_mmap(struct cdev *cdev, vm_ooffset_t offset, vm_paddr_t *paddr,
    int prot, vm_memattr_t *memattr)
{
	struct pptdev *ppt = cdev->si_drv1;
	device_t dev = ppt->dev;
	int bar;
	uint32_t lo;

	if (ppt->vm != NULL)
		return (EBUSY);

	/* verify offset falls within one of the device's MMIO BARs */
	for (bar = 0; bar <= 5; bar++) {
		uint64_t base;
		uint32_t hi;

		lo = pci_read_config(dev, PCIR_BAR(bar), 4);
		if (lo == 0 || lo == 0xFFFFFFFF || (lo & PCIM_BAR_IO_SPACE))
			continue;

		base = lo & ~0xFULL;
		if ((lo & PCIM_BAR_MEM_TYPE) == PCIM_BAR_MEM_64 && bar < 5) {
			hi = pci_read_config(dev, PCIR_BAR(bar + 1), 4);
			base |= ((uint64_t)hi << 32);
		}
		if (base == 0)
			continue;

		if (offset >= base) {
			*paddr   = offset;
			*memattr = VM_MEMATTR_UNCACHEABLE;
			return (0);
		}
	}
	return (EINVAL);
}

static int
uppt_irq_event(struct knote *kn, long hint)
{
	struct uppt_cdev_state *cs = kn->kn_hook;
	return (cs->irq.pending > 0);
}

static void
uppt_irq_detach(struct knote *kn)
{
	struct uppt_cdev_state *cs = kn->kn_hook;
	knlist_remove(&cs->irq.sel.si_note, kn, 0);
}

static struct filterops uppt_irq_filtops = {
	.f_isfd   = 1,
	.f_attach = NULL,
	.f_detach = uppt_irq_detach,
	.f_event  = uppt_irq_event,
};

static int
uppt_kqfilter(struct cdev *cdev, struct knote *kn)
{
	struct pptdev *ppt = cdev->si_drv1;
	struct uppt_cdev_state *cs = ppt->uppt_cdev;

	if (cs == NULL)
		return (ENXIO);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop  = &uppt_irq_filtops;
		kn->kn_hook = cs;
		knlist_add(&cs->irq.sel.si_note, kn, 0);
		return (0);
	default:
		return (EINVAL);
	}
}

static struct cdevsw uppt_cdevsw = {
	.d_version  = D_VERSION,
	.d_name     = "ppt",
	.d_open     = uppt_open,
	.d_ioctl    = uppt_ioctl,
	.d_mmap     = uppt_mmap,
	.d_kqfilter = uppt_kqfilter,
};

/* --- end uppt character device implementation --- */

static int
ppt_probe(device_t dev)
{
	int bus, slot, func;
	struct pci_devinfo *dinfo;

	dinfo = (struct pci_devinfo *)device_get_ivars(dev);

	bus = pci_get_bus(dev);
	slot = pci_get_slot(dev);
	func = pci_get_function(dev);

	/*
	 * To qualify as a pci passthrough device a device must:
	 * - be allowed by administrator to be used in this role
	 * - be an endpoint device
	 */
	if ((dinfo->cfg.hdrtype & PCIM_HDRTYPE) != PCIM_HDRTYPE_NORMAL)
		return (ENXIO);
	else if (vmm_is_pptdev(bus, slot, func))
		return (0);
	else
		/*
		 * Returning BUS_PROBE_NOWILDCARD here matches devices that the
		 * SR-IOV infrastructure specified as "ppt" passthrough devices.
		 * All normal devices that did not have "ppt" specified as their
		 * driver will not be matched by this.
		 */
		return (BUS_PROBE_NOWILDCARD);
}

static int
ppt_attach(device_t dev)
{
	struct pptdev *ppt;
	uint16_t cmd, cmd1;
	int error;

	ppt = device_get_softc(dev);

	cmd1 = cmd = pci_read_config(dev, PCIR_COMMAND, 2);
	cmd &= ~(PCIM_CMD_PORTEN | PCIM_CMD_MEMEN | PCIM_CMD_BUSMASTEREN);
	pci_write_config(dev, PCIR_COMMAND, cmd, 2);
	error = iommu_remove_device(iommu_host_domain(), dev, pci_get_rid(dev));
	if (error != 0) {
		pci_write_config(dev, PCIR_COMMAND, cmd1, 2);
		return (error);
	}
	num_pptdevs++;
	TAILQ_INSERT_TAIL(&pptdev_list, ppt, next);
	ppt->dev = dev;

	/* uppt: create /dev/pptN character device */
	{
		struct uppt_cdev_state *cs;
		struct make_dev_args mda;

		cs = malloc(sizeof(*cs), M_DEVBUF, M_WAITOK | M_ZERO);
		cs->unit = uppt_unit_counter++;
		mtx_init(&cs->irq.lock, "uppt_irq", NULL, MTX_DEF);
		knlist_init_mtx(&cs->irq.sel.si_note, &cs->irq.lock);

		make_dev_args_init(&mda);
		mda.mda_devsw   = &uppt_cdevsw;
		mda.mda_uid     = UID_ROOT;
		mda.mda_gid     = GID_WHEEL;
		mda.mda_mode    = 0600;
		mda.mda_si_drv1 = ppt;
		make_dev_s(&mda, &cs->cdev, "ppt%d", cs->unit);

		ppt->uppt_cdev = cs;
	}

	if (bootverbose)
		device_printf(dev, "attached\n");

	return (0);
}

static int
ppt_detach(device_t dev)
{
	struct pptdev *ppt;
	int error;

	ppt = device_get_softc(dev);

	if (ppt->vm != NULL)
		return (EBUSY);
	if (iommu_host_domain() != NULL) {
		error = iommu_add_device(iommu_host_domain(), dev,
		    pci_get_rid(dev));
	} else {
		error = 0;
	}
	if (error != 0)
		return (error);
	num_pptdevs--;
	TAILQ_REMOVE(&pptdev_list, ppt, next);

	/* uppt: destroy /dev/pptN */
	if (ppt->uppt_cdev != NULL) {
		struct uppt_cdev_state *cs = ppt->uppt_cdev;
		destroy_dev(cs->cdev);
		knlist_destroy(&cs->irq.sel.si_note);
		mtx_destroy(&cs->irq.lock);
		free(cs, M_DEVBUF);
		ppt->uppt_cdev = NULL;
	}

	return (0);
}

static device_method_t ppt_methods[] = {
	/* Device interface */
	DEVMETHOD(device_probe,		ppt_probe),
	DEVMETHOD(device_attach,	ppt_attach),
	DEVMETHOD(device_detach,	ppt_detach),
	{0, 0}
};

DEFINE_CLASS_0(ppt, ppt_driver, ppt_methods, sizeof(struct pptdev));
DRIVER_MODULE(ppt, pci, ppt_driver, NULL, NULL);

static int
ppt_find(struct vm *vm, int bus, int slot, int func, struct pptdev **pptp)
{
	device_t dev;
	struct pptdev *ppt;
	int b, s, f;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		dev = ppt->dev;
		b = pci_get_bus(dev);
		s = pci_get_slot(dev);
		f = pci_get_function(dev);
		if (bus == b && slot == s && func == f)
			break;
	}

	if (ppt == NULL)
		return (ENOENT);
	if (ppt->vm != vm)		/* Make sure we own this device */
		return (EBUSY);
	*pptp = ppt;
	return (0);
}

static void
ppt_unmap_all_mmio(struct vm *vm, struct pptdev *ppt)
{
	int i;
	struct pptseg *seg;

	for (i = 0; i < MAX_MMIOSEGS; i++) {
		seg = &ppt->mmio[i];
		if (seg->len == 0)
			continue;
		(void)vm_unmap_mmio(vm, seg->gpa, seg->len);
		bzero(seg, sizeof(struct pptseg));
	}
}

static void
ppt_teardown_msi(struct pptdev *ppt)
{
	int i, rid;
	void *cookie;
	struct resource *res;

	if (ppt->msi.num_msgs == 0)
		return;

	atomic_add_long(&ppt_msi_teardown_count, 1);

	for (i = 0; i < ppt->msi.num_msgs; i++) {
		rid = ppt->msi.startrid + i;
		res = ppt->msi.res[i];
		cookie = ppt->msi.cookie[i];

		if (cookie != NULL)
			bus_teardown_intr(ppt->dev, res, cookie);

		if (res != NULL)
			bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);

		ppt->msi.res[i] = NULL;
		ppt->msi.cookie[i] = NULL;
	}

	if (ppt->msi.startrid == 1)
		pci_release_msi(ppt->dev);

	ppt->msi.num_msgs = 0;
}

static void
ppt_teardown_msix_intr(struct pptdev *ppt, int idx)
{
	int rid;
	struct resource *res;
	void *cookie;

	rid = ppt->msix.startrid + idx;
	res = ppt->msix.res[idx];
	cookie = ppt->msix.cookie[idx];

	if (cookie != NULL)
		bus_teardown_intr(ppt->dev, res, cookie);

	if (res != NULL)
		bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, res);

	ppt->msix.res[idx] = NULL;
	ppt->msix.cookie[idx] = NULL;
}

static void
ppt_teardown_msix(struct pptdev *ppt)
{
	int i;

	if (ppt->msix.num_msgs == 0)
		return;

	for (i = 0; i < ppt->msix.num_msgs; i++)
		ppt_teardown_msix_intr(ppt, i);

	free(ppt->msix.res, M_PPTMSIX);
	free(ppt->msix.cookie, M_PPTMSIX);
	free(ppt->msix.arg, M_PPTMSIX);

	pci_release_msi(ppt->dev);

	if (ppt->msix.msix_table_res) {
		bus_release_resource(ppt->dev, SYS_RES_MEMORY,
				     ppt->msix.msix_table_rid,
				     ppt->msix.msix_table_res);
		ppt->msix.msix_table_res = NULL;
		ppt->msix.msix_table_rid = 0;
	}
	if (ppt->msix.msix_pba_res) {
		bus_release_resource(ppt->dev, SYS_RES_MEMORY,
				     ppt->msix.msix_pba_rid,
				     ppt->msix.msix_pba_res);
		ppt->msix.msix_pba_res = NULL;
		ppt->msix.msix_pba_rid = 0;
	}

	ppt->msix.num_msgs = 0;
}

int
ppt_avail_devices(void)
{

	return (num_pptdevs);
}

int
ppt_assigned_devices(struct vm *vm)
{
	struct pptdev *ppt;
	int num;

	num = 0;
	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm == vm)
			num++;
	}
	return (num);
}

bool
ppt_is_mmio(struct vm *vm, vm_paddr_t gpa)
{
	int i;
	struct pptdev *ppt;
	struct pptseg *seg;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm != vm)
			continue;

		for (i = 0; i < MAX_MMIOSEGS; i++) {
			seg = &ppt->mmio[i];
			if (seg->len == 0)
				continue;
			if (gpa >= seg->gpa && gpa < seg->gpa + seg->len)
				return (true);
		}
	}

	return (false);
}

static void
ppt_pci_reset(device_t dev)
{

	if (pcie_flr(dev,
	     max(pcie_get_max_completion_timeout(dev) / 1000, 10), true))
		return;

	pci_power_reset(dev);
}

/*
 * ppt_sbr_device - Secondary Bus Reset for a passthrough device.
 *
 * Must be called when the device is NOT assigned to any VM (ppt->vm == NULL).
 * Safe sequence: disable DMA → mask bridge AER/SERR → assert SBR →
 * deassert SBR → wait for link training → restore bridge → re-save state.
 *
 * This is the kernel equivalent of what Linux VFIO does in pci_reset_bus().
 * Userspace SBR (via pciconf) crashes the host because AER is unmasked.
 */
int
ppt_sbr_device(int bus, int slot, int func)
{
	struct pptdev *ppt;
	device_t dev, pcibus, bridge;
	uint16_t dev_cmd, bridge_cmd, bcr;
	uint32_t aer_uc_mask;
	int aer_cap, error;

	/* Device must be unowned */
	error = ppt_find(NULL, bus, slot, func, &ppt);
	if (error != 0)
		return (error);

	dev = ppt->dev;

	/* Step 1: stop DMA and SERR forwarding from the device */
	dev_cmd = pci_read_config(dev, PCIR_COMMAND, 2);
	pci_write_config(dev, PCIR_COMMAND,
	    dev_cmd & ~(PCIM_CMD_BUSMASTEREN | PCIM_CMD_SERRESPEN), 2);

	/*
	 * Step 2: get the upstream bridge.
	 * device_get_parent(endpoint) = PCI bus device
	 * device_get_parent(PCI bus) = bridge / root port
	 */
	pcibus = device_get_parent(dev);
	bridge = device_get_parent(pcibus);

	/* Step 3: save bridge SERR enable, then clear it to suppress NMI */
	bridge_cmd = pci_read_config(bridge, PCIR_COMMAND, 2);
	pci_write_config(bridge, PCIR_COMMAND,
	    bridge_cmd & ~PCIM_CMD_SERRESPEN, 2);

	/* Step 4: mask AER Uncorrectable errors on bridge (prevents AERI NMI) */
	aer_cap = pci_find_extcap(bridge, PCIZ_AER, NULL);
	if (aer_cap != 0) {
		aer_uc_mask = pci_read_config(bridge,
		    aer_cap + PCIR_AER_UC_MASK, 4);
		pci_write_config(bridge, aer_cap + PCIR_AER_UC_MASK,
		    0xFFFFFFFF, 4);
	}

	/* Step 5: read current Bridge Control Register */
	bcr = pci_read_config(bridge, PCIR_BRIDGECTL_1, 2);

	/* Step 6: assert Secondary Bus Reset (bit 6) */
	pci_write_config(bridge, PCIR_BRIDGECTL_1,
	    bcr | PCIB_BCR_SECBUS_RESET, 2);

	/* Step 7: hold for 500ms (PCIe spec min 1ms, practical min ~100ms) */
	pause("ppt_sbr", hz / 2);

	/* Step 8: deassert SBR */
	pci_write_config(bridge, PCIR_BRIDGECTL_1, bcr, 2);

	/* Step 9: wait for link re-training (Trhfa + margin) */
	pause("ppt_lnk", hz / 4);

	/* Step 10: restore bridge AER mask and SERR */
	if (aer_cap != 0) {
		pci_write_config(bridge, aer_cap + PCIR_AER_UC_MASK,
		    aer_uc_mask, 4);
	}
	pci_write_config(bridge, PCIR_COMMAND, bridge_cmd, 2);

	/* Step 11: restore device command register */
	pci_write_config(dev, PCIR_COMMAND, dev_cmd, 2);

	/* Step 12: save fresh post-reset config state */
	pci_save_state(dev);

	return (0);
}



static uint16_t
ppt_bar_enables(struct pptdev *ppt)
{
	struct pci_map *pm;
	uint16_t cmd;

	cmd = 0;
	for (pm = pci_first_bar(ppt->dev); pm != NULL; pm = pci_next_bar(pm)) {
		if (PCI_BAR_IO(pm->pm_value))
			cmd |= PCIM_CMD_PORTEN;
		if (PCI_BAR_MEM(pm->pm_value))
			cmd |= PCIM_CMD_MEMEN;
	}
	return (cmd);
}

int
ppt_assign_device(struct vm *vm, int bus, int slot, int func)
{
	struct pptdev *ppt;
	int error;
	uint16_t cmd;

	/* Passing NULL requires the device to be unowned. */
	error = ppt_find(NULL, bus, slot, func, &ppt);
	if (error)
		return (error);

	pci_save_state(ppt->dev);
	ppt_pci_reset(ppt->dev);
	pci_restore_state(ppt->dev);
	error = iommu_add_device(vm_iommu_domain(vm), ppt->dev,
	    pci_get_rid(ppt->dev));
	if (error != 0)
		return (error);
	ppt->vm = vm;
	cmd = pci_read_config(ppt->dev, PCIR_COMMAND, 2);
	cmd |= PCIM_CMD_BUSMASTEREN | ppt_bar_enables(ppt);
	pci_write_config(ppt->dev, PCIR_COMMAND, cmd, 2);
	return (0);
}

int
ppt_unassign_device(struct vm *vm, int bus, int slot, int func)
{
	struct pptdev *ppt;
	int error;
	uint16_t cmd;

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	cmd = pci_read_config(ppt->dev, PCIR_COMMAND, 2);
	cmd &= ~(PCIM_CMD_PORTEN | PCIM_CMD_MEMEN | PCIM_CMD_BUSMASTEREN);
	pci_write_config(ppt->dev, PCIR_COMMAND, cmd, 2);
	pci_save_state(ppt->dev);
	ppt_pci_reset(ppt->dev);
	pci_restore_state(ppt->dev);
	ppt_unmap_all_mmio(vm, ppt);
	ppt_teardown_msi(ppt);
	ppt_teardown_msix(ppt);
	error = iommu_remove_device(vm_iommu_domain(vm), ppt->dev,
	    pci_get_rid(ppt->dev));
	ppt->vm = NULL;
	return (error);
}

int
ppt_unassign_all(struct vm *vm)
{
	struct pptdev *ppt;
	int bus, slot, func;
	device_t dev;

	TAILQ_FOREACH(ppt, &pptdev_list, next) {
		if (ppt->vm == vm) {
			dev = ppt->dev;
			bus = pci_get_bus(dev);
			slot = pci_get_slot(dev);
			func = pci_get_function(dev);
			vm_unassign_pptdev(vm, bus, slot, func);
		}
	}

	return (0);
}

static bool
ppt_valid_bar_mapping(struct pptdev *ppt, vm_paddr_t hpa, size_t len)
{
	struct pci_map *pm;
	pci_addr_t base, size;

	for (pm = pci_first_bar(ppt->dev); pm != NULL; pm = pci_next_bar(pm)) {
		if (!PCI_BAR_MEM(pm->pm_value))
			continue;
		base = pm->pm_value & PCIM_BAR_MEM_BASE;
		size = (pci_addr_t)1 << pm->pm_size;
		if (hpa >= base && hpa + len <= base + size)
			return (true);
	}
	return (false);
}

int
ppt_map_mmio(struct vm *vm, int bus, int slot, int func,
	     vm_paddr_t gpa, size_t len, vm_paddr_t hpa)
{
	int i, error;
	struct pptseg *seg;
	struct pptdev *ppt;

	if (len % PAGE_SIZE != 0 || len == 0 || gpa % PAGE_SIZE != 0 ||
	    hpa % PAGE_SIZE != 0 || gpa + len < gpa || hpa + len < hpa)
		return (EINVAL);

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	if (!ppt_valid_bar_mapping(ppt, hpa, len))
		return (EINVAL);

	for (i = 0; i < MAX_MMIOSEGS; i++) {
		seg = &ppt->mmio[i];
		if (seg->len == 0) {
			error = vm_map_mmio(vm, gpa, len, hpa);
			if (error == 0) {
				seg->gpa = gpa;
				seg->len = len;
			}
			return (error);
		}
	}
	return (ENOSPC);
}

int
ppt_unmap_mmio(struct vm *vm, int bus, int slot, int func,
	       vm_paddr_t gpa, size_t len)
{
	int i, error;
	struct pptseg *seg;
	struct pptdev *ppt;

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	for (i = 0; i < MAX_MMIOSEGS; i++) {
		seg = &ppt->mmio[i];
		if (seg->gpa == gpa && seg->len == len) {
			error = vm_unmap_mmio(vm, seg->gpa, seg->len);
			if (error == 0) {
				seg->gpa = 0;
				seg->len = 0;
			}
			return (error);
		}
	}
	return (ENOENT);
}

static int
pptintr(void *arg)
{
	struct pptdev *ppt;
	struct pptintr_arg *pptarg;

	pptarg = arg;
	ppt = pptarg->pptdev;

	atomic_add_long(&ppt_intr_count, 1);
	ppt_intr_last_addr = pptarg->addr;
	ppt_intr_last_data = pptarg->msg_data;

	if (ppt->vm != NULL)
		lapic_intr_msi(ppt->vm, pptarg->addr, pptarg->msg_data);
	else {
		atomic_add_long(&ppt_intr_novm, 1);
	}

	/*
	 * For legacy interrupts give other filters a chance in case
	 * the interrupt was not generated by the passthrough device.
	 */
	if (ppt->msi.startrid == 0)
		return (FILTER_STRAY);
	else
		return (FILTER_HANDLED);
}

int
ppt_setup_msi(struct vm *vm, int bus, int slot, int func,
	      uint64_t addr, uint64_t msg, int numvec)
{
	int i, rid, flags;
	int msi_count, startrid, error, tmp;
	struct pptdev *ppt;

	if (numvec < 0 || numvec > MAX_MSIMSGS)
		return (EINVAL);

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	/* Reject attempts to enable MSI while MSI-X is active. */
	if (ppt->msix.num_msgs != 0 && numvec != 0)
		return (EBUSY);

	/* Free any allocated resources */
	ppt_teardown_msi(ppt);

	if (numvec == 0)		/* nothing more to do */
		return (0);

	flags = RF_ACTIVE;
	msi_count = pci_msi_count(ppt->dev);
	printf("ppt: MSI full-setup %d/%d/%d msi_count=%d numvec=%d addr=0x%lx data=0x%lx\n",
	    bus, slot, func, msi_count, numvec, (unsigned long)addr, (unsigned long)msg);
	if (msi_count == 0) {
		startrid = 0;		/* legacy interrupt */
		msi_count = 1;
		flags |= RF_SHAREABLE;
		printf("ppt: WARNING %d/%d/%d msi_count=0, falling back to LEGACY IRQ!\n",
		    bus, slot, func);
	} else
		startrid = 1;		/* MSI */

	/*
	 * The device must be capable of supporting the number of vectors
	 * the guest wants to allocate.
	 */
	if (numvec > msi_count)
		return (EINVAL);

	/*
	 * Make sure that we can allocate all the MSI vectors that are needed
	 * by the guest.
	 */
	if (startrid == 1) {
		tmp = numvec;
		error = pci_alloc_msi(ppt->dev, &tmp);
		printf("ppt: pci_alloc_msi %d/%d/%d error=%d tmp=%d\n",
		    bus, slot, func, error, tmp);
		if (error)
			return (error);
		else if (tmp != numvec) {
			pci_release_msi(ppt->dev);
			return (ENOSPC);
		} else {
			/* success */
		}
	}

	ppt->msi.startrid = startrid;

	/*
	 * Allocate the irq resource and attach it to the interrupt handler.
	 */
	for (i = 0; i < numvec; i++) {
		ppt->msi.num_msgs = i + 1;
		ppt->msi.cookie[i] = NULL;

		rid = startrid + i;
		ppt->msi.res[i] = bus_alloc_resource_any(ppt->dev, SYS_RES_IRQ,
							 &rid, flags);
		if (ppt->msi.res[i] == NULL)
			break;

		ppt->msi.arg[i].pptdev = ppt;
		ppt->msi.arg[i].addr = addr;
		ppt->msi.arg[i].msg_data = msg + i;

		error = bus_setup_intr(ppt->dev, ppt->msi.res[i],
				       INTR_TYPE_NET | INTR_MPSAFE,
				       pptintr, NULL, &ppt->msi.arg[i],
				       &ppt->msi.cookie[i]);
		if (error != 0)
			break;
	}

	if (i < numvec) {
		ppt_teardown_msi(ppt);
		return (ENXIO);
	}

	atomic_add_long(&ppt_msi_setup_count, 1);
	return (0);
}

int
ppt_setup_msix(struct vm *vm, int bus, int slot, int func,
	       int idx, uint64_t addr, uint64_t msg, uint32_t vector_control)
{
	struct pptdev *ppt;
	struct pci_devinfo *dinfo;
	int numvec, alloced, rid, error;
	size_t res_size, cookie_size, arg_size;

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	/* Reject attempts to enable MSI-X while MSI is active. */
	if (ppt->msi.num_msgs != 0)
		return (EBUSY);

	dinfo = device_get_ivars(ppt->dev);
	if (!dinfo)
		return (ENXIO);

	/*
	 * First-time configuration:
	 * 	Allocate the MSI-X table
	 *	Allocate the IRQ resources
	 *	Set up some variables in ppt->msix
	 */
	if (ppt->msix.num_msgs == 0) {
		numvec = pci_msix_count(ppt->dev);
		printf("ppt: setup_msix bus=%d slot=%d func=%d "
		    "msix_location=0x%x msix_count=%d\n",
		    bus, slot, func,
		    dinfo->cfg.msix.msix_location, numvec);
		/*
		 * PPT_MSIX_ORPHAN_FIX: Some NVIDIA GPUs (TU102/RTX 2080 Ti)
		 * have the MSI-X cap at 0xC8 disconnected from the standard
		 * PCI cap chain. The kernel PCI enumeration misses it, leaving
		 * msix_location=0 and pci_msix_count()=0. Fix up cfg.msix by
		 * scanning for cap ID 0x11 at known offsets.
		 */
		if (numvec <= 0 && dinfo->cfg.msix.msix_location == 0) {
			uint8_t scan;
			for (scan = 0x40; scan <= 0xF0; scan += 4) {
				uint8_t cap_id = pci_read_config(ppt->dev,
				    scan, 1);
				if (cap_id == PCIY_MSIX) {
					uint16_t ctrl = pci_read_config(
					    ppt->dev, scan + 2, 2);
					uint32_t tbl = pci_read_config(
					    ppt->dev, scan + 4, 4);
					uint32_t pba = pci_read_config(
					    ppt->dev, scan + 8, 4);
					dinfo->cfg.msix.msix_location = scan;
					dinfo->cfg.msix.msix_ctrl = ctrl;
					/* pci.c stores msix_table_bar as
					 * PCIR_BAR(BIR), not raw BIR */
					dinfo->cfg.msix.msix_table_bar =
					    PCIR_BAR(tbl & PCIM_MSIX_BIR_MASK);
					dinfo->cfg.msix.msix_table_offset =
					    tbl & ~PCIM_MSIX_BIR_MASK;
					dinfo->cfg.msix.msix_pba_bar =
					    PCIR_BAR(pba & PCIM_MSIX_BIR_MASK);
					dinfo->cfg.msix.msix_pba_offset =
					    pba & ~PCIM_MSIX_BIR_MASK;
					printf("ppt: fixed orphan MSI-X cap "
					    "at 0x%02x: %d vectors\n",
					    scan,
					    PCI_MSIX_MSGNUM(ctrl));
					numvec = pci_msix_count(ppt->dev);
					break;
				}
			}
		}
		if (numvec <= 0)
			return (EINVAL);

		ppt->msix.startrid = 1;
		ppt->msix.num_msgs = numvec;

		res_size = numvec * sizeof(ppt->msix.res[0]);
		cookie_size = numvec * sizeof(ppt->msix.cookie[0]);
		arg_size = numvec * sizeof(ppt->msix.arg[0]);

		ppt->msix.res = malloc(res_size, M_PPTMSIX, M_WAITOK | M_ZERO);
		ppt->msix.cookie = malloc(cookie_size, M_PPTMSIX,
					  M_WAITOK | M_ZERO);
		ppt->msix.arg = malloc(arg_size, M_PPTMSIX, M_WAITOK | M_ZERO);

		rid = dinfo->cfg.msix.msix_table_bar;
		printf("ppt: msix_table_bar=0x%x rid=0x%x\n",
		    dinfo->cfg.msix.msix_table_bar, rid);
		ppt->msix.msix_table_res = bus_alloc_resource_any(ppt->dev,
					       SYS_RES_MEMORY, &rid, RF_ACTIVE);

		if (ppt->msix.msix_table_res == NULL) {
			printf("ppt: bus_alloc_resource msix_table FAILED\n");
			ppt_teardown_msix(ppt);
			return (ENOSPC);
		}
		printf("ppt: bus_alloc_resource msix_table OK rid=0x%x\n", rid);
		ppt->msix.msix_table_rid = rid;

		if (dinfo->cfg.msix.msix_table_bar !=
		    dinfo->cfg.msix.msix_pba_bar) {
			rid = dinfo->cfg.msix.msix_pba_bar;
			ppt->msix.msix_pba_res = bus_alloc_resource_any(
			    ppt->dev, SYS_RES_MEMORY, &rid, RF_ACTIVE);

			if (ppt->msix.msix_pba_res == NULL) {
				printf("ppt: bus_alloc_resource msix_pba FAILED\n");
				ppt_teardown_msix(ppt);
				return (ENOSPC);
			}
		}

		alloced = numvec;
		error = pci_alloc_msix(ppt->dev, &alloced);
		printf("ppt: pci_alloc_msix error=%d alloced=%d numvec=%d\n",
		    error, alloced, numvec);
		if (error || alloced != numvec) {
			ppt_teardown_msix(ppt);
			return (error == 0 ? ENOSPC: error);
		}
	}

	if (idx >= ppt->msix.num_msgs)
		return (EINVAL);

	if ((vector_control & PCIM_MSIX_VCTRL_MASK) == 0) {
		/* Tear down the IRQ if it's already set up */
		ppt_teardown_msix_intr(ppt, idx);

		/* Allocate the IRQ resource */
		ppt->msix.cookie[idx] = NULL;
		rid = ppt->msix.startrid + idx;
		ppt->msix.res[idx] = bus_alloc_resource_any(ppt->dev, SYS_RES_IRQ,
							    &rid, RF_ACTIVE);
		if (ppt->msix.res[idx] == NULL) {
			printf("ppt: bus_alloc_resource IRQ idx=%d rid=%d FAILED\n",
			    idx, rid);
			return (ENXIO);
		}
		printf("ppt: bus_alloc_resource IRQ idx=%d rid=%d OK\n", idx, rid);

		ppt->msix.arg[idx].pptdev = ppt;
		ppt->msix.arg[idx].addr = addr;
		ppt->msix.arg[idx].msg_data = msg;

		/* Setup the MSI-X interrupt */
		error = bus_setup_intr(ppt->dev, ppt->msix.res[idx],
				       INTR_TYPE_NET | INTR_MPSAFE,
				       pptintr, NULL, &ppt->msix.arg[idx],
				       &ppt->msix.cookie[idx]);

		if (error != 0) {
			printf("ppt: bus_setup_intr idx=%d error=%d FAILED\n",
			    idx, error);
			bus_release_resource(ppt->dev, SYS_RES_IRQ, rid, ppt->msix.res[idx]);
			ppt->msix.cookie[idx] = NULL;
			ppt->msix.res[idx] = NULL;
			return (ENXIO);
		}
		printf("ppt: bus_setup_intr idx=%d OK addr=0x%lx data=0x%x\n",
		    idx, addr, (uint32_t)msg);
	} else {
		/* Masked, tear it down if it's already been set up */
		ppt_teardown_msix_intr(ppt, idx);
	}

	return (0);
}

int
ppt_disable_msix(struct vm *vm, int bus, int slot, int func)
{
	struct pptdev *ppt;
	int error;

	error = ppt_find(vm, bus, slot, func, &ppt);
	if (error)
		return (error);

	ppt_teardown_msix(ppt);
	return (0);
}
