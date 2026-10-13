/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * uppt — userspace ppt interface for FreeBSD
 *
 * Exposes /dev/pptN character devices so any userspace process can:
 *  - query BAR layout (UPPT_GET_BAR_INFO)
 *  - mmap BAR MMIO regions directly (d_mmap, offset = BAR physical address)
 *  - trigger FLR/power reset (UPPT_RESET_DEVICE)
 *  - receive IRQ notifications via kqueue EVFILT_READ
 *
 * The device must NOT be assigned to a VM (ppt->vm == NULL) for mmap/reset.
 * BAR info queries are allowed even while assigned.
 */

#ifndef _VMM_IO_PPT_UIO_H_
#define	_VMM_IO_PPT_UIO_H_

#include <sys/types.h>
#include <sys/ioccom.h>

/* Information about a single PCI BAR */
struct uppt_bar_info {
	int		bar;		/* in:  BAR index (0-5) */
	uint64_t	phys_addr;	/* out: physical base address */
	uint64_t	size;		/* out: size in bytes */
	int		is_mmio;	/* out: 1=MMIO, 0=IO port */
	int		is_64bit;	/* out: 1=64-bit BAR */
	int		is_prefetch;	/* out: 1=prefetchable */
};

/* ioctl definitions */
#define UPPT_GET_BAR_INFO	_IOWR('P', 0x10, struct uppt_bar_info)
#define UPPT_RESET_DEVICE	_IO  ('P', 0x14)

/*
 * mmap encoding: use BAR physical address as the mmap() offset.
 *
 * Userspace workflow:
 *   ioctl(fd, UPPT_GET_BAR_INFO, &bi);   // get phys_addr and size for BARn
 *   ptr = mmap(NULL, bi.size, PROT_READ|PROT_WRITE,
 *              MAP_SHARED, fd, bi.phys_addr);
 */

#endif /* _VMM_IO_PPT_UIO_H_ */
