/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Shared memory buffers of the WSLg virtio-fs device ("wslg" tag), for the
 * RDP backend of Weston running in a FreeBSD WSL guest.
 */

#ifndef _DEV_VIRTIO_FS_WSLG_SHM_H_
#define _DEV_VIRTIO_FS_WSLG_SHM_H_

#include <sys/types.h>
#include <sys/ioccom.h>

#define	WSLGSHM_DEVICE		"/dev/wslgshm"
#define	WSLGSHM_NAME_MAX	64

/*
 * Create the file "name" in the shared directory, give it "size" bytes and map
 * it into the shared memory window.  One buffer per open descriptor: map it
 * with mmap(fd, size, offset 0); closing the descriptor unmaps and releases it.
 */
struct wslgshm_create {
	char		name[WSLGSHM_NAME_MAX];	/* in, NUL terminated */
	uint64_t	size;			/* in */
	uint64_t	window_offset;		/* out, for diagnostics */
};

#define	WSLGSHM_CREATE		_IOWR('W', 1, struct wslgshm_create)

#endif /* _DEV_VIRTIO_FS_WSLG_SHM_H_ */
