/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Claude (Anthropic), for the FreeBSD-as-WSL2-kernel work.
 *
 * Shared memory buffers of the WSLg virtio-fs device ("wslg" tag).
 *
 * WSLg's RDP backend (Weston) puts every window surface in a file of the
 * "wslg" virtio-fs share, maps it with DAX and tells the Windows RDP client
 * the file name; the client opens the same file on the host side, so pixels
 * are never copied.  Linux does it with a full virtiofs mount (dax=always).
 * This is the narrow FreeBSD equivalent: a minimal in-kernel FUSE client on
 * the virtio-fs transport (dev/virtio/fs) that only creates a file, sizes
 * it, maps it into the device's shared memory window (FUSE_SETUPMAPPING) and
 * hands that window range to user space through /dev/wslgshm:
 *
 *	fd = open("/dev/wslgshm", O_RDWR);
 *	ioctl(fd, WSLGSHM_CREATE, &{ name, size });
 *	p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
 *	...
 *	munmap(p, size); close(fd);	-> REMOVEMAPPING, RELEASE, FORGET
 *
 * As on Linux the file is not unlinked: the client may still have it open.
 * The window is mapped write-back, like Linux's memremap() of the region.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/rwlock.h>
#include <sys/sglist.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/vmem.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>

#include <fs/fuse/fuse_kernel.h>

#include <dev/virtio/fs/virtio_fs.h>
#include <dev/virtio/fs/wslg_shm.h>

#define	WSHM_TAG		"wslg"
#define	WSHM_ROOT_ID		1		/* FUSE_ROOT_ID */
#define	WSHM_TIMEOUT		(10 * hz)

/* Open flags and file type as the (Linux) virtio-fs server expects them. */
#define	LINUX_O_RDWR		0x0002
#define	LINUX_O_CREAT		0x0040
#define	LINUX_O_EXCL		0x0080
#define	LINUX_S_IFREG		0100000

static MALLOC_DEFINE(M_WSHM, "wslgshm", "WSLg shared memory");

/* The single connection to the "wslg" share. */
static struct {
	struct sx	lock;		/* serializes setup and teardown */
	vtfs_instance	vtfs;
	bool		ready;
	bool		gone;
	vm_paddr_t	window;		/* physical address of the DAX window */
	uint64_t	window_len;
	uint64_t	align;		/* map_alignment, bytes */
	vmem_t		*arena;		/* free ranges of the window */
	uint64_t	unique;
	struct mtx	req_mtx;	/* request completion */
} wshm;

/* What the share holds right now, and what went wrong (under wshm.lock). */
static SYSCTL_NODE(_hw, OID_AUTO, wslgshm, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "WSLg shared memory");
static uint64_t wshm_created, wshm_destroyed, wshm_inuse, wshm_errors;
SYSCTL_U64(_hw_wslgshm, OID_AUTO, created, CTLFLAG_RD, &wshm_created, 0,
    "Buffers created and mapped");
SYSCTL_U64(_hw_wslgshm, OID_AUTO, destroyed, CTLFLAG_RD, &wshm_destroyed, 0,
    "Buffers unmapped");
SYSCTL_U64(_hw_wslgshm, OID_AUTO, inuse, CTLFLAG_RD, &wshm_inuse, 0,
    "Bytes of the window in use");
SYSCTL_U64(_hw_wslgshm, OID_AUTO, errors, CTLFLAG_RD, &wshm_errors, 0,
    "Failed requests to the virtio-fs server");

#define	WSHM_IN_MAX		128	/* largest request arguments */
#define	WSHM_OUT_MAX		256	/* largest reply arguments */

/*
 * One FUSE request in flight.  Arguments and reply live here, not in the
 * caller's frame: a request given up on (timeout) may still be completed by
 * the device, which then writes into this memory and the callback frees it.
 */
struct wshm_req {
	struct {
		struct fuse_in_header	h;
		uint8_t			args[WSHM_IN_MAX];
	} in;
	struct {
		struct fuse_out_header	h;
		uint8_t			args[WSHM_OUT_MAX];
	} out;
	uint32_t		len;	/* reply length */
	bool			done;
	bool			cancelled;
	bool			abandoned; /* freed by the callback */
	bool			forget;	/* no reply: freed by the callback */
};
CTASSERT(offsetof(struct wshm_req, in.args) == sizeof(struct fuse_in_header));
CTASSERT(offsetof(struct wshm_req, out.args) -
    offsetof(struct wshm_req, out.h) == sizeof(struct fuse_out_header));

/* One buffer, the state of an open descriptor. */
struct wshm_buf {
	char		name[WSLGSHM_NAME_MAX];
	uint64_t	nodeid;
	uint64_t	fh;
	uint64_t	size;
	uint64_t	moffset;	/* window offset */
	uint64_t	mlen;		/* mapped length (aligned) */
	bool		created;
	bool		mapped;
};

/* Called by the transport, with its queue lock held. */
static void
wshm_complete(struct wshm_req *r, uint32_t len, bool cancelled)
{
	bool orphan;

	if (r->forget) {
		free(r, M_WSHM);
		return;
	}
	mtx_lock(&wshm.req_mtx);
	r->len = len;
	r->cancelled = cancelled;
	r->done = true;
	orphan = r->abandoned;
	if (!orphan)
		wakeup(r);
	mtx_unlock(&wshm.req_mtx);
	if (orphan)
		free(r, M_WSHM);
}

static void
wshm_reply_cb(void *arg, uint32_t len)
{

	wshm_complete(arg, len, false);
}

static void
wshm_cancel_cb(void *arg, uint32_t len __unused)
{

	wshm_complete(arg, 0, true);
}

static void
wshm_teardown_cb(void *arg __unused)
{

	wshm.gone = true;
}

/*
 * Send one request: the arguments a1 and a2 follow the header back to back,
 * as FUSE lays them out; the reply arguments (up to "olen" bytes) are copied
 * to "o".  Returns a positive errno (the server answers with Linux errno
 * values; the ones met here match FreeBSD's).
 */
static int
wshm_request(uint32_t opcode, uint64_t nodeid, const void *a1, size_t l1,
    const void *a2, size_t l2, void *o, size_t olen)
{
	struct wshm_req *r;
	struct sglist *sg;
	int error, readable, writable;

	if (wshm.gone)
		return (ENXIO);
	KASSERT(l1 + l2 <= WSHM_IN_MAX && olen <= WSHM_OUT_MAX,
	    ("wslgshm: opcode %u too large", opcode));
	r = malloc(sizeof(*r), M_WSHM, M_WAITOK | M_ZERO);
	r->in.h.len = sizeof(r->in.h) + l1 + l2;
	r->in.h.opcode = opcode;
	r->in.h.unique = atomic_fetchadd_64(&wshm.unique, 1);
	r->in.h.nodeid = nodeid;
	r->in.h.pid = curproc->p_pid;
	if (l1 > 0)
		memcpy(r->in.args, a1, l1);
	if (l2 > 0)
		memcpy(r->in.args + l1, a2, l2);
	r->forget = (opcode == FUSE_FORGET);

	/* A buffer crossing a page boundary takes two segments. */
	sg = sglist_alloc(4, M_WAITOK);
	error = sglist_append(sg, &r->in, r->in.h.len);
	readable = sg->sg_nseg;
	if (error == 0 && !r->forget)
		error = sglist_append(sg, &r->out, sizeof(r->out.h) + olen);
	writable = sg->sg_nseg - readable;
	if (error != 0) {
		sglist_free(sg);
		free(r, M_WSHM);
		return (error);
	}

	/* vtfs_enqueue() frees the sglist, also on failure. */
	error = vtfs_enqueue(wshm.vtfs, r, sg, readable, writable, r->forget);
	if (error != 0) {
		free(r, M_WSHM);
		return (error);
	}
	/* A FORGET has no reply; the transport callback frees it. */
	if (r->forget)
		return (0);

	mtx_lock(&wshm.req_mtx);
	while (!r->done) {
		if (msleep(r, &wshm.req_mtx, 0, "wslgshm", WSHM_TIMEOUT) ==
		    EWOULDBLOCK && !r->done) {
			/* The device may still answer: leave r to it. */
			r->abandoned = true;
			mtx_unlock(&wshm.req_mtx);
			printf("wslgshm: opcode %u without reply\n", opcode);
			return (ETIMEDOUT);
		}
	}
	mtx_unlock(&wshm.req_mtx);

	if (r->cancelled)
		error = ENXIO;
	else if (r->out.h.len < sizeof(r->out.h) ||
	    r->out.h.unique != r->in.h.unique)
		error = EPROTO;
	else if (r->out.h.error != 0)
		error = -r->out.h.error;
	else if (olen > 0)
		/* Like Linux, trust the header, not the used length. */
		memcpy(o, r->out.args, MIN(olen, r->out.h.len -
		    sizeof(r->out.h)));
	free(r, M_WSHM);
	return (error);
}

/* First use: find the "wslg" device, FUSE_INIT, the shared memory window. */
static int
wshm_setup(void)
{
	struct fuse_init_in in;
	struct fuse_init_out out;
	int error;

	sx_assert(&wshm.lock, SA_XLOCKED);
	if (wshm.ready)
		return (wshm.gone ? ENXIO : 0);

	/*
	 * Once registered the callbacks stay: a late reply to a request given
	 * up on must still find them (the transport asserts on a NULL one).
	 */
	if (wshm.vtfs == NULL) {
		error = vtfs_find(__DECONST(char *, WSHM_TAG), &wshm.vtfs);
		if (error != 0) {
			wshm.vtfs = NULL;
			printf("wslgshm: no virtio-fs device \"%s\" (%d)\n",
			    WSHM_TAG, error);
			return (ENXIO);
		}
		vtfs_register_cb(wshm.vtfs, wshm_reply_cb, wshm_reply_cb,
		    wshm_cancel_cb, wshm_teardown_cb, NULL);
	}

	error = vtfs_get_shm_region(wshm.vtfs, VTFS_SHM_CACHE_ID, &wshm.window,
	    &wshm.window_len);
	if (error != 0) {
		printf("wslgshm: no shared memory window (%d)\n", error);
		return (ENXIO);
	}

	memset(&in, 0, sizeof(in));
	in.major = FUSE_KERNEL_VERSION;
	in.minor = FUSE_KERNEL_MINOR_VERSION;
	in.flags = FUSE_MAP_ALIGNMENT;
	memset(&out, 0, sizeof(out));
	error = wshm_request(FUSE_INIT, 0, &in, sizeof(in), NULL, 0, &out,
	    sizeof(out));
	if (error != 0) {
		printf("wslgshm: FUSE_INIT failed (%d)\n", error);
		return (ENXIO);
	}
	if (out.minor >= 31 && (out.flags & FUSE_MAP_ALIGNMENT) != 0 &&
	    out.map_alignment >= PAGE_SHIFT && out.map_alignment < 32)
		wshm.align = 1ULL << out.map_alignment;
	else
		wshm.align = PAGE_SIZE;

	wshm.arena = vmem_create("wslgshm", 0, wshm.window_len, wshm.align, 0,
	    M_WAITOK);
	wshm.ready = true;
	printf("wslgshm: FUSE %u.%u, window %#jx-%#jx (%ju MB), alignment "
	    "%#jx\n", out.major, out.minor, (uintmax_t)wshm.window,
	    (uintmax_t)(wshm.window + wshm.window_len - 1),
	    (uintmax_t)(wshm.window_len >> 20), (uintmax_t)wshm.align);
	return (0);
}

static void
wshm_destroy(struct wshm_buf *b)
{
	struct fuse_removemapping_in rin;
	struct fuse_removemapping_one rone;
	struct fuse_release_in rel;
	struct fuse_forget_in fin;
	int error;

	if (b->mapped) {
		memset(&rin, 0, sizeof(rin));
		rin.count = 1;
		rone.moffset = b->moffset;
		rone.len = b->mlen;
		error = wshm_request(FUSE_REMOVEMAPPING, b->nodeid, &rin,
		    sizeof(rin), &rone, sizeof(rone), NULL, 0);
		if (error != 0) {
			printf("wslgshm: REMOVEMAPPING %s: %d\n", b->name,
			    error);
			wshm_errors++;
		}
		/* Only reuse the range if the host let it go. */
		if (error == 0) {
			vmem_xfree(wshm.arena, b->moffset, b->mlen);
			wshm_inuse -= b->mlen;
		}
		wshm_destroyed++;
		b->mapped = false;
	}
	if (b->created) {
		memset(&rel, 0, sizeof(rel));
		rel.fh = b->fh;
		rel.flags = LINUX_O_RDWR;
		(void)wshm_request(FUSE_RELEASE, b->nodeid, &rel, sizeof(rel),
		    NULL, 0, NULL, 0);
		memset(&fin, 0, sizeof(fin));
		fin.nlookup = 1;
		(void)wshm_request(FUSE_FORGET, b->nodeid, &fin, sizeof(fin),
		    NULL, 0, NULL, 0);
		b->created = false;
	}
}

static void
wshm_dtor(void *arg)
{
	struct wshm_buf *b = arg;

	sx_xlock(&wshm.lock);
	if (wshm.ready)
		wshm_destroy(b);
	sx_xunlock(&wshm.lock);
	free(b, M_WSHM);
}

static int
wshm_create(struct wshm_buf *b, struct wslgshm_create *c)
{
	struct fuse_create_in cin;
	struct {
		struct fuse_entry_out entry;
		struct fuse_open_out open;
	} cout;		/* two reply arguments, back to back */
	struct fuse_fallocate_in fin;
	struct fuse_setattr_in sin;
	struct fuse_attr_out aout;
	struct fuse_setupmapping_in min;
	vmem_addr_t off;
	size_t namelen;
	int error;

	if (b->created)
		return (EBUSY);
	namelen = strnlen(c->name, sizeof(c->name));
	if (namelen == 0 || namelen == sizeof(c->name) ||
	    strchr(c->name, '/') != NULL || c->size == 0 ||
	    c->size > wshm.window_len)
		return (EINVAL);
	strlcpy(b->name, c->name, sizeof(b->name));
	b->size = c->size;

	memset(&cin, 0, sizeof(cin));
	cin.flags = LINUX_O_RDWR | LINUX_O_CREAT | LINUX_O_EXCL;
	cin.mode = LINUX_S_IFREG | 0600;
	memset(&cout, 0, sizeof(cout));
	error = wshm_request(FUSE_CREATE, WSHM_ROOT_ID, &cin, sizeof(cin),
	    b->name, namelen + 1, &cout, sizeof(cout));
	if (error != 0) {
		printf("wslgshm: CREATE %s: %d\n", b->name, error);
		wshm_errors++;
		return (error);
	}
	b->nodeid = cout.entry.nodeid;
	b->fh = cout.open.fh;
	b->created = true;

	/*
	 * The file covers the whole (aligned) mapping, so that the mapping
	 * never reaches past its end; the client only looks at "size" bytes.
	 * Weston uses fallocate(); fall back to a size change.
	 */
	b->mlen = roundup2(b->size, wshm.align);
	memset(&fin, 0, sizeof(fin));
	fin.fh = b->fh;
	fin.length = b->mlen;
	error = wshm_request(FUSE_FALLOCATE, b->nodeid, &fin, sizeof(fin),
	    NULL, 0, NULL, 0);
	if (error != 0) {
		memset(&sin, 0, sizeof(sin));
		sin.valid = FATTR_SIZE | FATTR_FH;
		sin.fh = b->fh;
		sin.size = b->mlen;
		error = wshm_request(FUSE_SETATTR, b->nodeid, &sin,
		    sizeof(sin), NULL, 0, &aout, sizeof(aout));
	}
	if (error != 0) {
		printf("wslgshm: size of %s: %d\n", b->name, error);
		wshm_errors++;
		wshm_destroy(b);
		return (error);
	}

	error = vmem_xalloc(wshm.arena, b->mlen, wshm.align, 0, 0,
	    VMEM_ADDR_MIN, VMEM_ADDR_MAX, M_NOWAIT | M_BESTFIT, &off);
	if (error != 0) {
		printf("wslgshm: window full (%ju bytes for %s)\n",
		    (uintmax_t)b->mlen, b->name);
		wshm_errors++;
		wshm_destroy(b);
		return (ENOMEM);
	}
	b->moffset = off;

	memset(&min, 0, sizeof(min));
	min.fh = b->fh;
	min.foffset = 0;
	min.len = b->mlen;
	min.flags = FUSE_SETUPMAPPING_FLAG_READ | FUSE_SETUPMAPPING_FLAG_WRITE;
	min.moffset = b->moffset;
	error = wshm_request(FUSE_SETUPMAPPING, b->nodeid, &min, sizeof(min),
	    NULL, 0, NULL, 0);
	if (error != 0) {
		printf("wslgshm: SETUPMAPPING %s: %d\n", b->name, error);
		wshm_errors++;
		vmem_xfree(wshm.arena, b->moffset, b->mlen);
		wshm_destroy(b);
		return (error);
	}
	b->mapped = true;
	wshm_created++;
	wshm_inuse += b->mlen;
	c->window_offset = b->moffset;
	return (0);
}

static int
wshm_open(struct cdev *dev __unused, int oflags __unused, int devtype __unused,
    struct thread *td __unused)
{
	struct wshm_buf *b;
	int error;

	sx_xlock(&wshm.lock);
	error = wshm_setup();
	sx_xunlock(&wshm.lock);
	if (error != 0)
		return (error);

	b = malloc(sizeof(*b), M_WSHM, M_WAITOK | M_ZERO);
	error = devfs_set_cdevpriv(b, wshm_dtor);
	if (error != 0)
		free(b, M_WSHM);
	return (error);
}

static int
wshm_ioctl(struct cdev *dev __unused, u_long cmd, caddr_t data,
    int fflag __unused, struct thread *td __unused)
{
	struct wshm_buf *b;
	int error;

	error = devfs_get_cdevpriv((void **)&b);
	if (error != 0)
		return (error);
	switch (cmd) {
	case WSLGSHM_CREATE:
		sx_xlock(&wshm.lock);
		error = wshm_create(b, (struct wslgshm_create *)data);
		sx_xunlock(&wshm.lock);
		return (error);
	default:
		return (ENOTTY);
	}
}

/* The buffer's window range only, write-back (an SG object over it). */
static int
wshm_mmap_single(struct cdev *dev __unused, vm_ooffset_t *offset,
    vm_size_t size, struct vm_object **objp, int nprot)
{
	struct wshm_buf *b;
	struct sglist *sg;
	vm_object_t obj;
	int error;

	error = devfs_get_cdevpriv((void **)&b);
	if (error != 0)
		return (error);
	if (!b->mapped || *offset != 0 || size == 0 || size > b->mlen)
		return (EINVAL);

	sg = sglist_alloc(1, M_WAITOK);
	error = sglist_append_phys(sg, wshm.window + b->moffset, size);
	if (error != 0) {
		sglist_free(sg);
		return (error);
	}
	obj = vm_pager_allocate(OBJT_SG, sg, size, nprot, 0, curthread->td_ucred);
	sglist_free(sg);
	if (obj == NULL)
		return (ENOMEM);
	VM_OBJECT_WLOCK(obj);
	vm_object_set_memattr(obj, VM_MEMATTR_WRITE_BACK);
	VM_OBJECT_WUNLOCK(obj);
	*objp = obj;
	return (0);
}

static struct cdevsw wshm_cdevsw = {
	.d_version =	D_VERSION,
	.d_name =	"wslgshm",
	.d_open =	wshm_open,
	.d_ioctl =	wshm_ioctl,
	.d_mmap_single = wshm_mmap_single,
};

static struct cdev *wshm_dev;

static int
wshm_modevent(module_t mod __unused, int type, void *data __unused)
{

	switch (type) {
	case MOD_LOAD:
		sx_init(&wshm.lock, "wslgshm");
		mtx_init(&wshm.req_mtx, "wslgshm req", NULL, MTX_DEF);
		wshm.unique = 1;
		wshm_dev = make_dev(&wshm_cdevsw, 0, UID_ROOT, GID_WHEEL, 0666,
		    "wslgshm");
		return (0);
	case MOD_UNLOAD:
		/* The window ranges may still be mapped by processes. */
		return (EBUSY);
	default:
		return (EOPNOTSUPP);
	}
}

static moduledata_t wshm_mod = {
	"wslgshm",
	wshm_modevent,
	NULL
};

DECLARE_MODULE(wslgshm, wshm_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_VERSION(wslgshm, 1);
MODULE_DEPEND(wslgshm, vtfs, 1, 1, 1);
