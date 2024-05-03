/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2024 FreeBSD Foundation
 *
 * Part of this software was developed by Tom Jones <thj@freebsd.org> under
 * sponsorship from the FreeBSD Foundation.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/bus.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <sys/eventhandler.h>

#include <machine/bus.h>

#include <vm/vm.h>
#include <vm/pmap.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/vm_phys.h>

struct contigmem_buffer {
	void           *addr;
	int             refcnt;
	struct mtx      mtx;
};

struct contigmem_device {
	struct contigmem_buffer	cm_buffers[RTE_CONTIGMEM_MAX_NUM_BUFS];
	struct cdev		*cm_cdev;
	int			cm_refcnt;
	int			cm_device_index;
	eventhandler_tag contigmem_eh_tag;
};

struct contigmem_vm_handle {
	int             buffer_index;
	int		device_index;
};

static int              contigmem_load(void);
static int              contigmem_unload(void);
static int              contigmem_physaddr(SYSCTL_HANDLER_ARGS);

static d_mmap_single_t  contigmem_mmap_single;
static d_open_t         contigmem_open;
static d_close_t        contigmem_close;

static struct           sysctl_ctx_list sysctl_ctx;
static struct           contigmem_device contigmem_device_list[RTE_CONTIGMEM_MAX_NUM_DEVS];

static int              contigmem_num_devices = RTE_CONTIGMEM_DEFAULT_NUM_DEVS;
static int              contigmem_num_buffers = RTE_CONTIGMEM_DEFAULT_NUM_BUFS;
static int64_t          contigmem_buffer_size = RTE_CONTIGMEM_DEFAULT_BUF_SIZE;
static int              contigmem_refcnt;

TUNABLE_INT("hw.contigmem.num_devices", &contigmem_num_devices);
TUNABLE_INT("hw.contigmem.num_buffers", &contigmem_num_buffers);
TUNABLE_QUAD("hw.contigmem.buffer_size", &contigmem_buffer_size);

MALLOC_DEFINE(M_CONTIGMEM, "contigmem", "contigmem(4) allocations");

static int contigmem_modevent(module_t mod, int type, void *arg)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		error = contigmem_load();
		break;
	case MOD_UNLOAD:
		error = contigmem_unload();
		break;
	default:
		break;
	}

	return error;
}

moduledata_t contigmem_mod = {
	"contigmem",
	(modeventhand_t)contigmem_modevent,
	0
};

DECLARE_MODULE(contigmem, contigmem_mod, SI_SUB_DRIVERS, SI_ORDER_ANY);
MODULE_VERSION(contigmem, 1);

static struct cdevsw contigmem_ops = {
	.d_name         = "contigmem",
	.d_version      = D_VERSION,
	.d_flags        = D_TRACKCLOSE,
	.d_mmap_single  = contigmem_mmap_single,
	.d_open         = contigmem_open,
	.d_close        = contigmem_close,
};

static int
contigmem_load(void)
{
	char index_string[8], description[32];
	int  i, j, created_devs = 0, error = 0;
	void *addr;

	if (contigmem_buffer_size < PAGE_SIZE ||
			(contigmem_buffer_size & (contigmem_buffer_size - 1)) != 0) {
		printf("buffer size 0x%lx is not greater than PAGE_SIZE and "
				"power of two\n", contigmem_buffer_size);
		error = EINVAL;
		goto error;
	}

	if (contigmem_num_devices > RTE_CONTIGMEM_MAX_NUM_BUFS) {
		printf("%d buffers requested is greater than %d allowed\n",
				contigmem_num_buffers, RTE_CONTIGMEM_MAX_NUM_BUFS);
		error = EINVAL;
		goto error;
	}

	if (contigmem_num_buffers > RTE_CONTIGMEM_MAX_NUM_DEVS) {
		printf("%d devices requested is greater than %d allowed\n",
				contigmem_num_buffers, RTE_CONTIGMEM_MAX_NUM_DEVS);
		error = EINVAL;
		goto error;
	}

	if (contigmem_num_devices == 0) {
		printf("contigmem_num_devices set to 0, not creating any allocations\n");
		error = EINVAL;
		goto error;
	}

	sysctl_ctx_init(&sysctl_ctx);

	static struct sysctl_oid *sysctl_root;
	sysctl_root = SYSCTL_ADD_NODE(&sysctl_ctx, SYSCTL_STATIC_CHILDREN(_hw),
			OID_AUTO, "contigmem", CTLFLAG_RD, 0, "contigmem");

	SYSCTL_ADD_INT(&sysctl_ctx, SYSCTL_CHILDREN(sysctl_root), OID_AUTO,
		"num_devices", CTLFLAG_RD, &contigmem_num_devices, 0,
		"Number of contigmem devices");
	SYSCTL_ADD_INT(&sysctl_ctx, SYSCTL_CHILDREN(sysctl_root), OID_AUTO,
		"num_buffers", CTLFLAG_RD, &contigmem_num_buffers, 0,
		"Number of contigmem buffers allocated");
	SYSCTL_ADD_QUAD(&sysctl_ctx, SYSCTL_CHILDREN(sysctl_root), OID_AUTO,
		"buffer_size", CTLFLAG_RD, &contigmem_buffer_size,
		"Size of each contiguous buffer");
	SYSCTL_ADD_INT(&sysctl_ctx, SYSCTL_CHILDREN(sysctl_root), OID_AUTO,
		"num_references", CTLFLAG_RD, &contigmem_refcnt, 0,
		"Number of references to contigmem");

	struct contigmem_device *cd;
	for (i = 0; i < contigmem_num_devices; i++) {
		cd = &contigmem_device_list[i];
		struct sysctl_oid *sysctl_dev;
		char namebuf[32];
		snprintf(namebuf, sizeof(namebuf), "contigmem%d", i);

		cd->cm_device_index = i;

		printf("Adding node at index %d\n", i);
		sysctl_dev = SYSCTL_ADD_NODE(&sysctl_ctx, SYSCTL_CHILDREN(sysctl_root),
				OID_AUTO, namebuf, CTLFLAG_RD, 0,
				"contigmem");
		SYSCTL_ADD_INT(&sysctl_ctx,
				SYSCTL_CHILDREN(sysctl_dev), OID_AUTO,
				"num_references", CTLFLAG_RD, &cd->cm_refcnt, 0,
				"Number of references to contigmem device");

		for (j = 0; j < contigmem_num_buffers; j++) {
			addr = contigmalloc(contigmem_buffer_size, M_CONTIGMEM, M_ZERO,
				0, BUS_SPACE_MAXADDR, contigmem_buffer_size, 0);
			if (addr == NULL) {
				printf("contigmalloc failed for device %d buffer %d\n",
					i, j);
				error = ENOMEM;
				goto error;
			}

			printf("dev: %2u %2u: virt=%p phys=%p\n", i, j, addr,
				(void *)pmap_kextract((vm_offset_t)addr));

			mtx_init(&cd->cm_buffers[j].mtx, "contigmem", NULL, MTX_DEF);
			cd->cm_buffers[j].addr = addr;
			cd->cm_buffers[j].refcnt = 0;

			snprintf(index_string, sizeof(index_string), "%d", j);
			snprintf(description, sizeof(description),
					"phys addr for buffer %d", j);

			SYSCTL_ADD_PROC(&sysctl_ctx,
				SYSCTL_CHILDREN(sysctl_dev), OID_AUTO,
				index_string, CTLTYPE_U64 | CTLFLAG_RD,
				(void *)&cd->cm_buffers[j], 0, contigmem_physaddr, "LU",
				description);
		}

		cd->cm_cdev = make_dev_credf(0, &contigmem_ops, i, NULL,
				UID_ROOT, GID_WHEEL, 0600, "contigmem%d", i);
		cd->cm_cdev->si_drv1 = cd;
		created_devs++;
	}

	return 0;

error:
	for (i = 0; i < created_devs; i++) {
		cd = &contigmem_device_list[i];
		for (j = 0; j < contigmem_num_buffers; j++) {
			if (cd->cm_buffers[j].addr != NULL) {
				contigfree(cd->cm_buffers[j].addr,
					contigmem_buffer_size, M_CONTIGMEM);
				cd->cm_buffers[j].addr = NULL;
			}
			if (mtx_initialized(&cd->cm_buffers[j].mtx))
				mtx_destroy(&cd->cm_buffers[j].mtx);
		}
	}

	sysctl_ctx_free(&sysctl_ctx);
	return error;
}

static int
contigmem_unload(void)
{
	struct contigmem_device *cd;

	if (contigmem_refcnt > 0)
		return EBUSY;

	for (int i = 0; i < contigmem_num_devices; i++) {
		cd = &contigmem_device_list[i];
		if (cd->cm_cdev != NULL)
			destroy_dev(cd->cm_cdev);

		if (cd->contigmem_eh_tag != NULL)
			EVENTHANDLER_DEREGISTER(process_exit, cd->contigmem_eh_tag);

		for (int j = 0; j < RTE_CONTIGMEM_MAX_NUM_BUFS; j++) {
			if (cd->cm_buffers[j].addr != NULL)
				contigfree(cd->cm_buffers[j].addr,
					contigmem_buffer_size, M_CONTIGMEM);
			if (mtx_initialized(&cd->cm_buffers[j].mtx))
				mtx_destroy(&cd->cm_buffers[j].mtx);
		}
	}

	sysctl_ctx_free(&sysctl_ctx);

	return 0;
}

static int
contigmem_physaddr(SYSCTL_HANDLER_ARGS)
{
	uint64_t physaddr;
	struct contigmem_buffer *buf;

	buf = (struct contigmem_buffer *)arg1;

	physaddr = (uint64_t)vtophys(buf->addr);
	return sysctl_handle_64(oidp, &physaddr, 0, req);
}

static int
contigmem_open(struct cdev *cdev, int fflags, int devtype,
		struct thread *td)
{
	struct contigmem_device *cd;
	cd = cdev->si_drv1;

	atomic_add_int(&contigmem_refcnt, 1);
	atomic_add_int(&cd->cm_refcnt, 1);

	return 0;
}

static int
contigmem_close(struct cdev *cdev, int fflags, int devtype,
		struct thread *td)
{
	struct contigmem_device *cd;
	cd = cdev->si_drv1;

	atomic_subtract_int(&contigmem_refcnt, 1);
	atomic_subtract_int(&cd->cm_refcnt, 1);

	return 0;
}

static int
contigmem_cdev_pager_ctor(void *handle, vm_ooffset_t size, vm_prot_t prot,
		vm_ooffset_t foff, struct ucred *cred, u_short *color)
{
	struct contigmem_vm_handle *vmh = handle;
	struct contigmem_buffer *buf;
	struct contigmem_device *cd;

	cd = &contigmem_device_list[vmh->device_index];
	buf = &cd->cm_buffers[vmh->buffer_index];
		vmh, vmh->buffer_index, vmh->device_index, cd, buf, buf->refcnt);

	atomic_add_int(&contigmem_refcnt, 1);
	atomic_add_int(&cd->cm_refcnt, 1);

	mtx_lock(&buf->mtx);
	if (buf->refcnt == 0)
		memset(buf->addr, 0, contigmem_buffer_size);
	buf->refcnt++;
	mtx_unlock(&buf->mtx);

	return 0;
}

static void
contigmem_cdev_pager_dtor(void *handle)
{
	struct contigmem_vm_handle *vmh = handle;
	struct contigmem_buffer *buf;
	struct contigmem_device *cd;

	cd = &contigmem_device_list[vmh->device_index];
	buf = &cd->cm_buffers[vmh->buffer_index];

	mtx_lock(&buf->mtx);
	buf->refcnt--;
	mtx_unlock(&buf->mtx);

	free(vmh, M_CONTIGMEM);

	atomic_subtract_int(&contigmem_refcnt, 1);
	atomic_subtract_int(&cd->cm_refcnt, 1);
}

static int
contigmem_cdev_pager_fault(vm_object_t object, vm_ooffset_t offset, int prot,
		vm_page_t *mres)
{
	vm_paddr_t paddr;
	vm_page_t m_paddr, page;
	vm_memattr_t memattr, memattr1;

	memattr = object->memattr;

	VM_OBJECT_WUNLOCK(object);

	paddr = offset;

	m_paddr = vm_phys_paddr_to_vm_page(paddr);
	if (m_paddr != NULL) {
		memattr1 = pmap_page_get_memattr(m_paddr);
		if (memattr1 != memattr)
			memattr = memattr1;
	}

	if (((*mres)->flags & PG_FICTITIOUS) != 0) {
		/*
		 * If the passed in result page is a fake page, update it with
		 * the new physical address.
		 */
		page = *mres;
		VM_OBJECT_WLOCK(object);
		vm_page_updatefake(page, paddr, memattr);
	} else {
		/*
		 * Replace the passed in reqpage page with our own fake page and
		 * free up the original page.
		 */
		page = vm_page_getfake(paddr, memattr);
		VM_OBJECT_WLOCK(object);
#if __FreeBSD__ >= 13
		vm_page_replace(page, object, (*mres)->pindex, *mres);
#else
		vm_page_t mret = vm_page_replace(page, object, (*mres)->pindex);
		KASSERT(mret == *mres,
		    ("invalid page replacement, old=%p, ret=%p", *mres, mret));
		vm_page_lock(mret);
		vm_page_free(mret);
		vm_page_unlock(mret);
#endif
		*mres = page;
	}

	page->valid = VM_PAGE_BITS_ALL;

	return VM_PAGER_OK;
}

static struct cdev_pager_ops contigmem_cdev_pager_ops = {
	.cdev_pg_ctor = contigmem_cdev_pager_ctor,
	.cdev_pg_dtor = contigmem_cdev_pager_dtor,
	.cdev_pg_fault = contigmem_cdev_pager_fault,
};

static int
contigmem_mmap_single(struct cdev *cdev, vm_ooffset_t *offset, vm_size_t size,
		struct vm_object **obj, int nprot)
{
	struct contigmem_vm_handle *vmh;
	struct contigmem_device *cd;
	uint64_t buffer_index;

	cd = (struct contigmem_device *)cdev->si_drv1;

	/*
	 * The buffer index is encoded in the offset.  Divide the offset by
	 *  PAGE_SIZE to get the index of the buffer requested by the user
	 *  app.
	 */
	buffer_index = *offset / PAGE_SIZE;
	if (buffer_index >= contigmem_num_buffers)
		return EINVAL;

	if (size > contigmem_buffer_size)
		return EINVAL;

	vmh = malloc(sizeof(*vmh), M_CONTIGMEM, M_NOWAIT | M_ZERO);
	if (vmh == NULL)
		return ENOMEM;
	vmh->buffer_index = buffer_index;
	vmh->device_index = cd->cm_device_index;

	*offset = (vm_ooffset_t)vtophys(cd->cm_buffers[buffer_index].addr);
	*obj = cdev_pager_allocate(vmh, OBJT_DEVICE, &contigmem_cdev_pager_ops,
			size, nprot, *offset, curthread->td_ucred);

	return 0;
}
