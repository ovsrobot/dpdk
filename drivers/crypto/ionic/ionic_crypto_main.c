/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021-2024 Advanced Micro Devices, Inc.
 */

#include <inttypes.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_bitops.h>

#include "ionic_crypto.h"

static int
iocpt_cq_init(struct iocpt_cq *cq, uint16_t num_descs)
{
	if (!rte_is_power_of_2(num_descs) ||
	    num_descs < IOCPT_MIN_RING_DESC ||
	    num_descs > IOCPT_MAX_RING_DESC) {
		IOCPT_PRINT(ERR, "%u descriptors (min: %u max: %u)",
			num_descs, IOCPT_MIN_RING_DESC, IOCPT_MAX_RING_DESC);
		return -EINVAL;
	}

	cq->num_descs = num_descs;
	cq->size_mask = num_descs - 1;
	cq->tail_idx = 0;
	cq->done_color = 1;

	return 0;
}

static void
iocpt_cq_map(struct iocpt_cq *cq, void *base, rte_iova_t base_pa)
{
	cq->base = base;
	cq->base_pa = base_pa;
}

uint32_t
iocpt_cq_service(struct iocpt_cq *cq, uint32_t work_to_do,
		iocpt_cq_cb cb, void *cb_arg)
{
	uint32_t work_done = 0;

	if (work_to_do == 0)
		return 0;

	while (cb(cq, cq->tail_idx, cb_arg)) {
		cq->tail_idx = Q_NEXT_TO_SRVC(cq, 1);
		if (cq->tail_idx == 0)
			cq->done_color = !cq->done_color;

		if (++work_done == work_to_do)
			break;
	}

	return work_done;
}

static int
iocpt_q_init(struct iocpt_queue *q, uint8_t type, uint32_t index,
	uint16_t num_descs, uint16_t num_segs, uint32_t socket_id)
{
	uint32_t ring_size;

	if (!rte_is_power_of_2(num_descs))
		return -EINVAL;

	ring_size = rte_log2_u32(num_descs);
	if (ring_size < 2 || ring_size > 16)
		return -EINVAL;

	q->type = type;
	q->index = index;
	q->num_descs = num_descs;
	q->num_segs = num_segs;
	q->size_mask = num_descs - 1;
	q->head_idx = 0;
	q->tail_idx = 0;

	q->info = rte_calloc_socket("iocpt",
				num_descs * num_segs, sizeof(void *),
				rte_mem_page_size(), socket_id);
	if (q->info == NULL) {
		IOCPT_PRINT(ERR, "Cannot allocate queue info");
		return -ENOMEM;
	}

	return 0;
}

static void
iocpt_q_map(struct iocpt_queue *q, void *base, rte_iova_t base_pa)
{
	q->base = base;
	q->base_pa = base_pa;
}

static void
iocpt_q_sg_map(struct iocpt_queue *q, void *base, rte_iova_t base_pa)
{
	q->sg_base = base;
	q->sg_base_pa = base_pa;
}

static void
iocpt_q_free(struct iocpt_queue *q)
{
	if (q->info != NULL) {
		rte_free(q->info);
		q->info = NULL;
	}
}

static const struct rte_memzone *
iocpt_dma_zone_reserve(const char *type_name, uint16_t qid, size_t size,
			unsigned int align, int socket_id)
{
	char zone_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	int err;

	err = snprintf(zone_name, sizeof(zone_name),
			"iocpt_%s_%u", type_name, qid);
	if (err >= RTE_MEMZONE_NAMESIZE) {
		IOCPT_PRINT(ERR, "Name %s too long", type_name);
		return NULL;
	}

	mz = rte_memzone_lookup(zone_name);
	if (mz != NULL)
		return mz;

	return rte_memzone_reserve_aligned(zone_name, size, socket_id,
			RTE_MEMZONE_IOVA_CONTIG, align);
}

static int
iocpt_commonq_alloc(struct iocpt_dev *dev,
		uint8_t type,
		size_t struct_size,
		uint32_t socket_id,
		uint32_t index,
		const char *type_name,
		uint16_t flags,
		uint16_t num_descs,
		uint16_t num_segs,
		uint16_t desc_size,
		uint16_t cq_desc_size,
		uint16_t sg_desc_size,
		struct iocpt_common_q **comq)
{
	struct iocpt_common_q *new;
	uint32_t q_size, cq_size, sg_size, total_size;
	void *q_base, *cq_base, *sg_base;
	rte_iova_t q_base_pa = 0;
	rte_iova_t cq_base_pa = 0;
	rte_iova_t sg_base_pa = 0;
	size_t page_size = rte_mem_page_size();
	int err;

	*comq = NULL;

	q_size	= num_descs * desc_size;
	cq_size = num_descs * cq_desc_size;
	sg_size = num_descs * sg_desc_size;

	/*
	 * Note: aligning q_size/cq_size is not enough due to cq_base address
	 * aligning as q_base could be not aligned to the page.
	 * Adding page_size.
	 */
	total_size = RTE_ALIGN(q_size, page_size) +
		RTE_ALIGN(cq_size, page_size) + page_size;
	if (flags & IOCPT_Q_F_SG)
		total_size += RTE_ALIGN(sg_size, page_size) + page_size;

	new = rte_zmalloc_socket("iocpt", struct_size,
			RTE_CACHE_LINE_SIZE, socket_id);
	if (new == NULL) {
		IOCPT_PRINT(ERR, "Cannot allocate queue structure");
		return -ENOMEM;
	}

	new->dev = dev;

	err = iocpt_q_init(&new->q, type, index, num_descs, num_segs,
			socket_id);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Queue initialization failed");
		goto err_free_q;
	}

	err = iocpt_cq_init(&new->cq, num_descs);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Completion queue initialization failed");
		goto err_deinit_q;
	}

	new->base_z = iocpt_dma_zone_reserve(type_name, index, total_size,
					IONIC_ALIGN, socket_id);
	if (new->base_z == NULL) {
		IOCPT_PRINT(ERR, "Cannot reserve queue DMA memory");
		err = -ENOMEM;
		goto err_deinit_cq;
	}

	new->base = new->base_z->addr;
	new->base_pa = new->base_z->iova;

	q_base = new->base;
	q_base_pa = new->base_pa;
	iocpt_q_map(&new->q, q_base, q_base_pa);

	cq_base = (void *)RTE_ALIGN((uintptr_t)q_base + q_size, page_size);
	cq_base_pa = RTE_ALIGN(q_base_pa + q_size, page_size);
	iocpt_cq_map(&new->cq, cq_base, cq_base_pa);

	if (flags & IOCPT_Q_F_SG) {
		sg_base = (void *)RTE_ALIGN((uintptr_t)cq_base + cq_size,
			page_size);
		sg_base_pa = RTE_ALIGN(cq_base_pa + cq_size, page_size);
		iocpt_q_sg_map(&new->q, sg_base, sg_base_pa);
	}

	IOCPT_PRINT(DEBUG, "q_base_pa %#jx cq_base_pa %#jx sg_base_pa %#jx",
		q_base_pa, cq_base_pa, sg_base_pa);

	*comq = new;

	return 0;

err_deinit_cq:
err_deinit_q:
	iocpt_q_free(&new->q);
err_free_q:
	rte_free(new);
	return err;
}

struct ionic_doorbell *
iocpt_db_map(struct iocpt_dev *dev, struct iocpt_queue *q)
{
	return dev->db_pages + q->hw_type;
}

static int
iocpt_adminq_alloc(struct iocpt_dev *dev)
{
	struct iocpt_admin_q *aq;
	uint16_t num_descs = IOCPT_ADMINQ_LENGTH;
	uint16_t flags = 0;
	int err;

	err = iocpt_commonq_alloc(dev,
		IOCPT_QTYPE_ADMINQ,
		sizeof(struct iocpt_admin_q),
		rte_socket_id(),
		0,
		"admin",
		flags,
		num_descs,
		1,
		sizeof(struct iocpt_admin_cmd),
		sizeof(struct iocpt_admin_comp),
		0,
		(struct iocpt_common_q **)&aq);
	if (err != 0)
		return err;

	aq->flags = flags;

	dev->adminq = aq;

	return 0;
}

static int
iocpt_adminq_init(struct iocpt_dev *dev)
{
	return iocpt_dev_adminq_init(dev);
}

static void
iocpt_adminq_deinit(struct iocpt_dev *dev)
{
	dev->adminq->flags &= ~IOCPT_Q_F_INITED;
}

static void
iocpt_adminq_free(struct iocpt_admin_q *aq)
{
	if (aq->base_z != NULL) {
		rte_memzone_free(aq->base_z);
		aq->base_z = NULL;
		aq->base = NULL;
		aq->base_pa = 0;
	}

	iocpt_q_free(&aq->q);

	rte_free(aq);
}

static int
iocpt_alloc_objs(struct iocpt_dev *dev)
{
	int err;

	IOCPT_PRINT(DEBUG, "Crypto: %s", dev->name);

	rte_spinlock_init(&dev->adminq_lock);
	rte_spinlock_init(&dev->adminq_service_lock);

	err = iocpt_adminq_alloc(dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot allocate admin queue");
		err = -ENOMEM;
		goto err_out;
	}

	dev->info_sz = RTE_ALIGN(sizeof(*dev->info), rte_mem_page_size());
	dev->info_z = iocpt_dma_zone_reserve("info", 0, dev->info_sz,
					IONIC_ALIGN, dev->socket_id);
	if (dev->info_z == NULL) {
		IOCPT_PRINT(ERR, "Cannot allocate dev info memory");
		err = -ENOMEM;
		goto err_free_adminq;
	}

	dev->info = dev->info_z->addr;
	dev->info_pa = dev->info_z->iova;

	return 0;

err_free_adminq:
	iocpt_adminq_free(dev->adminq);
	dev->adminq = NULL;
err_out:
	return err;
}

static int
iocpt_init(struct iocpt_dev *dev)
{
	int err;

	/* Uses dev_cmds */
	err = iocpt_dev_init(dev, dev->info_pa);
	if (err != 0)
		return err;

	err = iocpt_adminq_init(dev);
	if (err != 0)
		return err;

	dev->state |= IOCPT_DEV_F_INITED;

	return 0;
}

void
iocpt_configure(struct iocpt_dev *dev)
{
	RTE_SET_USED(dev);
}

void
iocpt_deinit(struct iocpt_dev *dev)
{
	IOCPT_PRINT_CALL();

	if (!(dev->state & IOCPT_DEV_F_INITED))
		return;

	iocpt_adminq_deinit(dev);

	dev->state &= ~IOCPT_DEV_F_INITED;
}

static void
iocpt_free_objs(struct iocpt_dev *dev)
{
	IOCPT_PRINT_CALL();

	if (dev->adminq != NULL) {
		iocpt_adminq_free(dev->adminq);
		dev->adminq = NULL;
	}

	if (dev->info != NULL) {
		rte_memzone_free(dev->info_z);
		dev->info_z = NULL;
		dev->info = NULL;
		dev->info_pa = 0;
	}
}

static int
iocpt_devargs(struct rte_devargs *devargs, struct iocpt_dev *dev)
{
	RTE_SET_USED(devargs);
	RTE_SET_USED(dev);

	return 0;
}

int
iocpt_probe(void *bus_dev, struct rte_device *rte_dev,
	struct iocpt_dev_bars *bars, const struct iocpt_dev_intf *intf,
	uint8_t driver_id, uint8_t socket_id)
{
	struct rte_cryptodev_pmd_init_params init_params = {
		"iocpt",
		sizeof(struct iocpt_dev),
		socket_id,
		RTE_CRYPTODEV_PMD_DEFAULT_MAX_NB_QUEUE_PAIRS
	};
	struct rte_cryptodev *cdev;
	struct iocpt_dev *dev;
	uint32_t i, sig;
	int err;

	/* Check structs (trigger error at compilation time) */
	iocpt_struct_size_checks();

	/* Multi-process not supported */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		err = -EPERM;
		goto err;
	}

	cdev = rte_cryptodev_pmd_create(rte_dev->name, rte_dev, &init_params);
	if (cdev == NULL) {
		IOCPT_PRINT(ERR, "OOM");
		err = -ENOMEM;
		goto err;
	}

	dev = cdev->data->dev_private;
	dev->crypto_dev = cdev;
	dev->bus_dev = bus_dev;
	dev->intf = intf;
	dev->driver_id = driver_id;
	dev->socket_id = socket_id;

	for (i = 0; i < bars->num_bars; i++) {
		struct ionic_dev_bar *bar = &bars->bar[i];

		IOCPT_PRINT(DEBUG,
			"bar[%u] = { .va = %p, .pa = %#jx, .len = %lu }",
			i, bar->vaddr, bar->bus_addr, bar->len);
		if (bar->vaddr == NULL) {
			IOCPT_PRINT(ERR, "Null bar found, aborting");
			err = -EFAULT;
			goto err_destroy_crypto_dev;
		}

		dev->bars.bar[i].vaddr = bar->vaddr;
		dev->bars.bar[i].bus_addr = bar->bus_addr;
		dev->bars.bar[i].len = bar->len;
	}
	dev->bars.num_bars = bars->num_bars;

	err = iocpt_devargs(rte_dev->devargs, dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot parse device arguments");
		goto err_destroy_crypto_dev;
	}

	err = iocpt_setup_bars(dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot setup BARs: %d, aborting", err);
		goto err_destroy_crypto_dev;
	}

	sig = ioread32(&dev->dev_info->signature);
	if (sig != IOCPT_DEV_INFO_SIGNATURE) {
		IOCPT_PRINT(ERR, "Incompatible firmware signature %#x", sig);
		err = -EFAULT;
		goto err_destroy_crypto_dev;
	}

	for (i = 0; i < IOCPT_FWVERS_BUFLEN; i++)
		dev->fw_version[i] = ioread8(&dev->dev_info->fw_version[i]);
	dev->fw_version[IOCPT_FWVERS_BUFLEN - 1] = '\0';
	IOCPT_PRINT(DEBUG, "%s firmware: %s", dev->name, dev->fw_version);

	err = iocpt_dev_identify(dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot identify device: %d, aborting",
			err);
		goto err_destroy_crypto_dev;
	}

	err = iocpt_alloc_objs(dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot alloc device objects: %d", err);
		goto err_destroy_crypto_dev;
	}

	err = iocpt_init(dev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Cannot init device: %d, aborting", err);
		goto err_free_objs;
	}

	err = iocpt_assign_ops(cdev);
	if (err != 0) {
		IOCPT_PRINT(ERR, "Failed to configure opts");
		goto err_deinit_dev;
	}

	return 0;

err_deinit_dev:
	iocpt_deinit(dev);
err_free_objs:
	iocpt_free_objs(dev);
err_destroy_crypto_dev:
	rte_cryptodev_pmd_destroy(cdev);
err:
	return err;
}

int
iocpt_remove(struct rte_device *rte_dev)
{
	struct rte_cryptodev *cdev;
	struct iocpt_dev *dev;

	cdev = rte_cryptodev_pmd_get_named_dev(rte_dev->name);
	if (cdev == NULL) {
		IOCPT_PRINT(DEBUG, "Cannot find device %s", rte_dev->name);
		return -ENODEV;
	}

	dev = cdev->data->dev_private;

	iocpt_deinit(dev);

	iocpt_dev_reset(dev);

	iocpt_free_objs(dev);

	rte_cryptodev_pmd_destroy(cdev);

	return 0;
}

RTE_LOG_REGISTER_DEFAULT(iocpt_logtype, NOTICE);
