/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Intel Corporation
 */

#include <rte_malloc.h>
#include <rte_common.h>
#include <rte_log.h>

#include "idxd_internal.h"

#define IDXD_PMD_NAME_STR "dmadev_idxd"

int
idxd_dump(const struct rte_dma_dev *dev, FILE *f)
{
	struct idxd_dmadev *idxd = dev->fp_obj->dev_private;
	unsigned int i;

	fprintf(f, "== IDXD Private Data ==\n");
	fprintf(f, "  Portal: %p\n", idxd->portal);
	fprintf(f, "  Config: { ring_size: %u }\n",
			idxd->qcfg.nb_desc);
	fprintf(f, "  Batch ring (sz = %u, max_batches = %u):\n\t",
			idxd->max_batches + 1, idxd->max_batches);
	for (i = 0; i <= idxd->max_batches; i++) {
		fprintf(f, " %u ", idxd->batch_idx_ring[i]);
		if (i == idxd->batch_idx_read && i == idxd->batch_idx_write)
			fprintf(f, "[rd ptr, wr ptr] ");
		else if (i == idxd->batch_idx_read)
			fprintf(f, "[rd ptr] ");
		else if (i == idxd->batch_idx_write)
			fprintf(f, "[wr ptr] ");
		if (i == idxd->max_batches)
			fprintf(f, "\n");
	}

	fprintf(f, "  Curr batch: start = %u, size = %u\n", idxd->batch_start, idxd->batch_size);
	fprintf(f, "  IDS: avail = %u, returned: %u\n", idxd->ids_avail, idxd->ids_returned);
	return 0;
}

int
idxd_dmadev_create(const char *name, struct rte_device *dev,
		   const struct idxd_dmadev *base_idxd,
		   const struct rte_dma_dev_ops *ops)
{
	struct idxd_dmadev *idxd = NULL;
	struct rte_dma_dev *dmadev = NULL;
	int ret = 0;

	RTE_BUILD_BUG_ON(sizeof(struct idxd_hw_desc) != 64);
	RTE_BUILD_BUG_ON(offsetof(struct idxd_hw_desc, size) != 32);
	RTE_BUILD_BUG_ON(sizeof(struct idxd_completion) != 32);

	if (!name) {
		IDXD_PMD_ERR("Invalid name of the device!");
		ret = -EINVAL;
		goto cleanup;
	}

	/* Allocate device structure */
	dmadev = rte_dma_pmd_allocate(name, dev->numa_node, sizeof(struct idxd_dmadev));
	if (dmadev == NULL) {
		IDXD_PMD_ERR("Unable to allocate raw device");
		ret = -ENOMEM;
		goto cleanup;
	}
	dmadev->dev_ops = ops;
	dmadev->device = dev;

	idxd = dmadev->data->dev_private;
	*idxd = *base_idxd; /* copy over the main fields already passed in */
	idxd->dmadev = dmadev;

	/* allocate batch index ring and completion ring.
	 * The +1 is because we can never fully use
	 * the ring, otherwise read == write means both full and empty.
	 */
	idxd->batch_comp_ring = rte_zmalloc(NULL, (sizeof(idxd->batch_idx_ring[0]) +
			sizeof(idxd->batch_comp_ring[0]))	* (idxd->max_batches + 1),
			sizeof(idxd->batch_comp_ring[0]));
	if (idxd->batch_comp_ring == NULL) {
		IDXD_PMD_ERR("Unable to reserve memory for batch data\n");
		ret = -ENOMEM;
		goto cleanup;
	}
	idxd->batch_idx_ring = (void *)&idxd->batch_comp_ring[idxd->max_batches+1];
	idxd->batch_iova = rte_mem_virt2iova(idxd->batch_comp_ring);

	dmadev->fp_obj->dev_private = idxd;

	idxd->dmadev->state = RTE_DMA_DEV_READY;

	return 0;

cleanup:
	if (dmadev)
		rte_dma_pmd_release(name);

	return ret;
}

int idxd_pmd_logtype;

RTE_LOG_REGISTER_DEFAULT(idxd_pmd_logtype, WARNING);
