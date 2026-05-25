/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <rte_bus_pci.h>
#include <bus_pci_driver.h>
#include <rte_dmadev_pmd.h>
#include <rte_malloc.h>

#include "ae4dma_internal.h"

/*
 * One dmadev per AE4DMA hardware channel; each dmadev has exactly one
 * virtual channel. The HW's per-queue register block must be densely
 * packed right after the engine-common config register at BAR0+0; the
 * build-time check below catches an accidental layout change.
 */
static_assert(sizeof(struct ae4dma_hwq_regs) == 32,
		"ae4dma_hwq_regs stride changed; per-queue offset math will break");

RTE_LOG_REGISTER_DEFAULT(ae4dma_pmd_logtype, INFO);

#define AE4DMA_PMD_NAME dmadev_ae4dma

static const struct rte_memzone *
ae4dma_queue_dma_zone_reserve(const char *queue_name,
		uint32_t queue_size, int socket_id)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(queue_name);
	if (mz != NULL) {
		if (((size_t)queue_size <= mz->len) &&
				((socket_id == SOCKET_ID_ANY) ||
				 (socket_id == mz->socket_id))) {
			AE4DMA_PMD_INFO("reuse memzone already "
					"allocated for %s", queue_name);
			return mz;
		}
		AE4DMA_PMD_ERR("Incompatible memzone already "
				"allocated %s, size %u, socket %d. "
				"Requested size %u, socket %u",
				queue_name, (uint32_t)mz->len,
				mz->socket_id, queue_size, socket_id);
		return NULL;
	}
	return rte_memzone_reserve_aligned(queue_name, queue_size,
			socket_id, RTE_MEMZONE_IOVA_CONTIG, queue_size);
}

/* Configure a device. */
static int
ae4dma_dev_configure(struct rte_dma_dev *dev __rte_unused,
		const struct rte_dma_conf *dev_conf,
		uint32_t conf_sz)
{
	if (sizeof(struct rte_dma_conf) != conf_sz)
		return -EINVAL;

	if (dev_conf->nb_vchans != 1)
		return -EINVAL;

	return 0;
}

/* Setup a virtual channel for AE4DMA, only 1 vchan is supported per dmadev. */
static int
ae4dma_vchan_setup(struct rte_dma_dev *dev, uint16_t vchan __rte_unused,
		const struct rte_dma_vchan_conf *qconf, uint32_t qconf_sz)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;
	uint16_t max_desc = qconf->nb_desc;

	if (sizeof(struct rte_dma_vchan_conf) != qconf_sz)
		return -EINVAL;

	if (max_desc < 2)
		return -EINVAL;

	if (!rte_is_power_of_2(max_desc))
		max_desc = rte_align32pow2(max_desc);

	if (max_desc > AE4DMA_DESCRIPTORS_PER_CMDQ) {
		AE4DMA_PMD_DEBUG("DMA dev %u nb_desc clamped to %u",
				dev->data->dev_id, AE4DMA_DESCRIPTORS_PER_CMDQ);
		max_desc = AE4DMA_DESCRIPTORS_PER_CMDQ;
	}

	cmd_q->qcfg = *qconf;
	cmd_q->qcfg.nb_desc = max_desc;

	/* Ensure all counters are reset, if reconfiguring/restarting device. */
	memset(&cmd_q->stats, 0, sizeof(cmd_q->stats));
	return 0;
}

/* Start a configured device. */
static int
ae4dma_dev_start(struct rte_dma_dev *dev)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;
	uint16_t nb = cmd_q->qcfg.nb_desc;

	if (nb == 0)
		return -EBUSY;

	/* Program ring depth expected by hardware. */
	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->max_idx, nb);
	return 0;
}

/* Stop a configured device. */
static int
ae4dma_dev_stop(struct rte_dma_dev *dev)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;

	if (cmd_q->hwq_regs != NULL)
		AE4DMA_WRITE_REG(&cmd_q->hwq_regs->control_reg.control_raw,
				AE4DMA_CMD_QUEUE_DISABLE);
	return 0;
}

/* Get device information of a device. */
static int
ae4dma_dev_info_get(const struct rte_dma_dev *dev, struct rte_dma_info *info,
		uint32_t size)
{
	if (size < sizeof(*info))
		return -EINVAL;
	info->dev_name = dev->device->name;
	info->dev_capa = RTE_DMA_CAPA_MEM_TO_MEM;
	info->max_vchans = 1;
	info->min_desc = 2;
	info->max_desc = AE4DMA_DESCRIPTORS_PER_CMDQ;
	info->nb_vchans = 1;
	return 0;
}

/* Close a configured device. */
static int
ae4dma_dev_close(struct rte_dma_dev *dev)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;

	if (cmd_q->hwq_regs != NULL)
		AE4DMA_WRITE_REG(&cmd_q->hwq_regs->control_reg.control_raw,
				AE4DMA_CMD_QUEUE_DISABLE);

	if (cmd_q->memz_name[0] != '\0') {
		const struct rte_memzone *mz = rte_memzone_lookup(cmd_q->memz_name);

		if (mz != NULL)
			rte_memzone_free(mz);
	}
	cmd_q->qbase_desc = NULL;
	cmd_q->qbase_addr = NULL;
	cmd_q->qbase_phys_addr = 0;
	return 0;
}
/* Dump DMA device info. */
static int
ae4dma_dev_dump(const struct rte_dma_dev *dev, FILE *f)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q;
	void *ae4dma_mmio_base_addr = (uint8_t *)ae4dma->io_regs;

	cmd_q = &ae4dma->cmd_q;
	fprintf(f, "cmd_q->id              = %" PRIx64 "\n", cmd_q->id);
	fprintf(f, "cmd_q->qidx            = %" PRIx64 "\n", cmd_q->qidx);
	fprintf(f, "cmd_q->qsize           = %" PRIx64 "\n", cmd_q->qsize);
	fprintf(f, "mmio_base_addr	= %p\n", ae4dma_mmio_base_addr);
	fprintf(f, "queues per ae4dma engine     = %d\n", AE4DMA_READ_REG_OFFSET(
				ae4dma_mmio_base_addr, AE4DMA_COMMON_CONFIG_OFFSET));
	fprintf(f, "== Private Data ==\n");
	fprintf(f, "  Config: { ring_size: %u }\n", cmd_q->qcfg.nb_desc);
	fprintf(f, "  Ring virt: %p\tphys: %#" PRIx64 "\n",
			(void *)cmd_q->qbase_desc,
			(uint64_t)cmd_q->qbase_phys_addr);
	fprintf(f, "  Next write: %u\n", cmd_q->next_write);
	fprintf(f, "  Next read: %u\n", cmd_q->next_read);
	fprintf(f, "  current queue depth: %u\n", cmd_q->ring_buff_count);
	fprintf(f, "  }\n");
	fprintf(f, "  Key Stats { submitted: %" PRIu64 ", comp: %" PRIu64 ", failed: %" PRIu64 " }\n",
		cmd_q->stats.submitted,
		cmd_q->stats.completed,
		cmd_q->stats.errors);
	return 0;
}
/* Retrieve the generic stats of a DMA device. */
static int
ae4dma_stats_get(const struct rte_dma_dev *dev, uint16_t vchan __rte_unused,
		struct rte_dma_stats *rte_stats, uint32_t size)
{
	const struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	const struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;
	const struct rte_dma_stats *stats = &cmd_q->stats;

	if (size < sizeof(*rte_stats))
		return -EINVAL;
	if (rte_stats == NULL)
		return -EINVAL;

	*rte_stats = *stats;
	return 0;
}

/* Reset the generic stat counters for the DMA device. */
static int
ae4dma_stats_reset(struct rte_dma_dev *dev, uint16_t vchan __rte_unused)
{
	struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;

	memset(&cmd_q->stats, 0, sizeof(cmd_q->stats));
	return 0;
}

/*
 * Report channel state to the dmadev framework.
 *
 *   RTE_DMA_VCHAN_HALTED_ERROR - HW queue is disabled (never started, or
 *                                stopped via dev_stop()).
 *   RTE_DMA_VCHAN_IDLE         - HW has caught up: read_idx == write_idx,
 *                                no descriptors in flight.
 *   RTE_DMA_VCHAN_ACTIVE       - HW still has descriptors to process.
 */
static int
ae4dma_vchan_status(const struct rte_dma_dev *dev, uint16_t vchan __rte_unused,
		enum rte_dma_vchan_status *status)
{
	const struct ae4dma_dmadev *ae4dma = dev->fp_obj->dev_private;
	const struct ae4dma_cmd_queue *cmd_q = &ae4dma->cmd_q;
	uint32_t ctrl, hw_read, hw_write;

	if (cmd_q->hwq_regs == NULL) {
		*status = RTE_DMA_VCHAN_HALTED_ERROR;
		return 0;
	}

	ctrl = AE4DMA_READ_REG(&cmd_q->hwq_regs->control_reg.control_raw);
	if ((ctrl & AE4DMA_CMD_QUEUE_ENABLE) == 0) {
		*status = RTE_DMA_VCHAN_HALTED_ERROR;
		return 0;
	}

	hw_read  = AE4DMA_READ_REG(&cmd_q->hwq_regs->read_idx);
	hw_write = AE4DMA_READ_REG(&cmd_q->hwq_regs->write_idx);

	*status = (hw_read == hw_write) ? RTE_DMA_VCHAN_IDLE
					: RTE_DMA_VCHAN_ACTIVE;
	return 0;
}

static int
ae4dma_add_queue(struct ae4dma_dmadev *dev, uint8_t qn, const char *pci_name)
{
	uint32_t dma_addr_lo, dma_addr_hi;
	struct ae4dma_cmd_queue *cmd_q;
	const struct rte_memzone *q_mz;

	dev->io_regs = dev->pci->mem_resource[AE4DMA_PCIE_BAR].addr;

	cmd_q = &dev->cmd_q;
	cmd_q->id = qn;
	cmd_q->qidx = 0;
	cmd_q->qsize = AE4DMA_QUEUE_SIZE(AE4DMA_QUEUE_DESC_SIZE);
	cmd_q->hwq_regs = (volatile struct ae4dma_hwq_regs *)dev->io_regs + (qn + 1);

	/*
	 * Memzone name must be globally unique. Embed PCI BDF so multiple
	 * PCI functions probed concurrently don't collide.
	 */
	snprintf(cmd_q->memz_name, sizeof(cmd_q->memz_name),
			"ae4dma_%s_q%u", pci_name, (unsigned int)qn);

	q_mz = ae4dma_queue_dma_zone_reserve(cmd_q->memz_name,
			cmd_q->qsize, rte_socket_id());
	if (q_mz == NULL) {
		AE4DMA_PMD_ERR("memzone reserve failed for %s", cmd_q->memz_name);
		return -ENOMEM;
	}

	cmd_q->qbase_addr = (void *)q_mz->addr;
	cmd_q->qbase_desc = (struct ae4dma_desc *)q_mz->addr;
	cmd_q->qbase_phys_addr = q_mz->iova;

	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->max_idx, AE4DMA_DESCRIPTORS_PER_CMDQ);
	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->control_reg.control_raw,
			AE4DMA_CMD_QUEUE_ENABLE);
	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->intr_status_reg.intr_status_raw,
			AE4DMA_DISABLE_INTR);
	cmd_q->next_write = (uint16_t)AE4DMA_READ_REG(&cmd_q->hwq_regs->write_idx);
	cmd_q->next_read = (uint16_t)AE4DMA_READ_REG(&cmd_q->hwq_regs->read_idx);
	cmd_q->ring_buff_count = 0;

	dma_addr_lo = low32_value(cmd_q->qbase_phys_addr);
	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->qbase_lo, dma_addr_lo);
	dma_addr_hi = high32_value(cmd_q->qbase_phys_addr);
	AE4DMA_WRITE_REG(&cmd_q->hwq_regs->qbase_hi, dma_addr_hi);

	return 0;
}

static void
ae4dma_channel_dev_name(char *out, size_t outlen, const char *pci_name,
		unsigned int ch)
{
	snprintf(out, outlen, "%s-ch%u", pci_name, ch);
}

/* Create a dmadev(dpdk DMA device) */
static int
ae4dma_dmadev_create(const char *name, struct rte_pci_device *dev, uint8_t qn)
{
	static const struct rte_dma_dev_ops ae4dma_dmadev_ops = {
		.dev_close = ae4dma_dev_close,
		.dev_configure = ae4dma_dev_configure,
		.dev_dump = ae4dma_dev_dump,
		.dev_info_get = ae4dma_dev_info_get,
		.dev_start = ae4dma_dev_start,
		.dev_stop = ae4dma_dev_stop,
		.stats_get = ae4dma_stats_get,
		.stats_reset = ae4dma_stats_reset,
		.vchan_status = ae4dma_vchan_status,
		.vchan_setup = ae4dma_vchan_setup,
	};

	struct rte_dma_dev *dmadev = NULL;
	struct ae4dma_dmadev *ae4dma = NULL;
	char hwq_dev_name[RTE_DEV_NAME_MAX_LEN];

	if (!name) {
		AE4DMA_PMD_ERR("Invalid name of the device!");
		return -EINVAL;
	}
	memset(hwq_dev_name, 0, sizeof(hwq_dev_name));
	ae4dma_channel_dev_name(hwq_dev_name, sizeof(hwq_dev_name), name, qn);

	dmadev = rte_dma_pmd_allocate(hwq_dev_name, dev->device.numa_node,
			sizeof(struct ae4dma_dmadev));
	if (dmadev == NULL) {
		AE4DMA_PMD_ERR("Unable to allocate dma device");
		return -ENOMEM;
	}
	dmadev->device = &dev->device;
	dmadev->fp_obj->dev_private = dmadev->data->dev_private;
	dmadev->dev_ops = &ae4dma_dmadev_ops;

	ae4dma = dmadev->data->dev_private;
	ae4dma->dmadev = dmadev;
	ae4dma->pci = dev;

	if (ae4dma_add_queue(ae4dma, qn, name) != 0)
		goto init_error;
	return 0;

init_error:
	AE4DMA_PMD_ERR("driver %s(): failed", __func__);
	rte_dma_pmd_release(hwq_dev_name);
	return -ENOMEM;
}

/* Probe DMA device. */
static int
ae4dma_dmadev_probe(struct rte_pci_driver *drv, struct rte_pci_device *dev)
{
	char name[32];
	char chname[RTE_DEV_NAME_MAX_LEN];
	void *mmio_base;
	uint32_t q_per_eng;
	int ret = 0;
	uint8_t i;

	rte_pci_device_name(&dev->addr, name, sizeof(name));
	AE4DMA_PMD_INFO("Init %s on NUMA node %d", name, dev->device.numa_node);
	dev->device.driver = &drv->driver;

	mmio_base = dev->mem_resource[AE4DMA_PCIE_BAR].addr;
	if (mmio_base == NULL) {
		AE4DMA_PMD_ERR("%s: BAR%d not mapped", name, AE4DMA_PCIE_BAR);
		return -ENODEV;
	}

	/* Program the per-engine HW queue count once. */
	AE4DMA_WRITE_REG_OFFSET(mmio_base, AE4DMA_COMMON_CONFIG_OFFSET,
			AE4DMA_MAX_HW_QUEUES);
	q_per_eng = AE4DMA_READ_REG_OFFSET(mmio_base, AE4DMA_COMMON_CONFIG_OFFSET);
	AE4DMA_PMD_INFO("%s: AE4DMA queues per engine = %u", name, q_per_eng);

	for (i = 0; i < AE4DMA_MAX_HW_QUEUES; i++) {
		ret = ae4dma_dmadev_create(name, dev, i);
		if (ret != 0) {
			AE4DMA_PMD_ERR("%s create dmadev %u failed!", name, i);
			while (i > 0) {
				i--;
				ae4dma_channel_dev_name(chname, sizeof(chname), name, i);
				rte_dma_pmd_release(chname);
			}
			break;
		}
	}
	return ret;
}

/* Remove DMA device. */
static int
ae4dma_dmadev_remove(struct rte_pci_device *dev)
{
	char name[32];
	char chname[RTE_DEV_NAME_MAX_LEN];
	unsigned int i;

	rte_pci_device_name(&dev->addr, name, sizeof(name));

	AE4DMA_PMD_INFO("Closing %s on NUMA node %d",
			name, dev->device.numa_node);

	for (i = 0; i < AE4DMA_MAX_HW_QUEUES; i++) {
		ae4dma_channel_dev_name(chname, sizeof(chname), name, i);
		rte_dma_pmd_release(chname);
	}
	return 0;
}

static const struct rte_pci_id pci_id_ae4dma_map[] = {
	{ RTE_PCI_DEVICE(AMD_VENDOR_ID, AE4DMA_DEVICE_ID) },
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver ae4dma_pmd_drv = {
	.id_table = pci_id_ae4dma_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = ae4dma_dmadev_probe,
	.remove = ae4dma_dmadev_remove,
};

RTE_PMD_REGISTER_PCI(AE4DMA_PMD_NAME, ae4dma_pmd_drv);
RTE_PMD_REGISTER_PCI_TABLE(AE4DMA_PMD_NAME, pci_id_ae4dma_map);
RTE_PMD_REGISTER_KMOD_DEP(AE4DMA_PMD_NAME, "* igb_uio | uio_pci_generic | vfio-pci");
