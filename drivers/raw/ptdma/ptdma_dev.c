/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/file.h>
#include <unistd.h>

#include <rte_hexdump.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_spinlock.h>
#include <rte_string_fns.h>

#include "ptdma_rawdev_spec.h"
#include "ptdma_pmd_private.h"
#include "rte_ptdma_rawdev_fns.h"

int iommu_mode;
static int ptdma_dev_id;

static const struct rte_memzone *
ptdma_queue_dma_zone_reserve(const char *queue_name,
			   uint32_t queue_size,
			   int socket_id)
{
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(queue_name);
	if (mz != 0) {
		if (((size_t)queue_size <= mz->len) &&
		    ((socket_id == SOCKET_ID_ANY) ||
		     (socket_id == mz->socket_id))) {
			PTDMA_PMD_INFO("re-use memzone already "
				     "allocated for %s", queue_name);
			return mz;
		}
		PTDMA_PMD_ERR("Incompatible memzone already "
			    "allocated %s, size %u, socket %d. "
			    "Requested size %u, socket %u",
			    queue_name, (uint32_t)mz->len,
			    mz->socket_id, queue_size, socket_id);
		return NULL;
	}

	PTDMA_PMD_INFO("Allocate memzone for %s, size %u on socket %u",
		     queue_name, queue_size, socket_id);

	return rte_memzone_reserve_aligned(queue_name, queue_size,
			socket_id, RTE_MEMZONE_IOVA_CONTIG, queue_size);
}

int
ptdma_add_queue(struct ptdma_device *dev)
{
	int i;
	uint32_t dma_addr_lo, dma_addr_hi;
	uint32_t ptdma_version = 0;
	struct ptdma_cmd_queue *cmd_q;
	const struct rte_memzone *q_mz;
	void *vaddr;

	if (dev == NULL)
		return -1;

	dev->id = ptdma_dev_id++;
	dev->qidx = 0;
	vaddr = (void *)(dev->pci.mem_resource[2].addr);

	PTDMA_WRITE_REG(vaddr, CMD_REQID_CONFIG_OFFSET, 0x0);
	ptdma_version = PTDMA_READ_REG(vaddr, CMD_PTDMA_VERSION);
	PTDMA_PMD_INFO("PTDMA VERSION  = 0x%x", ptdma_version);

	dev->cmd_q_count = 0;
	/* Find available queues */
	for (i = 0; i < MAX_HW_QUEUES; i++) {
		cmd_q = &dev->cmd_q[dev->cmd_q_count++];
		cmd_q->dev = dev;
		cmd_q->id = i;
		cmd_q->qidx = 0;
		cmd_q->qsize = Q_SIZE(Q_DESC_SIZE);

		cmd_q->reg_base = (uint8_t *)vaddr +
			CMD_Q_STATUS_INCR * (i + 1);

		/* PTDMA queue memory */
		snprintf(cmd_q->memz_name, sizeof(cmd_q->memz_name),
			 "%s_%d_%s_%d_%s",
			 "ptdma_dev",
			 (int)dev->id, "queue",
			 (int)cmd_q->id, "mem");
		q_mz = ptdma_queue_dma_zone_reserve(cmd_q->memz_name,
				cmd_q->qsize, dev->pci.device.numa_node);
		cmd_q->qbase_addr = (void *)q_mz->addr;
		cmd_q->qbase_desc = (void *)q_mz->addr;
		cmd_q->qbase_phys_addr =  q_mz->iova;

		cmd_q->qcontrol = 0;
		/* init control reg to zero */
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_CONTROL_BASE,
			      cmd_q->qcontrol);

		/* Disable the interrupts */
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_INT_ENABLE_BASE, 0x00);
		PTDMA_READ_REG(cmd_q->reg_base, CMD_Q_INT_STATUS_BASE);
		PTDMA_READ_REG(cmd_q->reg_base, CMD_Q_STATUS_BASE);

		/* Clear the interrupts */
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_INTERRUPT_STATUS_BASE,
			      ALL_INTERRUPTS);

		/* Configure size of each virtual queue accessible to host */
		cmd_q->qcontrol &= ~(CMD_Q_SIZE << CMD_Q_SHIFT);
		cmd_q->qcontrol |= QUEUE_SIZE_VAL << CMD_Q_SHIFT;

		dma_addr_lo = low32_value(cmd_q->qbase_phys_addr);
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_TAIL_LO_BASE,
			      (uint32_t)dma_addr_lo);
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_HEAD_LO_BASE,
			      (uint32_t)dma_addr_lo);

		dma_addr_hi = high32_value(cmd_q->qbase_phys_addr);
		cmd_q->qcontrol |= (dma_addr_hi << 16);
		PTDMA_WRITE_REG(cmd_q->reg_base, CMD_Q_CONTROL_BASE,
			      cmd_q->qcontrol);

	}
	return 0;
}
