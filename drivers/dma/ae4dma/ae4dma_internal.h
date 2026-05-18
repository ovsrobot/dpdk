/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef _AE4DMA_INTERNAL_H_
#define _AE4DMA_INTERNAL_H_

#include <stdint.h>

#include "ae4dma_hw_defs.h"

/**
 * upper_32_bits - return bits 32-63 of a number
 * @n: the number we're accessing
 */
#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))

/**
 * lower_32_bits - return bits 0-31 of a number
 * @n: the number we're accessing
 */
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffff))

/** Hardware ring depth (slots per queue); must be power of two. */
#define AE4DMA_DESCRIPTORS_PER_CMDQ	32
#define AE4DMA_QUEUE_DESC_SIZE		sizeof(struct ae4dma_desc)
#define AE4DMA_QUEUE_SIZE(n)		(AE4DMA_DESCRIPTORS_PER_CMDQ * (n))


/** AE4DMA registers Write/Read */
static inline void ae4dma_pci_reg_write(void *base, int offset,
		uint32_t value)
{
	volatile void *reg_addr = ((uint8_t *)base + offset);

	rte_write32((rte_cpu_to_le_32(value)), reg_addr);
}

static inline uint32_t ae4dma_pci_reg_read(void *base, int offset)
{
	volatile void *reg_addr = ((uint8_t *)base + offset);

	return rte_le_to_cpu_32(rte_read32(reg_addr));
}

#define AE4DMA_READ_REG_OFFSET(hw_addr, reg_offset) \
	ae4dma_pci_reg_read(hw_addr, reg_offset)

#define AE4DMA_WRITE_REG_OFFSET(hw_addr, reg_offset, value) \
	ae4dma_pci_reg_write(hw_addr, reg_offset, value)


#define AE4DMA_READ_REG(hw_addr) \
	ae4dma_pci_reg_read((void *)(uintptr_t)(hw_addr), 0)

#define AE4DMA_WRITE_REG(hw_addr, value) \
	ae4dma_pci_reg_write((void *)(uintptr_t)(hw_addr), 0, value)

static inline uint32_t
low32_value(unsigned long addr)
{
	return ((uint64_t)addr) & 0xffffffffUL;
}

static inline uint32_t
high32_value(unsigned long addr)
{
	return (uint32_t)(((uint64_t)addr) >> 32);
}

/**
 * A structure describing a AE4DMA command queue.
 */
struct ae4dma_cmd_queue {
	char memz_name[RTE_MEMZONE_NAMESIZE];
	volatile struct ae4dma_hwq_regs *hwq_regs;

	struct rte_dma_vchan_conf qcfg;
	struct rte_dma_stats stats;
	/* Queue address */
	struct ae4dma_desc *qbase_desc;
	void *qbase_addr;
	phys_addr_t qbase_phys_addr;
	enum ae4dma_dma_err status[AE4DMA_DESCRIPTORS_PER_CMDQ];
	/* Queue identifier */
	uint64_t id;    /**< queue id */
	uint64_t qidx;  /**< queue index */
	uint64_t qsize; /**< queue size */
	uint32_t ring_buff_count;
	unsigned short next_read;
	unsigned short next_write;
	unsigned short last_write; /* Used to compute submitted count. */
} __rte_cache_aligned;

/*
 * One dmadev per AE4DMA hardware channel: probe creates AE4DMA_MAX_HW_QUEUES
 * dmadevs per PCI function, each owning a single HW command queue.
 */
struct ae4dma_dmadev {
	struct rte_dma_dev *dmadev;
	void *io_regs;
	struct ae4dma_cmd_queue cmd_q; /**< single HW queue owned by this dmadev */
	struct rte_pci_device *pci;    /**< owning PCI device (not owned) */
};


extern int ae4dma_pmd_logtype;

#define AE4DMA_PMD_LOG(level, fmt, args...) rte_log(RTE_LOG_ ## level, \
		ae4dma_pmd_logtype, "AE4DMA: %s(): " fmt "\n", __func__, ##args)

#define AE4DMA_PMD_DEBUG(fmt, args...)  AE4DMA_PMD_LOG(DEBUG, fmt, ## args)
#define AE4DMA_PMD_INFO(fmt, args...)   AE4DMA_PMD_LOG(INFO, fmt, ## args)
#define AE4DMA_PMD_ERR(fmt, args...)    AE4DMA_PMD_LOG(ERR, fmt, ## args)
#define AE4DMA_PMD_WARN(fmt, args...)   AE4DMA_PMD_LOG(WARNING, fmt, ## args)

#endif /* _AE4DMA_INTERNAL_H_ */
