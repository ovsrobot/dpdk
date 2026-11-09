/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */
#ifndef __MCDMA_ETH_H_
#define __MCDMA_ETH_H_

#include <stddef.h>
#include <stdbool.h>

#include <ethdev_driver.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>

#include "mcdma_config_csr.h"

extern int mcdma_logtype_driver;
#define RTE_LOGTYPE_MCDMA_DRIVER mcdma_logtype_driver
#define PMD_DRV_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, MCDMA_DRIVER, "%s(): ", __func__, __VA_ARGS__)

#define MCDMA_LOG_ENABLE		1
#if MCDMA_LOG_ENABLE
#define PMD_DRV_LOG_DBG(level, ...) PMD_DRV_LOG(level, __VA_ARGS__)
#else
#define PMD_DRV_LOG_DBG(level, ...) RTE_SET_USED(level)
#endif
/* PCI resource */
#define MCDMA_BAR_MAX			6
#define MCDMA_CONFIG_BAR		0
#define MCDMA_PIO_BAR			2

/* SW resource and flags - start */
#define MCDMA_COMPL_WB			1	/* compl status: Write back */
#define MCDMA_MAX_PYLD_CNT		1048576
#define MCDMA_MAX_BURST			32
#define MCDMA_MAX_MAC_ADDRS		1
#define MCDMA_MIN_MTU			0x40
#define MCDMA_DIR_D2H			0
#define MCDMA_DIR_H2D			1
#define MCDMA_BATCH_DESC_DELAY		1
#define MCDMA_IP_MAX_FRAME_LEN		0x1FFFFF	/* HW descriptor len (20-bit) */
#define MCDMA_RX_ETH_OVERHEAD		(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN)
#define MCDMA_MAX_RX_FRAME_LEN		MCDMA_IP_MAX_FRAME_LEN
#define MCDMA_MAX_MTU \
	((uint16_t)RTE_MIN((uint32_t)(MCDMA_MAX_RX_FRAME_LEN - \
			    MCDMA_RX_ETH_OVERHEAD), (uint32_t)UINT16_MAX))
#define MCDMA_TX_MZONE_NAME		"TxHwRn"
#define MCDMA_RX_MZONE_NAME		"RxHwRn"
#define MCDMA_Q_RESET_TO		300000
#define MCDMA_SW_RESET_DELAY_MS		1000
#define MCDMA_DESC_SOF			RTE_BIT64(0)
#define MCDMA_DESC_EOF			RTE_BIT64(1)

#define MCDMA_CNT_HEAD_MOVE		100000
/* SW resource and flags - end */

/* HW resource - start */
#define MCDMA_MAX_PF			8
#define MCDMA_MAX_VF_PER_PF		2048
#define MCDMA_DESC_PAGE_SIZE		4096
#define MCDMA_DESC_LEN			32
#define MCDMA_NUM_DESC_PER_PAGE		(MCDMA_DESC_PAGE_SIZE / MCDMA_DESC_LEN)
#define MCDMA_NUM_DESC_BITS		16
/* HW ring capacity: 16-bit didx index space (1 << 16 descriptors) */
#define MCDMA_MAX_DESCS			(1U << MCDMA_NUM_DESC_BITS)
/*
 * Max ring depth exposed via ethdev (nb_*_desc is uint16_t): power of 2,
 * MCDMA_NUM_DESC_PER_PAGE-aligned; largest value the PMD accepts.
 */
#define MCDMA_MAX_RING_DESCS		(1U << (MCDMA_NUM_DESC_BITS - 1))
#define MCDMA_IFC_DATA_WIDTH		512

/* tail/head/cmpl ptr: [15:0] */
#define MCDMA_PTR_MASK			0xFFFF
/* HW resource - end */

/* Num QCSR per direction per device. 2048 for H2D and 2048 for D2H */
#define MCDMA_QCSR_NUM_MAX_PER_DIR	2048
#define MCDMA_QCSR_SIZE			256
#define MCDMA_QCSR_H2D_OFFSET		(MCDMA_QCSR_NUM_MAX_PER_DIR * MCDMA_QCSR_SIZE)

/* Max DMA channel per function */
#define MCDMA_MAX_CHAN_PER_FUNC		512
#define MCDMA_MAX_CHAN			2048

/* Config space CSR offset */
typedef enum {
	MCDMA_CONFIG_QCSR,
	MCDMA_CONFIG_MSIX,
	MCDMA_CONFIG_CSR,
	MCDMA_CONFIG_MBOX_CSR,
	MCDMA_CONFIG_DCA_CSR,
	MCDMA_MAX_CONFIGS,
} mcdma_config_idx_t;

struct mcdma_config_map {
	unsigned int idx;
	size_t offset;
};

struct mcdma_desc {
	uint64_t src;
	uint64_t dest;
	uint32_t len:20;
	uint32_t rsvd:12;
	uint32_t didx:16;
	uint32_t msix_en:1;
	uint32_t wb_en:1;
	uint32_t rsvd2:14;
	uint32_t rx_pyld_cnt:20;
	uint32_t rsvd3:10;
	uint32_t sof:1;
	uint32_t eof:1;
	uint32_t rsvd5:28;
	uint32_t pad_len:2;
	uint32_t desc_invalid:1;
	uint32_t link:1;
};

struct mcdma_queue {
	struct rte_eth_dev *ethdev;
	void *qcsr;
	struct rte_mbuf **sw_ring;
	struct rte_mempool *mb_pool;
	void *qbuf;
	uint64_t qbuf_dma;
	uint32_t qid;
	int socket_id;
	uint32_t dir;
	uint32_t num_desc_pages;
	uint32_t num_descs;
	uint32_t wbe;

	/* SW shadow of last freed HW didx (1 .. num_descs), 0 = none freed */
	volatile uint16_t freed_cons_didx;
	/* Last filled descriptor HW didx (1 .. num_descs), 0 = none */
	uint16_t prod_didx;
	/* HW writeback: last completed didx (1 .. num_descs), 0 = none */
	volatile uint16_t cons_didx;
	/* Last tail submit HW didx (1 .. num_descs), 0 = none */
	uint16_t submitted_didx;
	uint16_t ring_avail;
	uint16_t ring_to_submit;
	uint16_t processed_cur;
	/* 16 bits - Monotonic index and IP requires it to start from 1 */
	uint16_t didx;
	uint16_t burst_size;
	/** D2H: DMA length per buffer descriptor (full frame, <= mbuf data room). */
	uint32_t rx_seg_len;

	uint64_t rx_pkts;
	uint64_t rx_bytes;
	uint64_t tx_pkts;
	uint64_t tx_bytes;
	uint64_t drop_pkts;
	uint64_t rx_nombuf;
	uint64_t complete;
};

#define MCDMA_DESC_PTR(q, prod) \
	((struct mcdma_desc *)((uint8_t *)(q)->qbuf + \
	 sizeof(struct mcdma_desc) * (prod)))
#define MCDMA_NEXT_IDX(prod, qlen)  ((((uint32_t)(prod)) + 1) % (qlen))
#define MCDMA_PREV_IDX(cur, qlen) \
	({ \
		uint32_t _cur = (uint32_t)(cur); \
		uint32_t _qlen = (uint32_t)(qlen); \
		(_cur + _qlen - 1) % _qlen; \
	})
#define MCDMA_RING_AVAIL_COUNT(cur, base, size) \
	({ \
		uint32_t _cur = (uint32_t)(cur); \
		uint32_t _base = (uint32_t)(base); \
		uint32_t _size = (uint32_t)(size); \
		_cur < _base ? _base - _cur : _size - _cur + _base; \
	})
#define MCDMA_RING_USED_COUNT(cur, base, size) \
	({ \
		uint32_t _cur = (uint32_t)(cur); \
		uint32_t _base = (uint32_t)(base); \
		uint32_t _size = (uint32_t)(size); \
		_cur >= _base ? _cur - _base : _size - _base + _cur; \
	})

/* Monotonic descriptor didx assigned to d->didx; wraps at MCDMA_MAX_DESCS. */
#define MCDMA_DIDX_NEXT(cur, num_descs) \
	((uint16_t)((((uint16_t)(cur) + 1) % (num_descs))))

/* HW descriptor didx is 1-based (1 .. num_descs); ring slots are 0-based. */
#define MCDMA_RING_TO_HW_DIDX(ring_idx, num_descs) \
	((uint16_t)(((uint16_t)(ring_idx) % (uint16_t)(num_descs)) + 1))

static inline uint16_t
mcdma_hw_didx_to_ring(uint16_t hw_didx, uint16_t num_descs)
{
	if (hw_didx == 0)
		return num_descs - 1;

	return hw_didx - 1;
}

static inline uint16_t
mcdma_hw_didx_nudge(uint16_t hw_didx, uint16_t num_descs)
{
	hw_didx++;
	if (hw_didx > num_descs)
		return 1;

	return hw_didx;
}

static inline uint16_t
mcdma_qcsr_ptr_val(uint32_t reg)
{
	return (uint16_t)(reg & MCDMA_PTR_MASK);
}

static inline uint16_t
mcdma_queue_cons_ring(const struct mcdma_queue *q)
{
	return mcdma_hw_didx_to_ring(q->cons_didx, q->num_descs);
}

static inline uint16_t
mcdma_queue_freed_ring(const struct mcdma_queue *q)
{
	return mcdma_hw_didx_to_ring(q->freed_cons_didx, q->num_descs);
}

static inline uint16_t
mcdma_queue_prod_ring(const struct mcdma_queue *q)
{
	return mcdma_hw_didx_to_ring(q->prod_didx, q->num_descs);
}

struct mcdma_pci_device {
	struct rte_eth_dev *dev;
	/* config */
	void *bar_base;
	/* BAR region for user logic */
	uint64_t *pio;
	/** Size in bytes of the mapped PIO BAR (0 if unmapped). */
	uint64_t pio_bar_len;
	/* BAR region Bursting AVMM master */
	uint64_t *bam;
	/* num channels configured in IP */
	int ip_num_chan;
	bool is_pf;
	uint8_t pf_idx;
	uint8_t parent_pf_idx;
};

void *mcdma_get_csraddr(void *base, unsigned int idx);

static inline uint32_t mcdma_qcsr_reg_readl(void *base, uint32_t offset)
{
	void *addr = (uint8_t *)base + offset;

	return mcdma_reg_readl(addr);
}

static inline void mcdma_qcsr_reg_writel(void *base, uint32_t offset, uint32_t val)
{
	void *addr = (uint8_t *)base + offset;

	mcdma_reg_writel(addr, val);
}

static inline void mcdma_qcsr_reg_updatel(void *base, uint32_t offset,
					  uint32_t val, uint32_t shift, uint32_t mask)
{
	mcdma_reg_updatel(base, offset, val, shift, mask);
}

/* Except few registers all register access are restricted only to pf0 */
static inline uint32_t mcdma_dmacsr_reg_readl(void *base, mcdma_csr_offset_t offset)
{
	void *addr = (uint8_t *)mcdma_get_csraddr(base, MCDMA_CONFIG_CSR) + offset;

	return mcdma_reg_readl(addr);
}

static inline void mcdma_dmacsr_reg_writel(void *base, mcdma_csr_offset_t offset,
					     uint32_t val)
{
	void *addr = (uint8_t *)mcdma_get_csraddr(base, MCDMA_CONFIG_CSR) + offset;

	mcdma_reg_writel(addr, val);
}

static inline void mcdma_dmacsr_reg_updatel(void *base, mcdma_csr_offset_t offset,
					    uint32_t val, uint32_t shift, uint32_t mask)
{
	void *csr = mcdma_get_csraddr(base, MCDMA_CONFIG_CSR);

	mcdma_reg_updatel(csr, offset, val, shift, mask);
}

static inline uint32_t mcdma_pio_reg_readl(void *pio, uint32_t offset)
{
	void *addr = (uint8_t *)pio + offset;

	return mcdma_reg_readl(addr);
}

static inline void mcdma_pio_reg_writel(void *pio, uint32_t offset, uint32_t val)
{
	void *addr = (uint8_t *)pio + offset;

	mcdma_reg_writel(addr, val);
}

static inline uint64_t mcdma_pio_reg_read64(void *pio, uint64_t offset)
{
	volatile void *addr = (uint8_t *)pio + offset;

	return *(volatile uint64_t *)addr;
}

static inline void mcdma_pio_reg_write64(void *pio, uint64_t offset, uint64_t val)
{
	volatile void *addr = (uint8_t *)pio + offset;

	*(volatile uint64_t *)addr = val;
}

void mcdma_ethdev_ops_init(struct rte_eth_dev *dev);
uint16_t mcdma_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t mcdma_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
int mcdma_dev_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
			struct eth_queue_stats *qstats);

#endif /* __MCDMA_ETH_H_ */
