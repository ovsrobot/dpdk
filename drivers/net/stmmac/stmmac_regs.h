/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Qualcomm Technologies, Inc.
 */

#ifndef _STMMAC_REGS_H_
#define _STMMAC_REGS_H_

#include <stdint.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_io.h>

/*
 * Register and bitfield definitions for the Synopsys DWC EQoS GMAC4 core
 * ("stmmac" / "dwmac4" in the Linux driver family). Offsets and bit positions
 * follow drivers/net/ethernet/stmicro/stmmac/{dwmac4.h, dwmac4_dma.h,
 * dwmac4_descs.h, descs.h, stmmac_mdio.c, dwmac4_core.c}.
 */

/*
 * Per-channel DMA/MTL register stride. The generic dwmac4 layout is used by
 * default; platforms with has_emac_ge_3 use a 0x1000 stride.
 */
struct stmmac_chan_addrs {
	uint32_t dma_chan_base;
	uint32_t dma_chan_stride;
	uint32_t mtl_chan_base;
	uint32_t mtl_chan_stride;
};

/* ---------------------------------------------------------------- */
/* MAC registers                                                     */
/* ---------------------------------------------------------------- */

#define GMAC_CONFIG			0x00000000
#define GMAC_PACKET_FILTER		0x00000008
#define GMAC_HW_FEATURE1		0x00000120
#define GMAC_MDIO_ADDR			0x00000200
#define GMAC_MDIO_DATA			0x00000204
#define GMAC_RXQ_CTRL0			0x000000a0
#define GMAC_ADDR_HIGH(reg)		(0x300 + (reg) * 8)
#define GMAC_ADDR_LOW(reg)		(0x304 + (reg) * 8)

/* GMAC_CONFIG bits */
#define GMAC_CONFIG_IPC			RTE_BIT32(27)
#define GMAC_CONFIG_ACS			RTE_BIT32(20)
#define GMAC_CONFIG_TE			RTE_BIT32(1)
#define GMAC_CONFIG_RE			RTE_BIT32(0)

/* GMAC_PACKET_FILTER bits */
#define GMAC_PACKET_FILTER_PR		RTE_BIT32(0)

/* GMAC_HW_FEATURE1: RX/TX FIFO size encodings */
#define GMAC_HWF1_RXFIFOSIZE_MASK	0x1fu		/* [4:0]  */
#define GMAC_HWF1_TXFIFOSIZE_SHIFT	6		/* [10:6] */
#define GMAC_HWF1_TXFIFOSIZE_MASK	0x1fu

/* ---------------------------------------------------------------- */
/* MTL registers                                                     */
/* ---------------------------------------------------------------- */

#define MTL_CHAN_BASE_ADDR		0x00000d00
#define MTL_CHAN_BASE_OFFSET		0x40
#define MTL_RXQ_DMA_MAP0		0x00000c30

static inline uint32_t
stmmac_mtl_chan_base(const struct stmmac_chan_addrs *addrs, uint32_t x)
{
	if (addrs != NULL)
		return addrs->mtl_chan_base + x * addrs->mtl_chan_stride;
	return MTL_CHAN_BASE_ADDR + x * MTL_CHAN_BASE_OFFSET;
}

#define MTL_CHAN_TX_OP_MODE(addrs, x) \
	(stmmac_mtl_chan_base((addrs), (x)))
#define MTL_CHAN_RX_OP_MODE(addrs, x) \
	(stmmac_mtl_chan_base((addrs), (x)) + 0x30)

#define MTL_OP_MODE_TSF			RTE_BIT32(1)
#define MTL_OP_MODE_TXQEN		RTE_BIT32(3)
#define MTL_OP_MODE_TXQEN_MASK		(0x3u << 2)
#define MTL_OP_MODE_RSF			RTE_BIT32(5)
#define MTL_OP_MODE_TQS_MASK		(0x1ffu << 16)
#define MTL_OP_MODE_TQS_SHIFT		16
#define MTL_OP_MODE_RQS_MASK		(0x3ffu << 20)
#define MTL_OP_MODE_RQS_SHIFT		20

/* ---------------------------------------------------------------- */
/* DMA registers                                                     */
/* ---------------------------------------------------------------- */

#define DMA_BUS_MODE			0x00001000
#define DMA_SYS_BUS_MODE		0x00001004
#define DMA_AXI_BUS_MODE		0x00001028

#define DMA_BUS_MODE_SFT_RESET		RTE_BIT32(0)

/* DMA_SYS_BUS_MODE bits */
#define DMA_SYS_BUS_MB			RTE_BIT32(14)
#define DMA_SYS_BUS_AAL			RTE_BIT32(12)
#define DMA_SYS_BUS_EAME		RTE_BIT32(11)
#define DMA_SYS_BUS_FB			RTE_BIT32(0)

/* DMA_AXI_BUS_MODE bits */
#define DMA_AXI_WR_OSR_LMT		(0xfu << 24)
#define DMA_AXI_WR_OSR_LMT_SHIFT	24
#define DMA_AXI_RD_OSR_LMT		(0xfu << 16)
#define DMA_AXI_RD_OSR_LMT_SHIFT	16
#define DMA_AXI_BLEN16			RTE_BIT32(3)
#define DMA_AXI_OSR_MAX			0xf

/* Per-channel DMA registers */
#define DMA_CHAN_BASE_ADDR		0x00001100
#define DMA_CHAN_BASE_OFFSET		0x80

static inline uint32_t
stmmac_dma_chan_base(const struct stmmac_chan_addrs *addrs, uint32_t x)
{
	if (addrs != NULL)
		return addrs->dma_chan_base + x * addrs->dma_chan_stride;
	return DMA_CHAN_BASE_ADDR + x * DMA_CHAN_BASE_OFFSET;
}

/*
 * Offsets relative to a resolved per-channel base (chan_base already holds
 * mac_base + stmmac_dma_chan_base(addrs, 0)).
 */
#define DMA_CHAN_OFF_CONTROL		0x00
#define DMA_CHAN_OFF_TX_CONTROL		0x04
#define DMA_CHAN_OFF_RX_CONTROL		0x08
#define DMA_CHAN_OFF_TX_BASE_ADDR_HI	0x10
#define DMA_CHAN_OFF_TX_BASE_ADDR	0x14
#define DMA_CHAN_OFF_RX_BASE_ADDR_HI	0x18
#define DMA_CHAN_OFF_RX_BASE_ADDR	0x1c
#define DMA_CHAN_OFF_RX_END_ADDR_HI	0x24
#define DMA_CHAN_OFF_TX_END_ADDR	0x20
#define DMA_CHAN_OFF_RX_END_ADDR	0x28
#define DMA_CHAN_OFF_TX_RING_LEN	0x2c
#define DMA_CHAN_OFF_RX_RING_LEN	0x30
#define DMA_CHAN_OFF_CURTXD		0x44
#define DMA_CHAN_OFF_STATUS		0x60

#define DMA_CHAN_TX_CONTROL_OSP		RTE_BIT32(4)

/* DMA_CHAN_CONTROL / TX / RX control bits */
#define DMA_CONTROL_PBLX8		RTE_BIT32(16)
#define DMA_CONTROL_ST			RTE_BIT32(0)
#define DMA_CONTROL_RPF			RTE_BIT32(31)
#define DMA_CONTROL_SR			RTE_BIT32(0)
#define DMA_CONTROL_PBL_SHIFT		16
#define DMA_CONTROL_PBL_MASK		(0x3fu << DMA_CONTROL_PBL_SHIFT)
#define DMA_CONTROL_RBSZ_SHIFT		1
#define DMA_CONTROL_RBSZ_MASK		(0x3fffu << DMA_CONTROL_RBSZ_SHIFT)

/* DMA_CHAN_STATUS bits */
#define DMA_CHAN_STATUS_TI		RTE_BIT32(0)
#define DMA_CHAN_STATUS_RI		RTE_BIT32(6)
#define DMA_CHAN_STATUS_RBU		RTE_BIT32(7)

/*
 * The Shikra EMAC is not DMA-coherent: CPU writes to descriptors must be
 * cleaned to the point of coherency before the DMA reads them, and lines must
 * be invalidated before the CPU reads DMA write-back.
 */
#define STMMAC_CACHE_LINE		64
/* 16-byte descriptors, four per cache line; the ring base is 64-byte aligned */
#define STMMAC_DESCS_PER_LINE		(STMMAC_CACHE_LINE / 16)

/*
 * Cache maintenance for a non-coherent DMA (arm64). Clean writes CPU-written
 * lines back so the DMA reads them; flush also discards CPU copies before the
 * CPU reads DMA write-back. dsb orders the maintenance before the DMA sees it.
 */
static inline void
stmmac_dcache_clean(const void *addr, size_t len)
{
	uintptr_t p = (uintptr_t)addr & ~(uintptr_t)(STMMAC_CACHE_LINE - 1);
	uintptr_t end = (uintptr_t)addr + len;

	for (; p < end; p += STMMAC_CACHE_LINE)
		asm volatile("dc cvac, %0" : : "r"(p) : "memory");
	asm volatile("dsb sy" : : : "memory");
}

static inline void
stmmac_dcache_flush(const void *addr, size_t len)
{
	uintptr_t p = (uintptr_t)addr & ~(uintptr_t)(STMMAC_CACHE_LINE - 1);
	uintptr_t end = (uintptr_t)addr + len;

	for (; p < end; p += STMMAC_CACHE_LINE)
		asm volatile("dc civac, %0" : : "r"(p) : "memory");
	asm volatile("dsb sy" : : : "memory");
}

static inline void
stmmac_dcache_inval_line(const void *addr)
{
	asm volatile("dc civac, %0" : : "r"(addr) : "memory");
	rte_io_rmb();
}

/* ---------------------------------------------------------------- */
/* TX descriptor bits                                                */
/* ---------------------------------------------------------------- */

/* TDES2 (read format) */
#define TDES2_BUFFER1_SIZE_MASK		0x3fffu
#define TDES2_INTERRUPT_ON_COMPLETION	RTE_BIT32(31)

/* TDES3 (read format) */
#define TDES3_PACKET_SIZE_MASK		0x7fffu
#define TDES3_CHECKSUM_INSERTION_MASK	(0x3u << 16)
#define TDES3_CHECKSUM_INSERTION_SHIFT	16

/* Insert IP header and pseudo-header checksums */
#define TX_CIC_FULL			3

/* TDES3 (write-back and common) */
#define TDES3_ERROR_SUMMARY		RTE_BIT32(15)
#define TDES3_LAST_DESCRIPTOR		RTE_BIT32(28)
#define TDES3_FIRST_DESCRIPTOR		RTE_BIT32(29)
#define TDES3_CONTEXT_TYPE		RTE_BIT32(30)
#define TDES3_OWN			RTE_BIT32(31)

/* ---------------------------------------------------------------- */
/* RX descriptor bits                                                */
/* ---------------------------------------------------------------- */

/* RDES1 (write-back format) */
#define RDES1_IP_HDR_ERROR		RTE_BIT32(3)
#define RDES1_IPV4_HEADER		RTE_BIT32(4)
#define RDES1_IPV6_HEADER		RTE_BIT32(5)
#define RDES1_IP_CSUM_BYPASSED		RTE_BIT32(6)
#define RDES1_IP_CSUM_ERROR		RTE_BIT32(7)

/* RDES3 (write-back format) */
#define RDES3_PACKET_SIZE_MASK		0x7fffu
#define RDES3_ERROR_SUMMARY		RTE_BIT32(15)
#define RDES3_OVERFLOW_ERROR		RTE_BIT32(21)
#define RDES3_CRC_ERROR			RTE_BIT32(24)
#define RDES3_LAST_DESCRIPTOR		RTE_BIT32(28)
#define RDES3_FIRST_DESCRIPTOR		RTE_BIT32(29)
#define RDES3_CONTEXT_DESCRIPTOR	RTE_BIT32(30)

/* RDES3 (read format) */
#define RDES3_BUFFER1_VALID_ADDR	RTE_BIT32(24)
#define RDES3_INT_ON_COMPLETION_EN	RTE_BIT32(30)
#define RDES3_OWN			RTE_BIT32(31)

/* ---------------------------------------------------------------- */
/* MDIO                                                              */
/* ---------------------------------------------------------------- */

#define MII_BUSY			RTE_BIT32(0)
#define MII_DATA_MASK			0xffffu

#define MII_GMAC4_GOC_SHIFT		2
#define MII_GMAC4_WRITE			(1 << MII_GMAC4_GOC_SHIFT)
#define MII_GMAC4_READ			(3 << MII_GMAC4_GOC_SHIFT)

#define MII_ADDR_SHIFT			21
#define MII_ADDR_MASK			(0x1fu << MII_ADDR_SHIFT)
#define MII_REG_SHIFT			16
#define MII_REG_MASK			(0x1fu << MII_REG_SHIFT)

/* IEEE 802.3 clause-22 registers */
#define STMMAC_MII_BMSR			0x01
#define STMMAC_MII_BMSR_LSTATUS		RTE_BIT32(2)

/*
 * DP83867 PHY registers (clause-22 direct access).
 * PHYSTS bits: 15:14 speed (11 = 1000, 10 = 100, 01 = 10 Mb/s),
 * 13 duplex (1 = full), 10 link (not latched).
 */
#define DP83867_PHYSTS			0x11
#define DP83867_PHYSTS_LINK_BIT		RTE_BIT32(10)
#define DP83867_PHYSTS_SPEED_MASK	(RTE_BIT32(15) | RTE_BIT32(14))
#define DP83867_PHYSTS_SPEED_1G		RTE_BIT32(15)
#define DP83867_PHYSTS_SPEED_100M	RTE_BIT32(14)
#define DP83867_PHYSTS_DUPLEX_BIT	RTE_BIT32(13)

/* ---------------------------------------------------------------- */
/* Channel stride presets                                            */
/* ---------------------------------------------------------------- */

#define STMMAC_CHAN_ADDRS_GENERIC_INIT {		\
	.dma_chan_base   = DMA_CHAN_BASE_ADDR,		\
	.dma_chan_stride = DMA_CHAN_BASE_OFFSET,	\
	.mtl_chan_base   = MTL_CHAN_BASE_ADDR,		\
	.mtl_chan_stride = MTL_CHAN_BASE_OFFSET,	\
}

/* has_emac_ge_3 layout (dwmac-qcom-ethqos.c emac_v4_0_0_data) */
#define STMMAC_CHAN_ADDRS_EMAC_GE3_INIT {		\
	.dma_chan_base   = 0x8100,			\
	.dma_chan_stride = 0x1000,			\
	.mtl_chan_base   = 0x8000,			\
	.mtl_chan_stride = 0x1000,			\
}

#endif /* _STMMAC_REGS_H_ */
