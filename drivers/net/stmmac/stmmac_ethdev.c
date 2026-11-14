/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Qualcomm Technologies, Inc.
 *
 * DPDK poll-mode driver for the Synopsys DWC EQoS (GMAC4, "stmmac") MAC.
 *
 * Scope:
 *   - DMA channel 0 with one TX and one RX queue.
 *   - Polling only: the platform bus has no interrupt support, so TX and RX
 *     completion and link state are polled.
 *   - Single-segment mbufs only; no TSO, PTP, or secondary process support.
 *   - Link state from the DP83867 PHY (BMSR and PHYSTS), using generic
 *     IEEE 802.3 clause-22 MDIO.
 *   - The RGMII IO macro and the DP83867 RGMII delays are configured here.
 *     The kernel recovery driver handles the clocks and the PHY reset.
 */

#include <stdlib.h>
#include <string.h>

#include <bus_platform_driver.h>
#include <ethdev_driver.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_kvargs.h>
#include <rte_malloc.h>

#include "stmmac.h"
#include "stmmac_regs.h"
#include "stmmac_logs.h"

RTE_LOG_REGISTER_DEFAULT(stmmac_logtype_pmd, NOTICE);

#define STMMAC_DRIVER_NAME		net_stmmac

#define STMMAC_DEVARG_HAS_EMAC_GE_3	"has_emac_ge_3"
#define STMMAC_DEVARG_MDIO_ADDR		"mdio_addr"

/* Shikra EVK PHY (DP83867) MDIO address */
#define STMMAC_DEFAULT_MDIO_ADDR	7

#define STMMAC_DMA_RESET_POLL_US	1000
#define STMMAC_DMA_RESET_POLLS		1000	/* 1 s in total, as dwmac4_dma_reset() */

#define STMMAC_DMA_PBL			32
#define STMMAC_DMA_PBL_SHIFT		16
#define STMMAC_DMA_PBL_MASK		(0x3fu << STMMAC_DMA_PBL_SHIFT)

/* MTL RX/TX queue FIFO size fields (see stmmac_mtl_init) */
#define STMMAC_ACTIVE_QUEUES		1

/* Qualcomm RGMII IO macro and SDCC registers (offsets within the rgmii resource) */
#define RGMII_IO_MACRO_CONFIG		0x00
#define RGMII_IO_MACRO_CONFIG2		0x1c
#define SDCC_HC_REG_DLL_CONFIG		0x04
#define SDCC_USR_CTL			0x18

#define RGMII_CONFIG_FUNC_CLK_EN	RTE_BIT32(30)
#define RGMII_CFG_DDR_MODE		RTE_BIT32(0)
#define RGMII_CFG_PROG_SWAP		RTE_BIT32(1)
#define RGMII_CFG_LOOPBACK_EN		RTE_BIT32(2)
#define RGMII_CFG_BYPASS_TX_ID_EN	RTE_BIT32(3)
#define RGMII_CFG_POS_NEG_DATA_SEL	RTE_BIT32(23)
#define RGMII_CFG2_TX_TO_RX_LOOPBACK	RTE_BIT32(13)
#define RGMII_CFG2_RSVD_CONFIG15	(0x7fffu << 17)
#define RGMII_CFG2_RX_PROG_SWAP		RTE_BIT32(7)
#define RGMII_CFG2_DATA_DIV_CLK_SEL	RTE_BIT32(6)
#define RGMII_CFG2_TX_PHASE_SHIFT_EN	RTE_BIT32(5)
#define SDCC_DLL_CONFIG_PDN		RTE_BIT32(29)
#define SDCC_USR_CTL_DDR_BYPASS		RTE_BIT32(30)

/* DP83867 RGMII internal delays, set through the MMD indirect registers */
#define MII_PHYSID1			0x02
#define MII_PHYSID2			0x03
#define MII_REGCR			0x0d
#define MII_ADDAR			0x0e
#define MII_REGCR_ADDR			0x001f
#define MII_REGCR_DATA			0x401f
#define DP83867_RGMIICTL		0x0032
#define DP83867_RGMIIDCTL		0x0086
#define DP83867_RGMII_TX_CLK_DELAY_EN	RTE_BIT32(1)
#define DP83867_RGMII_RX_CLK_DELAY_EN	RTE_BIT32(0)
#define DP83867_RGMIIDCTL_2_00_NS	0x7
#define DP83867_PHYCTRL			0x10
#define DP83867_PHY_ID			0x2000a231

static const char * const stmmac_valid_args[] = {
	STMMAC_DEVARG_HAS_EMAC_GE_3,
	STMMAC_DEVARG_MDIO_ADDR,
	NULL,
};

static uint64_t dev_rx_offloads_sup = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;
static uint64_t dev_tx_offloads_sup = RTE_ETH_TX_OFFLOAD_IPV4_CKSUM |
				      RTE_ETH_TX_OFFLOAD_TCP_CKSUM |
				      RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

static int
stmmac_kvarg_handler(const char *key, const char *value, void *opaque)
{
	unsigned long v;
	char *end;

	RTE_SET_USED(key);

	v = strtoul(value, &end, 0);
	if (*end != '\0')
		return -EINVAL;

	*(uint32_t *)opaque = (uint32_t)v;
	return 0;
}

static void
stmmac_parse_devargs(struct rte_platform_device *pdev, struct stmmac_priv *priv)
{
	struct rte_kvargs *kvlist;
	uint32_t v;

	priv->has_emac_ge_3 = 1;
	priv->mdio_addr = STMMAC_DEFAULT_MDIO_ADDR;

	if (pdev->device.devargs == NULL ||
	    pdev->device.devargs->args == NULL)
		return;

	kvlist = rte_kvargs_parse(pdev->device.devargs->args,
				  stmmac_valid_args);
	if (kvlist == NULL)
		return;

	if (rte_kvargs_count(kvlist, STMMAC_DEVARG_HAS_EMAC_GE_3) > 0) {
		v = 0;
		if (rte_kvargs_process(kvlist, STMMAC_DEVARG_HAS_EMAC_GE_3,
				       stmmac_kvarg_handler, &v) == 0)
			priv->has_emac_ge_3 = (int)v;
	}

	if (rte_kvargs_count(kvlist, STMMAC_DEVARG_MDIO_ADDR) > 0) {
		v = 0;
		if (rte_kvargs_process(kvlist, STMMAC_DEVARG_MDIO_ADDR,
				       stmmac_kvarg_handler, &v) == 0)
			priv->mdio_addr = (uint16_t)v;
	}

	rte_kvargs_free(kvlist);
}

/*
 * Keep the RGMII IO macro clock enabled. Without FUNC_CLK_EN the DMA reset
 * can time out because the PHY clock is missing.
 */
static void
stmmac_rgmii_func_clk_en(struct stmmac_priv *priv)
{
	void *reg;

	if (priv->rgmii_base == NULL) {
		STMMAC_PMD_WARN("RGMII region not mapped, FUNC_CLK_EN not set");
		return;
	}
	reg = (uint8_t *)priv->rgmii_base + RGMII_IO_MACRO_CONFIG;
	rte_write32(rte_read32(reg) | RGMII_CONFIG_FUNC_CLK_EN, reg);
}

static void
stmmac_rgmii_rmw(struct stmmac_priv *priv, uint32_t off, uint32_t clr, uint32_t set)
{
	void *reg = (uint8_t *)priv->rgmii_base + off;

	rte_write32((rte_read32(reg) & ~clr) | set, reg);
}

/*
 * RGMII IO macro setup for rgmii-id at 1 Gb/s, as the kernel does at link-up.
 * The PHY adds the RGMII delays, so the MAC-side DLL is powered down and the
 * DDR path is bypassed. TX-to-RX loopback is disabled so RX data comes from
 * the PHY.
 */
static void
stmmac_rgmii_id_1g_init(struct stmmac_priv *priv)
{
	if (priv->rgmii_base == NULL)
		return;

	stmmac_rgmii_rmw(priv, SDCC_HC_REG_DLL_CONFIG, 0, SDCC_DLL_CONFIG_PDN);
	stmmac_rgmii_rmw(priv, SDCC_USR_CTL, 0, SDCC_USR_CTL_DDR_BYPASS);

	stmmac_rgmii_rmw(priv, RGMII_IO_MACRO_CONFIG2, RGMII_CFG2_TX_TO_RX_LOOPBACK, 0);
	stmmac_rgmii_rmw(priv, RGMII_IO_MACRO_CONFIG,
			 RGMII_CFG_POS_NEG_DATA_SEL | RGMII_CFG_PROG_SWAP |
			 RGMII_CFG_LOOPBACK_EN,
			 RGMII_CFG_DDR_MODE | RGMII_CFG_BYPASS_TX_ID_EN);
	stmmac_rgmii_rmw(priv, RGMII_IO_MACRO_CONFIG2,
			 RGMII_CFG2_DATA_DIV_CLK_SEL | RGMII_CFG2_TX_PHASE_SHIFT_EN |
			 RGMII_CFG2_RSVD_CONFIG15,
			 RGMII_CFG2_RX_PROG_SWAP);
}

static uint16_t
stmmac_phy_mmd_read(struct stmmac_priv *priv, uint16_t reg)
{
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_REGCR, MII_REGCR_ADDR);
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_ADDAR, reg);
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_REGCR, MII_REGCR_DATA);
	return stmmac_mdio_read(priv->mac_base, priv->mdio_addr, MII_ADDAR);
}

static void
stmmac_phy_mmd_write(struct stmmac_priv *priv, uint16_t reg, uint16_t val)
{
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_REGCR, MII_REGCR_ADDR);
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_ADDAR, reg);
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_REGCR, MII_REGCR_DATA);
	stmmac_mdio_write(priv->mac_base, priv->mdio_addr, MII_ADDAR, val);
}

/*
 * Set the DP83867 RGMII internal delays to 2.00 ns on both TX and RX. The
 * kernel does the same for phy-mode "rgmii-id". The MAC does not add these
 * delays, so without them RX frames are sampled off the data eye.
 */
static void
stmmac_phy_rgmii_id_init(struct stmmac_priv *priv)
{
	uint16_t id1, id2, ctl;

	id1 = stmmac_mdio_read(priv->mac_base, priv->mdio_addr, MII_PHYSID1);
	id2 = stmmac_mdio_read(priv->mac_base, priv->mdio_addr, MII_PHYSID2);
	if (id1 == 0xffff || id2 == 0xffff) {
		STMMAC_PMD_WARN("PHY not responding on MDIO, RGMII delays not set");
		return;
	}
	if (((uint32_t)id1 << 16 | id2) != DP83867_PHY_ID)
		STMMAC_PMD_WARN("unexpected PHY ID 0x%04x%04x", id1, id2);

	ctl = stmmac_phy_mmd_read(priv, DP83867_RGMIICTL);
	stmmac_phy_mmd_write(priv, DP83867_RGMIICTL,
			     ctl | DP83867_RGMII_TX_CLK_DELAY_EN |
			     DP83867_RGMII_RX_CLK_DELAY_EN);
	stmmac_phy_mmd_write(priv, DP83867_RGMIIDCTL,
			     DP83867_RGMIIDCTL_2_00_NS |
			     (DP83867_RGMIIDCTL_2_00_NS << 4));
}

/*
 * DMA soft reset, as dwmac4_dma_reset(): poll the SWR bit for up to 1 s.
 */
static int
stmmac_dma_reset(void *mac_base)
{
	void *reg = (uint8_t *)mac_base + DMA_BUS_MODE;
	unsigned int i;

	rte_write32(rte_read32(reg) | DMA_BUS_MODE_SFT_RESET, reg);

	for (i = 0; i < STMMAC_DMA_RESET_POLLS; i++) {
		if (!(rte_read32(reg) & DMA_BUS_MODE_SFT_RESET))
			return 0;
		rte_delay_us(STMMAC_DMA_RESET_POLL_US);
	}

	STMMAC_PMD_ERR("DMA soft reset timed out");
	return -ETIMEDOUT;
}

/*
 * DMA system and AXI bus configuration. Fixed burst, mixed burst and AAL are
 * enabled, with BLEN16 and the maximum outstanding requests. EAME is set
 * because the rings and mbufs are above 4 GiB.
 */
static void
stmmac_dma_sysbus_init(void *mac_base)
{
	void *sysbus_reg = (uint8_t *)mac_base + DMA_SYS_BUS_MODE;
	void *axi_reg = (uint8_t *)mac_base + DMA_AXI_BUS_MODE;
	uint32_t value;

	value = rte_read32(sysbus_reg);
	value |= DMA_SYS_BUS_FB | DMA_SYS_BUS_MB | DMA_SYS_BUS_AAL;
	value |= DMA_SYS_BUS_EAME;
	rte_write32(value, sysbus_reg);

	value = rte_read32(axi_reg);
	value &= ~(DMA_AXI_WR_OSR_LMT | DMA_AXI_RD_OSR_LMT);
	value |= (DMA_AXI_OSR_MAX << DMA_AXI_WR_OSR_LMT_SHIFT) & DMA_AXI_WR_OSR_LMT;
	value |= (DMA_AXI_OSR_MAX << DMA_AXI_RD_OSR_LMT_SHIFT) & DMA_AXI_RD_OSR_LMT;
	value |= DMA_AXI_BLEN16;
	rte_write32(value, axi_reg);
}

/*
 * Per-channel DMA burst settings: PBL 32, PBLx8 on, and OSP on TX. The DMA is
 * too slow to keep up with the wire if these stay at the reset values.
 */
static void
stmmac_dma_chan_cfg(void *chan_base)
{
	void *ch_ctrl = (uint8_t *)chan_base + DMA_CHAN_OFF_CONTROL;
	void *tx_ctrl = (uint8_t *)chan_base + DMA_CHAN_OFF_TX_CONTROL;
	void *rx_ctrl = (uint8_t *)chan_base + DMA_CHAN_OFF_RX_CONTROL;
	uint32_t v;

	v = rte_read32(ch_ctrl);
	rte_write32(v | DMA_CONTROL_PBLX8, ch_ctrl);

	v = rte_read32(tx_ctrl);
	v &= ~STMMAC_DMA_PBL_MASK;
	v |= ((uint32_t)STMMAC_DMA_PBL << STMMAC_DMA_PBL_SHIFT) | DMA_CHAN_TX_CONTROL_OSP;
	rte_write32(v, tx_ctrl);

	v = rte_read32(rx_ctrl);
	v &= ~STMMAC_DMA_PBL_MASK;
	v |= (uint32_t)STMMAC_DMA_PBL << STMMAC_DMA_PBL_SHIFT;
	rte_write32(v, rx_ctrl);
}

static int
stmmac_tx_ring_setup(struct stmmac_tx_queue *txq)
{
	uint8_t *chan = txq->chan_base;
	unsigned int i;

	for (i = 0; i < txq->nb_desc; i++)
		memset(&txq->tx_ring[i], 0, sizeof(struct stmmac_desc));
	/* the non-coherent DMA must see the zeroed ring */
	stmmac_dcache_clean(txq->tx_ring, (size_t)txq->nb_desc * sizeof(struct stmmac_desc));

	rte_write32((uint32_t)(txq->tx_ring_iova >> 32), chan + DMA_CHAN_OFF_TX_BASE_ADDR_HI);
	rte_write32((uint32_t)txq->tx_ring_iova, chan + DMA_CHAN_OFF_TX_BASE_ADDR);
	/* the ring length register holds nb_desc - 1 */
	rte_write32(txq->nb_desc - 1, chan + DMA_CHAN_OFF_TX_RING_LEN);
	rte_write32((uint32_t)txq->tx_ring_iova, chan + DMA_CHAN_OFF_TX_END_ADDR);

	return 0;
}

static int
stmmac_rx_ring_setup(struct stmmac_rx_queue *rxq)
{
	uint8_t *chan = rxq->chan_base;
	unsigned int i;
	uint64_t tail;
	uint32_t bufsz, v;

	for (i = 0; i < rxq->nb_desc; i++) {
		struct rte_mbuf *mb = rte_pktmbuf_alloc(rxq->mb_pool);
		uint64_t iova;

		if (mb == NULL) {
			STMMAC_PMD_ERR("failed to allocate RX mbuf %u", i);
			return -ENOMEM;
		}

		iova = rte_pktmbuf_iova(mb);
		rxq->sw_ring[i] = mb;
		/* drop any dirty lines over the buffer before the DMA writes it */
		stmmac_dcache_flush(rte_pktmbuf_mtod(mb, void *),
				    rte_pktmbuf_data_room_size(rxq->mb_pool) -
				    RTE_PKTMBUF_HEADROOM);
		rxq->rx_ring[i].des[0] = (uint32_t)iova;
		rxq->rx_ring[i].des[1] = (uint32_t)(iova >> 32);
		rxq->rx_ring[i].des[2] = 0;
		rxq->rx_ring[i].des[3] = RDES3_OWN | RDES3_BUFFER1_VALID_ADDR |
					 RDES3_INT_ON_COMPLETION_EN;
	}
	/* the non-coherent DMA must see every OWN=1 descriptor before RXTAIL is set */
	stmmac_dcache_clean(rxq->rx_ring, (size_t)rxq->nb_desc * sizeof(struct stmmac_desc));

	/* RX buffer size, which must be non-zero and a multiple of 4 */
	bufsz = (rte_pktmbuf_data_room_size(rxq->mb_pool) - RTE_PKTMBUF_HEADROOM) & ~3u;
	v = rte_read32(chan + DMA_CHAN_OFF_RX_CONTROL);
	v = (v & ~DMA_CONTROL_RBSZ_MASK) | ((bufsz << DMA_CONTROL_RBSZ_SHIFT) &
					    DMA_CONTROL_RBSZ_MASK);
	rte_write32(v, chan + DMA_CHAN_OFF_RX_CONTROL);

	rte_write32((uint32_t)(rxq->rx_ring_iova >> 32), chan + DMA_CHAN_OFF_RX_BASE_ADDR_HI);
	rte_write32((uint32_t)rxq->rx_ring_iova, chan + DMA_CHAN_OFF_RX_BASE_ADDR);
	/* the ring length register holds nb_desc - 1 */
	rte_write32(rxq->nb_desc - 1, chan + DMA_CHAN_OFF_RX_RING_LEN);
	tail = rxq->rx_ring_iova + (uint64_t)rxq->nb_desc * sizeof(struct stmmac_desc);
	rte_write32((uint32_t)tail, chan + DMA_CHAN_OFF_RX_END_ADDR);

	return 0;
}

/*
 * MTL operating mode for the single active queue. Store-and-forward is
 * enabled, and the queue FIFO sizes (RQS/TQS) are programmed from
 * HW_FEATURE1. The reset value of 256 bytes is too small for store-and-forward.
 * Queue 0 owns the whole FIFO and maps to DMA channel 0. Flow control is not
 * enabled.
 */
static void
stmmac_mtl_init(void *mac_base, const struct stmmac_chan_addrs *addrs)
{
	void *tx_op = (uint8_t *)mac_base + MTL_CHAN_TX_OP_MODE(addrs, 0);
	void *rx_op = (uint8_t *)mac_base + MTL_CHAN_RX_OP_MODE(addrs, 0);
	void *rxq_map = (uint8_t *)mac_base + MTL_RXQ_DMA_MAP0;
	uint32_t hwf1 = rte_read32((uint8_t *)mac_base + GMAC_HW_FEATURE1);
	uint32_t rx_fifo = 128u << (hwf1 & GMAC_HWF1_RXFIFOSIZE_MASK);
	uint32_t tx_fifo = 128u << ((hwf1 >> GMAC_HWF1_TXFIFOSIZE_SHIFT) &
				    GMAC_HWF1_TXFIFOSIZE_MASK);
	uint32_t rqs = rx_fifo / STMMAC_ACTIVE_QUEUES >= 256 ?
		       rx_fifo / STMMAC_ACTIVE_QUEUES / 256 - 1 : 0;
	uint32_t tqs = tx_fifo / STMMAC_ACTIVE_QUEUES >= 256 ?
		       tx_fifo / STMMAC_ACTIVE_QUEUES / 256 - 1 : 0;
	uint32_t value;

	if (rqs > (MTL_OP_MODE_RQS_MASK >> MTL_OP_MODE_RQS_SHIFT))
		rqs = MTL_OP_MODE_RQS_MASK >> MTL_OP_MODE_RQS_SHIFT;
	if (tqs > (MTL_OP_MODE_TQS_MASK >> MTL_OP_MODE_TQS_SHIFT))
		tqs = MTL_OP_MODE_TQS_MASK >> MTL_OP_MODE_TQS_SHIFT;

	value = rte_read32(tx_op);
	value &= ~MTL_OP_MODE_TQS_MASK;
	value |= MTL_OP_MODE_TSF | MTL_OP_MODE_TXQEN | (tqs << MTL_OP_MODE_TQS_SHIFT);
	rte_write32(value, tx_op);

	value = rte_read32(rx_op);
	value &= ~MTL_OP_MODE_RQS_MASK;
	value |= MTL_OP_MODE_RSF | (rqs << MTL_OP_MODE_RQS_SHIFT);
	rte_write32(value, rx_op);

	/* RX queue 0 maps to DMA channel 0 */
	value = rte_read32(rxq_map);
	value &= ~0xfu;
	rte_write32(value, rxq_map);
}

static void
stmmac_mac_init(void *mac_base, struct rte_ether_addr *mac_addr)
{
	void *config_reg = (uint8_t *)mac_base + GMAC_CONFIG;
	uint32_t value;
	uint32_t addr_lo, addr_hi;

	addr_lo = mac_addr->addr_bytes[0] | (mac_addr->addr_bytes[1] << 8) |
		  (mac_addr->addr_bytes[2] << 16) | (mac_addr->addr_bytes[3] << 24);
	addr_hi = mac_addr->addr_bytes[4] | (mac_addr->addr_bytes[5] << 8);

	rte_write32(addr_lo, (uint8_t *)mac_base + GMAC_ADDR_LOW(0));
	rte_write32(addr_hi, (uint8_t *)mac_base + GMAC_ADDR_HIGH(0));

	value = rte_read32(config_reg);
	value |= GMAC_CONFIG_IPC | GMAC_CONFIG_ACS;
	value |= GMAC_CONFIG_TE | GMAC_CONFIG_RE;
	rte_write32(value, config_reg);
}

static void
stmmac_dma_start(struct stmmac_priv *priv)
{
	uint8_t *chan = (uint8_t *)priv->mac_base + stmmac_dma_chan_base(&priv->chan_addrs, 0);
	void *tx_ctrl = chan + DMA_CHAN_OFF_TX_CONTROL;
	void *rx_ctrl = chan + DMA_CHAN_OFF_RX_CONTROL;
	uint32_t value;

	value = rte_read32(tx_ctrl);
	value |= DMA_CONTROL_ST;
	rte_write32(value, tx_ctrl);

	value = rte_read32(rx_ctrl);
	value &= ~DMA_CONTROL_RPF;
	value |= DMA_CONTROL_SR;
	rte_write32(value, rx_ctrl);
}

static void
stmmac_dma_stop(struct stmmac_priv *priv)
{
	uint8_t *chan = (uint8_t *)priv->mac_base + stmmac_dma_chan_base(&priv->chan_addrs, 0);
	void *tx_ctrl = chan + DMA_CHAN_OFF_TX_CONTROL;
	void *rx_ctrl = chan + DMA_CHAN_OFF_RX_CONTROL;
	uint32_t value;

	value = rte_read32(tx_ctrl);
	value &= ~DMA_CONTROL_ST;
	rte_write32(value, tx_ctrl);

	value = rte_read32(rx_ctrl);
	value |= DMA_CONTROL_RPF;
	value &= ~DMA_CONTROL_SR;
	rte_write32(value, rx_ctrl);
}

static int
stmmac_eth_configure(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static int
stmmac_eth_start(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	int ret;

	if (priv->rxq[0] == NULL || priv->txq[0] == NULL) {
		STMMAC_PMD_ERR("queues not set up");
		return -EINVAL;
	}

	/* the RGMII clock must run before the DMA reset */
	stmmac_rgmii_func_clk_en(priv);
	stmmac_rgmii_id_1g_init(priv);
	stmmac_phy_rgmii_id_init(priv);

	ret = stmmac_dma_reset(priv->mac_base);
	if (ret != 0)
		return ret;

	stmmac_dma_sysbus_init(priv->mac_base);
	stmmac_dma_chan_cfg((uint8_t *)priv->mac_base +
			    stmmac_dma_chan_base(&priv->chan_addrs, 0));

	ret = stmmac_tx_ring_setup(priv->txq[0]);
	if (ret != 0)
		return ret;

	ret = stmmac_rx_ring_setup(priv->rxq[0]);
	if (ret != 0)
		return ret;

	stmmac_mac_init(priv->mac_base, &priv->mac_addr);

	/* enable RX queue 0 in generic (non-DCB) mode */
	{
		void *rxq_ctrl = (uint8_t *)priv->mac_base + GMAC_RXQ_CTRL0;
		uint32_t v = rte_read32(rxq_ctrl);

		rte_write32((v & ~0x3u) | 0x2u, rxq_ctrl);
	}

	stmmac_mtl_init(priv->mac_base, &priv->chan_addrs);
	stmmac_dma_start(priv);

	dev->rx_pkt_burst = stmmac_rx_pkt_burst_nc;
	dev->tx_pkt_burst = stmmac_tx_pkt_burst_nc;

	dev->data->dev_started = 1;
	dev->data->rx_queue_state[0] = RTE_ETH_QUEUE_STATE_STARTED;
	dev->data->tx_queue_state[0] = RTE_ETH_QUEUE_STATE_STARTED;

	return 0;
}

static int
stmmac_eth_stop(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;

	dev->data->dev_started = 0;
	stmmac_dma_stop(priv);
	dev->data->rx_queue_state[0] = RTE_ETH_QUEUE_STATE_STOPPED;
	dev->data->tx_queue_state[0] = RTE_ETH_QUEUE_STATE_STOPPED;
	return 0;
}

static void
stmmac_queue_release(struct stmmac_priv *priv)
{
	if (priv->txq[0] != NULL) {
		rte_free(priv->txq[0]->sw_ring);
		rte_free(priv->txq[0]);
		priv->txq[0] = NULL;
	}
	if (priv->rxq[0] != NULL) {
		unsigned int i;

		for (i = 0; i < priv->rxq[0]->nb_desc; i++)
			rte_pktmbuf_free(priv->rxq[0]->sw_ring[i]);
		rte_free(priv->rxq[0]->sw_ring);
		rte_free(priv->rxq[0]);
		priv->rxq[0] = NULL;
	}
}

static int
stmmac_eth_close(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;

	stmmac_queue_release(priv);

	return 0;
}

/*
 * Link state. The DP83867 BMSR link bit is latched low, so BMSR is read twice
 * to clear the latch. The live link state and the speed and duplex come from
 * PHYSTS, which is not latched. BMSR is used only if PHYSTS does not respond.
 */
static int
stmmac_eth_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	struct rte_eth_link link;
	uint16_t bmsr, physts;

	RTE_SET_USED(wait_to_complete);

	memset(&link, 0, sizeof(link));

	/* the first read clears the latched link bit */
	(void)stmmac_mdio_read(priv->mac_base, priv->mdio_addr, STMMAC_MII_BMSR);
	bmsr = stmmac_mdio_read(priv->mac_base, priv->mdio_addr, STMMAC_MII_BMSR);
	physts = stmmac_mdio_read(priv->mac_base, priv->mdio_addr, DP83867_PHYSTS);

	if (physts != 0xffff)
		priv->link_up = !!(physts & DP83867_PHYSTS_LINK_BIT);
	else
		priv->link_up = !!(bmsr & STMMAC_MII_BMSR_LSTATUS);
	link.link_status = priv->link_up;

	if (physts != 0xffff && priv->link_up) {
		uint16_t spd = physts & DP83867_PHYSTS_SPEED_MASK;

		if (spd == DP83867_PHYSTS_SPEED_1G)
			link.link_speed = RTE_ETH_SPEED_NUM_1G;
		else if (spd == DP83867_PHYSTS_SPEED_100M)
			link.link_speed = RTE_ETH_SPEED_NUM_100M;
		else
			link.link_speed = RTE_ETH_SPEED_NUM_10M;

		link.link_duplex = (physts & DP83867_PHYSTS_DUPLEX_BIT) ?
			RTE_ETH_LINK_FULL_DUPLEX : RTE_ETH_LINK_HALF_DUPLEX;
	} else {
		link.link_speed = RTE_ETH_SPEED_NUM_1G;
		link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	}

	link.link_autoneg = RTE_ETH_LINK_AUTONEG;

	return rte_eth_linkstatus_set(dev, &link);
}

static int
stmmac_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	void *filter_reg = (uint8_t *)priv->mac_base + GMAC_PACKET_FILTER;

	rte_write32(rte_read32(filter_reg) | GMAC_PACKET_FILTER_PR, filter_reg);

	return 0;
}

static int
stmmac_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	void *filter_reg = (uint8_t *)priv->mac_base + GMAC_PACKET_FILTER;

	rte_write32(rte_read32(filter_reg) & ~GMAC_PACKET_FILTER_PR, filter_reg);

	return 0;
}

static int
stmmac_mac_addr_set(struct rte_eth_dev *dev, struct rte_ether_addr *addr)
{
	struct stmmac_priv *priv = dev->data->dev_private;

	rte_ether_addr_copy(addr, &priv->mac_addr);

	rte_write32(addr->addr_bytes[0] | (addr->addr_bytes[1] << 8) |
		    (addr->addr_bytes[2] << 16) | (addr->addr_bytes[3] << 24),
		    (uint8_t *)priv->mac_base + GMAC_ADDR_LOW(0));
	rte_write32(addr->addr_bytes[4] | (addr->addr_bytes[5] << 8),
		    (uint8_t *)priv->mac_base + GMAC_ADDR_HIGH(0));

	return 0;
}

static int
stmmac_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *stats,
		 struct eth_queue_stats *qstats)
{
	struct stmmac_priv *priv = dev->data->dev_private;

	RTE_SET_USED(qstats);
	memcpy(stats, &priv->stats, sizeof(*stats));

	/* the queue counters are updated by the burst functions */
	if (priv->rxq[0] != NULL) {
		stats->ipackets = priv->rxq[0]->rx_packets;
		stats->ibytes = priv->rxq[0]->rx_bytes;
		stats->ierrors = priv->rxq[0]->rx_errors;
		stats->rx_nombuf = priv->rxq[0]->rx_nombuf;
	}
	if (priv->txq[0] != NULL) {
		stats->opackets = priv->txq[0]->tx_packets;
		stats->obytes = priv->txq[0]->tx_bytes;
		stats->oerrors = priv->txq[0]->tx_errors;
	}

	return 0;
}

static int
stmmac_stats_reset(struct rte_eth_dev *dev)
{
	struct stmmac_priv *priv = dev->data->dev_private;

	memset(&priv->stats, 0, sizeof(priv->stats));
	if (priv->rxq[0] != NULL) {
		priv->rxq[0]->rx_packets = 0;
		priv->rxq[0]->rx_bytes = 0;
		priv->rxq[0]->rx_errors = 0;
		priv->rxq[0]->rx_nombuf = 0;
	}
	if (priv->txq[0] != NULL) {
		priv->txq[0]->tx_packets = 0;
		priv->txq[0]->tx_bytes = 0;
		priv->txq[0]->tx_errors = 0;
		priv->txq[0]->tx_ring_full = 0;
	}

	return 0;
}

static int
stmmac_dev_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{
	RTE_SET_USED(dev);

	dev_info->max_rx_queues = STMMAC_MAX_Q;
	dev_info->max_tx_queues = STMMAC_MAX_Q;
	dev_info->min_rx_bufsize = RTE_ETHER_MIN_LEN;
	dev_info->max_rx_pktlen = RTE_ETHER_MAX_LEN;
	dev_info->rx_offload_capa = dev_rx_offloads_sup;
	dev_info->tx_offload_capa = dev_tx_offloads_sup;

	/*
	 * Ring sizes follow the Linux limits (64..1024). Sizes must be a
	 * multiple of 4, one descriptor cache line. One segment per packet.
	 */
	dev_info->rx_desc_lim = (struct rte_eth_desc_lim) {
		.nb_max = STMMAC_MAX_RING_SIZE,
		.nb_min = 64,
		.nb_align = 4,
		.nb_seg_max = 1,
		.nb_mtu_seg_max = 1,
	};
	dev_info->tx_desc_lim = dev_info->rx_desc_lim;
	dev_info->default_rxportconf.ring_size = STMMAC_MAX_RING_SIZE;
	dev_info->default_txportconf.ring_size = STMMAC_MAX_RING_SIZE;

	return 0;
}

static int
stmmac_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		      uint16_t nb_rx_desc, unsigned int socket_id,
		      const struct rte_eth_rxconf *rx_conf,
		      struct rte_mempool *mb_pool)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	struct stmmac_rx_queue *rxq;
	const struct rte_memzone *mz;
	size_t ring_size;

	RTE_SET_USED(rx_conf);

	if (rx_queue_id >= STMMAC_MAX_Q) {
		STMMAC_PMD_ERR("invalid rx queue id %u, max %u",
			       rx_queue_id, STMMAC_MAX_Q);
		return -EINVAL;
	}

	if (nb_rx_desc == 0)
		nb_rx_desc = STMMAC_DEFAULT_RING_SIZE;

	rxq = rte_zmalloc_socket("stmmac_rxq", sizeof(*rxq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL)
		return -ENOMEM;

	ring_size = nb_rx_desc * sizeof(struct stmmac_desc);
	mz = rte_eth_dma_zone_reserve(dev, "rx_ring", rx_queue_id, ring_size,
				      RTE_CACHE_LINE_SIZE, socket_id);
	if (mz == NULL) {
		rte_free(rxq);
		return -ENOMEM;
	}

	rxq->sw_ring = rte_zmalloc_socket("stmmac_rx_sw_ring",
			nb_rx_desc * sizeof(struct rte_mbuf *),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->sw_ring == NULL) {
		rte_free(rxq);
		return -ENOMEM;
	}

	rxq->rx_ring = mz->addr;
	rxq->rx_ring_iova = mz->iova;
	rxq->nb_desc = nb_rx_desc;
	rxq->rx_tail = 0;
	rxq->rx_refill = 0;
	rxq->queue_id = rx_queue_id;
	rxq->port_id = dev->data->port_id;
	rxq->mb_pool = mb_pool;
	rxq->chan_base = (uint8_t *)priv->mac_base +
		stmmac_dma_chan_base(&priv->chan_addrs, 0);
	rxq->mz = mz;

	priv->rxq[rx_queue_id] = rxq;
	dev->data->rx_queues[rx_queue_id] = rxq;
	return 0;
}

static int
stmmac_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		      uint16_t nb_tx_desc, unsigned int socket_id,
		      const struct rte_eth_txconf *tx_conf)
{
	struct stmmac_priv *priv = dev->data->dev_private;
	struct stmmac_tx_queue *txq;
	const struct rte_memzone *mz;
	size_t ring_size;

	RTE_SET_USED(tx_conf);

	if (tx_queue_id >= STMMAC_MAX_Q) {
		STMMAC_PMD_ERR("invalid tx queue id %u, max %u",
			       tx_queue_id, STMMAC_MAX_Q);
		return -EINVAL;
	}

	if (nb_tx_desc == 0)
		nb_tx_desc = STMMAC_DEFAULT_RING_SIZE;
	/* the TX burst writes whole descriptor cache lines: the ring must be a multiple of 4 */
	if (nb_tx_desc % STMMAC_DESCS_PER_LINE) {
		STMMAC_PMD_ERR("nb_tx_desc %u must be a multiple of %u",
			       nb_tx_desc, STMMAC_DESCS_PER_LINE);
		return -EINVAL;
	}

	txq = rte_zmalloc_socket("stmmac_txq", sizeof(*txq),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL)
		return -ENOMEM;

	ring_size = nb_tx_desc * sizeof(struct stmmac_desc);
	mz = rte_eth_dma_zone_reserve(dev, "tx_ring", tx_queue_id, ring_size,
				      RTE_CACHE_LINE_SIZE, socket_id);
	if (mz == NULL) {
		rte_free(txq);
		return -ENOMEM;
	}

	txq->sw_ring = rte_zmalloc_socket("stmmac_tx_sw_ring",
			nb_tx_desc * sizeof(struct rte_mbuf *),
			RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->sw_ring == NULL) {
		rte_free(txq);
		return -ENOMEM;
	}

	txq->tx_ring = mz->addr;
	txq->tx_ring_iova = mz->iova;
	txq->nb_desc = nb_tx_desc;
	txq->tx_tail = 0;
	txq->tx_free = 0;
	txq->queue_id = tx_queue_id;
	txq->port_id = dev->data->port_id;
	txq->chan_base = (uint8_t *)priv->mac_base +
		stmmac_dma_chan_base(&priv->chan_addrs, 0);
	txq->mz = mz;

	priv->txq[tx_queue_id] = txq;
	dev->data->tx_queues[tx_queue_id] = txq;
	return 0;
}

static void
stmmac_rxq_info_get(struct rte_eth_dev *dev, uint16_t qid,
		    struct rte_eth_rxq_info *qinfo)
{
	struct stmmac_rx_queue *rxq = dev->data->rx_queues[qid];

	qinfo->mp = rxq->mb_pool;
	qinfo->nb_desc = rxq->nb_desc;
}

static void
stmmac_txq_info_get(struct rte_eth_dev *dev, uint16_t qid,
		    struct rte_eth_txq_info *qinfo)
{
	struct stmmac_tx_queue *txq = dev->data->tx_queues[qid];

	qinfo->nb_desc = txq->nb_desc;
}

static const struct eth_dev_ops stmmac_eth_ops = {
	.dev_configure		= stmmac_eth_configure,
	.dev_start		= stmmac_eth_start,
	.dev_stop		= stmmac_eth_stop,
	.dev_close		= stmmac_eth_close,
	.link_update		= stmmac_eth_link_update,
	.promiscuous_enable	= stmmac_promiscuous_enable,
	.promiscuous_disable	= stmmac_promiscuous_disable,
	.mac_addr_set		= stmmac_mac_addr_set,
	.stats_get		= stmmac_stats_get,
	.stats_reset		= stmmac_stats_reset,
	.dev_infos_get		= stmmac_dev_infos_get,
	.rx_queue_setup		= stmmac_rx_queue_setup,
	.tx_queue_setup		= stmmac_tx_queue_setup,
	.rxq_info_get		= stmmac_rxq_info_get,
	.txq_info_get		= stmmac_txq_info_get,
};

static int
stmmac_platform_probe(struct rte_platform_device *pdev)
{
	struct rte_eth_dev *dev;
	struct stmmac_priv *priv;
	unsigned int i;

	if (pdev->num_resource < 1 || pdev->resource[0].mem.addr == NULL) {
		STMMAC_PMD_ERR("probe failed: no MMIO resource[0] (MAC/DMA/MTL block)");
		return -EINVAL;
	}

	dev = rte_eth_dev_allocate(pdev->device.name);
	if (dev == NULL) {
		STMMAC_PMD_ERR("probe failed: rte_eth_dev_allocate() returned NULL for %s",
			       pdev->device.name);
		return -ENOMEM;
	}
	dev->device = &pdev->device;

	priv = rte_zmalloc_socket(NULL, sizeof(*priv), RTE_CACHE_LINE_SIZE,
				  dev->data->numa_node);
	if (priv == NULL) {
		STMMAC_PMD_ERR("probe failed: unable to allocate stmmac_priv for %s",
			       pdev->device.name);
		rte_eth_dev_release_port(dev);
		return -ENOMEM;
	}
	dev->data->dev_private = priv;

	priv->mac_base = pdev->resource[0].mem.addr;
	/* DT reg-names = "stmmaceth", "rgmii": resource[1] is the RGMII IO macro */
	if (pdev->num_resource > 1)
		priv->rgmii_base = pdev->resource[1].mem.addr;

	stmmac_parse_devargs(pdev, priv);

	if (priv->has_emac_ge_3) {
		struct stmmac_chan_addrs ge3 = STMMAC_CHAN_ADDRS_EMAC_GE3_INIT;

		priv->chan_addrs = ge3;
	} else {
		struct stmmac_chan_addrs generic = STMMAC_CHAN_ADDRS_GENERIC_INIT;

		priv->chan_addrs = generic;
	}

	dev->data->mac_addrs = rte_zmalloc(NULL, RTE_ETHER_ADDR_LEN, 0);
	if (dev->data->mac_addrs == NULL) {
		STMMAC_PMD_ERR("probe failed: unable to allocate mac_addrs for %s",
			       pdev->device.name);
		rte_free(priv);
		rte_eth_dev_release_port(dev);
		return -ENOMEM;
	}
	for (i = 0; i < RTE_ETHER_ADDR_LEN; i++)
		dev->data->mac_addrs[0].addr_bytes[i] = 0x02;
	rte_ether_addr_copy(&dev->data->mac_addrs[0], &priv->mac_addr);

	dev->dev_ops = &stmmac_eth_ops;

	rte_eth_dev_probing_finish(dev);

	return 0;
}

static int
stmmac_platform_remove(struct rte_platform_device *pdev)
{
	struct rte_eth_dev *dev;

	dev = rte_eth_dev_allocated(pdev->device.name);
	if (dev == NULL)
		return 0;

	stmmac_eth_close(dev);
	rte_free(dev->data->dev_private);
	rte_eth_dev_release_port(dev);

	return 0;
}

static struct rte_platform_driver stmmac_platform_drv = {
	.probe = stmmac_platform_probe,
	.remove = stmmac_platform_remove,
};

RTE_PMD_REGISTER_PLATFORM(STMMAC_DRIVER_NAME, stmmac_platform_drv);
RTE_PMD_REGISTER_ALIAS(STMMAC_DRIVER_NAME, vfio-platform);
RTE_PMD_REGISTER_PARAM_STRING(STMMAC_DRIVER_NAME,
	STMMAC_DEVARG_HAS_EMAC_GE_3 "=<0|1> "
	STMMAC_DEVARG_MDIO_ADDR "=<uint16>");
