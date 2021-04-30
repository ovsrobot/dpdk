/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 NXP
 */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <rte_kvargs.h>
#include <ethdev_vdev.h>
#include <rte_bus_vdev.h>
#include <rte_dev.h>
#include <rte_ether.h>
#include <rte_io.h>
#include "enet_pmd_logs.h"
#include "enet_ethdev.h"
#include "enet_regs.h"
#include "enet_uio.h"

#define ENETFEC_NAME_PMD        net_enetfec
#define ENET_VDEV_GEM_ID_ARG    "intf"
#define ENET_CDEV_INVALID_FD    -1

#define BIT(nr)			(1 << (nr))
/* FEC receive acceleration */
#define ENET_RACC_IPDIS		(1 << 1)
#define ENET_RACC_PRODIS	(1 << 2)
#define ENET_RACC_SHIFT16	BIT(7)
#define ENET_RACC_OPTIONS	(ENET_RACC_IPDIS | ENET_RACC_PRODIS)

/* Transmitter timeout */
#define TX_TIMEOUT (2 * HZ)

#define ENET_PAUSE_FLAG_AUTONEG		0x1
#define ENET_PAUSE_FLAG_ENABLE		0x2
#define ENET_WOL_HAS_MAGIC_PACKET	(0x1 << 0)
#define ENET_WOL_FLAG_ENABLE		(0x1 << 1)
#define ENET_WOL_FLAG_SLEEP_ON		(0x1 << 2)

/* Pause frame feild and FIFO threshold */
#define ENET_ENET_FCE		(1 << 5)
#define ENET_ENET_RSEM_V	0x84
#define ENET_ENET_RSFL_V	16
#define ENET_ENET_RAEM_V	0x8
#define ENET_ENET_RAFL_V	0x8
#define ENET_ENET_OPD_V		0xFFF0
#define ENET_MDIO_PM_TIMEOUT	100 /* ms */

int enetfec_logtype_pmd;

/* Supported Rx offloads */
static uint64_t dev_rx_offloads_sup =
		DEV_RX_OFFLOAD_IPV4_CKSUM |
		DEV_RX_OFFLOAD_UDP_CKSUM |
		DEV_RX_OFFLOAD_TCP_CKSUM |
		DEV_RX_OFFLOAD_VLAN_STRIP |
		DEV_RX_OFFLOAD_CHECKSUM;

static uint64_t dev_tx_offloads_sup =
		DEV_TX_OFFLOAD_IPV4_CKSUM |
		DEV_TX_OFFLOAD_UDP_CKSUM |
		DEV_TX_OFFLOAD_TCP_CKSUM;

/*
 * This function is called to start or restart the FEC during a link
 * change, transmit timeout or to reconfigure the FEC. The network
 * packet processing for this device must be stopped before this call.
 */
static void
enetfec_restart(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	uint32_t temp_mac[2];
	uint32_t rcntl = OPT_FRAME_SIZE | 0x04;
	uint32_t ecntl = ENET_ETHEREN; /* ETHEREN */
	/* TODO get eth addr from eth dev */
	struct rte_ether_addr addr = {
		.addr_bytes = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6} };
	uint32_t val;

	/*
	 * enet-mac reset will reset mac address registers too,
	 * so need to reconfigure it.
	 */
	memcpy(&temp_mac, addr.addr_bytes, ETH_ALEN);
	rte_write32(rte_cpu_to_be_32(temp_mac[0]),
		fep->hw_baseaddr_v + ENET_PALR);
	rte_write32(rte_cpu_to_be_32(temp_mac[1]),
		fep->hw_baseaddr_v + ENET_PAUR);

	/* Clear any outstanding interrupt. */
	writel(0xffffffff, fep->hw_baseaddr_v + ENET_EIR);

	/* Enable MII mode */
	if (fep->full_duplex == FULL_DUPLEX) {
		/* FD enable */
		rte_write32(0x04, fep->hw_baseaddr_v + ENET_TCR);
	} else {
		/* No Rcv on Xmit */
		rcntl |= 0x02;
		rte_write32(0x0, fep->hw_baseaddr_v + ENET_TCR);
	}

	if (fep->quirks & QUIRK_RACC) {
		val = rte_read32(fep->hw_baseaddr_v + ENET_RACC);
		/* align IP header */
		val |= ENET_RACC_SHIFT16;
		if (fep->flag_csum & RX_FLAG_CSUM_EN)
			/* set RX checksum */
			val |= ENET_RACC_OPTIONS;
		else
			val &= ~ENET_RACC_OPTIONS;
		rte_write32(val, fep->hw_baseaddr_v + ENET_RACC);
		rte_write32(PKT_MAX_BUF_SIZE,
			fep->hw_baseaddr_v + ENET_FRAME_TRL);
	}

	/*
	 * The phy interface and speed need to get configured
	 * differently on enet-mac.
	 */
	if (fep->quirks & QUIRK_HAS_ENET_MAC) {
		/* Enable flow control and length check */
		rcntl |= 0x40000000 | 0x00000020;

		/* RGMII, RMII or MII */
		rcntl |= (1 << 6);
		ecntl |= (1 << 5);
	}

	/* enable pause frame*/
	if ((fep->flag_pause & ENET_PAUSE_FLAG_ENABLE) ||
		((fep->flag_pause & ENET_PAUSE_FLAG_AUTONEG)
		/*&& ndev->phydev && ndev->phydev->pause*/)) {
		rcntl |= ENET_ENET_FCE;

		/* set FIFO threshold parameter to reduce overrun */
		rte_write32(ENET_ENET_RSEM_V,
				fep->hw_baseaddr_v + ENET_R_FIFO_SEM);
		rte_write32(ENET_ENET_RSFL_V,
				fep->hw_baseaddr_v + ENET_R_FIFO_SFL);
		rte_write32(ENET_ENET_RAEM_V,
				fep->hw_baseaddr_v + ENET_R_FIFO_AEM);
		rte_write32(ENET_ENET_RAFL_V,
				fep->hw_baseaddr_v + ENET_R_FIFO_AFL);

		/* OPD */
		rte_write32(ENET_ENET_OPD_V, fep->hw_baseaddr_v + ENET_OPD);
	} else {
		rcntl &= ~ENET_ENET_FCE;
	}

	rte_write32(rcntl, fep->hw_baseaddr_v + ENET_RCR);

	rte_write32(0, fep->hw_baseaddr_v + ENET_IAUR);
	rte_write32(0, fep->hw_baseaddr_v + ENET_IALR);

	if (fep->quirks & QUIRK_HAS_ENET_MAC) {
		/* enable ENET endian swap */
		ecntl |= (1 << 8);
		/* enable ENET store and forward mode */
		rte_write32(1 << 8, fep->hw_baseaddr_v + ENET_TFWR);
	}

	if (fep->bufdesc_ex)
		ecntl |= (1 << 4);

	if (fep->quirks & QUIRK_SUPPORT_DELAYED_CLKS &&
		fep->rgmii_txc_delay)
		ecntl |= ENET_TXC_DLY;
	if (fep->quirks & QUIRK_SUPPORT_DELAYED_CLKS &&
		fep->rgmii_rxc_delay)
		ecntl |= ENET_RXC_DLY;

	/* Enable the MIB statistic event counters */
	rte_write32(0 << 31, fep->hw_baseaddr_v + ENET_MIBC);

	ecntl |= 0x70000000;
	/* And last, enable the transmit and receive processing */
	rte_write32(ecntl, fep->hw_baseaddr_v + ENET_ECR);
	rte_delay_us(10);
}

static int
enetfec_eth_open(struct rte_eth_dev *dev)
{
	enetfec_restart(dev);

	return 0;
}


static int
enetfec_eth_configure(__rte_unused struct rte_eth_dev *dev)
{
	ENET_PMD_INFO("%s: returning zero ", __func__);
	return 0;
}

static int
enetfec_eth_info(__rte_unused struct rte_eth_dev *dev,
	     struct rte_eth_dev_info *dev_info)
{
	dev_info->max_rx_queues = ENET_MAX_Q;
	dev_info->max_tx_queues = ENET_MAX_Q;
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;
	dev_info->rx_offload_capa = dev_rx_offloads_sup;
	dev_info->tx_offload_capa = dev_tx_offloads_sup;

	return 0;
}

static const unsigned short offset_des_active_rxq[] = {
	ENET_RDAR_0, ENET_RDAR_1, ENET_RDAR_2
};

static const unsigned short offset_des_active_txq[] = {
	ENET_TDAR_0, ENET_TDAR_1, ENET_TDAR_2
};

static int
enetfec_tx_queue_setup(struct rte_eth_dev *dev,
			uint16_t queue_idx,
			uint16_t nb_desc,
			__rte_unused unsigned int socket_id,
			__rte_unused const struct rte_eth_txconf *tx_conf)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	struct bufdesc *bdp, *bd_base;
	struct enetfec_priv_tx_q *txq;
	unsigned int size;
	unsigned int dsize = fep->bufdesc_ex ? sizeof(struct bufdesc_ex) :
			sizeof(struct bufdesc);
	unsigned int dsize_log2 = fls64(dsize);

	/* allocate transmit queue */
	txq = rte_zmalloc(NULL, sizeof(*txq), RTE_CACHE_LINE_SIZE);
	if (!txq) {
		ENET_PMD_ERR("transmit queue allocation failed");
		return -ENOMEM;
	}

	if (nb_desc > MAX_TX_BD_RING_SIZE) {
		nb_desc = MAX_TX_BD_RING_SIZE;
		ENET_PMD_WARN("modified the nb_desc to MAX_TX_BD_RING_SIZE\n");
	}
	txq->bd.ring_size = nb_desc;
	fep->total_tx_ring_size += txq->bd.ring_size;
	fep->tx_queues[queue_idx] = txq;

	rte_write32(fep->bd_addr_p_t[queue_idx],
		fep->hw_baseaddr_v + ENET_TD_START(queue_idx));

	/* Set transmit descriptor base. */
	txq = fep->tx_queues[queue_idx];
	txq->fep = fep;
	size = dsize * txq->bd.ring_size;
	bd_base = (struct bufdesc *)fep->dma_baseaddr_t[queue_idx];
	txq->bd.que_id = queue_idx;
	txq->bd.base = bd_base;
	txq->bd.cur = bd_base;
	txq->bd.d_size = dsize;
	txq->bd.d_size_log2 = dsize_log2;
	txq->bd.active_reg_desc =
			fep->hw_baseaddr_v + offset_des_active_txq[queue_idx];
	bd_base = (struct bufdesc *)(((void *)bd_base) + size);
	txq->bd.last = (struct bufdesc *)(((void *)bd_base) - dsize);
	bdp = txq->bd.base;
	bdp = txq->bd.cur;

	for (i = 0; i < txq->bd.ring_size; i++) {
		/* Initialize the BD for every fragment in the page. */
		rte_write16(rte_cpu_to_le_16(0), &bdp->bd_sc);
		if (txq->tx_mbuf[i]) {
			rte_pktmbuf_free(txq->tx_mbuf[i]);
			txq->tx_mbuf[i] = NULL;
		}
		rte_write32(rte_cpu_to_le_32(0), &bdp->bd_bufaddr);
		bdp = enet_get_nextdesc(bdp, &txq->bd);
	}

	/* Set the last buffer to wrap */
	bdp = enet_get_prevdesc(bdp, &txq->bd);
	rte_write16((rte_cpu_to_le_16(TX_BD_WRAP) |
		     rte_read16(&bdp->bd_sc)), &bdp->bd_sc);
	txq->dirty_tx = bdp;
	dev->data->tx_queues[queue_idx] = fep->tx_queues[queue_idx];
	return 0;
}

static int
enetfec_rx_queue_setup(struct rte_eth_dev *dev,
			uint16_t queue_idx,
			uint16_t nb_rx_desc,
			 __rte_unused unsigned int socket_id,
			 __rte_unused const struct rte_eth_rxconf *rx_conf,
			struct rte_mempool *mb_pool)
{
	struct enetfec_private *fep = dev->data->dev_private;
	unsigned int i;
	struct bufdesc *bd_base;
	struct bufdesc  *bdp;
	struct enetfec_priv_rx_q *rxq;
	unsigned int size;
	unsigned int dsize = fep->bufdesc_ex ? sizeof(struct bufdesc_ex) :
			sizeof(struct bufdesc);
	unsigned int dsize_log2 = fls64(dsize);

	/* allocate receive queue */
	rxq = rte_zmalloc(NULL, sizeof(*rxq), RTE_CACHE_LINE_SIZE);
	if (!rxq) {
		ENET_PMD_ERR("receive queue allocation failed");
		return -ENOMEM;
	}

	if (nb_rx_desc > MAX_RX_BD_RING_SIZE) {
		nb_rx_desc = MAX_RX_BD_RING_SIZE;
		ENET_PMD_WARN("modified the nb_desc to MAX_RX_BD_RING_SIZE\n");
	}

	rxq->bd.ring_size = nb_rx_desc;
	fep->total_rx_ring_size += rxq->bd.ring_size;
	fep->rx_queues[queue_idx] = rxq;

	rte_write32(fep->bd_addr_p_r[queue_idx],
			fep->hw_baseaddr_v + ENET_RD_START(queue_idx));
	rte_write32(PKT_MAX_BUF_SIZE,
			fep->hw_baseaddr_v + ENET_MRB_SIZE(queue_idx));

	/* Set receive descriptor base. */
	rxq = fep->rx_queues[queue_idx];
	rxq->pool = mb_pool;
	size = dsize * rxq->bd.ring_size;
	bd_base = (struct bufdesc *)fep->dma_baseaddr_r[queue_idx];
	rxq->bd.que_id = queue_idx;
	rxq->bd.base = bd_base;
	rxq->bd.cur = bd_base;
	rxq->bd.d_size = dsize;
	rxq->bd.d_size_log2 = dsize_log2;
	rxq->bd.active_reg_desc =
			fep->hw_baseaddr_v + offset_des_active_rxq[queue_idx];
	bd_base = (struct bufdesc *)(((void *)bd_base) + size);
	rxq->bd.last = (struct bufdesc *)(((void *)bd_base) - dsize);

	rxq->fep = fep;
	bdp = rxq->bd.base;
	rxq->bd.cur = bdp;

	for (i = 0; i < nb_rx_desc; i++) {
		/* Initialize Rx buffers from pktmbuf pool */
		struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mb_pool);
		if (mbuf == NULL) {
			ENET_PMD_ERR("mbuf failed\n");
			goto err_alloc;
		}

		/* Get the virtual address & physical address */
		rte_write32(rte_cpu_to_le_32(rte_pktmbuf_iova(mbuf)),
				&bdp->bd_bufaddr);

		rxq->rx_mbuf[i] = mbuf;
		rte_write16(rte_cpu_to_le_16(RX_BD_EMPTY), &bdp->bd_sc);

		bdp = enet_get_nextdesc(bdp, &rxq->bd);
	}

	/* Initialize the receive buffer descriptors. */
	bdp = rxq->bd.cur;
	for (i = 0; i < rxq->bd.ring_size; i++) {
		/* Initialize the BD for every fragment in the page. */
		if (rte_read32(&bdp->bd_bufaddr))
			rte_write16(rte_cpu_to_le_16(RX_BD_EMPTY),
				&bdp->bd_sc);
		else
			rte_write16(rte_cpu_to_le_16(0), &bdp->bd_sc);

		bdp = enet_get_nextdesc(bdp, &rxq->bd);
	}

	/* Set the last buffer to wrap */
	bdp = enet_get_prevdesc(bdp, &rxq->bd);
	rte_write16((rte_cpu_to_le_16(RX_BD_WRAP) |
		     rte_read16(&bdp->bd_sc)),	&bdp->bd_sc);
	dev->data->rx_queues[queue_idx] = fep->rx_queues[queue_idx];
	rte_write32(0x0, fep->rx_queues[queue_idx]->bd.active_reg_desc);
	return 0;

err_alloc:
	for (i = 0; i < nb_rx_desc; i++) {
		rte_pktmbuf_free(rxq->rx_mbuf[i]);
		rxq->rx_mbuf[i] = NULL;
	}
	rte_free(rxq);
	return -1;
}

static const struct eth_dev_ops ops = {
	.dev_start = enetfec_eth_open,
	.dev_configure = enetfec_eth_configure,
	.dev_infos_get = enetfec_eth_info,
	.rx_queue_setup = enetfec_rx_queue_setup,
	.tx_queue_setup = enetfec_tx_queue_setup,
};

static int
enetfec_eth_init(struct rte_eth_dev *dev)
{
	struct enetfec_private *fep = dev->data->dev_private;
	struct rte_eth_conf *eth_conf = &fep->dev->data->dev_conf;
	uint64_t rx_offloads = eth_conf->rxmode.offloads;

	fep->full_duplex = FULL_DUPLEX;

	dev->dev_ops = &ops;
	if (fep->quirks & QUIRK_VLAN)
		/* enable hw VLAN support */
		rx_offloads |= DEV_RX_OFFLOAD_VLAN;

	if (fep->quirks & QUIRK_CSUM) {
		/* enable hw accelerator */
		rx_offloads |= DEV_RX_OFFLOAD_CHECKSUM;
		fep->flag_csum |= RX_FLAG_CSUM_EN;
	}

	rte_eth_dev_probing_finish(dev);
	return 0;
}

static int
pmd_enetfec_probe(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *dev = NULL;
	struct enetfec_private *fep;
	const char *name;
	int rc = -1;
	int i;
	unsigned int bdsize;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;
	ENET_PMD_LOG(INFO, "Initializing pmd_fec for %s", name);

	dev = rte_eth_vdev_allocate(vdev, sizeof(*fep));
	if (dev == NULL)
		return -ENOMEM;

	/* setup board info structure */
	fep = dev->data->dev_private;
	fep->dev = dev;

	fep->max_rx_queues = ENET_MAX_Q;
	fep->max_tx_queues = ENET_MAX_Q;
	fep->quirks = QUIRK_HAS_ENET_MAC | QUIRK_GBIT | QUIRK_BUFDESC_EX
		| QUIRK_CSUM | QUIRK_VLAN | QUIRK_ERR007885
		| QUIRK_RACC | QUIRK_COALESCE | QUIRK_EEE;

	config_enetfec_uio(fep);

	/* Get the BD size for distributing among six queues */
	bdsize = (fep->bd_size) / 6;

	for (i = 0; i < fep->max_tx_queues; i++) {
		fep->dma_baseaddr_t[i] = fep->bd_addr_v;
		fep->bd_addr_p_t[i] = fep->bd_addr_p;
		fep->bd_addr_v = fep->bd_addr_v + bdsize;
		fep->bd_addr_p = fep->bd_addr_p + bdsize;
	}
	for (i = 0; i < fep->max_rx_queues; i++) {
		fep->dma_baseaddr_r[i] = fep->bd_addr_v;
		fep->bd_addr_p_r[i] = fep->bd_addr_p;
		fep->bd_addr_v = fep->bd_addr_v + bdsize;
		fep->bd_addr_p = fep->bd_addr_p + bdsize;
	}

	rc = enetfec_eth_init(dev);
	if (rc)
		goto failed_init;
	return 0;
failed_init:
	ENET_PMD_ERR("Failed to init");
	return rc;
}

static int
pmd_enetfec_remove(struct rte_vdev_device *vdev)
{
	struct rte_eth_dev *eth_dev = NULL;

	/* find the ethdev entry */
	eth_dev = rte_eth_dev_allocated(rte_vdev_device_name(vdev));
	if (!eth_dev)
		return -ENODEV;

	rte_eth_dev_release_port(eth_dev);

	ENET_PMD_INFO("Closing sw device\n");
	return 0;
}

static
struct rte_vdev_driver pmd_enetfec_drv = {
	.probe = pmd_enetfec_probe,
	.remove = pmd_enetfec_remove,
};

RTE_PMD_REGISTER_VDEV(ENETFEC_NAME_PMD, pmd_enetfec_drv);
RTE_PMD_REGISTER_PARAM_STRING(ENETFEC_NAME_PMD, ENET_VDEV_GEM_ID_ARG "=<int>");

RTE_INIT(enetfec_pmd_init_log)
{
	enetfec_logtype_pmd = rte_log_register("pmd.net.enetfec");
	if (enetfec_logtype_pmd >= 0)
		rte_log_set_level(enetfec_logtype_pmd, RTE_LOG_NOTICE);
}
