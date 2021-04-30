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

static const struct eth_dev_ops ops = {
	.dev_start = enetfec_eth_open,
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
