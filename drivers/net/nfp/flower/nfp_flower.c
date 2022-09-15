/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include <rte_common.h>
#include <ethdev_driver.h>
#include <rte_service_component.h>
#include <rte_malloc.h>
#include <rte_alarm.h>
#include <ethdev_pci.h>
#include <ethdev_driver.h>

#include "../nfp_common.h"
#include "../nfp_logs.h"
#include "../nfp_ctrl.h"
#include "../nfp_cpp_bridge.h"
#include "../nfp_rxtx.h"
#include "../nfpcore/nfp_mip.h"
#include "../nfpcore/nfp_rtsym.h"
#include "../nfpcore/nfp_nsp.h"
#include "nfp_flower.h"

#define MAX_PKT_BURST 32
#define MBUF_PRIV_SIZE 128
#define MEMPOOL_CACHE_SIZE 512
#define DEFAULT_FLBUF_SIZE 9216

#define PF_VNIC_NB_DESC 1024

static const struct rte_eth_rxconf rx_conf = {
	.rx_free_thresh = DEFAULT_RX_FREE_THRESH,
	.rx_drop_en = 1,
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh  = DEFAULT_TX_PTHRESH,
		.hthresh = DEFAULT_TX_HTHRESH,
		.wthresh = DEFAULT_TX_WTHRESH,
	},
	.tx_free_thresh = DEFAULT_TX_FREE_THRESH,
};

static int
nfp_flower_pf_start(struct rte_eth_dev *dev)
{
	int ret;
	uint32_t new_ctrl;
	uint32_t update = 0;
	struct nfp_net_hw *hw;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	/* Disabling queues just in case... */
	nfp_net_disable_queues(dev);

	/* Enabling the required queues in the device */
	nfp_net_enable_queues(dev);

	new_ctrl = nfp_check_offloads(dev);

	/* Writing configuration parameters in the device */
	nfp_net_params_setup(hw);

	nfp_net_rss_config_default(dev);
	update |= NFP_NET_CFG_UPDATE_RSS;

	if (hw->cap & NFP_NET_CFG_CTRL_RSS2)
		new_ctrl |= NFP_NET_CFG_CTRL_RSS2;
	else
		new_ctrl |= NFP_NET_CFG_CTRL_RSS;

	/* Enable device */
	new_ctrl |= NFP_NET_CFG_CTRL_ENABLE;

	update |= NFP_NET_CFG_UPDATE_GEN | NFP_NET_CFG_UPDATE_RING;

	if (hw->cap & NFP_NET_CFG_CTRL_RINGCFG)
		new_ctrl |= NFP_NET_CFG_CTRL_RINGCFG;

	nn_cfg_writel(hw, NFP_NET_CFG_CTRL, new_ctrl);

	/* If an error when reconfig we avoid to change hw state */
	ret = nfp_net_reconfig(hw, new_ctrl, update);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to reconfig PF vnic");
		return -EIO;
	}

	hw->ctrl = new_ctrl;

	/* Setup the freelist ring */
	ret = nfp_net_rx_freelist_setup(dev);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Error with flower PF vNIC freelist setup");
		return -EIO;
	}

	return 0;
}

/* Stop device: disable rx and tx functions to allow for reconfiguring. */
static int
nfp_flower_pf_stop(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct nfp_net_hw *hw;
	struct nfp_net_txq *this_tx_q;
	struct nfp_net_rxq *this_rx_q;

	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	nfp_net_disable_queues(dev);

	/* Clear queues */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		this_tx_q = (struct nfp_net_txq *)dev->data->tx_queues[i];
		nfp_net_reset_tx_queue(this_tx_q);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		this_rx_q = (struct nfp_net_rxq *)dev->data->rx_queues[i];
		nfp_net_reset_rx_queue(this_rx_q);
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		/* Configure the physical port down */
		nfp_eth_set_configured(hw->cpp, hw->nfp_idx, 0);
	else
		nfp_eth_set_configured(dev->process_private, hw->nfp_idx, 0);

	return 0;
}

/* Reset and stop device. The device can not be restarted. */
static int
nfp_flower_pf_close(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct nfp_net_hw *hw;
	struct nfp_pf_dev *pf_dev;
	struct nfp_net_txq *this_tx_q;
	struct nfp_net_rxq *this_rx_q;
	struct rte_pci_device *pci_dev;
	struct nfp_app_fw_flower *app_fw_flower;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	pf_dev = NFP_NET_DEV_PRIVATE_TO_PF(dev->data->dev_private);
	hw = NFP_NET_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	app_fw_flower = NFP_PRIV_TO_APP_FW_FLOWER(pf_dev->app_fw_priv);

	/*
	 * We assume that the DPDK application is stopping all the
	 * threads/queues before calling the device close function.
	 */
	nfp_net_disable_queues(dev);

	/* Clear queues */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		this_tx_q = (struct nfp_net_txq *)dev->data->tx_queues[i];
		nfp_net_reset_tx_queue(this_tx_q);
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		this_rx_q = (struct nfp_net_rxq *)dev->data->rx_queues[i];
		nfp_net_reset_rx_queue(this_rx_q);
	}

	/* Cancel possible impending LSC work here before releasing the port*/
	rte_eal_alarm_cancel(nfp_net_dev_interrupt_delayed_handler, (void *)dev);

	nn_cfg_writeb(hw, NFP_NET_CFG_LSC, 0xff);

	rte_eth_dev_release_port(dev);

	/* Now it is safe to free all PF resources */
	PMD_DRV_LOG(INFO, "Freeing PF resources");
	nfp_cpp_area_free(pf_dev->ctrl_area);
	nfp_cpp_area_free(pf_dev->hwqueues_area);
	free(pf_dev->hwinfo);
	free(pf_dev->sym_tbl);
	nfp_cpp_free(pf_dev->cpp);
	rte_free(app_fw_flower);
	rte_free(pf_dev);

	rte_intr_disable(pci_dev->intr_handle);

	/* unregister callback func from eal lib */
	rte_intr_callback_unregister(pci_dev->intr_handle,
			nfp_net_dev_interrupt_handler, (void *)dev);

	return 0;
}

static const struct eth_dev_ops nfp_flower_pf_vnic_ops = {
	.dev_infos_get          = nfp_net_infos_get,
	.link_update            = nfp_net_link_update,
	.dev_configure          = nfp_net_configure,

	.dev_start              = nfp_flower_pf_start,
	.dev_stop               = nfp_flower_pf_stop,
	.dev_close              = nfp_flower_pf_close,
};

struct dp_packet {
	struct rte_mbuf mbuf;
	uint32_t source;
};

static void
nfp_flower_pf_mp_init(__rte_unused struct rte_mempool *mp,
		__rte_unused void *opaque_arg,
		void *packet,
		__rte_unused unsigned int i)
{
	struct dp_packet *pkt = packet;
	/* Indicate that this pkt is from DPDK */
	pkt->source = 3;
}

static struct rte_mempool *
nfp_flower_pf_mp_create(void)
{
	uint32_t nb_mbufs;
	unsigned int numa_node;
	struct rte_mempool *pktmbuf_pool;
	uint32_t n_rxd = PF_VNIC_NB_DESC;
	uint32_t n_txd = PF_VNIC_NB_DESC;

	nb_mbufs = RTE_MAX(n_rxd + n_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE, 81920U);

	numa_node = rte_socket_id();
	pktmbuf_pool = rte_pktmbuf_pool_create("flower_pf_mbuf_pool", nb_mbufs,
			MEMPOOL_CACHE_SIZE, MBUF_PRIV_SIZE,
			RTE_MBUF_DEFAULT_BUF_SIZE, numa_node);
	if (pktmbuf_pool == NULL) {
		PMD_INIT_LOG(ERR, "Cannot init pf vnic mbuf pool");
		return NULL;
	}

	rte_mempool_obj_iter(pktmbuf_pool, nfp_flower_pf_mp_init, NULL);

	return pktmbuf_pool;
}

static int
nfp_flower_init_vnic_common(struct nfp_net_hw *hw, const char *vnic_type)
{
	uint32_t start_q;
	uint64_t rx_bar_off;
	uint64_t tx_bar_off;
	const int stride = 4;
	struct nfp_pf_dev *pf_dev;
	struct rte_pci_device *pci_dev;

	pf_dev = hw->pf_dev;
	pci_dev = hw->pf_dev->pci_dev;

	/* NFP can not handle DMA addresses requiring more than 40 bits */
	if (rte_mem_check_dma_mask(40)) {
		PMD_INIT_LOG(ERR, "Device %s can not be used: restricted dma mask to 40 bits!\n",
				pci_dev->device.name);
		return -ENODEV;
	};

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->subsystem_device_id = pci_dev->id.subsystem_device_id;
	hw->subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;

	PMD_INIT_LOG(DEBUG, "%s vNIC ctrl bar: %p", vnic_type, hw->ctrl_bar);

	/* Read the number of available rx/tx queues from hardware */
	hw->max_rx_queues = nn_cfg_readl(hw, NFP_NET_CFG_MAX_RXRINGS);
	hw->max_tx_queues = nn_cfg_readl(hw, NFP_NET_CFG_MAX_TXRINGS);

	/* Work out where in the BAR the queues start */
	start_q = nn_cfg_readl(hw, NFP_NET_CFG_START_TXQ);
	tx_bar_off = (uint64_t)start_q * NFP_QCP_QUEUE_ADDR_SZ;
	start_q = nn_cfg_readl(hw, NFP_NET_CFG_START_RXQ);
	rx_bar_off = (uint64_t)start_q * NFP_QCP_QUEUE_ADDR_SZ;

	hw->tx_bar = pf_dev->hw_queues + tx_bar_off;
	hw->rx_bar = pf_dev->hw_queues + rx_bar_off;

	/* Get some of the read-only fields from the config BAR */
	hw->ver = nn_cfg_readl(hw, NFP_NET_CFG_VERSION);
	hw->cap = nn_cfg_readl(hw, NFP_NET_CFG_CAP);
	hw->max_mtu = nn_cfg_readl(hw, NFP_NET_CFG_MAX_MTU);
	/* Set the current MTU to the maximum supported */
	hw->mtu = hw->max_mtu;
	hw->flbufsz = DEFAULT_FLBUF_SIZE;

	/* read the Rx offset configured from firmware */
	if (NFD_CFG_MAJOR_VERSION_of(hw->ver) < 2)
		hw->rx_offset = NFP_NET_RX_OFFSET;
	else
		hw->rx_offset = nn_cfg_readl(hw, NFP_NET_CFG_RX_OFFSET_ADDR);

	hw->ctrl = 0;
	hw->stride_rx = stride;
	hw->stride_tx = stride;

	/* Reuse cfg queue setup function */
	nfp_net_cfg_queue_setup(hw);

	PMD_INIT_LOG(INFO, "%s vNIC max_rx_queues: %u, max_tx_queues: %u",
			vnic_type, hw->max_rx_queues, hw->max_tx_queues);

	/* Initializing spinlock for reconfigs */
	rte_spinlock_init(&hw->reconfig_lock);

	return 0;
}

static int
nfp_flower_init_pf_vnic(struct nfp_net_hw *hw)
{
	int ret;
	uint16_t i;
	uint16_t n_txq;
	uint16_t n_rxq;
	unsigned int numa_node;
	struct rte_mempool *mp;
	struct nfp_pf_dev *pf_dev;
	struct rte_eth_dev *eth_dev;
	struct nfp_app_fw_flower *app_fw_flower;

	static const struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode  = RTE_ETH_MQ_RX_RSS,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
		},
	};

	/* Set up some pointers here for ease of use */
	pf_dev = hw->pf_dev;
	app_fw_flower = NFP_PRIV_TO_APP_FW_FLOWER(pf_dev->app_fw_priv);

	/*
	 * Perform the "common" part of setting up a flower vNIC.
	 * Mostly reading configuration from hardware.
	 */
	ret = nfp_flower_init_vnic_common(hw, "pf_vnic");
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Could not init pf vnic");
		return -EINVAL;
	}

	hw->eth_dev = rte_eth_dev_allocate("nfp_pf_vnic");
	if (hw->eth_dev == NULL) {
		PMD_INIT_LOG(ERR, "Could not allocate pf vnic");
		return -ENOMEM;
	}

	/* Grab the pointer to the newly created rte_eth_dev here */
	eth_dev = hw->eth_dev;

	numa_node = rte_socket_id();

	/* Create a mbuf pool for the PF */
	app_fw_flower->pf_pktmbuf_pool = nfp_flower_pf_mp_create();
	if (app_fw_flower->pf_pktmbuf_pool == NULL) {
		PMD_INIT_LOG(ERR, "Could not create mempool for pf vnic");
		ret = -ENOMEM;
		goto port_release;
	}

	mp = app_fw_flower->pf_pktmbuf_pool;

	/* Add Rx/Tx functions */
	eth_dev->dev_ops = &nfp_flower_pf_vnic_ops;

	/* PF vNIC gets a random MAC */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr", RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Could not allocate mac addr");
		ret = -ENOMEM;
		goto mempool_cleanup;
	}

	rte_eth_random_addr(eth_dev->data->mac_addrs->addr_bytes);
	rte_eth_dev_probing_finish(eth_dev);

	/* Configure the PF device now */
	n_rxq = hw->max_rx_queues;
	n_txq = hw->max_tx_queues;
	memcpy(&eth_dev->data->dev_conf, &port_conf, sizeof(struct rte_eth_conf));
	eth_dev->data->rx_queues = rte_zmalloc("ethdev->rx_queues",
		sizeof(eth_dev->data->rx_queues[0]) * n_rxq, RTE_CACHE_LINE_SIZE);
	if (eth_dev->data->rx_queues == NULL) {
		PMD_INIT_LOG(ERR, "rte_zmalloc failed for PF vNIC rx queues");
		ret = -ENOMEM;
		goto mac_cleanup;
	}

	eth_dev->data->tx_queues = rte_zmalloc("ethdev->tx_queues",
		sizeof(eth_dev->data->tx_queues[0]) * n_txq, RTE_CACHE_LINE_SIZE);
	if (eth_dev->data->tx_queues == NULL) {
		PMD_INIT_LOG(ERR, "rte_zmalloc failed for PF vNIC tx queues");
		ret = -ENOMEM;
		goto rx_queue_free;
	}

	/* Fill in some of the eth_dev fields */
	eth_dev->device = &pf_dev->pci_dev->device;
	eth_dev->data->nb_tx_queues = n_rxq;
	eth_dev->data->nb_rx_queues = n_txq;
	eth_dev->data->dev_private = hw;
	eth_dev->data->dev_configured = 1;

	/* Set up the Rx queues */
	for (i = 0; i < n_rxq; i++) {
		ret = nfp_net_rx_queue_setup(eth_dev, i, PF_VNIC_NB_DESC, numa_node,
				&rx_conf, mp);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Configure flower PF vNIC Rx queue %d failed", i);
			goto rx_queue_cleanup;
		}
	}

	/* Set up the Tx queues */
	for (i = 0; i < n_txq; i++) {
		ret = nfp_net_nfd3_tx_queue_setup(eth_dev, i, PF_VNIC_NB_DESC, numa_node,
				&tx_conf);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Configure flower PF vNIC Tx queue %d failed", i);
			goto tx_queue_cleanup;
		}
	}

	return 0;

tx_queue_cleanup:
	for (i = 0; i < n_txq; i++)
		nfp_net_tx_queue_release(eth_dev, i);
rx_queue_cleanup:
	for (i = 0; i < n_rxq; i++)
		nfp_net_rx_queue_release(eth_dev, i);
	rte_free(eth_dev->data->tx_queues);
rx_queue_free:
	rte_free(eth_dev->data->rx_queues);
mac_cleanup:
	rte_free(eth_dev->data->mac_addrs);
mempool_cleanup:
	rte_mempool_free(mp);
port_release:
	rte_eth_dev_release_port(hw->eth_dev);

	return ret;
}

static void
nfp_flower_cleanup_pf_vnic(struct nfp_net_hw *hw)
{
	uint16_t i;
	struct nfp_app_fw_flower *app_fw_flower;

	app_fw_flower = NFP_PRIV_TO_APP_FW_FLOWER(hw->pf_dev->app_fw_priv);

	for (i = 0; i < hw->max_tx_queues; i++)
		nfp_net_tx_queue_release(hw->eth_dev, i);

	for (i = 0; i < hw->max_tx_queues; i++)
		nfp_net_rx_queue_release(hw->eth_dev, i);

	rte_free(hw->eth_dev->data->tx_queues);
	rte_free(hw->eth_dev->data->rx_queues);
	rte_free(hw->eth_dev->data->mac_addrs);
	rte_mempool_free(app_fw_flower->pf_pktmbuf_pool);
	rte_eth_dev_release_port(hw->eth_dev);
}

static int
nfp_flower_start_pf_vnic(struct nfp_net_hw *hw)
{
	int ret;
	struct rte_eth_dev *dev;

	dev = hw->eth_dev;

	/* Start the device */
	ret = nfp_flower_pf_start(dev);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Could not start pf vnic");
		return -EINVAL;
	}

	dev->data->dev_started = 1;
	nfp_net_link_update(dev, 0);

	return 0;
}

int
nfp_init_app_fw_flower(struct nfp_pf_dev *pf_dev)
{
	int ret;
	unsigned int numa_node;
	struct nfp_net_hw *pf_hw;
	struct nfp_app_fw_flower *app_fw_flower;

	numa_node = rte_socket_id();

	/* Allocate memory for the Flower app */
	app_fw_flower = rte_zmalloc_socket("nfp_app_fw_flower", sizeof(*app_fw_flower),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (app_fw_flower == NULL) {
		PMD_INIT_LOG(ERR, "Could not malloc app fw flower");
		return -ENOMEM;
	}

	pf_dev->app_fw_priv = app_fw_flower;

	/* Allocate memory for the PF AND ctrl vNIC here (hence the * 2) */
	pf_hw = rte_zmalloc_socket("nfp_pf_vnic", 2 * sizeof(struct nfp_net_adapter),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (pf_hw == NULL) {
		PMD_INIT_LOG(ERR, "Could not malloc nfp pf vnic");
		ret = -ENOMEM;
		goto app_cleanup;
	}

	/* Grab the number of physical ports present on hardware */
	app_fw_flower->nfp_eth_table = nfp_eth_read_ports(pf_dev->cpp);
	if (app_fw_flower->nfp_eth_table == NULL) {
		PMD_INIT_LOG(ERR, "error reading nfp ethernet table");
		ret = -EIO;
		goto vnic_cleanup;
	}

	/* Map the PF ctrl bar */
	pf_dev->ctrl_bar = nfp_rtsym_map(pf_dev->sym_tbl, "_pf0_net_bar0",
			32768, &pf_dev->ctrl_area);
	if (pf_dev->ctrl_bar == NULL) {
		PMD_INIT_LOG(ERR, "Cloud not map the PF vNIC ctrl bar");
		ret = -ENODEV;
		goto eth_tbl_cleanup;
	}

	/* Fill in the PF vNIC and populate app struct */
	app_fw_flower->pf_hw = pf_hw;
	pf_hw->ctrl_bar = pf_dev->ctrl_bar;
	pf_hw->pf_dev = pf_dev;
	pf_hw->cpp = pf_dev->cpp;

	ret = nfp_flower_init_pf_vnic(app_fw_flower->pf_hw);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Could not initialize flower PF vNIC");
		goto pf_cpp_area_cleanup;
	}

	/* Start the PF vNIC */
	ret = nfp_flower_start_pf_vnic(app_fw_flower->pf_hw);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Could not start flower PF vNIC");
		goto pf_vnic_cleanup;
	}

	return 0;

pf_vnic_cleanup:
	nfp_flower_cleanup_pf_vnic(app_fw_flower->pf_hw);
pf_cpp_area_cleanup:
	nfp_cpp_area_free(pf_dev->ctrl_area);
eth_tbl_cleanup:
	free(app_fw_flower->nfp_eth_table);
vnic_cleanup:
	rte_free(pf_hw);
app_cleanup:
	rte_free(app_fw_flower);

	return ret;
}

int
nfp_secondary_init_app_fw_flower(struct nfp_cpp *cpp)
{
	struct rte_eth_dev *eth_dev;
	const char *port_name = "pf_vnic_eth_dev";

	PMD_INIT_LOG(DEBUG, "Secondary attaching to port %s", port_name);

	eth_dev = rte_eth_dev_attach_secondary(port_name);
	if (eth_dev == NULL) {
		PMD_INIT_LOG(ERR, "Secondary process attach to port %s failed", port_name);
		return -ENODEV;
	}

	eth_dev->process_private = cpp;
	eth_dev->dev_ops = &nfp_flower_pf_vnic_ops;
	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}
