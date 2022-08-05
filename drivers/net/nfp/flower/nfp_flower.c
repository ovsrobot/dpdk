/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Corigine, Inc.
 * All rights reserved.
 */

#include <rte_common.h>
#include <ethdev_driver.h>
#include <rte_service_component.h>
#include <rte_malloc.h>
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
#include "nfp_flower_ovs_compat.h"

#define MAX_PKT_BURST 32
#define MEMPOOL_CACHE_SIZE 512
#define DEFAULT_FLBUF_SIZE 9216

/*
 * Simple dev ops functions for the flower PF. Because a rte_device is exposed
 * to DPDK the flower logic also makes use of helper functions like
 * rte_dev_configure() to set up the PF device. Stub functions are needed to
 * use these helper functions
 */
static int
nfp_flower_pf_configure(__rte_unused struct rte_eth_dev *dev)
{
	return 0;
}

static const struct eth_dev_ops nfp_flower_pf_dev_ops = {
	.dev_configure          = nfp_flower_pf_configure,

	/* Use the normal dev_infos_get functionality in the NFP PMD */
	.dev_infos_get          = nfp_net_infos_get,
};

static struct rte_service_spec flower_services[NFP_FLOWER_SERVICE_MAX] = {
};

static int
nfp_flower_enable_services(struct nfp_app_flower *app_flower)
{
	int i;
	int ret = 0;

	for (i = 0; i < NFP_FLOWER_SERVICE_MAX; i++) {
		/* Pass a pointer to the flower app to the service */
		flower_services[i].callback_userdata = (void *)app_flower;

		/* Register the flower services */
		ret = rte_service_component_register(&flower_services[i],
				&app_flower->flower_services_ids[i]);
		if (ret) {
			PMD_INIT_LOG(WARNING,
				"Could not register Flower PF vNIC service");
			break;
		}

		PMD_INIT_LOG(INFO, "Flower PF vNIC service registered");

		/* Map them to available service cores*/
		ret = nfp_map_service(app_flower->flower_services_ids[i]);
		if (ret)
			break;
	}

	return ret;
}

static void
nfp_flower_pf_mp_init(__rte_unused struct rte_mempool *mp,
		__rte_unused void *opaque_arg,
		void *_p,
		__rte_unused unsigned int i)
{
	struct dp_packet *pkt = _p;
	pkt->source      = DPBUF_DPDK;
	pkt->l2_pad_size = 0;
	pkt->l2_5_ofs    = UINT16_MAX;
	pkt->l3_ofs      = UINT16_MAX;
	pkt->l4_ofs      = UINT16_MAX;
	pkt->packet_type = 0; /* PT_ETH */
}

static struct rte_mempool *
nfp_flower_pf_mp_create(void)
{
	uint32_t nb_mbufs;
	uint32_t pkt_size;
	uint32_t n_rxd = 1024;
	uint32_t n_txd = 1024;
	unsigned int numa_node;
	uint32_t aligned_mbuf_size;
	uint32_t mbuf_priv_data_len;
	struct rte_mempool *pktmbuf_pool;

	nb_mbufs = RTE_MAX(n_rxd + n_txd + MAX_PKT_BURST + MEMPOOL_CACHE_SIZE,
			81920U);

	/*
	 * The size of the mbuf's private area (i.e. area that holds OvS'
	 * dp_packet data)
	 */
	mbuf_priv_data_len = sizeof(struct dp_packet) - sizeof(struct rte_mbuf);
	/* The size of the entire dp_packet. */
	pkt_size = sizeof(struct dp_packet) + RTE_MBUF_DEFAULT_BUF_SIZE;
	/* mbuf size, rounded up to cacheline size. */
	aligned_mbuf_size = ROUND_UP(pkt_size, RTE_CACHE_LINE_SIZE);
	mbuf_priv_data_len += (aligned_mbuf_size - pkt_size);

	numa_node = rte_socket_id();
	pktmbuf_pool = rte_pktmbuf_pool_create("flower_pf_mbuf_pool", nb_mbufs,
			MEMPOOL_CACHE_SIZE, mbuf_priv_data_len,
			RTE_MBUF_DEFAULT_BUF_SIZE, numa_node);
	if (pktmbuf_pool == NULL) {
		RTE_LOG(ERR, PMD, "Cannot init mbuf pool\n");
		return NULL;
	}

	rte_mempool_obj_iter(pktmbuf_pool, nfp_flower_pf_mp_init, NULL);

	return pktmbuf_pool;
}

static void
nfp_flower_cleanup_pf_vnic(struct nfp_net_hw *hw)
{
	uint16_t i;
	struct rte_eth_dev *eth_dev;
	struct nfp_app_flower *app_flower;

	eth_dev = hw->eth_dev;
	app_flower = NFP_APP_PRIV_TO_APP_FLOWER(hw->pf_dev->app_priv);

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		nfp_net_tx_queue_release(eth_dev, i);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		nfp_net_rx_queue_release(eth_dev, i);

	rte_free(eth_dev->data->mac_addrs);
	rte_mempool_free(app_flower->pf_pktmbuf_pool);
	rte_free(eth_dev->data->dev_private);
	rte_eth_dev_release_port(hw->eth_dev);
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
		RTE_LOG(ERR, PMD,
			"device %s can not be used: restricted dma mask to 40 bits!\n",
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
	uint16_t port_id;
	unsigned int numa_node;
	struct rte_mempool *mp;
	struct nfp_pf_dev *pf_dev;
	struct rte_eth_dev *eth_dev;
	struct nfp_app_flower *app_flower;

	const struct rte_eth_rxconf rx_conf = {
		.rx_free_thresh = DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 1,
	};

	const struct rte_eth_txconf tx_conf = {
		.tx_thresh = {
			.pthresh  = DEFAULT_TX_PTHRESH,
			.hthresh = DEFAULT_TX_HTHRESH,
			.wthresh = DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = DEFAULT_TX_FREE_THRESH,
	};

	static struct rte_eth_conf port_conf = {
		.rxmode = {
			.mq_mode  = RTE_ETH_MQ_RX_RSS,
			.offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
		},
		.txmode = {
			.mq_mode = RTE_ETH_MQ_TX_NONE,
		},
	};

	/* Set up some pointers here for ease of use */
	pf_dev = hw->pf_dev;
	app_flower = NFP_APP_PRIV_TO_APP_FLOWER(pf_dev->app_priv);

	/*
	 * Perform the "common" part of setting up a flower vNIC.
	 * Mostly reading configuration from hardware.
	 */
	ret = nfp_flower_init_vnic_common(hw, "pf_vnic");
	if (ret)
		goto done;

	hw->eth_dev = rte_eth_dev_allocate("pf_vnic_eth_dev");
	if (hw->eth_dev == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	/* Grab the pointer to the newly created rte_eth_dev here */
	eth_dev = hw->eth_dev;

	numa_node = rte_socket_id();
	eth_dev->data->dev_private =
		rte_zmalloc_socket("pf_vnic_eth_dev", sizeof(struct nfp_net_hw),
				   RTE_CACHE_LINE_SIZE, numa_node);
	if (eth_dev->data->dev_private == NULL) {
		ret = -ENOMEM;
		goto port_release;
	}

	/* Fill in some of the eth_dev fields */
	eth_dev->device = &pf_dev->pci_dev->device;
	eth_dev->data->nb_tx_queues = hw->max_tx_queues;
	eth_dev->data->nb_rx_queues = hw->max_rx_queues;
	eth_dev->data->dev_private = hw;

	/* Create a mbuf pool for the PF */
	app_flower->pf_pktmbuf_pool = nfp_flower_pf_mp_create();
	if (app_flower->pf_pktmbuf_pool == NULL) {
		ret = -ENOMEM;
		goto private_cleanup;
	}

	mp = app_flower->pf_pktmbuf_pool;

	/* Add Rx/Tx functions */
	eth_dev->dev_ops = &nfp_flower_pf_dev_ops;

	/* PF vNIC gets a random MAC */
	eth_dev->data->mac_addrs = rte_zmalloc("mac_addr",
			RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		ret = -ENOMEM;
		goto mempool_cleanup;
	}

	rte_eth_random_addr(eth_dev->data->mac_addrs->addr_bytes);
	rte_eth_dev_probing_finish(eth_dev);

	/* Configure the PF device now */
	n_rxq = hw->eth_dev->data->nb_rx_queues;
	n_txq = hw->eth_dev->data->nb_tx_queues;
	port_id = hw->eth_dev->data->port_id;

	ret = rte_eth_dev_configure(port_id, n_rxq, n_txq, &port_conf);
	if (ret) {
		PMD_INIT_LOG(ERR, "Could not configure PF device %d", ret);
		goto mac_cleanup;
	}

	/* Set up the Rx queues */
	for (i = 0; i < n_rxq; i++) {
		/* Hardcoded number of desc to 1024 */
		ret = nfp_net_rx_queue_setup(eth_dev, i, 1024, numa_node,
			&rx_conf, mp);
		if (ret) {
			PMD_INIT_LOG(ERR, "Configure flower PF vNIC Rx queue %d failed", i);
			goto rx_queue_cleanup;
		}
	}

	/* Set up the Tx queues */
	for (i = 0; i < n_txq; i++) {
		/* Hardcoded number of desc to 1024 */
		ret = nfp_net_nfd3_tx_queue_setup(eth_dev, i, 1024, numa_node,
			&tx_conf);
		if (ret) {
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
mac_cleanup:
	rte_free(eth_dev->data->mac_addrs);
mempool_cleanup:
	rte_mempool_free(mp);
private_cleanup:
	rte_free(eth_dev->data->dev_private);
port_release:
	rte_eth_dev_release_port(hw->eth_dev);
done:
	return ret;
}

int
nfp_init_app_flower(struct nfp_pf_dev *pf_dev)
{
	int ret;
	unsigned int numa_node;
	struct nfp_net_hw *pf_hw;
	struct nfp_app_flower *app_flower;

	numa_node = rte_socket_id();

	/* Allocate memory for the Flower app */
	app_flower = rte_zmalloc_socket("nfp_app_flower", sizeof(*app_flower),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (app_flower == NULL) {
		ret = -ENOMEM;
		goto done;
	}

	pf_dev->app_priv = app_flower;

	/* Allocate memory for the PF AND ctrl vNIC here (hence the * 2) */
	pf_hw = rte_zmalloc_socket("nfp_pf_vnic", 2 * sizeof(struct nfp_net_adapter),
			RTE_CACHE_LINE_SIZE, numa_node);
	if (pf_hw == NULL) {
		ret = -ENOMEM;
		goto app_cleanup;
	}

	/* Grab the number of physical ports present on hardware */
	app_flower->nfp_eth_table = nfp_eth_read_ports(pf_dev->cpp);
	if (app_flower->nfp_eth_table == NULL) {
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
	app_flower->pf_hw = pf_hw;
	pf_hw->ctrl_bar = pf_dev->ctrl_bar;
	pf_hw->pf_dev = pf_dev;
	pf_hw->cpp = pf_dev->cpp;

	ret = nfp_flower_init_pf_vnic(app_flower->pf_hw);
	if (ret) {
		PMD_INIT_LOG(ERR, "Could not initialize flower PF vNIC");
		goto pf_cpp_area_cleanup;
	}

	/* Start up flower services */
	if (nfp_flower_enable_services(app_flower)) {
		ret = -ESRCH;
		goto pf_vnic_cleanup;
	}

	return 0;

pf_vnic_cleanup:
	nfp_flower_cleanup_pf_vnic(app_flower->pf_hw);
pf_cpp_area_cleanup:
	nfp_cpp_area_free(pf_dev->ctrl_area);
eth_tbl_cleanup:
	free(app_flower->nfp_eth_table);
vnic_cleanup:
	rte_free(pf_hw);
app_cleanup:
	rte_free(app_flower);
done:
	return ret;
}

int
nfp_secondary_init_app_flower(struct nfp_cpp *cpp)
{
	struct rte_eth_dev *eth_dev;
	const char *port_name = "pf_vnic_eth_dev";

	PMD_DRV_LOG(DEBUG, "Secondary attaching to port %s", port_name);

	eth_dev = rte_eth_dev_attach_secondary(port_name);
	if (eth_dev == NULL) {
		RTE_LOG(ERR, EAL, "secondary process attach failed, "
			"ethdev doesn't exist");
		return -ENODEV;
	}

	eth_dev->process_private = cpp;
	eth_dev->dev_ops = &nfp_flower_pf_dev_ops;
	rte_eth_dev_probing_finish(eth_dev);

	return 0;
}
