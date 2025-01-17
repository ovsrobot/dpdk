/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2025 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <ethdev_pci.h>

#include "ngbe_logs.h"
#include "base/ngbe.h"
#include "ngbe_ethdev.h"
#include "ngbe_rxtx.h"
#include "ngbe_regs_group.h"

#define NGBEVF_PMD_NAME "rte_ngbevf_pmd" /* PMD name */
static int ngbevf_dev_close(struct rte_eth_dev *dev);
static int ngbevf_vlan_offload_config(struct rte_eth_dev *dev, int mask);
static void ngbevf_set_vfta_all(struct rte_eth_dev *dev, bool on);
static int ngbevf_dev_promiscuous_enable(struct rte_eth_dev *dev);
static int ngbevf_dev_promiscuous_disable(struct rte_eth_dev *dev);
static void ngbevf_remove_mac_addr(struct rte_eth_dev *dev, uint32_t index);

/*
 * The set of PCI devices this driver supports (for VF)
 */
static const struct rte_pci_id pci_id_ngbevf_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL_W_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A2_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A2S_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A4_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A4S_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL2_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL2S_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL4_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860AL4S_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860NCSI_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A1_VF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_WANGXUN, NGBE_DEV_ID_EM_WX1860A1L_VF) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = NGBE_RING_DESC_MAX,
	.nb_min = NGBE_RING_DESC_MIN,
	.nb_align = NGBE_RXD_ALIGN,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = NGBE_RING_DESC_MAX,
	.nb_min = NGBE_RING_DESC_MIN,
	.nb_align = NGBE_TXD_ALIGN,
	.nb_seg_max = NGBE_TX_MAX_SEG,
	.nb_mtu_seg_max = NGBE_TX_MAX_SEG,
};

static const struct eth_dev_ops ngbevf_eth_dev_ops;

/*
 * Negotiate mailbox API version with the PF.
 * After reset API version is always set to the basic one (ngbe_mbox_api_10).
 * Then we try to negotiate starting with the most recent one.
 * If all negotiation attempts fail, then we will proceed with
 * the default one (ngbe_mbox_api_10).
 */
static void
ngbevf_negotiate_api(struct ngbe_hw *hw)
{
	int32_t i;

	/* start with highest supported, proceed down */
	static const int sup_ver[] = {
		ngbe_mbox_api_13,
		ngbe_mbox_api_12,
		ngbe_mbox_api_11,
		ngbe_mbox_api_10,
	};

	for (i = 0; i < ARRAY_SIZE(sup_ver); i++) {
		if (ngbevf_negotiate_api_version(hw, sup_ver[i]) == 0)
			break;
	}
}

static void
generate_random_mac_addr(struct rte_ether_addr *mac_addr)
{
	uint64_t random;

	/* Set Organizationally Unique Identifier (OUI) prefix. */
	mac_addr->addr_bytes[0] = 0x00;
	mac_addr->addr_bytes[1] = 0x09;
	mac_addr->addr_bytes[2] = 0xC0;
	/* Force indication of locally assigned MAC address. */
	mac_addr->addr_bytes[0] |= RTE_ETHER_LOCAL_ADMIN_ADDR;
	/* Generate the last 3 bytes of the MAC address with a random number. */
	random = rte_rand();
	memcpy(&mac_addr->addr_bytes[3], &random, 3);
}

/*
 * Virtual Function device init
 */
static int
eth_ngbevf_dev_init(struct rte_eth_dev *eth_dev)
{
	int err;
	uint32_t tc, tcs;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct ngbe_hw *hw = ngbe_dev_hw(eth_dev);
	struct ngbe_vfta *shadow_vfta = NGBE_DEV_VFTA(eth_dev);
	struct ngbe_hwstrip *hwstrip = NGBE_DEV_HWSTRIP(eth_dev);
	struct rte_ether_addr *perm_addr =
			(struct rte_ether_addr *)hw->mac.perm_addr;

	PMD_INIT_FUNC_TRACE();

	eth_dev->dev_ops = &ngbevf_eth_dev_ops;
	eth_dev->rx_descriptor_status = ngbe_dev_rx_descriptor_status;
	eth_dev->tx_descriptor_status = ngbe_dev_tx_descriptor_status;
	eth_dev->rx_pkt_burst = &ngbe_recv_pkts;
	eth_dev->tx_pkt_burst = &ngbe_xmit_pkts;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work. Only check we don't need a different
	 * RX function
	 */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		struct ngbe_tx_queue *txq;
		uint16_t nb_tx_queues = eth_dev->data->nb_tx_queues;
		/* TX queue function in primary, set by last queue initialized
		 * Tx queue may not initialized by primary process
		 */
		if (eth_dev->data->tx_queues) {
			txq = eth_dev->data->tx_queues[nb_tx_queues - 1];
			ngbe_set_tx_function(eth_dev, txq);
		} else {
			/* Use default TX function if we get here */
			PMD_INIT_LOG(NOTICE,
				     "No TX queues configured yet. Using default TX function.");
		}

		ngbe_set_rx_function(eth_dev);

		return 0;
	}

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;
	hw->sub_system_id = pci_dev->id.subsystem_device_id;
	ngbe_map_device_id(hw);
	hw->hw_addr = (void *)pci_dev->mem_resource[0].addr;

	/* initialize the vfta */
	memset(shadow_vfta, 0, sizeof(*shadow_vfta));

	/* initialize the hw strip bitmap*/
	memset(hwstrip, 0, sizeof(*hwstrip));

	/* Initialize the shared code (base driver) */
	err = ngbe_init_shared_code(hw);
	if (err != 0) {
		PMD_INIT_LOG(ERR,
			"Shared code init failed for ngbevf: %d", err);
		return -EIO;
	}

	/* init_mailbox_params */
	hw->mbx.init_params(hw);

	hw->mac.num_rar_entries = 32; /* The MAX of the underlying PF */
	err = hw->mac.reset_hw(hw);

	/*
	 * The VF reset operation returns the NGBE_ERR_INVALID_MAC_ADDR when
	 * the underlying PF driver has not assigned a MAC address to the VF.
	 * In this case, assign a random MAC address.
	 */
	if (err != 0 && err != NGBE_ERR_INVALID_MAC_ADDR) {
		PMD_INIT_LOG(ERR, "VF Initialization Failure: %d", err);
		/*
		 * This error code will be propagated to the app by
		 * rte_eth_dev_reset, so use a public error code rather than
		 * the internal-only NGBE_ERR_RESET_FAILED
		 */
		return -EAGAIN;
	}

	/* negotiate mailbox API version to use with the PF. */
	ngbevf_negotiate_api(hw);

	/* Get Rx/Tx queue count via mailbox, which is ready after reset_hw */
	ngbevf_get_queues(hw, &tcs, &tc);

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("ngbevf", RTE_ETHER_ADDR_LEN *
					       hw->mac.num_rar_entries, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR,
			     "Failed to allocate %u bytes needed to store MAC addresses",
			     RTE_ETHER_ADDR_LEN * hw->mac.num_rar_entries);
		return -ENOMEM;
	}

	/* Generate a random MAC address, if none was assigned by PF. */
	if (rte_is_zero_ether_addr(perm_addr)) {
		generate_random_mac_addr(perm_addr);
		err = ngbe_set_rar_vf(hw, 1, perm_addr->addr_bytes, 0, 1);
		if (err) {
			rte_free(eth_dev->data->mac_addrs);
			eth_dev->data->mac_addrs = NULL;
			return err;
		}
		PMD_INIT_LOG(INFO, "\tVF MAC address not assigned by Host PF");
		PMD_INIT_LOG(INFO, "\tAssign randomly generated MAC address "
			     "%02x:%02x:%02x:%02x:%02x:%02x",
			     perm_addr->addr_bytes[0],
			     perm_addr->addr_bytes[1],
			     perm_addr->addr_bytes[2],
			     perm_addr->addr_bytes[3],
			     perm_addr->addr_bytes[4],
			     perm_addr->addr_bytes[5]);
	}

	/* Copy the permanent MAC address */
	rte_ether_addr_copy(perm_addr, &eth_dev->data->mac_addrs[0]);

	/* reset the hardware with the new settings */
	err = hw->mac.start_hw(hw);
	if (err) {
		PMD_INIT_LOG(ERR, "VF Initialization Failure: %d", err);
		return -EIO;
	}

	/* enter promiscuous mode */
	ngbevf_dev_promiscuous_enable(eth_dev);

	PMD_INIT_LOG(DEBUG, "port %d vendorID=0x%x deviceID=0x%x mac.type=%s",
		     eth_dev->data->port_id, pci_dev->id.vendor_id,
		     pci_dev->id.device_id, "ngbe_mac_sp_vf");

	return 0;
}

/* Virtual Function device uninit */
static int
eth_ngbevf_dev_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	ngbevf_dev_close(eth_dev);

	return 0;
}

static int eth_ngbevf_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct ngbe_adapter), eth_ngbevf_dev_init);
}

static int eth_ngbevf_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, eth_ngbevf_dev_uninit);
}

/*
 * virtual function driver struct
 */
static struct rte_pci_driver rte_ngbevf_pmd = {
	.id_table = pci_id_ngbevf_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_ngbevf_pci_probe,
	.remove = eth_ngbevf_pci_remove,
};

static int
ngbevf_dev_info_get(struct rte_eth_dev *dev,
		     struct rte_eth_dev_info *dev_info)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct ngbe_hw *hw = ngbe_dev_hw(dev);

	dev_info->max_rx_queues = (uint16_t)hw->mac.max_rx_queues;
	dev_info->max_tx_queues = (uint16_t)hw->mac.max_tx_queues;
	dev_info->min_rx_bufsize = 1024;
	dev_info->max_rx_pktlen = NGBE_FRAME_SIZE_MAX;
	dev_info->max_mac_addrs = hw->mac.num_rar_entries;
	dev_info->max_hash_mac_addrs = NGBE_VMDQ_NUM_UC_MAC;
	dev_info->max_vfs = pci_dev->max_vfs;
	dev_info->max_vmdq_pools = RTE_ETH_64_POOLS;
	dev_info->rx_queue_offload_capa = ngbe_get_rx_queue_offloads(dev);
	dev_info->rx_offload_capa = (ngbe_get_rx_port_offloads(dev) |
				     dev_info->rx_queue_offload_capa);
	dev_info->tx_queue_offload_capa = 0;
	dev_info->tx_offload_capa = ngbe_get_tx_port_offloads(dev);
	dev_info->hash_key_size = NGBE_HKEY_MAX_INDEX * sizeof(uint32_t);
	dev_info->reta_size = RTE_ETH_RSS_RETA_SIZE_128;
	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = NGBE_DEFAULT_RX_PTHRESH,
			.hthresh = NGBE_DEFAULT_RX_HTHRESH,
			.wthresh = NGBE_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = NGBE_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = NGBE_DEFAULT_TX_PTHRESH,
			.hthresh = NGBE_DEFAULT_TX_HTHRESH,
			.wthresh = NGBE_DEFAULT_TX_WTHRESH,
		},
		.tx_free_thresh = NGBE_DEFAULT_TX_FREE_THRESH,
		.offloads = 0,
	};

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;

	return 0;
}

static int
ngbevf_dev_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_conf *conf = &dev->data->dev_conf;
	struct ngbe_adapter *adapter = ngbe_dev_adapter(dev);

	PMD_INIT_LOG(DEBUG, "Configured Virtual Function port id: %d",
		     dev->data->port_id);

	/*
	 * VF has no ability to enable/disable HW CRC
	 * Keep the persistent behavior the same as Host PF
	 */
#ifndef RTE_LIBRTE_NGBE_PF_DISABLE_STRIP_CRC
	if (conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC) {
		PMD_INIT_LOG(NOTICE, "VF can't disable HW CRC Strip");
		conf->rxmode.offloads &= ~RTE_ETH_RX_OFFLOAD_KEEP_CRC;
	}
#else
	if (!(conf->rxmode.offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)) {
		PMD_INIT_LOG(NOTICE, "VF can't enable HW CRC Strip");
		conf->rxmode.offloads |= RTE_ETH_RX_OFFLOAD_KEEP_CRC;
	}
#endif

	/*
	 * Initialize to TRUE. If any of Rx queues doesn't meet the bulk
	 * allocation or vector Rx preconditions we will reset it.
	 */
	adapter->rx_bulk_alloc_allowed = true;

	return 0;
}

static int
ngbevf_dev_close(struct rte_eth_dev *dev)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);

	PMD_INIT_FUNC_TRACE();
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	hw->mac.reset_hw(hw);

	/**
	 * Remove the VF MAC address ro ensure
	 * that the VF traffic goes to the PF
	 * after stop, close and detach of the VF
	 **/
	ngbevf_remove_mac_addr(dev, 0);

	dev->rx_pkt_burst = NULL;
	dev->tx_pkt_burst = NULL;

	rte_free(dev->data->mac_addrs);
	dev->data->mac_addrs = NULL;

	return 0;
}

static void ngbevf_set_vfta_all(struct rte_eth_dev *dev, bool on)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	struct ngbe_vfta *shadow_vfta = NGBE_DEV_VFTA(dev);
	int i = 0, j = 0, vfta = 0, mask = 1;

	for (i = 0; i < NGBE_VFTA_SIZE; i++) {
		vfta = shadow_vfta->vfta[i];
		if (vfta) {
			mask = 1;
			for (j = 0; j < 32; j++) {
				if (vfta & mask)
					hw->mac.set_vfta(hw, (i << 5) + j, 0,
						       on, false);
				mask <<= 1;
			}
		}
	}
}

static int
ngbevf_vlan_filter_set(struct rte_eth_dev *dev, uint16_t vlan_id, int on)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	struct ngbe_vfta *shadow_vfta = NGBE_DEV_VFTA(dev);
	uint32_t vid_idx = 0;
	uint32_t vid_bit = 0;
	int ret = 0;

	PMD_INIT_FUNC_TRACE();

	/* vind is not used in VF driver, set to 0, check ngbe_set_vfta_vf */
	ret = hw->mac.set_vfta(hw, vlan_id, 0, !!on, false);
	if (ret) {
		PMD_INIT_LOG(ERR, "Unable to set VF vlan");
		return ret;
	}
	vid_idx = (uint32_t)((vlan_id >> 5) & 0x7F);
	vid_bit = (uint32_t)(1 << (vlan_id & 0x1F));

	/* Save what we set and restore it after device reset */
	if (on)
		shadow_vfta->vfta[vid_idx] |= vid_bit;
	else
		shadow_vfta->vfta[vid_idx] &= ~vid_bit;

	return 0;
}

static void
ngbevf_vlan_strip_queue_set(struct rte_eth_dev *dev, uint16_t queue, int on)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	uint32_t ctrl;

	PMD_INIT_FUNC_TRACE();

	if (queue >= hw->mac.max_rx_queues)
		return;

	ctrl = rd32(hw, NGBE_RXCFG(queue));
	if (on)
		ctrl |= NGBE_RXCFG_VLAN;
	else
		ctrl &= ~NGBE_RXCFG_VLAN;
	wr32(hw, NGBE_RXCFG(queue), ctrl);

	ngbe_vlan_hw_strip_bitmap_set(dev, queue, on);
}

static int
ngbevf_vlan_offload_config(struct rte_eth_dev *dev, int mask)
{
	struct ngbe_rx_queue *rxq;
	uint16_t i;
	int on = 0;

	/* VF function only support hw strip feature, others are not support */
	if (mask & RTE_ETH_VLAN_STRIP_MASK) {
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			on = !!(rxq->offloads &	RTE_ETH_RX_OFFLOAD_VLAN_STRIP);
			ngbevf_vlan_strip_queue_set(dev, i, on);
		}
	}

	return 0;
}

static int
ngbevf_vlan_offload_set(struct rte_eth_dev *dev, int mask)
{
	ngbe_config_vlan_strip_on_all_queues(dev, mask);

	ngbevf_vlan_offload_config(dev, mask);

	return 0;
}

static int
ngbevf_add_mac_addr(struct rte_eth_dev *dev, struct rte_ether_addr *mac_addr,
		     __rte_unused uint32_t index,
		     __rte_unused uint32_t pool)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	int err;

	/*
	 * On a VF, adding again the same MAC addr is not an idempotent
	 * operation. Trap this case to avoid exhausting the [very limited]
	 * set of PF resources used to store VF MAC addresses.
	 */
	if (memcmp(hw->mac.perm_addr, mac_addr,
			sizeof(struct rte_ether_addr)) == 0)
		return -1;
	err = ngbevf_set_uc_addr_vf(hw, 2, mac_addr->addr_bytes);
	if (err != 0)
		PMD_DRV_LOG(ERR, "Unable to add MAC address "
			    "%02x:%02x:%02x:%02x:%02x:%02x - err=%d",
			    mac_addr->addr_bytes[0],
			    mac_addr->addr_bytes[1],
			    mac_addr->addr_bytes[2],
			    mac_addr->addr_bytes[3],
			    mac_addr->addr_bytes[4],
			    mac_addr->addr_bytes[5],
			    err);
	return err;
}

static void
ngbevf_remove_mac_addr(struct rte_eth_dev *dev, uint32_t index)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	struct rte_ether_addr *perm_addr =
			(struct rte_ether_addr *)hw->mac.perm_addr;
	struct rte_ether_addr *mac_addr;
	uint32_t i;
	int err;

	/*
	 * The NGBE_VF_SET_MACVLAN command of the ngbe-pf driver does
	 * not support the deletion of a given MAC address.
	 * Instead, it imposes to delete all MAC addresses, then to add again
	 * all MAC addresses with the exception of the one to be deleted.
	 */
	(void)ngbevf_set_uc_addr_vf(hw, 0, NULL);

	/*
	 * Add again all MAC addresses, with the exception of the deleted one
	 * and of the permanent MAC address.
	 */
	for (i = 0, mac_addr = dev->data->mac_addrs;
	     i < hw->mac.num_rar_entries; i++, mac_addr++) {
		/* Skip the deleted MAC address */
		if (i == index)
			continue;
		/* Skip NULL MAC addresses */
		if (rte_is_zero_ether_addr(mac_addr))
			continue;
		/* Skip the permanent MAC address */
		if (memcmp(perm_addr, mac_addr,
				sizeof(struct rte_ether_addr)) == 0)
			continue;
		err = ngbevf_set_uc_addr_vf(hw, 2, mac_addr->addr_bytes);
		if (err != 0)
			PMD_DRV_LOG(ERR,
				    "Adding again MAC address "
				    "%02x:%02x:%02x:%02x:%02x:%02x failed "
				    "err=%d",
				    mac_addr->addr_bytes[0],
				    mac_addr->addr_bytes[1],
				    mac_addr->addr_bytes[2],
				    mac_addr->addr_bytes[3],
				    mac_addr->addr_bytes[4],
				    mac_addr->addr_bytes[5],
				    err);
	}
}

static int
ngbevf_set_default_mac_addr(struct rte_eth_dev *dev,
		struct rte_ether_addr *addr)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);

	hw->mac.set_rar(hw, 0, (void *)addr, 0, 0);

	return 0;
}

static int
ngbevf_dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct ngbe_hw *hw;
	uint32_t max_frame = mtu + RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN;
	struct rte_eth_dev_data *dev_data = dev->data;

	hw = ngbe_dev_hw(dev);

	if (mtu < RTE_ETHER_MIN_MTU ||
			max_frame > RTE_ETHER_MAX_JUMBO_FRAME_LEN)
		return -EINVAL;

	/* If device is started, refuse mtu that requires the support of
	 * scattered packets when this feature has not been enabled before.
	 */
	if (dev_data->dev_started && !dev_data->scattered_rx &&
	    (max_frame + 2 * RTE_VLAN_HLEN >
	     dev->data->min_rx_buf_size - RTE_PKTMBUF_HEADROOM)) {
		PMD_INIT_LOG(ERR, "Stop port first.");
		return -EINVAL;
	}

	/*
	 * When supported by the underlying PF driver, use the NGBE_VF_SET_MTU
	 * request of the version 2.0 of the mailbox API.
	 * For now, use the NGBE_VF_SET_LPE request of the version 1.0
	 * of the mailbox API.
	 */
	if (ngbevf_rlpml_set_vf(hw, max_frame))
		return -EINVAL;

	return 0;
}

static int
ngbevf_dev_promiscuous_enable(struct rte_eth_dev *dev)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	int ret;

	switch (hw->mac.update_xcast_mode(hw, NGBEVF_XCAST_MODE_PROMISC)) {
	case 0:
		ret = 0;
		break;
	case NGBE_ERR_FEATURE_NOT_SUPPORTED:
		ret = -ENOTSUP;
		break;
	default:
		ret = -EAGAIN;
		break;
	}

	return ret;
}

static int
ngbevf_dev_promiscuous_disable(struct rte_eth_dev *dev)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	int ret;

	switch (hw->mac.update_xcast_mode(hw, NGBEVF_XCAST_MODE_NONE)) {
	case 0:
		ret = 0;
		break;
	case NGBE_ERR_FEATURE_NOT_SUPPORTED:
		ret = -ENOTSUP;
		break;
	default:
		ret = -EAGAIN;
		break;
	}

	return ret;
}

static int
ngbevf_dev_allmulticast_enable(struct rte_eth_dev *dev)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	int ret;

	if (dev->data->promiscuous == 1)
		return 0;

	switch (hw->mac.update_xcast_mode(hw, NGBEVF_XCAST_MODE_ALLMULTI)) {
	case 0:
		ret = 0;
		break;
	case NGBE_ERR_FEATURE_NOT_SUPPORTED:
		ret = -ENOTSUP;
		break;
	default:
		ret = -EAGAIN;
		break;
	}

	return ret;
}

static int
ngbevf_dev_allmulticast_disable(struct rte_eth_dev *dev)
{
	struct ngbe_hw *hw = ngbe_dev_hw(dev);
	int ret;

	switch (hw->mac.update_xcast_mode(hw, NGBEVF_XCAST_MODE_MULTI)) {
	case 0:
		ret = 0;
		break;
	case NGBE_ERR_FEATURE_NOT_SUPPORTED:
		ret = -ENOTSUP;
		break;
	default:
		ret = -EAGAIN;
		break;
	}

	return ret;
}

/*
 * dev_ops for virtual function, bare necessities for basic vf
 * operation have been implemented
 */
static const struct eth_dev_ops ngbevf_eth_dev_ops = {
	.dev_configure        = ngbevf_dev_configure,
	.promiscuous_enable   = ngbevf_dev_promiscuous_enable,
	.promiscuous_disable  = ngbevf_dev_promiscuous_disable,
	.allmulticast_enable  = ngbevf_dev_allmulticast_enable,
	.allmulticast_disable = ngbevf_dev_allmulticast_disable,
	.dev_infos_get        = ngbevf_dev_info_get,
	.mtu_set              = ngbevf_dev_set_mtu,
	.vlan_filter_set      = ngbevf_vlan_filter_set,
	.vlan_strip_queue_set = ngbevf_vlan_strip_queue_set,
	.vlan_offload_set     = ngbevf_vlan_offload_set,
	.mac_addr_add         = ngbevf_add_mac_addr,
	.mac_addr_remove      = ngbevf_remove_mac_addr,
	.mac_addr_set         = ngbevf_set_default_mac_addr,
};

RTE_PMD_REGISTER_PCI(net_ngbe_vf, rte_ngbevf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ngbe_vf, pci_id_ngbevf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ngbe_vf, "* igb_uio | vfio-pci");
