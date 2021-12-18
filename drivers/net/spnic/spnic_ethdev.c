/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_malloc.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "base/spnic_compat.h"
#include "base/spnic_cmd.h"
#include "base/spnic_csr.h"
#include "base/spnic_wq.h"
#include "base/spnic_eqs.h"
#include "base/spnic_mgmt.h"
#include "base/spnic_cmdq.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_hwif.h"
#include "base/spnic_hw_cfg.h"
#include "base/spnic_hw_comm.h"
#include "base/spnic_nic_cfg.h"
#include "base/spnic_nic_event.h"
#include "spnic_ethdev.h"

/* Driver-specific log messages type */
int spnic_logtype;

#define SPNIC_MAX_UC_MAC_ADDRS		128
#define SPNIC_MAX_MC_MAC_ADDRS		128

/**
 * Deinit mac_vlan table in hardware.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 */

/**
 * Set ethernet device link state up.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err;

	/* Link status follow phy port status, mpu will open pma */
	err = spnic_set_port_enable(nic_dev->hwdev, true);
	if (err)
		PMD_DRV_LOG(ERR, "Set MAC link up failed, dev_name: %s, port_id: %d",
			    nic_dev->dev_name, dev->data->port_id);

	return err;
}

/**
 * Set ethernet device link state down.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure.
 */
static int spnic_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err;

	/* Link status follow phy port status, mpu will close pma */
	err = spnic_set_port_enable(nic_dev->hwdev, false);
	if (err)
		PMD_DRV_LOG(ERR, "Set MAC link down failed, dev_name: %s, port_id: %d",
			    nic_dev->dev_name, dev->data->port_id);

	return err;
}

/**
 * Get device physical link information.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] wait_to_complete
 *   Wait for request completion.
 *
 * @retval 0 : Link status changed
 * @retval -1 : Link status not changed.
 */
static int spnic_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
#define CHECK_INTERVAL 10  /* 10ms */
#define MAX_REPEAT_TIME 100  /* 1s (100 * 10ms) in total */
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	struct rte_eth_link link;
	u8 link_state;
	unsigned int rep_cnt = MAX_REPEAT_TIME;
	int ret;

	memset(&link, 0, sizeof(link));
	do {
		/* Get link status information from hardware */
		ret = spnic_get_link_state(nic_dev->hwdev, &link_state);
		if (ret) {
			link.link_status = ETH_LINK_DOWN;
			link.link_speed = ETH_SPEED_NUM_NONE;
			link.link_duplex = ETH_LINK_HALF_DUPLEX;
			link.link_autoneg = ETH_LINK_FIXED;
			goto out;
		}

		get_port_info(nic_dev->hwdev, link_state, &link);

		if (!wait_to_complete || link.link_status)
			break;

		rte_delay_ms(CHECK_INTERVAL);
	} while (rep_cnt--);

out:
	return rte_eth_linkstatus_set(dev, &link);
}

static void spnic_delete_mc_addr_list(struct spnic_nic_dev *nic_dev);

/**
 * Deinit mac_vlan table in hardware.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 */
static void spnic_deinit_mac_addr(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
				SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u16 func_id = 0;
	int err;
	int i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[i]))
			continue;

		err = spnic_del_mac(nic_dev->hwdev,
				    eth_dev->data->mac_addrs[i].addr_bytes,
				    0, func_id);
		if (err && err != SPNIC_PF_SET_VF_ALREADY)
			PMD_DRV_LOG(ERR, "Delete mac table failed, dev_name: %s",
				    eth_dev->data->name);

		memset(&eth_dev->data->mac_addrs[i], 0,
		       sizeof(struct rte_ether_addr));
	}

	/* Delete multicast mac addrs */
	spnic_delete_mc_addr_list(nic_dev);
}

static int spnic_init_sw_rxtxqs(struct spnic_nic_dev *nic_dev)
{
	u32 txq_size;
	u32 rxq_size;

	/* Allocate software txq array */
	txq_size = nic_dev->max_sqs * sizeof(*nic_dev->txqs);
	nic_dev->txqs = rte_zmalloc("spnic_txqs", txq_size,
				    RTE_CACHE_LINE_SIZE);
	if (!nic_dev->txqs) {
		PMD_DRV_LOG(ERR, "Allocate txqs failed");
		return -ENOMEM;
	}

	/* Allocate software rxq array */
	rxq_size = nic_dev->max_rqs * sizeof(*nic_dev->rxqs);
	nic_dev->rxqs = rte_zmalloc("spnic_rxqs", rxq_size,
				    RTE_CACHE_LINE_SIZE);
	if (!nic_dev->rxqs) {
		/* Free txqs */
		rte_free(nic_dev->txqs);
		nic_dev->txqs = NULL;

		PMD_DRV_LOG(ERR, "Allocate rxqs failed");
		return -ENOMEM;
	}

	return 0;
}

static void spnic_deinit_sw_rxtxqs(struct spnic_nic_dev *nic_dev)
{
	rte_free(nic_dev->txqs);
	nic_dev->txqs = NULL;

	rte_free(nic_dev->rxqs);
	nic_dev->rxqs = NULL;
}

/**
 * Start the device.
 *
 * Initialize function table, rxq and txq context, config rx offload, and enable
 * vport and port to prepare receiving packets.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
static int spnic_dev_start(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev;
	int err;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	err = spnic_init_function_table(nic_dev->hwdev, nic_dev->rx_buff_len);
	if (err) {
		PMD_DRV_LOG(ERR, "Init function table failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_func_tbl_fail;
	}

	/* Set default mtu */
	err = spnic_set_port_mtu(nic_dev->hwdev, nic_dev->mtu_size);
	if (err) {
		PMD_DRV_LOG(ERR, "Set mtu_size[%d] failed, dev_name: %s",
			    nic_dev->mtu_size, eth_dev->data->name);
		goto set_mtu_fail;
	}


	/* Update eth_dev link status */
	if (eth_dev->data->dev_conf.intr_conf.lsc != 0)
		(void)spnic_link_update(eth_dev, 0);

	rte_bit_relaxed_set32(SPNIC_DEV_START, &nic_dev->dev_status);

	return 0;

set_mtu_fail:
init_func_tbl_fail:

	return err;
}

/**
 * Stop the device.
 *
 * Stop phy port and vport, flush pending io request, clean context configure
 * and free io resourece.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_stop(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;
	struct rte_eth_link link;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	if (!rte_bit_relaxed_test_and_clear32(SPNIC_DEV_START, &nic_dev->dev_status)) {
		PMD_DRV_LOG(INFO, "Device %s already stopped",
			    nic_dev->dev_name);
		return 0;
	}

	/* Clear recorded link status */
	memset(&link, 0, sizeof(link));
	(void)rte_eth_linkstatus_set(dev, &link);

	return 0;
}

/**
 * Close the device.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_close(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	if (rte_bit_relaxed_test_and_set32(SPNIC_DEV_CLOSE, &nic_dev->dev_status)) {
		PMD_DRV_LOG(WARNING, "Device %s already closed",
			    nic_dev->dev_name);
		return 0;
	}

	spnic_dev_stop(eth_dev);

	spnic_deinit_sw_rxtxqs(nic_dev);
	spnic_deinit_mac_addr(eth_dev);
	rte_free(nic_dev->mc_list);

	rte_bit_relaxed_clear32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);


	/* Destroy rx mode mutex */
	spnic_mutex_destroy(&nic_dev->rx_mode_mutex);

	spnic_free_nic_hwdev(nic_dev->hwdev);
	spnic_free_hwdev(nic_dev->hwdev);

	eth_dev->dev_ops = NULL;

	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

	return 0;
}

static int spnic_dev_set_mtu(struct rte_eth_dev *dev, uint16_t mtu)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	int err = 0;

	PMD_DRV_LOG(INFO, "Set port mtu, port_id: %d, mtu: %d, max_pkt_len: %d",
		    dev->data->port_id, mtu, SPNIC_MTU_TO_PKTLEN(mtu));

	if (mtu < SPNIC_MIN_MTU_SIZE || mtu > SPNIC_MAX_MTU_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid mtu: %d, must between %d and %d",
			    mtu, SPNIC_MIN_MTU_SIZE, SPNIC_MAX_MTU_SIZE);
		return -EINVAL;
	}

	err = spnic_set_port_mtu(nic_dev->hwdev, mtu);
	if (err) {
		PMD_DRV_LOG(ERR, "Set port mtu failed, err: %d", err);
		return err;
	}

	/* Update max frame size */
	dev->data->dev_conf.rxmode.mtu = SPNIC_MTU_TO_PKTLEN(mtu);
	nic_dev->mtu_size = mtu;

	return err;
}

/**
 * Update MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] addr
 *   Pointer to MAC address
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mac_addr(struct rte_eth_dev *dev,
			      struct rte_ether_addr *addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(addr)) {
		rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE, addr);
		PMD_DRV_LOG(ERR, "Set invalid MAC address %s", mac_addr);
		return -EINVAL;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_update_mac(nic_dev->hwdev,
				nic_dev->default_addr.addr_bytes,
				addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	rte_ether_addr_copy(addr, &nic_dev->default_addr);
	rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
			      &nic_dev->default_addr);

	PMD_DRV_LOG(INFO, "Set new MAC address %s", mac_addr);

	return 0;
}

/**
 * Remove a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] index
 *   MAC address index.
 */
static void spnic_mac_addr_remove(struct rte_eth_dev *dev, uint32_t index)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	u16 func_id;
	int err;

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(INFO, "Remove MAC index(%u) is out of range",
			    index);
		return;
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_del_mac(nic_dev->hwdev,
			     dev->data->mac_addrs[index].addr_bytes,
			     0, func_id);
	if (err)
		PMD_DRV_LOG(ERR, "Remove MAC index(%u) failed", index);
}

/**
 * Add a MAC address.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mac_addr
 *   MAC address to register.
 * @param[in] index
 *   MAC address index.
 * @param[in] vmdq
 *   VMDq pool index to associate address with (unused_).
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_mac_addr_add(struct rte_eth_dev *dev,
			      struct rte_ether_addr *mac_addr, uint32_t index,
			      __rte_unused uint32_t vmdq)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	unsigned int i;
	u16 func_id;
	int err;

	if (!rte_is_valid_assigned_ether_addr(mac_addr)) {
		PMD_DRV_LOG(ERR, "Add invalid MAC address");
		return -EINVAL;
	}

	if (index >= SPNIC_MAX_UC_MAC_ADDRS) {
		PMD_DRV_LOG(ERR, "Add MAC index(%u) is out of range", index);
		return -EINVAL;
	}

	/* Make sure this address doesn't already be configured */
	for (i = 0; i < SPNIC_MAX_UC_MAC_ADDRS; i++) {
		if (rte_is_same_ether_addr(mac_addr,
			&dev->data->mac_addrs[i])) {
			PMD_DRV_LOG(ERR, "MAC address is already configured");
			return -EADDRINUSE;
		}
	}

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev, mac_addr->addr_bytes, 0, func_id);
	if (err)
		return err;

	return 0;
}

static void spnic_delete_mc_addr_list(struct spnic_nic_dev *nic_dev)
{
	u16 func_id;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	for (i = 0; i < SPNIC_MAX_MC_MAC_ADDRS; i++) {
		if (rte_is_zero_ether_addr(&nic_dev->mc_list[i]))
			break;

		spnic_del_mac(nic_dev->hwdev, nic_dev->mc_list[i].addr_bytes,
			      0, func_id);
		memset(&nic_dev->mc_list[i], 0, sizeof(struct rte_ether_addr));
	}
}

/**
 * Set multicast MAC address
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 * @param[in] mc_addr_set
 *   Pointer to multicast MAC address
 * @param[in] nb_mc_addr
 *   The number of multicast MAC address to set
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_set_mc_addr_list(struct rte_eth_dev *dev,
				  struct rte_ether_addr *mc_addr_set,
				  uint32_t nb_mc_addr)
{
	struct spnic_nic_dev *nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	u16 func_id;
	int err;
	u32 i;

	func_id = spnic_global_func_id(nic_dev->hwdev);

	/* Delete old multi_cast addrs firstly */
	spnic_delete_mc_addr_list(nic_dev);

	if (nb_mc_addr > SPNIC_MAX_MC_MAC_ADDRS)
		return -EINVAL;

	for (i = 0; i < nb_mc_addr; i++) {
		if (!rte_is_multicast_ether_addr(&mc_addr_set[i])) {
			rte_ether_format_addr(mac_addr, RTE_ETHER_ADDR_FMT_SIZE,
					      &mc_addr_set[i]);
			PMD_DRV_LOG(ERR, "Set mc MAC addr failed, addr(%s) invalid",
				    mac_addr);
			return -EINVAL;
		}
	}

	for (i = 0; i < nb_mc_addr; i++) {
		err = spnic_set_mac(nic_dev->hwdev, mc_addr_set[i].addr_bytes,
				    0, func_id);
		if (err) {
			spnic_delete_mc_addr_list(nic_dev);
			return err;
		}

		rte_ether_addr_copy(&mc_addr_set[i], &nic_dev->mc_list[i]);
	}

	return 0;
}

static const struct eth_dev_ops spnic_pmd_ops = {
	.dev_set_link_up               = spnic_dev_set_link_up,
	.dev_set_link_down             = spnic_dev_set_link_down,
	.link_update                   = spnic_link_update,
	.dev_start                     = spnic_dev_start,
	.dev_stop                      = spnic_dev_stop,
	.dev_close                     = spnic_dev_close,
	.mtu_set                       = spnic_dev_set_mtu,
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

static const struct eth_dev_ops spnic_pmd_vf_ops = {
	.link_update                   = spnic_link_update,
	.dev_start                     = spnic_dev_start,
	.dev_stop                      = spnic_dev_stop,
	.dev_close                     = spnic_dev_close,
	.mtu_set                       = spnic_dev_set_mtu,
	.mac_addr_set                  = spnic_set_mac_addr,
	.mac_addr_remove               = spnic_mac_addr_remove,
	.mac_addr_add                  = spnic_mac_addr_add,
	.set_mc_addr_list              = spnic_set_mc_addr_list,
};

/**
 * Init mac_vlan table in hardwares.
 *
 * @param[in] eth_dev
 *   Pointer to ethernet device structure.
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
static int spnic_init_mac_table(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	u8 addr_bytes[RTE_ETHER_ADDR_LEN];
	u16 func_id = 0;
	int err = 0;

	err = spnic_get_default_mac(nic_dev->hwdev, addr_bytes,
				     RTE_ETHER_ADDR_LEN);
	if (err)
		return err;

	rte_ether_addr_copy((struct rte_ether_addr *)addr_bytes,
			    &eth_dev->data->mac_addrs[0]);
	if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[0]))
		rte_eth_random_addr(eth_dev->data->mac_addrs[0].addr_bytes);

	func_id = spnic_global_func_id(nic_dev->hwdev);
	err = spnic_set_mac(nic_dev->hwdev,
			    eth_dev->data->mac_addrs[0].addr_bytes,
			    0, func_id);
	if (err && err != SPNIC_PF_SET_VF_ALREADY)
		return err;

	rte_ether_addr_copy(&eth_dev->data->mac_addrs[0],
			    &nic_dev->default_addr);

	return 0;
}

static int spnic_pf_get_default_cos(struct spnic_hwdev *hwdev, u8 *cos_id)
{
	u8 default_cos = 0;
	u8 valid_cos_bitmap;
	u8 i;

	valid_cos_bitmap = hwdev->cfg_mgmt->svc_cap.cos_valid_bitmap;
	if (!valid_cos_bitmap) {
		PMD_DRV_LOG(ERR, "PF has none cos to support\n");
		return -EFAULT;
	}

	for (i = 0; i < SPNIC_COS_NUM_MAX; i++) {
		if (valid_cos_bitmap & BIT(i))
			/* Find max cos id as default cos */
			default_cos = i;
	}

	*cos_id = default_cos;

	return 0;
}

static int spnic_init_default_cos(struct spnic_nic_dev *nic_dev)
{
	u8 cos_id = 0;
	int err;

	if (!SPNIC_IS_VF(nic_dev->hwdev)) {
		err = spnic_pf_get_default_cos(nic_dev->hwdev, &cos_id);
		if (err) {
			PMD_DRV_LOG(ERR, "Get PF default cos failed, err: %d",
				    err);
			return err;
		}
	} else {
		err = spnic_vf_get_default_cos(nic_dev->hwdev, &cos_id);
		if (err) {
			PMD_DRV_LOG(ERR, "Get VF default cos failed, err: %d",
				    err);
			return err;
		}
	}

	nic_dev->default_cos = cos_id;
	PMD_DRV_LOG(INFO, "Default cos %d", nic_dev->default_cos);
	return 0;
}

static int spnic_set_default_hw_feature(struct spnic_nic_dev *nic_dev)
{
	int err;

	err = spnic_init_default_cos(nic_dev);
	if (err)
		return err;

	return 0;
}

static int spnic_func_init(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct rte_pci_device *pci_dev = NULL;
	int err;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* EAL is secondary and eth_dev is already created */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(INFO, "Initialize %s in secondary process",
			    eth_dev->data->name);

		return 0;
	}

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	memset(nic_dev, 0, sizeof(*nic_dev));
	snprintf(nic_dev->dev_name, sizeof(nic_dev->dev_name),
		 "spnic-%.4x:%.2x:%.2x.%x",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	/* Alloc mac_addrs */
	eth_dev->data->mac_addrs = rte_zmalloc("spnic_mac",
		SPNIC_MAX_UC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!eth_dev->data->mac_addrs) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store MAC addresses "
			    "failed, dev_name: %s",
			    SPNIC_MAX_UC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_eth_addr_fail;
	}

	nic_dev->mc_list = rte_zmalloc("spnic_mc",
		SPNIC_MAX_MC_MAC_ADDRS * sizeof(struct rte_ether_addr), 0);
	if (!nic_dev->mc_list) {
		PMD_DRV_LOG(ERR, "Allocate %zx bytes to store multicast "
			    "addresses failed, dev_name: %s",
			    SPNIC_MAX_MC_MAC_ADDRS *
			    sizeof(struct rte_ether_addr),
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_mc_list_fail;
	}

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;
	/* Create hardware device */
	nic_dev->hwdev = rte_zmalloc("spnic_hwdev", sizeof(*nic_dev->hwdev),
				     RTE_CACHE_LINE_SIZE);
	if (!nic_dev->hwdev) {
		PMD_DRV_LOG(ERR, "Allocate hwdev memory failed, dev_name: %s",
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_hwdev_mem_fail;
	}
	nic_dev->hwdev->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	nic_dev->hwdev->dev_handle = nic_dev;
	nic_dev->hwdev->eth_dev = eth_dev;
	nic_dev->hwdev->port_id = eth_dev->data->port_id;

	err = spnic_init_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init chip hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_hwdev_fail;
	}

	nic_dev->max_sqs = spnic_func_max_sqs(nic_dev->hwdev);
	nic_dev->max_rqs = spnic_func_max_rqs(nic_dev->hwdev);

	if (SPNIC_FUNC_TYPE(nic_dev->hwdev) == TYPE_VF)
		eth_dev->dev_ops = &spnic_pmd_vf_ops;
	else
		eth_dev->dev_ops = &spnic_pmd_ops;

	err = spnic_init_nic_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init nic hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_nic_hwdev_fail;
	}

	err = spnic_init_sw_rxtxqs(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init sw rxqs or txqs failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_sw_rxtxqs_fail;
	}

	err = spnic_init_mac_table(eth_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mac table failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_mac_table_fail;
	}

	/* Set hardware feature to default status */
	err = spnic_set_default_hw_feature(nic_dev);
	if (err) {
		PMD_DRV_LOG(ERR, "Set hw default features failed, dev_name: %s",
			    eth_dev->data->name);
		goto set_default_feature_fail;
	}

	spnic_mutex_init(&nic_dev->rx_mode_mutex, NULL);

	rte_bit_relaxed_set32(SPNIC_DEV_INTR_EN, &nic_dev->dev_status);

	rte_bit_relaxed_set32(SPNIC_DEV_INIT, &nic_dev->dev_status);
	PMD_DRV_LOG(INFO, "Initialize %s in primary succeed",
		    eth_dev->data->name);

	return 0;

set_default_feature_fail:
	spnic_deinit_mac_addr(eth_dev);

init_mac_table_fail:
	spnic_deinit_sw_rxtxqs(nic_dev);

init_sw_rxtxqs_fail:
	spnic_free_nic_hwdev(nic_dev->hwdev);

init_nic_hwdev_fail:
	spnic_free_hwdev(nic_dev->hwdev);
	eth_dev->dev_ops = NULL;

init_hwdev_fail:
	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

alloc_hwdev_mem_fail:
	rte_free(nic_dev->mc_list);
	nic_dev->mc_list = NULL;

alloc_mc_list_fail:
	rte_free(eth_dev->data->mac_addrs);
	eth_dev->data->mac_addrs = NULL;

alloc_eth_addr_fail:
	PMD_DRV_LOG(ERR, "Initialize %s in primary failed",
		    eth_dev->data->name);
	return err;
}

static int spnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	PMD_DRV_LOG(INFO, "Initializing spnic-%.4x:%.2x:%.2x.%x in %s process",
		    pci_dev->addr.domain, pci_dev->addr.bus,
		    pci_dev->addr.devid, pci_dev->addr.function,
		    (rte_eal_process_type() == RTE_PROC_PRIMARY) ?
		    "primary" : "secondary");

	return spnic_func_init(eth_dev);
}

static int spnic_dev_uninit(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	rte_bit_relaxed_clear32(SPNIC_DEV_INIT, &nic_dev->dev_status);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	spnic_dev_close(dev);

	return 0;
}

static struct rte_pci_id pci_id_spnic_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_PF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_VF) },
	{.vendor_id = 0},
};

static int spnic_pci_probe(__rte_unused struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct spnic_nic_dev),
					     spnic_dev_init);
}

static int spnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, spnic_dev_uninit);
}

static struct rte_pci_driver rte_spnic_pmd = {
	.id_table = pci_id_spnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = spnic_pci_probe,
	.remove = spnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_spnic, rte_spnic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_spnic, pci_id_spnic_map);

RTE_INIT(spnic_init_log)
{
	spnic_logtype = rte_log_register("pmd.net.spnic");
	if (spnic_logtype >= 0)
		rte_log_set_level(spnic_logtype, RTE_LOG_INFO);
}
