/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_link.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"

static const uint32_t sssnic_ethdev_speed_map[] = { RTE_ETH_SPEED_NUM_NONE,
	RTE_ETH_SPEED_NUM_10M, RTE_ETH_SPEED_NUM_100M, RTE_ETH_SPEED_NUM_1G,
	RTE_ETH_SPEED_NUM_10G, RTE_ETH_SPEED_NUM_25G, RTE_ETH_SPEED_NUM_40G,
	RTE_ETH_SPEED_NUM_50G, RTE_ETH_SPEED_NUM_100G, RTE_ETH_SPEED_NUM_200G };

#define SSSNIC_ETHDEV_NUM_SPEED_TYPE RTE_DIM(sssnic_ethdev_speed_map)

static int
sssnic_ethdev_link_get(struct rte_eth_dev *ethdev, struct rte_eth_link *link)
{
	int ret;
	struct sssnic_netif_link_info info;
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	memset(&info, 0, sizeof(info));
	ret = sssnic_netif_link_info_get(hw, &info);
	if (ret != 0) {
		link->link_status = RTE_ETH_LINK_DOWN;
		link->link_speed = RTE_ETH_SPEED_NUM_NONE;
		link->link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
		link->link_autoneg = RTE_ETH_LINK_FIXED;
		PMD_DRV_LOG(ERR, "Failed to get netif link info");
		return ret;
	}

	if (!info.status) {
		link->link_status = RTE_ETH_LINK_DOWN;
		link->link_speed = RTE_ETH_SPEED_NUM_NONE;
		link->link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
		link->link_autoneg = RTE_ETH_LINK_FIXED;
	} else {
		link->link_status = RTE_ETH_LINK_UP;
		link->link_duplex = info.duplex;
		link->link_autoneg = info.autoneg;
		if (info.speed >= SSSNIC_ETHDEV_NUM_SPEED_TYPE)
			link->link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
		else
			link->link_speed = sssnic_ethdev_speed_map[info.speed];
	}

	return 0;
}

int
sssnic_ethdev_set_link_up(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_netif_enable_set(hw, 1);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable netif");
		return ret;
	}

	return 0;
}

int
sssnic_ethdev_set_link_down(struct rte_eth_dev *ethdev)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	ret = sssnic_netif_enable_set(hw, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to disable netif");
		return ret;
	}

	return 0;
}

int
sssnic_ethdev_link_update(struct rte_eth_dev *ethdev, int wait_to_complete)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_REPEAT_TIME 10 /* 1s (10 * 100ms) in total */
	int ret;
	struct rte_eth_link link;
	unsigned int rep_cnt = MAX_REPEAT_TIME;

	memset(&link, 0, sizeof(link));
	do {
		ret = sssnic_ethdev_link_get(ethdev, &link);
		if (ret != 0)
			goto out;

		if (!wait_to_complete || link.link_status)
			goto out;

		rte_delay_ms(CHECK_INTERVAL);

	} while (--rep_cnt);

out:
	return rte_eth_linkstatus_set(ethdev, &link);
}

static void
sssnic_ethdev_link_status_print(struct rte_eth_dev *ethdev,
	struct rte_eth_link *link)
{
	if (link->link_status) {
		PMD_DRV_LOG(INFO, "Port %u Link Up - speed %s - %s",
			ethdev->data->port_id,
			rte_eth_link_speed_to_str(link->link_speed),
			link->link_duplex == RTE_ETH_LINK_FULL_DUPLEX ?
				      "full-duplex" :
				      "half-duplex");
	} else {
		PMD_DRV_LOG(INFO, "Port %u Link Down", ethdev->data->port_id);
	}
}

static void
sssnic_ethdev_link_event_cb(__rte_unused uint8_t port,
	__rte_unused enum sssnic_link_status status, void *arg)
{
	struct rte_eth_dev *ethdev = (struct rte_eth_dev *)arg;
	struct rte_eth_link link;
	int ret;

	memset(&link, 0, sizeof(link));
	sssnic_ethdev_link_get(ethdev, &link);

	ret = rte_eth_linkstatus_set(ethdev, &link);
	if (ret == 0) {
		sssnic_ethdev_link_status_print(ethdev, &link);
		rte_eth_dev_callback_process(ethdev, RTE_ETH_EVENT_INTR_LSC,
			NULL);
	}
}

static void
sssnic_ethdev_link_intr_callback(void *arg)
{
	struct rte_eth_dev *ethdev = (struct rte_eth_dev *)arg;
	struct sssnic_hw *hw;

	hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	sssnic_link_intr_handle(hw);
}

void
sssnic_ethdev_link_intr_enable(struct rte_eth_dev *ethdev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;

	sssnic_link_event_callback_register(hw, sssnic_ethdev_link_event_cb,
		ethdev);

	ret = rte_intr_callback_register(pci_dev->intr_handle,
		sssnic_ethdev_link_intr_callback, ethdev);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to register port %u intr callback!",
			ethdev->data->port_id);

		sssnic_link_event_callback_unregister(hw);

		return;
	}

	ret = rte_intr_enable(pci_dev->intr_handle);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to enable port %u interrupt!",
			ethdev->data->port_id);

		rte_intr_callback_unregister(pci_dev->intr_handle,
			sssnic_ethdev_link_intr_callback, ethdev);
		sssnic_link_event_callback_unregister(hw);

		return;
	}

	sssnic_msix_state_set(hw, SSSNIC_LINK_INTR_MSIX_ID, SSSNIC_MSIX_ENABLE);
}

void
sssnic_ethdev_link_intr_disable(struct rte_eth_dev *ethdev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(ethdev);
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);

	sssnic_msix_state_set(hw, SSSNIC_LINK_INTR_MSIX_ID,
		SSSNIC_MSIX_DISABLE);

	rte_intr_disable(pci_dev->intr_handle);
	rte_intr_callback_unregister(pci_dev->intr_handle,
		sssnic_ethdev_link_intr_callback, ethdev);

	sssnic_link_event_callback_unregister(hw);
}
