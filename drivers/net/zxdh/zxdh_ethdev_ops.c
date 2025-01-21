/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "zxdh_ethdev.h"
#include "zxdh_pci.h"
#include "zxdh_msg.h"
#include "zxdh_ethdev_ops.h"
#include "zxdh_tables.h"
#include "zxdh_logs.h"

static int32_t zxdh_config_port_status(struct rte_eth_dev *dev, uint16_t link_status)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct zxdh_port_attr_table port_attr = {0};
	struct zxdh_msg_info msg_info = {0};
	int32_t ret = 0;

	if (hw->is_pf) {
		ret = zxdh_get_port_attr(hw->vfid, &port_attr);
		if (ret) {
			PMD_DRV_LOG(ERR, "write port_attr failed");
			return -1;
		}
		port_attr.is_up = link_status;

		ret = zxdh_set_port_attr(hw->vfid, &port_attr);
		if (ret) {
			PMD_DRV_LOG(ERR, "write port_attr failed");
			return -1;
		}
	} else {
		struct zxdh_port_attr_set_msg *port_attr_msg = &msg_info.data.port_attr_msg;

		zxdh_msg_head_build(hw, ZXDH_PORT_ATTRS_SET, &msg_info);
		port_attr_msg->mode = ZXDH_PORT_ATTR_IS_UP_FLAG;
		port_attr_msg->value = link_status;
		ret = zxdh_vf_send_msg_to_pf(dev, &msg_info, sizeof(msg_info), NULL, 0);
		if (ret) {
			PMD_DRV_LOG(ERR, "Failed to send msg: port 0x%x msg type %d",
				hw->vport.vport, ZXDH_PORT_ATTR_IS_UP_FLAG);
			return ret;
		}
	}
	return ret;
}

static int32_t
zxdh_link_info_get(struct rte_eth_dev *dev, struct rte_eth_link *link)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct zxdh_msg_info msg_info = {0};
	struct zxdh_msg_reply_info reply_info = {0};
	uint16_t status = 0;
	int32_t ret = 0;

	if (zxdh_pci_with_feature(hw, ZXDH_NET_F_STATUS))
		zxdh_pci_read_dev_config(hw, offsetof(struct zxdh_net_config, status),
					&status, sizeof(status));

	link->link_status = status;

	if (status == RTE_ETH_LINK_DOWN) {
		link->link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
		link->link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	} else {
		zxdh_agent_msg_build(hw, ZXDH_MAC_LINK_GET, &msg_info);

		ret = zxdh_send_msg_to_riscv(dev, &msg_info, sizeof(struct zxdh_msg_info),
				&reply_info, sizeof(struct zxdh_msg_reply_info),
				ZXDH_BAR_MODULE_MAC);
		if (ret) {
			PMD_DRV_LOG(ERR, "Failed to send msg: port 0x%x msg type %d",
					hw->vport.vport, ZXDH_MAC_LINK_GET);
			return -1;
		}
		link->link_speed = reply_info.reply_body.link_msg.speed;
		hw->speed_mode = reply_info.reply_body.link_msg.speed_modes;
		if ((reply_info.reply_body.link_msg.duplex & RTE_ETH_LINK_FULL_DUPLEX) ==
				RTE_ETH_LINK_FULL_DUPLEX)
			link->link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
		else
			link->link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	}
	hw->speed = link->link_speed;

	return 0;
}

static int zxdh_set_link_status(struct rte_eth_dev *dev, uint8_t link_status)
{
	uint16_t curr_link_status = dev->data->dev_link.link_status;

	struct rte_eth_link link;
	struct zxdh_hw *hw = dev->data->dev_private;
	int32_t ret = 0;

	if (link_status == curr_link_status) {
		PMD_DRV_LOG(DEBUG, "curr_link_status %u", curr_link_status);
		return 0;
	}

	hw->admin_status = link_status;
	ret = zxdh_link_info_get(dev, &link);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get link status from hw");
		return ret;
	}
	dev->data->dev_link.link_status = hw->admin_status & link.link_status;

	if (dev->data->dev_link.link_status == RTE_ETH_LINK_UP) {
		dev->data->dev_link.link_speed = link.link_speed;
		dev->data->dev_link.link_duplex = link.link_duplex;
	} else {
		dev->data->dev_link.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
		dev->data->dev_link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	}
	return zxdh_config_port_status(dev, dev->data->dev_link.link_status);
}

int zxdh_dev_set_link_up(struct rte_eth_dev *dev)
{
	int ret = zxdh_set_link_status(dev, RTE_ETH_LINK_UP);

	if (ret)
		PMD_DRV_LOG(ERR, "Set link up failed, code:%d", ret);

	return ret;
}

int32_t zxdh_dev_link_update(struct rte_eth_dev *dev, int32_t wait_to_complete __rte_unused)
{
	struct rte_eth_link link;
	struct zxdh_hw *hw = dev->data->dev_private;
	int32_t ret = 0;

	memset(&link, 0, sizeof(link));
	link.link_duplex = hw->duplex;
	link.link_speed  = hw->speed;
	link.link_autoneg = RTE_ETH_LINK_AUTONEG;

	ret = zxdh_link_info_get(dev, &link);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, " Failed to get link status from hw");
		return ret;
	}
	link.link_status &= hw->admin_status;
	if (link.link_status == RTE_ETH_LINK_DOWN)
		link.link_speed  = RTE_ETH_SPEED_NUM_UNKNOWN;

	ret = zxdh_config_port_status(dev, link.link_status);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "set port attr %d failed.", link.link_status);
		return ret;
	}
	return rte_eth_linkstatus_set(dev, &link);
}

int zxdh_dev_set_link_down(struct rte_eth_dev *dev)
{
	int ret = zxdh_set_link_status(dev, RTE_ETH_LINK_DOWN);

	if (ret)
		PMD_DRV_LOG(ERR, "Set link down failed");
	return ret;
}
