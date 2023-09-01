/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_cmd.h"
#include "sssnic_mbox.h"
#include "sssnic_api.h"

int
sssnic_msix_attr_get(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_msix_ctrl_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.opcode = SSSNIC_CMD_OPCODE_GET;
	cmd.idx = msix_idx;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_MSIX_CTRL_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to MSIX_CTRL_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}
	attr->lli_credit = cmd.lli_credit;
	attr->lli_timer = cmd.lli_timer;
	attr->pending_limit = cmd.pending_count;
	attr->coalescing_timer = cmd.coalescing_timer;
	attr->resend_timer = cmd.resend_timer;

	return 0;
}

int
sssnic_msix_attr_set(struct sssnic_hw *hw, uint16_t msix_idx,
	struct sssnic_msix_attr *attr)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_msix_ctrl_cmd cmd;
	struct sssnic_msix_attr tmp;
	uint32_t cmd_len;

	ret = sssnic_msix_attr_get(hw, msix_idx, &tmp);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get interrupt configuration");
		return ret;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd.idx = msix_idx;
	cmd.lli_credit = tmp.lli_credit;
	cmd.lli_timer = tmp.lli_timer;
	cmd.pending_count = tmp.pending_limit;
	cmd.coalescing_timer = tmp.coalescing_timer;
	cmd.resend_timer = tmp.resend_timer;
	if (attr->lli_set != 0) {
		cmd.lli_credit = attr->lli_credit;
		cmd.lli_timer = attr->lli_timer;
	}
	if (attr->coalescing_set != 0) {
		cmd.pending_count = attr->pending_limit;
		cmd.coalescing_timer = attr->coalescing_timer;
		cmd.resend_timer = attr->resend_timer;
	}
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_MSIX_CTRL_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to MSIX_CTRL_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_capability_get(struct sssnic_hw *hw, struct sssnic_capability *capa)
{
	struct sssnic_capability_get_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	int ret;

	memset(&cmd, 0, sizeof(cmd));
	cmd_len = sizeof(cmd);
	cmd.function = SSSNIC_FUNC_IDX(hw);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_GET_CAPABILITY_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_CFG_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_CAPABILITY_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	capa->phy_port = cmd.phy_port;
	capa->max_num_rxq = cmd.rxq_max_id + 1;
	capa->max_num_txq = cmd.txq_max_id + 1;

	return 0;
}

int
sssnic_mac_addr_get(struct sssnic_hw *hw, uint8_t *addr)
{
	int ret;
	struct sssnic_mac_addr_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	uint16_t func;

	if (hw == NULL || addr == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		func = SSSNIC_PF_FUNC_IDX(hw);
	else
		func = SSSNIC_MPU_FUNC_IDX;

	memset(&cmd, 0, sizeof(cmd));
	cmd_len = sizeof(cmd);
	cmd.function = SSSNIC_FUNC_IDX(hw);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_GET_MAC_ADDR_CMD,
		func, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_DEF_MAC_ADDR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	rte_memcpy(addr, cmd.addr, 6);

	return 0;
}

int
sssnic_mac_addr_update(struct sssnic_hw *hw, uint8_t *new, uint8_t *old)
{
	int ret;
	struct sssnic_mac_addr_update_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	uint16_t func;

	if (hw == NULL || new == NULL || old == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		func = SSSNIC_PF_FUNC_IDX(hw);
	else
		func = SSSNIC_MPU_FUNC_IDX;

	memset(&cmd, 0, sizeof(cmd));
	cmd_len = sizeof(cmd);
	cmd.function = SSSNIC_FUNC_IDX(hw);
	rte_memcpy(cmd.new_addr, new, 6);
	rte_memcpy(cmd.old_addr, old, 6);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_UPDATE_MAC_ADDR_CMD, func, SSSNIC_LAN_MODULE,
		SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		if (cmd.common.status == SSSNIC_MAC_ADDR_CMD_STATUS_IGNORED) {
			PMD_DRV_LOG(WARNING,
				"MAC address operation is ignored");
			return 0;
		}
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_UPDATE_MAC_ADDR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_mac_addr_add(struct sssnic_hw *hw, uint8_t *addr)
{
	int ret;
	struct sssnic_mac_addr_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	uint16_t func;

	if (hw == NULL || addr == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		func = SSSNIC_PF_FUNC_IDX(hw);
	else
		func = SSSNIC_MPU_FUNC_IDX;

	memset(&cmd, 0, sizeof(cmd));
	cmd_len = sizeof(cmd);
	cmd.function = SSSNIC_FUNC_IDX(hw);
	rte_memcpy(cmd.addr, addr, 6);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_ADD_MAC_ADDR_CMD,
		func, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		if (cmd.common.status == SSSNIC_MAC_ADDR_CMD_STATUS_IGNORED) {
			PMD_DRV_LOG(WARNING,
				"MAC address operation is ignored");
			return 0;
		}
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_ADD_MAC_ADDR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_mac_addr_del(struct sssnic_hw *hw, uint8_t *addr)
{
	int ret;
	struct sssnic_mac_addr_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	uint16_t func;

	if (hw == NULL || addr == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		func = SSSNIC_PF_FUNC_IDX(hw);
	else
		func = SSSNIC_MPU_FUNC_IDX;

	memset(&cmd, 0, sizeof(cmd));
	cmd_len = sizeof(cmd);
	cmd.function = SSSNIC_FUNC_IDX(hw);
	rte_memcpy(cmd.addr, addr, 6);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_DEL_MAC_ADDR_CMD,
		func, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		if (cmd.common.status == SSSNIC_MAC_ADDR_CMD_STATUS_IGNORED) {
			PMD_DRV_LOG(WARNING,
				"MAC address operation is ignored");
			return 0;
		}
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_DEL_MAC_ADDR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_netif_link_status_get(struct sssnic_hw *hw, uint8_t *status)
{
	int ret;
	struct sssnic_netif_link_status_get_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;
	uint16_t func;

	if (hw == NULL || status == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		func = SSSNIC_PF_FUNC_IDX(hw);
	else
		func = SSSNIC_MPU_FUNC_IDX;

	memset(&cmd, 0, sizeof(cmd));
	cmd.port = SSSNIC_PHY_PORT(hw);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_GET_NETIF_LINK_STATUS_CMD, func, SSSNIC_NETIF_MODULE,
		SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_NETIF_LINK_STATUS_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	*status = cmd.status;

	return 0;
}

int
sssnic_netif_link_info_get(struct sssnic_hw *hw,
	struct sssnic_netif_link_info *info)
{
	int ret;
	struct sssnic_netif_link_info_get_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (hw == NULL || info == NULL)
		return -EINVAL;

	ret = sssnic_netif_link_status_get(hw, &info->status);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get netif link state!");
		return ret;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.port = SSSNIC_PHY_PORT(hw);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_GET_NETIF_LINK_INFO_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_NETIF_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_NETIF_LINK_INFO_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	info->speed = cmd.speed;
	info->duplex = cmd.duplex;
	info->fec = cmd.fec;
	info->type = cmd.type;
	info->autoneg_capa = cmd.autoneg_capa;
	info->autoneg = cmd.autoneg;

	return 0;
}

int
sssnic_netif_enable_set(struct sssnic_hw *hw, uint8_t state)
{
	int ret;
	struct sssnic_netif_enable_set_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (hw == NULL)
		return -EINVAL;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		return 0;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	if (state != 0)
		cmd.flag = SSSNIC_SET_NETIF_ENABLE_CMD_FLAG_RX_EN |
			   SSSNIC_SET_NETIF_ENABLE_CMD_FLAG_TX_EN;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_NETIF_ENABLE_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_NETIF_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_NETIF_ENABLE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}
