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
#include "sssnic_ctrlq.h"
#include "sssnic_api.h"
#include "sssnic_misc.h"

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

int
sssnic_port_enable_set(struct sssnic_hw *hw, bool state)
{
	int ret;
	struct sssnic_port_enable_set_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (hw == NULL)
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.state = state ? 1 : 0;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_PORT_ENABLE_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_PORT_ENABLE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_rxq_flush(struct sssnic_hw *hw, uint16_t qid)
{
	struct sssnic_ctrlq_cmd cmd;
	struct sssnic_rxq_flush_cmd data;
	int ret;

	data.u32 = 0;
	data.qid = qid;
	data.u32 = rte_cpu_to_be_32(data.u32);

	memset(&cmd, 0, sizeof(cmd));
	cmd.data = &data;
	cmd.module = SSSNIC_LAN_MODULE;
	cmd.data_len = sizeof(data);
	cmd.cmd = SSSNIC_FLUSH_RXQ_CMD;

	ret = sssnic_ctrlq_cmd_exec(hw, &cmd, 0);
	if (ret != 0 || cmd.result != 0) {
		PMD_DRV_LOG(ERR,
			"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
			"SSSNIC_FLUSH_RXQ_CMD", ret, cmd.result);
		return -EIO;
	}

	return 0;
}

static int
sssnic_rxtx_size_set(struct sssnic_hw *hw, uint16_t rx_size, uint16_t tx_size,
	uint32_t flags)
{
	int ret;
	struct sssnic_rxtx_size_set_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (hw == NULL)
		return -EINVAL;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.rx_size = rx_size;
	cmd.tx_size = tx_size;
	cmd.flags = flags;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_PORT_RXTX_SIZE_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_PORT_RXTX_SIZE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_rxtx_max_size_init(struct sssnic_hw *hw, uint16_t rx_size,
	uint16_t tx_size)
{
	return sssnic_rxtx_size_set(hw, rx_size, tx_size,
		SSSNIC_CMD_INIT_RXTX_SIZE_FLAG | SSSNIC_CMD_SET_RX_SIZE_FLAG |
			SSSNIC_CMD_SET_TX_SIZE_FLAG);
}

int
sssnic_tx_max_size_set(struct sssnic_hw *hw, uint16_t tx_size)
{
	return sssnic_rxtx_size_set(hw, 0, tx_size,
		SSSNIC_CMD_SET_TX_SIZE_FLAG);
}

int
sssnic_port_features_get(struct sssnic_hw *hw, uint64_t *features)
{
	int ret;
	struct sssnic_port_feature_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.opcode = SSSNIC_CMD_OPCODE_GET;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_PORT_FEATURE_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_FEATURE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	*features = cmd.features;

	return 0;
}

int
sssnic_port_features_set(struct sssnic_hw *hw, uint64_t features)
{
	int ret;
	struct sssnic_port_feature_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.features = features;
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_PORT_FEATURE_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_FEATURE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

#define SSSNIC_MAX_NUM_RXTXQ_CTX_SET_IN_BULK                                   \
	((SSSNIC_CTRLQ_MAX_CMD_DATA_LEN - SSSNIC_RXTXQ_CTX_CMD_INFO_LEN) /     \
		SSSNIC_RXTXQ_CTX_SIZE)

static int
sssnic_rxtxq_ctx_set(struct sssnic_hw *hw, struct sssnic_rxtxq_ctx *q_ctx,
	uint16_t q_start, enum sssnic_rxtxq_ctx_type type, uint16_t count)
{
	struct sssnic_ctrlq_cmd *cmd;
	struct sssnic_rxtxq_ctx_cmd *data;
	struct sssnic_rxtxq_ctx *ctx;
	uint32_t num, i;
	uint32_t max_num;
	struct sssnic_rxtxq_ctx_cmd_info cmd_info;
	int ret = 0;

	cmd = sssnic_ctrlq_cmd_alloc(hw);
	if (cmd == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc ctrlq command");
		return -ENOMEM;
	}

	data = cmd->data;
	ctx = (struct sssnic_rxtxq_ctx *)(data + 1);
	max_num = SSSNIC_MAX_NUM_RXTXQ_CTX_SET_IN_BULK;

	while (count > 0) {
		num = RTE_MIN(count, max_num);

		cmd_info.q_count = num;
		cmd_info.q_type = type;
		cmd_info.q_start = q_start;
		cmd_info.resvd0 = 0;
		sssnic_mem_cpu_to_be_32(&cmd_info, &data->info,
			sizeof(struct sssnic_rxtxq_ctx_cmd_info));

		for (i = 0; i < num; i++)
			sssnic_mem_cpu_to_be_32(q_ctx + i, ctx + i,
				SSSNIC_RXTXQ_CTX_SIZE);

		cmd->data_len = sizeof(struct sssnic_rxtxq_ctx_cmd_info) +
				(SSSNIC_RXTXQ_CTX_SIZE * num);
		cmd->module = SSSNIC_LAN_MODULE;
		cmd->cmd = SSSNIC_SET_RXTXQ_CTX_CMD;

		rte_wmb();

		ret = sssnic_ctrlq_cmd_exec(hw, cmd, 0);
		if (ret != 0 || cmd->result != 0) {
			PMD_DRV_LOG(ERR,
				"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
				"SSSNIC_SET_RXTXQ_CTX_CMD", ret, cmd->result);
			ret = -EIO;
			goto out;
		}

		count -= num;
		q_ctx += num;
		q_start += num;
	}

out:
	sssnic_ctrlq_cmd_destroy(hw, cmd);
	return ret;
}

int
sssnic_txq_ctx_set(struct sssnic_hw *hw, struct sssnic_txq_ctx *ctx,
	uint16_t qstart, uint16_t count)
{
	return sssnic_rxtxq_ctx_set(hw, (struct sssnic_rxtxq_ctx *)ctx, qstart,
		SSSNIC_TXQ_CTX, count);
}

int
sssnic_rxq_ctx_set(struct sssnic_hw *hw, struct sssnic_rxq_ctx *ctx,
	uint16_t qstart, uint16_t count)
{
	return sssnic_rxtxq_ctx_set(hw, (struct sssnic_rxtxq_ctx *)ctx, qstart,
		SSSNIC_RXQ_CTX, count);
}

static int
sssnic_offload_ctx_reset(struct sssnic_hw *hw, uint16_t q_start,
	enum sssnic_rxtxq_ctx_type q_type, uint16_t count)
{
	struct sssnic_ctrlq_cmd cmd;
	struct sssnic_offload_ctx_reset_cmd data;
	int ret;

	memset(&cmd, 0, sizeof(cmd));
	memset(&data, 0, sizeof(data));

	data.info.q_count = count;
	data.info.q_start = q_start;
	data.info.q_type = q_type;

	cmd.data = &data;
	cmd.module = SSSNIC_LAN_MODULE;
	cmd.data_len = sizeof(data);
	cmd.cmd = SSSNIC_RESET_OFFLOAD_CTX_CMD;

	sssnic_mem_cpu_to_be_32(&data, &data, sizeof(data));

	ret = sssnic_ctrlq_cmd_exec(hw, &cmd, 0);
	if (ret != 0 || cmd.result != 0) {
		PMD_DRV_LOG(ERR,
			"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
			"SSSNIC_RESET_OFFLOAD_CTX_CMD", ret, cmd.result);

		return -EIO;
	}

	return 0;
}

int
sssnic_rx_offload_ctx_reset(struct sssnic_hw *hw)
{
	return sssnic_offload_ctx_reset(hw, 0, SSSNIC_RXQ_CTX,
		SSSNIC_MAX_NUM_RXQ(hw));
}

int
sssnic_tx_offload_ctx_reset(struct sssnic_hw *hw)
{
	return sssnic_offload_ctx_reset(hw, 0, SSSNIC_TXQ_CTX,
		SSSNIC_MAX_NUM_TXQ(hw));
}

int
sssnic_rxtx_ctx_set(struct sssnic_hw *hw, bool lro_en, uint16_t rxq_depth,
	uint16_t rx_buf, uint16_t txq_depth)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_root_ctx_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.lro_enable = lro_en ? 1 : 0;
	cmd.rx_buf = rx_buf;
	cmd.rxq_depth = (uint16_t)rte_log2_u32(rxq_depth);
	cmd.txq_depth = (uint16_t)rte_log2_u32(txq_depth);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_SET_ROOT_CTX_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SET_ROOT_CTX_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_port_tx_ci_attr_set(struct sssnic_hw *hw, uint16_t tx_qid,
	uint8_t pending_limit, uint8_t coalescing_time, uint64_t dma_addr)
{
	int ret;
	struct sssnic_port_tx_ci_attr_set_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.coalescing_time = coalescing_time;
	cmd.pending_limit = pending_limit;
	cmd.qid = tx_qid;
	cmd.dma_addr = dma_addr >> 2;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_PORT_TX_CI_ATTR_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_PORT_TX_CI_ATTR_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_port_rx_mode_set(struct sssnic_hw *hw, uint32_t mode)
{
	int ret;
	struct sssnic_port_rx_mode_set_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.mode = mode;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_PORT_RX_MODE_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_PORT_RX_MODE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_lro_enable_set(struct sssnic_hw *hw, bool ipv4_en, bool ipv6_en,
	uint8_t nb_lro_bufs)
{
	int ret;
	struct sssnic_lro_cfg_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.ipv4_en = ipv4_en ? 1 : 0;
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd.ipv6_en = ipv6_en ? 1 : 0;
	cmd.nb_bufs = nb_lro_bufs;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_PORT_LRO_CFG_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_LRO_CFG_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_lro_timer_set(struct sssnic_hw *hw, uint32_t timer)
{
	int ret;
	struct sssnic_lro_timer_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
		return 0;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd.timer = timer;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_PORT_LRO_TIMER_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_LRO_TIMER_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_vlan_filter_enable_set(struct sssnic_hw *hw, bool state)
{
	int ret;
	struct sssnic_vlan_filter_enable_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.state = state ? 1 : 0;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_ENABLE_PORT_VLAN_FILTER_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_ENABLE_PORT_VLAN_FILTER_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_vlan_strip_enable_set(struct sssnic_hw *hw, bool state)
{
	int ret;
	struct sssnic_vlan_strip_enable_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.state = state ? 1 : 0;
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_ENABLE_PORT_VLAN_STRIP_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_ENABLE_PORT_VLAN_STRIP_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_port_resource_clean(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_port_resource_clean_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_CLEAN_PORT_RES_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_CLEAN_PORT_RES_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_port_stats_get(struct sssnic_hw *hw, struct sssnic_port_stats *stats)
{
	int ret;
	struct sssnic_port_stats_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len, resp_len;
	struct {
		struct sssnic_cmd_common common;
		uint32_t size;
		uint32_t resvd0;
		struct sssnic_port_stats stats;
		uint64_t rsvd1[6];
	} resp;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_GET_PORT_STATS_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	memset(&resp, 0, sizeof(resp));
	resp_len = sizeof(resp);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&resp, &resp_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (resp_len == 0 || resp.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_PORT_STATS_CMD, len=%u, status=%u",
			resp_len, resp.common.status);
		return -EIO;
	}

	memcpy(stats, &resp.stats, sizeof(resp.stats));

	return 0;
}

int
sssnic_port_stats_clear(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_port_stats_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_CLEAR_PORT_STATS_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_CLEAN_PORT_RES_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_mac_stats_get(struct sssnic_hw *hw, struct sssnic_mac_stats *stats)
{
	int ret;
	struct sssnic_msg msg;
	uint32_t cmd_len, resp_len;
	struct sssnic_mac_stats_cmd cmd;
	struct {
		struct sssnic_cmd_common common;
		struct sssnic_mac_stats stats;
		uint64_t resvd[15];
	} *resp;

	memset(&cmd, 0, sizeof(cmd));
	cmd.port = SSSNIC_PHY_PORT(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_GET_NETIF_MAC_STATS_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_NETIF_MODULE, SSSNIC_MSG_TYPE_REQ);

	resp_len = sizeof(*resp);
	resp = rte_zmalloc(NULL, resp_len, 0);
	if (resp == NULL) {
		PMD_DRV_LOG(ERR,
			"Failed to alloc memory for mac stats response cmd");
		return -ENOMEM;
	}

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)resp, &resp_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		goto out;
	}

	if (resp_len == 0 || resp->common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_NETIF_MAC_STATS_CMD, len=%u, status=%u",
			resp_len, resp->common.status);
		ret = -EIO;
		goto out;
	}

	memcpy(stats, &resp->stats, sizeof(resp->stats));

out:
	rte_free(resp);
	return ret;
}

int
sssnic_mac_stats_clear(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_mac_stats_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.port = SSSNIC_PHY_PORT(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_CLEAR_NETIF_MAC_STATS_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_NETIF_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_CLEAR_NETIF_MAC_STATS_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_rss_enable_set(struct sssnic_hw *hw, bool state)
{
	int ret;
	struct sssnic_rss_enable_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.state = state ? 1 : 0;
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_ENABLE_RSS_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_ENABLE_RSS_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

static int
sssnic_rss_profile_config(struct sssnic_hw *hw, bool new)
{
	int ret;
	struct sssnic_rss_profile_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = new ? SSSNIC_RSS_PROFILE_CMD_OP_NEW :
				 SSSNIC_RSS_PROFILE_CMD_OP_DEL;
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_RSS_PROFILE_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_RSS_PROFILE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_rss_profile_create(struct sssnic_hw *hw)
{
	return sssnic_rss_profile_config(hw, true);
}

int
sssnic_rss_profile_destroy(struct sssnic_hw *hw)
{
	return sssnic_rss_profile_config(hw, false);
}

int
sssnic_rss_hash_key_set(struct sssnic_hw *hw, uint8_t *key, uint16_t len)
{
	int ret;
	struct sssnic_rss_hash_key_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	if (len > sizeof(cmd.key)) {
		PMD_DRV_LOG(ERR, "Invalid rss hash key length: %u", len);
		return -EINVAL;
	}

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd.function = SSSNIC_FUNC_IDX(hw);
	rte_memcpy(cmd.key, key, len);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_RSS_HASH_KEY_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_RSS_PROFILE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

static int
sssnic_rss_type_set_by_mbox(struct sssnic_hw *hw, struct sssnic_rss_type *type)
{
	int ret;
	struct sssnic_rss_type_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.mask = type->mask;
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_SET_RSS_TYPE_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd.common.status == 0xff)
		return -EOPNOTSUPP;

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_SET_RSS_TYPE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

static int
sssnic_rss_type_set_by_ctrlq(struct sssnic_hw *hw, struct sssnic_rss_type *type)
{
	struct sssnic_ctrlq_cmd cmd;
	struct sssnic_rss_hash_type_ctrlq_cmd data;
	int ret;

	memset(&data, 0, sizeof(data));
	data.mask = rte_cpu_to_be_32(type->mask);

	memset(&cmd, 0, sizeof(cmd));
	cmd.data = &data;
	cmd.module = SSSNIC_LAN_MODULE;
	cmd.data_len = sizeof(data);
	cmd.cmd = SSSNIC_SET_RSS_KEY_CTRLQ_CMD;

	ret = sssnic_ctrlq_cmd_exec(hw, &cmd, 0);
	if (ret || cmd.result) {
		PMD_DRV_LOG(ERR,
			"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
			"SSSNIC_SET_RSS_KEY_CTRLQ_CMD", ret, cmd.result);
		return -EIO;
	}

	return 0;
}

int
sssnic_rss_type_set(struct sssnic_hw *hw, struct sssnic_rss_type *type)
{
	int ret;

	ret = sssnic_rss_type_set_by_mbox(hw, type);
	if (ret == -EOPNOTSUPP)
		ret = sssnic_rss_type_set_by_ctrlq(hw, type);

	return ret;
}

int
sssnic_rss_type_get(struct sssnic_hw *hw, struct sssnic_rss_type *type)
{
	int ret;
	struct sssnic_rss_type_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_GET_RSS_TYPE_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_RSS_TYPE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	type->mask = cmd.mask;

	return 0;
}

int
sssnic_rss_hash_engine_set(struct sssnic_hw *hw,
	enum sssnic_rss_hash_engine_type engine)
{
	int ret;
	struct sssnic_rss_hash_engine_cmd cmd;
	struct sssnic_msg msg;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.function = SSSNIC_FUNC_IDX(hw);
	cmd.engine = engine;
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_RSS_HASH_ENGINE_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);

	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmd_len == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_RSS_HASH_ENGINE_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_rss_indir_table_set(struct sssnic_hw *hw, const uint16_t *entry,
	uint32_t num_entries)
{
	struct sssnic_ctrlq_cmd *cmd;
	struct sssnic_rss_indir_table_cmd *data;
	uint32_t i;
	int ret;

	cmd = sssnic_ctrlq_cmd_alloc(hw);
	if (cmd == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc ctrlq command");
		return -ENOMEM;
	}

	data = cmd->data;
	memset(data, 0, sizeof(struct sssnic_rss_indir_table_cmd));
	for (i = 0; i < num_entries; i++)
		data->entry[i] = entry[i];

	rte_wmb();

	sssnic_mem_cpu_to_be_32(data->entry, data->entry, sizeof(data->entry));

	cmd->data_len = sizeof(struct sssnic_rss_indir_table_cmd);
	cmd->module = SSSNIC_LAN_MODULE;
	cmd->cmd = SSSNIC_SET_RSS_INDIR_TABLE_CMD;

	ret = sssnic_ctrlq_cmd_exec(hw, cmd, 0);
	if (ret != 0 || cmd->result != 0) {
		PMD_DRV_LOG(ERR,
			"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
			"SSSNIC_SET_RSS_INDIR_TABLE_CMD", ret, cmd->result);
		ret = -EIO;
	}

	sssnic_ctrlq_cmd_destroy(hw, cmd);

	return ret;
}

int
sssnic_rss_indir_table_get(struct sssnic_hw *hw, uint16_t *entry,
	uint32_t num_entries)
{
	struct sssnic_ctrlq_cmd *cmd;
	struct sssnic_rss_indir_table_cmd *data;
	uint32_t i;
	int ret = 0;

	cmd = sssnic_ctrlq_cmd_alloc(hw);
	if (cmd == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc ctrlq command");
		return -ENOMEM;
	}

	data = cmd->data;
	memset(data, 0, sizeof(struct sssnic_rss_indir_table_cmd));
	cmd->data_len = sizeof(struct sssnic_rss_indir_table_cmd);
	cmd->module = SSSNIC_LAN_MODULE;
	cmd->cmd = SSSNIC_GET_RSS_INDIR_TABLE_CMD;
	cmd->response_len = sizeof(data->entry);
	cmd->response_data = data->entry;

	ret = sssnic_ctrlq_cmd_exec(hw, cmd, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR,
			"Failed to execulte ctrlq command %s, ret=%d, result=%" PRIu64,
			"SSSNIC_GET_RSS_INDIR_TABLE_CMD", ret, cmd->result);
		ret = -EIO;
		goto out;
	}

	for (i = 0; i < num_entries; i++)
		entry[i] = data->entry[i];

out:
	sssnic_ctrlq_cmd_destroy(hw, cmd);
	return ret;
}

int
sssnic_fw_version_get(struct sssnic_hw *hw, struct sssnic_fw_version *version)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_fw_version_get_cmd cmd;
	uint32_t cmdlen = sizeof(cmd);
	int len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.type = 1; /* get MPU firmware version */

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmdlen,
		SSSNIC_GET_FW_VERSION_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmdlen, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmdlen == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_GET_FW_VERSION_CMD, len=%u, status=%u",
			cmdlen, cmd.common.status);
		return -EIO;
	}

	len = RTE_MIN(sizeof(version->version), sizeof(cmd.version));
	rte_memcpy(version->version, cmd.version, len);
	len = RTE_MIN(sizeof(version->time), sizeof(cmd.time));
	rte_memcpy(version->time, cmd.time, len);

	return 0;
}

int
sssnic_flow_ctrl_set(struct sssnic_hw *hw, bool autoneg, bool rx_en, bool tx_en)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_flow_ctrl_cmd cmd;
	uint32_t cmdlen = sizeof(cmd);

	memset(&cmd, 0, sizeof(cmd));
	cmd.auto_neg = autoneg ? 1 : 0;
	cmd.rx_en = rx_en ? 1 : 0;
	cmd.tx_en = tx_en ? 1 : 0;
	cmd.opcode = SSSNIC_CMD_OPCODE_SET;

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmdlen,
		SSSNIC_PORT_FLOW_CTRL_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmdlen, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmdlen == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_FLOW_CTRL_CMD, len=%u, status=%u",
			cmdlen, cmd.common.status);
		return -EIO;
	}

	return 0;
}

int
sssnic_flow_ctrl_get(struct sssnic_hw *hw, bool *autoneg, bool *rx_en,
	bool *tx_en)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_flow_ctrl_cmd cmd;
	uint32_t cmdlen = sizeof(cmd);

	memset(&cmd, 0, sizeof(cmd));
	cmd.opcode = SSSNIC_CMD_OPCODE_GET;

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmdlen,
		SSSNIC_PORT_FLOW_CTRL_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_LAN_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmdlen, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}

	if (cmdlen == 0 || cmd.common.status != 0) {
		PMD_DRV_LOG(ERR,
			"Bad response to SSSNIC_PORT_FLOW_CTRL_CMD, len=%u, status=%u",
			cmdlen, cmd.common.status);
		return -EIO;
	}

	*autoneg = cmd.auto_neg;
	*rx_en = cmd.rx_en;
	*tx_en = cmd.tx_en;

	return 0;
}
