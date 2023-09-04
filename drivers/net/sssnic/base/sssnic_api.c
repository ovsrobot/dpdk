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
