/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_reg.h"
#include "sssnic_cmd.h"
#include "sssnic_msg.h"
#include "sssnic_eventq.h"
#include "sssnic_mbox.h"
#include "sssnic_exception.h"

static void
sssnic_link_event_msg_handle(struct sssnic_hw *hw, struct sssnic_msg *msg,
	__rte_unused enum sssnic_msg_chann_id chan_id)
{
	struct sssnic_netif_link_status_get_cmd *cmd;
	sssnic_link_event_cb_t *cb;
	enum sssnic_link_status status;
	void *priv;

	cb = hw->link_event_handler.cb;
	priv = hw->link_event_handler.priv;

	cmd = (struct sssnic_netif_link_status_get_cmd *)msg->data_buf;
	if (cb != NULL) {
		if (cmd->status)
			status = SSSNIC_LINK_STATUS_UP;
		else
			status = SSSNIC_LINK_STATUS_DOWN;

		PMD_DRV_LOG(DEBUG, "Received sssnic%u link %s event",
			SSSNIC_ETH_PORT_ID(hw), status ? "up" : "down");

		return cb(cmd->port, status, priv);
	}

	PMD_DRV_LOG(WARNING, "Link event was not processed, port=%u, status=%u",
		cmd->port, cmd->status);
}

static void
sssnic_netif_vf_link_status_msg_handle(struct sssnic_hw *hw,
	struct sssnic_msg *msg)
{
	int ret;

	if (msg->ack != 0) {
		msg->ack = 0;
		msg->type = SSSNIC_MSG_TYPE_RESP;
		msg->data_len = 1; /* indicate no data */
		ret = sssnic_mbox_send(hw, msg, NULL, 0, 0);
		if (ret != 0)
			PMD_DRV_LOG(ERR,
				"Failed to send VF link status response, ret=%d",
				ret);
	}
}

static void
sssnic_netif_exception_msg_handle(struct sssnic_hw *hw, struct sssnic_msg *msg,
	enum sssnic_msg_chann_id chan_id)
{
	if (msg->command == SSSNIC_GET_NETIF_LINK_STATUS_CMD) {
		if (SSSNIC_FUNC_TYPE(hw) == SSSNIC_FUNC_TYPE_VF)
			sssnic_netif_vf_link_status_msg_handle(hw, msg);

		sssnic_link_event_msg_handle(hw, msg, chan_id);
		return;
	}

	PMD_DRV_LOG(WARNING,
		"Netif exception message was not processed, cmd=%u",
		msg->command);
}

static int
sssnic_exception_msg_process(struct sssnic_msg *msg,
	enum sssnic_msg_chann_id chan_id, void *priv)
{
	struct sssnic_hw *hw = (struct sssnic_hw *)priv;

	SSSNIC_DEBUG("command=%u, func=%u module=%u, type=%u, ack=%u, seq=%u, "
		     "status=%u, id=%u data_buf=%p, data_len=%u",
		msg->command, msg->func, msg->module, msg->type, msg->ack,
		msg->seg, msg->status, msg->id, msg->data_buf, msg->data_len);

	if (msg->module == SSSNIC_NETIF_MODULE) {
		sssnic_netif_exception_msg_handle(hw, msg, chan_id);
		return SSSNIC_MSG_DONE;
	}

	PMD_DRV_LOG(WARNING, "Exception message was not processed, moule=%u",
		msg->module);

	return SSSNIC_MSG_DONE;
}

int
sssnic_exception_process_init(struct sssnic_hw *hw)
{
	if (hw == NULL)
		return -EINVAL;

	sssnic_msg_rx_handler_register(hw, SSSNIC_MSG_CHAN_MPU,
		SSSNIC_MSG_TYPE_REQ, sssnic_exception_msg_process, hw);
	sssnic_msg_rx_handler_register(hw, SSSNIC_MSG_CHAN_MBOX,
		SSSNIC_MSG_TYPE_REQ, sssnic_exception_msg_process, hw);

	return 0;
}
