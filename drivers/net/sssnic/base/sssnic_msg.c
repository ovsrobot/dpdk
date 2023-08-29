/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_memcpy.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_msg.h"

/* Receive message segment based on message header
 * @param msghdr
 *	message header
 * @param msg
 *	message where segment store
 * @return
 *	SSSNIC_MSG_REJECT - Message segment was not received because of bad
 *                          parameter of message header.
 *	SSSNIC_MSG_ACCEPT - Message segment was received.
 *	SSSNIC_MSG_DONE   - The last message segment was received.
 */
static int
sssnic_msg_rx_seg(struct sssnic_msg_hdr *msghdr, struct sssnic_msg *msg)
{
	if (msghdr->seg_id > SSSNIC_MSG_MAX_SEG_ID ||
		msghdr->seg_len > SSSNIC_MSG_MAX_SEG_SIZE) {
		PMD_DRV_LOG(ERR,
			"Bad segment id or segment size of message header");
		return SSSNIC_MSG_REJECT;
	}

	if (msghdr->seg_id == 0) {
		msg->command = msghdr->command;
		msg->type = msghdr->type;
		msg->module = msghdr->module;
		msg->id = msghdr->id;
	} else {
		if (msghdr->seg_id != (msg->seg + 1) || msghdr->id != msg->id ||
			msghdr->module != msg->module ||
			msghdr->command != msg->command) {
			PMD_DRV_LOG(ERR, "Bad parameters of message header");
			return SSSNIC_MSG_REJECT;
		}
	}
	rte_memcpy(msg->data_buf + (SSSNIC_MSG_MAX_SEG_SIZE * msghdr->seg_id),
		SSSNIC_MSG_DATA(msghdr), msghdr->seg_len);

	if (!msghdr->last_seg) {
		msg->seg = msghdr->seg_id;
		return SSSNIC_MSG_ACCEPT;
	}

	msg->ack = !msghdr->no_response;
	msg->status = msghdr->status;
	msg->data_len = msghdr->length;
	msg->func = msghdr->function;
	msg->seg = SSSNIC_MSG_MAX_SEG_ID;

	return SSSNIC_MSG_DONE;
}

static int
sssnic_msg_buf_alloc(struct sssnic_msg *msg, size_t size)
{
	msg->data_buf = rte_zmalloc("sssnic_msg_data", size, 1);
	if (msg->data_buf == NULL) {
		PMD_DRV_LOG(ERR, "Could not all message data buffer!");
		return -ENOMEM;
	}

	return 0;
}

static void
sssnic_msg_buf_free(struct sssnic_msg *msg)
{
	rte_free(msg->data_buf);
}

int
sssnic_msg_rx_handle(struct sssnic_hw *hw, struct sssnic_msg_hdr *msghdr)
{
	struct sssnic_msg *msg;
	struct sssnic_msg_handler *msg_handler;
	int msg_src;
	int msg_chan;
	int msg_type;
	int ret;

	msg_src = SSSNIC_MSG_SRC(msghdr->function);
	msg_chan = msghdr->channel;
	msg_type = msghdr->type;
	msg = SSSNIC_MSG_LOCATE(hw, msg_chan, msg_type, msg_src);

	ret = sssnic_msg_rx_seg(msghdr, msg);
	if (ret != SSSNIC_MSG_DONE)
		return ret;

	msg_handler = SSSNIC_MSG_HANDLER(hw, msg_chan, msg_type);
	if (msg_handler->func == NULL) {
		PMD_DRV_LOG(NOTICE,
			"No message handler, message channel:%d, type:%d.",
			msg_chan, msg_type);
		return SSSNIC_MSG_REJECT;
	}
	ret = msg_handler->func(msg, msg_chan, msg_handler->priv);

	return ret;
}

int
sssnic_msg_rx_handler_register(struct sssnic_hw *hw,
	enum sssnic_msg_chann_id chann_id, enum sssnic_msg_type msg_type,
	sssnic_msg_handler_func_t *func, void *priv)
{
	struct sssnic_msg_handler *msg_handler;

	if (chann_id >= SSSNIC_MSG_CHAN_COUNT ||
		msg_type >= SSSNIC_MSG_TYPE_CONUT || func == NULL) {
		PMD_DRV_LOG(ERR,
			"Bad parameters for register rx message handler.");
		return -EINVAL;
	}

	msg_handler = SSSNIC_MSG_HANDLER(hw, chann_id, msg_type);
	if (msg_handler->func != NULL)
		PMD_DRV_LOG(WARNING,
			"RX message handler has existed, chann_id:%u, msg_type:%u",
			chann_id, msg_type);

	msg_handler->func = func;
	msg_handler->priv = priv;

	return 0;
}

static int
sssnic_msg_channel_init(struct sssnic_hw *hw, struct sssnic_msg_channel *chan)
{
	struct sssnic_msg *msg;
	int i;
	int ret;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < SSSNIC_MSG_TYPE_CONUT; i++) {
		msg = &chan->msg[i][SSSNIC_MSG_SRC_MPU];
		ret = sssnic_msg_buf_alloc(msg, SSSNIC_MSG_BUF_SIZE);
		if (ret) {
			PMD_DRV_LOG(ERR,
				"Could not alloc MPU message buf for message inbox channel %d of sssnic%u.",
				SSSNIC_ETH_PORT_ID(hw), chan->id);
			goto msg_buf_alloc_fail;
		}
		msg = &chan->msg[i][SSSNIC_MSG_SRC_PF];
		ret = sssnic_msg_buf_alloc(msg, SSSNIC_MSG_BUF_SIZE);
		if (ret) {
			PMD_DRV_LOG(ERR,
				"Could not alloc PF message buf for message inbox channel %d of sssnic%u.",
				SSSNIC_ETH_PORT_ID(hw), chan->id);
			msg = &chan->msg[i][SSSNIC_MSG_SRC_MPU];
			sssnic_msg_buf_free(msg);
			goto msg_buf_alloc_fail;
		}
	}

	return 0;

msg_buf_alloc_fail:
	while (i--) {
		msg = &chan->msg[i][SSSNIC_MSG_SRC_MPU];
		sssnic_msg_buf_free(msg);
		msg = &chan->msg[i][SSSNIC_MSG_SRC_PF];
		sssnic_msg_buf_free(msg);
	}
	return ret;
}

static void
sssnic_msg_channel_shutdown(__rte_unused struct sssnic_hw *hw,
	struct sssnic_msg_channel *chan)
{
	struct sssnic_msg *msg;
	int i;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < SSSNIC_MSG_TYPE_CONUT; i++) {
		msg = &chan->msg[i][SSSNIC_MSG_SRC_MPU];
		sssnic_msg_buf_free(msg);
		msg = &chan->msg[i][SSSNIC_MSG_SRC_PF];
		sssnic_msg_buf_free(msg);
	}
}

int
sssnic_msg_inbox_init(struct sssnic_hw *hw)
{
	struct sssnic_msg_inbox *inbox;
	struct sssnic_msg_channel *chan;
	int i;
	int ret;

	PMD_INIT_FUNC_TRACE();

	inbox = rte_zmalloc(NULL, sizeof(struct sssnic_msg_inbox), 1);
	if (inbox == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for message inbox");
		return -ENOMEM;
	}

	inbox->hw = hw;
	hw->msg_inbox = inbox;

	for (i = 0; i < SSSNIC_MSG_CHAN_COUNT; i++) {
		chan = &inbox->channel[i];
		ret = sssnic_msg_channel_init(hw, chan);
		if (ret) {
			PMD_DRV_LOG(ERR,
				"Failed to initialize channel%u of message inbox",
				i);
			goto init_msg_channel_fail;
		}
		chan->id = i;
	}

	return 0;

init_msg_channel_fail:
	while (i--) {
		chan = &inbox->channel[i];
		sssnic_msg_channel_shutdown(hw, chan);
	}
	rte_free(inbox);
	return ret;
}

void
sssnic_msg_inbox_shutdown(struct sssnic_hw *hw)
{
	struct sssnic_msg_channel *chan;
	int i;

	PMD_INIT_FUNC_TRACE();

	for (i = 0; i < SSSNIC_MSG_CHAN_COUNT; i++) {
		chan = &hw->msg_inbox->channel[i];
		sssnic_msg_channel_shutdown(hw, chan);
	}
	rte_free(hw->msg_inbox);
}
