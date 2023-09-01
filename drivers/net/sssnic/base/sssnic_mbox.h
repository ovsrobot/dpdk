/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_MBOX_H_
#define _SSSNIC_MBOX_H_

#include <rte_spinlock.h>

#include "sssnic_msg.h"

enum sssnic_mbox_state {
	/* Mbox is sending message or waiting for response */
	SSSNIC_MBOX_STATE_RUNNING,
	/* Waiting for response timed out*/
	SSSNIC_MBOX_STATE_TIMEOUT,
	/* Mbox failed to send message */
	SSSNIC_MBOX_STATE_FAILED,
	/* Response is ready */
	SSSNIC_MBOX_STATE_READY,
	/* Mbox is idle, it can send message */
	SSSNIC_MBOX_STATE_IDLE,
};

struct sssnic_sendbox;

struct sssnic_mbox {
	struct sssnic_hw *hw;
	/* just be used for sending request msg*/
	pthread_mutex_t req_lock;
	/* request msg id*/
	uint8_t req_id;
	struct sssnic_sendbox *sendbox;
	/*current state*/
	enum sssnic_mbox_state state;
	rte_spinlock_t state_lock;
};

int sssnic_mbox_send(struct sssnic_hw *hw, struct sssnic_msg *msg,
	uint8_t *resp_data, uint32_t *resp_data_len, uint32_t timeout_ms);

int sssnic_mbox_init(struct sssnic_hw *hw);
void sssnic_mbox_shutdown(struct sssnic_hw *hw);

#endif /* _SSSNIC_MBOX_H_ */
