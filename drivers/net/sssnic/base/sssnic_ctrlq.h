/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_CTRLQ_H_
#define _SSSNIC_CTRLQ_H_

#include "sssnic_workq.h"

#define SSSNIC_CTRLQ_MBUF_SIZE 2048
#define SSSNIC_CTRLQ_MAX_CMD_DATA_LEN                                          \
	(SSSNIC_CTRLQ_MBUF_SIZE - RTE_PKTMBUF_HEADROOM)

struct sssnic_ctrlq_cmd {
	uint32_t module;
	/* Command ID */
	uint32_t cmd;
	/* Command data */
	void *data;
	/* mbuf is just used for dynamic allocation of ctrlq cmd,
	 * cmd data will point to mbuf data to reduce data copying
	 * as well as response_data.
	 */
	struct rte_mbuf *mbuf;
	union {
		/* response data buffer */
		void *response_data;
		/* result of command executing */
		uint64_t result;
	};
	/* command data length */
	uint32_t data_len;
	/* length of response data buffer, return result of command
	 * if response_len=0, else return response_data
	 */
	uint32_t response_len;
};

struct sssnic_ctrlq {
	struct sssnic_hw *hw;
	struct sssnic_workq *workq;
	struct rte_mempool *mbuf_pool;
	uint8_t *doorbell;
	uint32_t wrapped;
	uint32_t resvd0;
	rte_spinlock_t lock;
};

struct sssnic_ctrlq_cmd *sssnic_ctrlq_cmd_alloc(struct sssnic_hw *hw);
void sssnic_ctrlq_cmd_destroy(__rte_unused struct sssnic_hw *hw,
	struct sssnic_ctrlq_cmd *cmd);

int sssnic_ctrlq_cmd_exec(struct sssnic_hw *hw, struct sssnic_ctrlq_cmd *cmd,
	uint32_t timeout_ms);
int sssnic_ctrlq_init(struct sssnic_hw *hw);
void sssnic_ctrlq_shutdown(struct sssnic_hw *hw);

#endif /* _SSSNIC_CTRLQ_H_ */
