/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "../sssnic_log.h"
#include "sssnic_hw.h"
#include "sssnic_reg.h"
#include "sssnic_cmd.h"
#include "sssnic_mbox.h"
#include "sssnic_ctrlq.h"

#define SSSNIC_CTRLQ_DOORBELL_OFFSET 0
#define SSSNIC_CTRLQ_BUF_SIZE 4096
#define SSSNIC_CTRLQ_ENTRY_SIZE 64
#define SSSNIC_CTRLQ_DEPTH 64

#define SSSNIC_CTRLQ_RESP_TIMEOUT 5000 /* Default response timeout */

enum sssnic_ctrlq_response_fmt {
	/* return result and write it back into corresponding field of ctrlq entry */
	SSSNIC_CTRLQ_RESPONSE_RESULT,
	/* return data write it into DMA memory that usually is pktmbuf*/
	SSSNIC_CTRLQ_RESPONSE_DATA,
};

struct sssnic_ctrlq_entry_desc_section {
	union {
		uint32_t dword;
		struct {
			/* buffer section length, always 2*/
			uint32_t buf_sec_len : 8;
			uint32_t resvd0 : 7;
			/* response fmt, 0:result 1:data */
			uint32_t resp_fmt : 1;
			uint32_t resvd1 : 6;
			/* buffer data format,always 0 */
			uint32_t buf_fmt : 1;
			/* always 1 */
			uint32_t need_resp : 1;
			uint32_t resvd2 : 3;
			/* response section length, always 3 */
			uint32_t resp_sec_len : 2;
			/* control section length, always 1 */
			uint32_t ctrl_sec_len : 2;
			/* wrapped bit */
			uint32_t wrapped : 1;
		};
	};
};

struct sssnic_ctrlq_entry_status_section {
	union {
		uint32_t dword;
		struct {
			/* status value, usually it  saves error code */
			uint32_t value : 31;
			uint32_t resvd0 : 1;
		};
	};
};

struct sssnic_ctrlq_entry_ctrl_section {
	union {
		uint32_t dword;
		struct {
			/* producer index*/
			uint32_t pi : 16;
			/* command ID */
			uint32_t cmd : 8;
			/* hardware module */
			uint32_t module : 5;
			uint32_t resvd0 : 2;
			/* Indication of command done */
			uint32_t done : 1;
		};
	};
};

struct sssnic_ctrlq_entry_response_section {
	union {
		struct {
			uint32_t hi_addr;
			uint32_t lo_addr;
			uint32_t len;
			uint32_t resvd0;
		} data;
		struct {
			uint64_t value;
			uint64_t resvd0;
		} result;
	};
};

struct sssnic_ctrlq_entry_buf_section {
	struct {
		uint32_t hi_addr;
		uint32_t lo_addr;
		uint32_t len;
		uint32_t resvd0;
	} sge;
	uint64_t resvd0[2];
};

/* Hardware format of control queue entry */
struct sssnic_ctrlq_entry {
	union {
		uint32_t dword[16];
		struct {
			struct sssnic_ctrlq_entry_desc_section desc;
			uint32_t resvd0;
			struct sssnic_ctrlq_entry_status_section status;
			struct sssnic_ctrlq_entry_ctrl_section ctrl;
			struct sssnic_ctrlq_entry_response_section response;
			struct sssnic_ctrlq_entry_buf_section buf;
		};
	};
};

/* Hardware format of control queue doorbell */
struct sssnic_ctrlq_doorbell {
	union {
		uint64_t u64;
		struct {
			uint64_t resvd0 : 23;
			/* ctrlq type is always 1*/
			uint64_t qtype : 1;
			/* cltrq id is always 0*/
			uint64_t qid : 3;
			uint64_t resvd1 : 5;
			/* most significant byte of pi*/
			uint64_t pi_msb : 8;
			uint64_t resvd2 : 24;
		};
	};
};
static int
sssnic_ctrlq_wait_response(struct sssnic_ctrlq *ctrlq, int *err_code,
	uint32_t timeout_ms)
{
	struct sssnic_ctrlq_entry *entry;
	struct sssnic_workq *workq;
	uint64_t end;
	int done = 0;

	workq = ctrlq->workq;
	entry = (struct sssnic_ctrlq_entry *)sssnic_workq_peek(workq);
	if (entry == NULL) {
		PMD_DRV_LOG(ERR, "Not found executing ctrlq command");
		return -EINVAL;
	}
	if (timeout_ms == 0)
		timeout_ms = SSSNIC_CTRLQ_RESP_TIMEOUT;
	end = rte_get_timer_cycles() + rte_get_timer_hz() * timeout_ms / 1000;
	do {
		done = entry->ctrl.done;
		if (done)
			break;
		rte_delay_us(1);
	} while (((long)(rte_get_timer_cycles() - end)) < 0);

	if (!done) {
		PMD_DRV_LOG(ERR, "Waiting ctrlq response timeout, ci=%u",
			workq->ci);
		return -ETIMEDOUT;
	}
	if (err_code)
		*err_code = entry->status.value;
	sssnic_workq_consume(workq, 1, NULL);
	return 0;
}

static void
sssnic_ctrlq_doorbell_ring(struct sssnic_ctrlq *ctrlq, uint16_t next_pi)
{
	struct sssnic_ctrlq_doorbell db;

	db.u64 = 0;
	db.qtype = 1;
	db.qid = 0;
	db.pi_msb = (next_pi >> 8) & 0xff;
	rte_wmb();
	rte_write64(db.u64, ctrlq->doorbell + ((next_pi & 0xff) << 3));
}

static void
sssnic_ctrlq_entry_init(struct sssnic_ctrlq_entry *entry, struct rte_mbuf *mbuf,
	struct sssnic_ctrlq_cmd *cmd, uint16_t pi, uint16_t wrapped)
{
	struct sssnic_ctrlq_entry tmp_entry;
	void *buf_addr;
	rte_iova_t buf_iova;

	/* Fill the temporary ctrlq entry */
	memset(&tmp_entry, 0, sizeof(tmp_entry));
	tmp_entry.desc.buf_fmt = 0;
	tmp_entry.desc.buf_sec_len = 2;
	tmp_entry.desc.need_resp = 1;
	tmp_entry.desc.resp_sec_len = 3;
	tmp_entry.desc.ctrl_sec_len = 1;
	tmp_entry.desc.wrapped = wrapped;

	tmp_entry.status.value = 0;

	tmp_entry.ctrl.cmd = cmd->cmd;
	tmp_entry.ctrl.pi = pi;
	tmp_entry.ctrl.module = cmd->module;
	tmp_entry.ctrl.done = 0;

	buf_iova = rte_mbuf_data_iova(mbuf);
	if (cmd->mbuf == NULL && cmd->data != NULL) {
		/* cmd data is not allocated in mbuf*/
		buf_addr = rte_pktmbuf_mtod(mbuf, void *);
		rte_memcpy(buf_addr, cmd->data, cmd->data_len);
	}
	tmp_entry.buf.sge.hi_addr = (uint32_t)((buf_iova >> 16) >> 16);
	tmp_entry.buf.sge.lo_addr = (uint32_t)buf_iova;
	tmp_entry.buf.sge.len = cmd->data_len;

	if (cmd->response_len == 0) {
		tmp_entry.desc.resp_fmt = SSSNIC_CTRLQ_RESPONSE_RESULT;
		tmp_entry.response.result.value = 0;
	} else {
		tmp_entry.desc.resp_fmt = SSSNIC_CTRLQ_RESPONSE_DATA;
		/* response sge shares cmd mbuf */
		tmp_entry.response.data.hi_addr =
			(uint32_t)((buf_iova >> 16) >> 16);
		tmp_entry.response.data.lo_addr = (uint32_t)buf_iova;
		tmp_entry.response.data.len = SSSNIC_CTRLQ_MBUF_SIZE;
	}

	/* write temporary entry to real ctrlq entry
	 * the first 64bits must be copied last
	 */
	rte_memcpy(((uint8_t *)entry) + sizeof(uint64_t),
		((uint8_t *)&tmp_entry) + sizeof(uint64_t),
		SSSNIC_CTRLQ_ENTRY_SIZE - sizeof(sizeof(uint64_t)));
	rte_wmb();
	*((uint64_t *)entry) = *((uint64_t *)&tmp_entry);
}

static int
sssnic_ctrlq_cmd_exec_internal(struct sssnic_ctrlq *ctrlq,
	struct sssnic_ctrlq_cmd *cmd, uint32_t timeout_ms)
{
	struct rte_mbuf *mbuf;
	struct sssnic_ctrlq_entry *entry;
	struct sssnic_workq *workq;
	uint16_t pi; /* current pi */
	uint16_t next_pi;
	uint16_t wrapped;
	int ret;
	int err_code;

	/* Allocate cmd mbuf */
	if (cmd->mbuf == NULL) {
		mbuf = rte_pktmbuf_alloc(ctrlq->mbuf_pool);
		if (mbuf == NULL) {
			PMD_DRV_LOG(ERR, "Could not alloc mbuf for ctrlq cmd");
			return -ENOMEM;
		}
	} else {
		mbuf = cmd->mbuf;
	}

	/* allocate ctrlq entry */
	workq = ctrlq->workq;
	wrapped = ctrlq->wrapped;
	entry = (struct sssnic_ctrlq_entry *)sssnic_workq_produce(workq, 1,
		&pi);
	if (entry == NULL) {
		PMD_DRV_LOG(ERR, "No enough control queue entry");
		ret = -EBUSY;
		goto out;
	}
	/* workq->pi will be the next pi, the next pi could not exceed workq
	 * depth else must recalculate next pi, and reverse wrapped bit.
	 */
	if (workq->pi >= workq->num_entries) {
		ctrlq->wrapped = !ctrlq->wrapped;
		workq->pi -= workq->num_entries;
	}
	next_pi = workq->pi;

	/* fill ctrlq entry */
	sssnic_ctrlq_entry_init(entry, mbuf, cmd, pi, wrapped);

	/* Ring doorbell */
	sssnic_ctrlq_doorbell_ring(ctrlq, next_pi);

	/* Wait response */
	ret = sssnic_ctrlq_wait_response(ctrlq, &err_code, timeout_ms);
	if (ret != 0)
		goto out;

	if (err_code) {
		PMD_DRV_LOG(ERR,
			"Found error while control queue command executing, error code:%x.",
			err_code);
		ret = err_code;
		goto out;
	}

	if (cmd->response_len == 0) {
		cmd->result = entry->response.result.value;
	} else if ((cmd->mbuf != NULL && cmd->response_data != cmd->data) ||
		   cmd->mbuf == NULL) {
		/* cmd data may be as same as response data if mbuf is not null */
		rte_memcpy(cmd->response_data, rte_pktmbuf_mtod(mbuf, void *),
			cmd->response_len);
	}
out:
	if (cmd->mbuf == NULL)
		rte_pktmbuf_free(mbuf);
	return ret;
}

int
sssnic_ctrlq_cmd_exec(struct sssnic_hw *hw, struct sssnic_ctrlq_cmd *cmd,
	uint32_t timeout_ms)
{
	int ret;
	struct sssnic_ctrlq *ctrlq;

	if (hw == NULL || hw->ctrlq == NULL || cmd == NULL ||
		(cmd->response_len != 0 && cmd->response_data == NULL)) {
		PMD_DRV_LOG(ERR, "Bad parameter to execute ctrlq command");
		return -EINVAL;
	}

	SSSNIC_DEBUG("module=%u, cmd=%u, data=%p, data_len=%u, response_len=%u",
		cmd->module, cmd->cmd, cmd->data, cmd->data_len,
		cmd->response_len);

	ctrlq = hw->ctrlq;
	rte_spinlock_lock(&ctrlq->lock);
	ret = sssnic_ctrlq_cmd_exec_internal(ctrlq, cmd, timeout_ms);
	rte_spinlock_unlock(&ctrlq->lock);

	return ret;
}

static int
sssnic_ctrlq_depth_set(struct sssnic_hw *hw, uint32_t depth)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_root_ctx_cmd cmd;
	uint32_t cmd_len;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.set_ctrlq_depth = 1;
	cmd.ctrlq_depth = (uint8_t)rte_log2_u32(depth);
	cmd_len = sizeof(cmd);

	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len, SSSNIC_SET_ROOT_CTX_CMD,
		SSSNIC_MPU_FUNC_IDX, SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send mbox message, ret=%d", ret);
		return ret;
	}
	if (!cmd_len || cmd.common.status) {
		PMD_DRV_LOG(ERR,
			"Bad response to SET_ROOT_CTX_CMD, len=%u, status=%u",
			cmd_len, cmd.common.status);
		return -EIO;
	}
	return 0;
}

static int
sssnic_ctrlq_ctx_setup(struct sssnic_ctrlq *ctrlq)
{
	int ret;
	struct sssnic_msg msg;
	struct sssnic_set_ctrlq_ctx_cmd cmd;
	uint32_t cmd_len;
	struct sssnic_hw *hw = ctrlq->hw;

	memset(&cmd, 0, sizeof(cmd));
	cmd.func_id = SSSNIC_FUNC_IDX(hw);
	cmd.qid = 0;
	cmd.pfn = ctrlq->workq->buf_phyaddr / RTE_PGSIZE_4K;
	cmd.wrapped = !!ctrlq->wrapped;
	cmd.start_ci = 0;
	cmd.block_pfn = cmd.pfn;

	cmd_len = sizeof(cmd);
	sssnic_msg_init(&msg, (uint8_t *)&cmd, cmd_len,
		SSSNIC_SET_CTRLQ_CTX_CMD, SSSNIC_MPU_FUNC_IDX,
		SSSNIC_COMM_MODULE, SSSNIC_MSG_TYPE_REQ);
	ret = sssnic_mbox_send(hw, &msg, (uint8_t *)&cmd, &cmd_len, 0);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send SSSNIC_SET_CTRLQ_CTX_CMD");
		return ret;
	}
	return 0;
}

struct sssnic_ctrlq_cmd *
sssnic_ctrlq_cmd_alloc(struct sssnic_hw *hw)
{
	struct sssnic_ctrlq_cmd *cmd;

	cmd = rte_zmalloc(NULL, sizeof(struct sssnic_ctrlq_cmd), 0);
	if (cmd == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate sssnic_ctrlq_cmd");
		return NULL;
	}

	cmd->mbuf = rte_pktmbuf_alloc(hw->ctrlq->mbuf_pool);
	if (cmd->mbuf == NULL) {
		PMD_DRV_LOG(ERR, "Failed to allocate sssnic_ctrlq_cmd mbuf");
		rte_free(cmd);
		return NULL;
	}

	cmd->data = rte_pktmbuf_mtod(cmd->mbuf, void *);
	cmd->response_data = cmd->data;

	return cmd;
}

void
sssnic_ctrlq_cmd_destroy(__rte_unused struct sssnic_hw *hw,
	struct sssnic_ctrlq_cmd *cmd)
{
	if (cmd != NULL) {
		if (cmd->mbuf != NULL)
			rte_pktmbuf_free(cmd->mbuf);

		rte_free(cmd);
	}
}

int
sssnic_ctrlq_init(struct sssnic_hw *hw)
{
	int ret;
	struct sssnic_ctrlq *ctrlq;
	char m_name[RTE_MEMPOOL_NAMESIZE];

	PMD_INIT_FUNC_TRACE();

	ctrlq = rte_zmalloc(NULL, sizeof(struct sssnic_ctrlq), 0);
	if (ctrlq == NULL) {
		PMD_DRV_LOG(ERR, "Could not alloc memory for ctrlq");
		return -ENOMEM;
	}

	ctrlq->hw = hw;
	rte_spinlock_init(&ctrlq->lock);
	ctrlq->doorbell = hw->db_base_addr + SSSNIC_CTRLQ_DOORBELL_OFFSET;

	snprintf(m_name, sizeof(m_name), "sssnic%u_ctrlq_wq",
		SSSNIC_ETH_PORT_ID(hw));
	ctrlq->workq = sssnic_workq_new(m_name, rte_socket_id(),
		SSSNIC_CTRLQ_ENTRY_SIZE, SSSNIC_CTRLQ_DEPTH);
	if (ctrlq->workq == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc work queue for ctrlq");
		ret = -ENOMEM;
		goto new_workq_fail;
	}
	ctrlq->wrapped = 1;

	snprintf(m_name, sizeof(m_name), "sssnic%u_ctrlq_mbuf",
		SSSNIC_ETH_PORT_ID(hw));
	ctrlq->mbuf_pool = rte_pktmbuf_pool_create(m_name, SSSNIC_CTRLQ_DEPTH,
		0, 0, SSSNIC_CTRLQ_MBUF_SIZE, rte_socket_id());
	if (ctrlq->mbuf_pool == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc mbuf for %s", m_name);
		ret = -ENOMEM;
		goto alloc_mbuf_fail;
	}

	ret = sssnic_ctrlq_ctx_setup(ctrlq);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to setup control queue context");
		goto setup_ctrlq_ctx_fail;
	}

	ret = sssnic_ctrlq_depth_set(hw, SSSNIC_CTRLQ_DEPTH);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to initialize control queue depth");
		goto setup_ctrlq_ctx_fail;
	}

	hw->ctrlq = ctrlq;

	return 0;

setup_ctrlq_ctx_fail:
	rte_mempool_free(ctrlq->mbuf_pool);
alloc_mbuf_fail:
	sssnic_workq_destroy(ctrlq->workq);
new_workq_fail:
	rte_free(ctrlq);
	return ret;
}

void
sssnic_ctrlq_shutdown(struct sssnic_hw *hw)
{
	struct sssnic_ctrlq *ctrlq;

	PMD_INIT_FUNC_TRACE();

	if (hw == NULL || hw->ctrlq == NULL)
		return;
	ctrlq = hw->ctrlq;
	rte_mempool_free(ctrlq->mbuf_pool);
	sssnic_workq_destroy(ctrlq->workq);
	rte_free(ctrlq);
}
