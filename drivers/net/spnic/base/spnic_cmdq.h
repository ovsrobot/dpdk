/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_CMDQ_H_
#define _SPNIC_CMDQ_H_

#define SPNIC_SCMD_DATA_LEN		16

/* Pmd driver uses 64, kernel l2nic uses 4096 */
#define SPNIC_CMDQ_DEPTH		64

#define SPNIC_CMDQ_BUF_SIZE		2048U
#define SPNIC_CMDQ_BUF_HW_RSVD		8
#define SPNIC_CMDQ_MAX_DATA_SIZE	(SPNIC_CMDQ_BUF_SIZE	\
					 - SPNIC_CMDQ_BUF_HW_RSVD)

#define SPNIC_CEQ_ID_CMDQ		0

enum cmdq_scmd_type {
	CMDQ_SET_ARM_CMD = 2,
};

enum cmdq_wqe_type {
	WQE_LCMD_TYPE,
	WQE_SCMD_TYPE
};

enum ctrl_sect_len {
	CTRL_SECT_LEN = 1,
	CTRL_DIRECT_SECT_LEN = 2
};

enum bufdesc_len {
	BUFDESC_LCMD_LEN = 2,
	BUFDESC_SCMD_LEN = 3
};

enum data_format {
	DATA_SGE,
};

enum completion_format {
	COMPLETE_DIRECT,
	COMPLETE_SGE
};

enum completion_request {
	CEQ_SET = 1,
};

enum cmdq_cmd_type {
	SYNC_CMD_DIRECT_RESP,
	SYNC_CMD_SGE_RESP,
	ASYNC_CMD
};

enum spnic_cmdq_type {
	SPNIC_CMDQ_SYNC,
	SPNIC_CMDQ_ASYNC,
	SPNIC_MAX_CMDQ_TYPES
};

enum spnic_db_src_type {
	SPNIC_DB_SRC_CMDQ_TYPE,
	SPNIC_DB_SRC_L2NIC_SQ_TYPE
};

enum spnic_cmdq_db_type {
	SPNIC_DB_SQ_RQ_TYPE,
	SPNIC_DB_CMDQ_TYPE
};

/* Cmdq ack type */
enum spnic_ack_type {
	SPNIC_ACK_TYPE_CMDQ,
	SPNIC_ACK_TYPE_SHARE_CQN,
	SPNIC_ACK_TYPE_APP_CQN,

	SPNIC_MOD_ACK_MAX = 15
};

/* Cmdq wqe ctrls */
struct spnic_cmdq_header {
	u32 header_info;
	u32 saved_data;
};

struct spnic_scmd_bufdesc {
	u32 buf_len;
	u32 rsvd;
	u8  data[SPNIC_SCMD_DATA_LEN];
};

struct spnic_lcmd_bufdesc {
	struct spnic_sge sge;
	u32 rsvd1;
	u64 saved_async_buf;
	u64 rsvd3;
};

struct spnic_cmdq_db {
	u32 db_head;
	u32 db_info;
};

struct spnic_status {
	u32 status_info;
};

struct spnic_ctrl {
	u32 ctrl_info;
};

struct spnic_sge_resp {
	struct spnic_sge sge;
	u32 rsvd;
};

struct spnic_cmdq_completion {
	/* HW format */
	union {
		struct spnic_sge_resp sge_resp;
		u64 direct_resp;
	};
};

struct spnic_cmdq_wqe_scmd {
	struct spnic_cmdq_header       header;
	u64                            rsvd;
	struct spnic_status            status;
	struct spnic_ctrl              ctrl;
	struct spnic_cmdq_completion   completion;
	struct spnic_scmd_bufdesc      buf_desc;
};

struct spnic_cmdq_wqe_lcmd {
	struct spnic_cmdq_header       header;
	struct spnic_status            status;
	struct spnic_ctrl              ctrl;
	struct spnic_cmdq_completion   completion;
	struct spnic_lcmd_bufdesc      buf_desc;
};

struct spnic_cmdq_inline_wqe {
	struct spnic_cmdq_wqe_scmd wqe_scmd;
};

struct spnic_cmdq_wqe {
	/* HW format */
	union {
		struct spnic_cmdq_inline_wqe inline_wqe;
		struct spnic_cmdq_wqe_lcmd wqe_lcmd;
	};
};

struct spnic_cmdq_ctxt_info {
	u64 curr_wqe_page_pfn;
	u64 wq_block_pfn;
};

struct spnic_cmd_cmdq_ctxt {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_idx;
	u8  cmdq_id;
	u8  rsvd1[5];

	struct spnic_cmdq_ctxt_info ctxt_info;
};

enum spnic_cmdq_status {
	SPNIC_CMDQ_ENABLE = BIT(0),
};

enum spnic_cmdq_cmd_type {
	SPNIC_CMD_TYPE_NONE,
	SPNIC_CMD_TYPE_SET_ARM,
	SPNIC_CMD_TYPE_DIRECT_RESP,
	SPNIC_CMD_TYPE_SGE_RESP
};

struct spnic_cmdq_cmd_info {
	enum spnic_cmdq_cmd_type cmd_type;
};

struct spnic_cmdq {
	struct spnic_wq *wq;

	enum spnic_cmdq_type cmdq_type;
	int wrapped;

	int *errcode;
	u8  *db_base;

	rte_spinlock_t cmdq_lock;

	struct spnic_cmdq_ctxt_info cmdq_ctxt;

	struct spnic_cmdq_cmd_info *cmd_infos;
};

struct spnic_cmdqs {
	struct spnic_hwdev *hwdev;

	struct rte_mempool *cmd_buf_pool;

	struct spnic_wq *saved_wqs;

	struct spnic_cmdq cmdq[SPNIC_MAX_CMDQ_TYPES];

	u32 status;
};

struct spnic_cmd_buf {
	void *buf;
	uint64_t dma_addr;
	struct rte_mbuf *mbuf;
	u16 size;
};

int spnic_reinit_cmdq_ctxts(struct spnic_hwdev *hwdev);

bool spnic_cmdq_idle(struct spnic_cmdq *cmdq);

struct spnic_cmd_buf *spnic_alloc_cmd_buf(struct spnic_hwdev *hwdev);

void spnic_free_cmd_buf(struct spnic_cmd_buf *cmd_buf);

/*
 * PF/VF sends cmd to ucode by cmdq, and return 0 if success.
 * timeout=0, use default timeout.
 */
int spnic_cmdq_direct_resp(struct spnic_hwdev *hwdev, enum spnic_mod_type mod, u8 cmd,
			   struct spnic_cmd_buf *buf_in, u64 *out_param,
			   u32 timeout);

int spnic_cmdq_detail_resp(struct spnic_hwdev *hwdev, enum spnic_mod_type mod, u8 cmd,
			   struct spnic_cmd_buf *buf_in,
			   struct spnic_cmd_buf *buf_out, u32 timeout);

int spnic_cmdqs_init(struct spnic_hwdev *hwdev);

void spnic_cmdqs_free(struct spnic_hwdev *hwdev);

#endif /* _SPNIC_CMDQ_H_ */
