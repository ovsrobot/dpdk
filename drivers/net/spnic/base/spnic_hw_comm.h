/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HW_COMM_H_
#define _SPNIC_HW_COMM_H_

#define SPNIC_MGMT_CMD_OP_GET	0
#define SPNIC_MGMT_CMD_OP_SET	1

#define	SPNIC_MSIX_CNT_LLI_TIMER_SHIFT			0
#define	SPNIC_MSIX_CNT_LLI_CREDIT_SHIFT			8
#define	SPNIC_MSIX_CNT_COALESC_TIMER_SHIFT		8
#define	SPNIC_MSIX_CNT_PENDING_SHIFT			8
#define	SPNIC_MSIX_CNT_RESEND_TIMER_SHIFT		29

#define	SPNIC_MSIX_CNT_LLI_TIMER_MASK			0xFFU
#define	SPNIC_MSIX_CNT_LLI_CREDIT_MASK			0xFFU
#define	SPNIC_MSIX_CNT_COALESC_TIMER_MASK		0xFFU
#define	SPNIC_MSIX_CNT_PENDING_MASK			0x1FU
#define	SPNIC_MSIX_CNT_RESEND_TIMER_MASK		0x7U

#define SPNIC_MSIX_CNT_SET(val, member)		\
		(((val) & SPNIC_MSIX_CNT_##member##_MASK) << \
		SPNIC_MSIX_CNT_##member##_SHIFT)

#define MSG_TO_MGMT_SYNC_RETURN_ERR(err, out_size, status)	\
		((err) || (status) || !(out_size))

struct spnic_cmd_msix_config {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u16 msix_index;
	u8  pending_cnt;
	u8  coalesct_timer_cnt;
	u8  resend_timer_cnt;
	u8  lli_tmier_cnt;
	u8  lli_credit_cnt;
	u8  rsvd2[5];
};

#define SPNIC_PAGE_SIZE_HW(pg_size)	((u8)ilog2((u32)((pg_size) >> 12)))

struct spnic_cmd_wq_page_size {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	u16 func_idx;
	u8  opcode;
	/*
	 * Real size is 4KB * 2^page_size, range(0~20) must be checked
	 * by driver
	 */
	u8  page_size;

	u32 rsvd1;
};

struct spnic_reset {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	u16 func_id;
	u16 rsvd1[3];
	u64 reset_flag;
};

struct spnic_cmd_root_ctxt {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	u16 func_idx;
	u8  set_cmdq_depth;
	u8  cmdq_depth;
	u16 rx_buf_sz;
	u8  lro_en;
	u8  rsvd1;
	u16 sq_depth;
	u16 rq_depth;
	u64 rsvd2;
};

enum spnic_fw_ver_type {
	SPNIC_FW_VER_TYPE_BOOT,
	SPNIC_FW_VER_TYPE_MPU,
	SPNIC_FW_VER_TYPE_NPU,
	SPNIC_FW_VER_TYPE_SMU,
	SPNIC_FW_VER_TYPE_CFG,
};

#define MGMT_MSG_CMD_OP_SET	1
#define MGMT_MSG_CMD_OP_GET	0

struct comm_cmd_feature_nego {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 opcode;	/* 1: set, 0: get */
	u8 rsvd;
	u64 s_feature[MAX_FEATURE_QWORD];
};

struct comm_cmd_dma_attr_config {
	struct mgmt_msg_head head;

	u16 func_id;
	u8 entry_idx;
	u8 st;
	u8 at;
	u8 ph;
	u8 no_snooping;
	u8 tph_en;
	u32 resv1;
};

#define SPNIC_FW_VERSION_LEN		16
#define SPNIC_FW_COMPILE_TIME_LEN	20
#define SPNIC_MGMT_VERSION_MAX_LEN	32
struct spnic_cmd_get_fw_version {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 fw_type;
	u16 rsvd1;
	u8 ver[SPNIC_FW_VERSION_LEN];
	u8 time[SPNIC_FW_COMPILE_TIME_LEN];
};

struct spnic_cmd_clear_doorbell {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_idx;
	u16 rsvd1[3];
};

struct spnic_cmd_clear_resource {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	u16 func_idx;
	u16 rsvd1[3];
};

struct spnic_cmd_board_info {
	u8  status;
	u8  version;
	u8  rsvd0[6];

	struct spnic_board_info info;

	u32 rsvd1[25];
};

struct interrupt_info {
	u32 lli_set;
	u32 interrupt_coalesc_set;
	u16 msix_index;
	u8 lli_credit_limit;
	u8 lli_timer_cfg;
	u8 pending_limt;
	u8 coalesc_timer_cfg;
	u8 resend_timer_cfg;
};

int spnic_func_reset(void *hwdev, u64 reset_flag);

int spnic_get_mgmt_version(void *hwdev, char *mgmt_ver, int max_mgmt_len);

int spnic_get_board_info(void *hwdev, struct spnic_board_info *info);

int spnic_set_root_ctxt(void *hwdev, u32 rq_depth, u32 sq_depth, u16 rx_buf_sz);

int spnic_clean_root_ctxt(void *hwdev);

int spnic_get_interrupt_cfg(void *dev, struct interrupt_info *info);

int spnic_set_interrupt_cfg(void *dev, struct interrupt_info info);

int spnic_set_wq_page_size(void *hwdev, u16 func_idx, u32 page_size);

int spnic_set_cmdq_depth(void *hwdev, u16 cmdq_depth);

int spnic_convert_rx_buf_size(u32 rx_buf_sz, u32 *match_sz);

int spnic_get_comm_features(void *hwdev, u64 *s_feature, u16 size);

int spnic_set_comm_features(void *hwdev, u64 *s_feature, u16 size);

int spnic_set_dma_attr_tbl(struct spnic_hwdev *hwdev, u32 entry_idx, u8 st,
			   u8 at, u8 ph, u8 no_snooping, u8 tph_en);

#endif
