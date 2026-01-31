/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 */

#ifndef _HINIC3_CMDQ_ENHANCE_H_
#define _HINIC3_CMDQ_ENHANCE_H_

#include "hinic3_mgmt.h"

#define NORMAL_WQE_TYPE  0
#define COMPACT_WQE_TYPE 1

/* First part 16B */
#define ENHANCED_CMDQ_CTXT0_CI_WQE_ADDR_SHIFT   0
#define ENHANCED_CMDQ_CTXT0_RSV1_SHIFT          52
#define ENHANCED_CMDQ_CTXT0_EQ_SHIFT            53
#define ENHANCED_CMDQ_CTXT0_CEQ_ARM_SHIFT       61
#define ENHANCED_CMDQ_CTXT0_CEQ_EN_SHIFT        62
#define ENHANCED_CMDQ_CTXT0_HW_BUSY_BIT_SHIFT   63

#define ENHANCED_CMDQ_CTXT0_CI_WQE_ADDR_MASK    0xFFFFFFFFFFFFFU
#define ENHANCED_CMDQ_CTXT0_RSV1_MASK           0x1U
#define ENHANCED_CMDQ_CTXT0_EQ_MASK             0xFFU
#define ENHANCED_CMDQ_CTXT0_CEQ_ARM_MASK        0x1U
#define ENHANCED_CMDQ_CTXT0_CEQ_EN_MASK         0x1U
#define ENHANCED_CMDQ_CTXT0_HW_BUSY_BIT_MASK    0x1U

#define ENHANCED_CMDQ_CTXT1_Q_DIS_SHIFT         0
#define ENHANCED_CMDQ_CTXT1_ERR_CODE_SHIFT      1
#define ENHANCED_CMDQ_CTXT1_RSV1_SHIFT          3
#define ENHANCED_CMDQ_CTXT1_PI_SHIFT            32
#define ENHANCED_CMDQ_CTXT1_CI_SHIFT            48

#define ENHANCED_CMDQ_CTXT1_Q_DIS_MASK          0x1U
#define ENHANCED_CMDQ_CTXT1_ERR_CODE_MASK       0x3U
#define ENHANCED_CMDQ_CTXT1_RSV1_MASK           0x1FFFFFFFU
#define ENHANCED_CMDQ_CTXT1_PI_MASK             0xFFFFU
#define ENHANCED_CMDQ_CTXT1_CI_MASK             0xFFFFU

/* Second part 16B */
#define ENHANCED_CMDQ_CTXT2_PFT_CI_SHIFT        0
#define ENHANCED_CMDQ_CTXT2_O_BIT_SHIFT         4
#define ENHANCED_CMDQ_CTXT2_PFT_THD_SHIFT       32
#define ENHANCED_CMDQ_CTXT2_PFT_MAX_SHIFT       46
#define ENHANCED_CMDQ_CTXT2_PFT_MIN_SHIFT       57

#define ENHANCED_CMDQ_CTXT2_PFT_CI_MASK         0xFU
#define ENHANCED_CMDQ_CTXT2_O_BIT_MASK          0x1U
#define ENHANCED_CMDQ_CTXT2_PFT_THD_MASK        0x3FFFFU
#define ENHANCED_CMDQ_CTXT2_PFT_MAX_MASK        0x7FFFU
#define ENHANCED_CMDQ_CTXT2_PFT_MIN_MASK        0x7FU

#define ENHANCED_CMDQ_CTXT3_PFT_CI_ADDR_SHIFT	0
#define ENHANCED_CMDQ_CTXT3_PFT_CI_SHIFT		52

#define ENHANCED_CMDQ_CTXT3_PFT_CI_ADDR_MASK	0xFFFFFFFFFFFFFU
#define ENHANCED_CMDQ_CTXT3_PFT_CI_MASK			0xFFFFU

/* Third part 16B */
#define ENHANCED_CMDQ_CTXT4_CI_CLA_ADDR_SHIFT	0
#define ENHANCED_CMDQ_CTXT4_CI_CLA_ADDR_MASK	0x7FFFFFFFFFFFFFU

#define ENHANCED_CMDQ_SET(val, member)      \
			(((uint64_t)(val) & ENHANCED_CMDQ_##member##_MASK) << \
			 ENHANCED_CMDQ_##member##_SHIFT)

#define CI_IDX_HIGH_SHIFH       12
#define CI_HIGN_IDX(val)        ((val) >> CI_IDX_HIGH_SHIFH)

#define ENHANCE_CMDQ_WQE_HEADER_SEND_SGE_LEN_SHIFT  0
#define ENHANCE_CMDQ_WQE_HEADER_BDSL_SHIFT          19
#define ENHANCE_CMDQ_WQE_HEADER_DF_SHIFT            28
#define ENHANCE_CMDQ_WQE_HEADER_DN_SHIFT            29
#define ENHANCE_CMDQ_WQE_HEADER_EC_SHIFT            30
#define ENHANCE_CMDQ_WQE_HEADER_HW_BUSY_BIT_SHIFT   31

#define ENHANCE_CMDQ_WQE_HEADER_SEND_SGE_LEN_MASK   0x3FFFFU
#define ENHANCE_CMDQ_WQE_HEADER_BDSL_MASK           0xFFU
#define ENHANCE_CMDQ_WQE_HEADER_DF_MASK             0x1U
#define ENHANCE_CMDQ_WQE_HEADER_DN_MASK             0x1U
#define ENHANCE_CMDQ_WQE_HEADER_EC_MASK             0x1U
#define ENHANCE_CMDQ_WQE_HEADER_HW_BUSY_BIT_MASK    0x1U

#define ENHANCE_CMDQ_WQE_HEADER_SET(val, member)        \
			((((uint32_t)(val)) & ENHANCE_CMDQ_WQE_HEADER_##member##_MASK) << \
			 ENHANCE_CMDQ_WQE_HEADER_##member##_SHIFT)

#define ENHANCE_CMDQ_WQE_HEADER_GET(val, member)        \
			(((val) >> ENHANCE_CMDQ_WQE_HEADER_##member##_SHIFT) & \
			 ENHANCE_CMDQ_WQE_HEADER_##member##_MASK)

#define ENHANCE_CMDQ_WQE_CS_ERR_CODE_SHIFT          0
#define ENHANCE_CMDQ_WQE_CS_CMD_SHIFT               4
#define ENHANCE_CMDQ_WQE_CS_ACK_TYPE_SHIFT          12
#define ENHANCE_CMDQ_WQE_CS_HW_BUSY_SHIFT           14
#define ENHANCE_CMDQ_WQE_CS_MOD_SHIFT               16
#define ENHANCE_CMDQ_WQE_CS_CF_SHIFT                31

#define ENHANCE_CMDQ_WQE_CS_ERR_CODE_MASK           0xFU
#define ENHANCE_CMDQ_WQE_CS_CMD_MASK                0xFFU
#define ENHANCE_CMDQ_WQE_CS_ACK_TYPE_MASK           0x3U
#define ENHANCE_CMDQ_WQE_CS_HW_BUSY_MASK            0x1U
#define ENHANCE_CMDQ_WQE_CS_MOD_MASK                0x1FU
#define ENHANCE_CMDQ_WQE_CS_CF_MASK                 0x1U

#define ENHANCE_CMDQ_WQE_CS_SET(val, member)        \
			((((uint32_t)(val)) & ENHANCE_CMDQ_WQE_CS_##member##_MASK) << \
			 ENHANCE_CMDQ_WQE_CS_##member##_SHIFT)

#define ENHANCE_CMDQ_WQE_CS_GET(val, member)        \
			(((val) >> ENHANCE_CMDQ_WQE_CS_##member##_SHIFT) & \
			 ENHANCE_CMDQ_WQE_CS_##member##_MASK)

enum complete_format {
	INLINE_DATA,
	SGE_RESPONSE
};

struct cmdq_enhance_completion {
	uint32_t cs_format;
	uint32_t sge_resp_hi_addr;
	uint32_t sge_resp_lo_addr;
	uint32_t sge_resp_len; /* bit 14~31 rsvd, soft can't use. */
};

struct cmdq_enhance_response {
	uint32_t cs_format;
	uint32_t resvd;
	uint64_t direct_data;
};

struct sge_send_info {
	uint32_t sge_hi_addr;
	uint32_t sge_li_addr;
	uint32_t seg_len;
	uint32_t rsvd;
};

struct ctrl_section {
	uint32_t header;
	uint32_t rsv;
	uint32_t sge_send_hi_addr;
	uint32_t sge_send_lo_addr;
};

struct enhanced_cmdq_wqe {
	struct ctrl_section     ctrl_sec; /* 16B */
	struct cmdq_enhance_completion  completion; /* 16B */
};

/* 	Enhance cmdq context of hardware */
struct enhance_cmdq_ctxt_info {
	uint64_t eq_cfg;
	uint64_t dfx_pi_ci;

	uint64_t pft_thd;
	uint64_t pft_ci;

	uint64_t rsv;
	uint64_t ci_cla_addr;
};

void enhance_cmdq_set_wqe(struct hinic3_cmdq_wqe *wqe, enum cmdq_cmd_type cmd_type,
			   const struct hinic3_cmd_buf *buf_in, const struct hinic3_cmd_buf *buf_out,
			   int wrapped, uint8_t mod, uint8_t cmd);

void enhance_cmdq_init_queue_ctxt(struct hinic3_cmdq *cmdq);

#endif /*_HINIC3_CMDQ_ENHANCE_H_ */
