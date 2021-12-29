/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_MBOX_H_
#define _SPNIC_MBOX_H_

#define SPNIC_MBOX_PF_SEND_ERR		0x1
#define SPNIC_MBOX_PF_BUSY_ACTIVE_FW	0x2
#define SPNIC_MBOX_VF_CMD_ERROR         0x3

#define SPNIC_MGMT_SRC_ID		0x1FFF
#define SPNIC_MAX_FUNCTIONS		4096
#define SPNIC_MAX_PF_FUNCS		32

/* Message header define */
#define SPNIC_MSG_HEADER_SRC_GLB_FUNC_IDX_SHIFT                 0
#define SPNIC_MSG_HEADER_STATUS_SHIFT				13
#define SPNIC_MSG_HEADER_SOURCE_SHIFT				15
#define SPNIC_MSG_HEADER_AEQ_ID_SHIFT				16
#define SPNIC_MSG_HEADER_MSG_ID_SHIFT				18
#define SPNIC_MSG_HEADER_CMD_SHIFT				22

#define SPNIC_MSG_HEADER_MSG_LEN_SHIFT				32
#define SPNIC_MSG_HEADER_MODULE_SHIFT				43
#define SPNIC_MSG_HEADER_SEG_LEN_SHIFT				48
#define SPNIC_MSG_HEADER_NO_ACK_SHIFT				54
#define SPNIC_MSG_HEADER_DATA_TYPE_SHIFT			55
#define SPNIC_MSG_HEADER_SEQID_SHIFT				56
#define SPNIC_MSG_HEADER_LAST_SHIFT				62
#define SPNIC_MSG_HEADER_DIRECTION_SHIFT			63

#define SPNIC_MSG_HEADER_CMD_MASK				0x3FF
#define SPNIC_MSG_HEADER_MSG_ID_MASK				0xF
#define SPNIC_MSG_HEADER_AEQ_ID_MASK				0x3
#define SPNIC_MSG_HEADER_SOURCE_MASK				0x1
#define SPNIC_MSG_HEADER_STATUS_MASK				0x1
#define SPNIC_MSG_HEADER_SRC_GLB_FUNC_IDX_MASK			0x1FFF

#define SPNIC_MSG_HEADER_MSG_LEN_MASK				0x7FF
#define SPNIC_MSG_HEADER_MODULE_MASK				0x1F
#define SPNIC_MSG_HEADER_SEG_LEN_MASK				0x3F
#define SPNIC_MSG_HEADER_NO_ACK_MASK				0x1
#define SPNIC_MSG_HEADER_DATA_TYPE_MASK                         0x1
#define SPNIC_MSG_HEADER_SEQID_MASK				0x3F
#define SPNIC_MSG_HEADER_LAST_MASK				0x1
#define SPNIC_MSG_HEADER_DIRECTION_MASK                         0x1

#define SPNIC_MSG_HEADER_GET(val, field)	\
			(((val) >> SPNIC_MSG_HEADER_##field##_SHIFT) & \
			SPNIC_MSG_HEADER_##field##_MASK)
#define SPNIC_MSG_HEADER_SET(val, field)	\
			((u64)(((u64)(val)) &	\
			SPNIC_MSG_HEADER_##field##_MASK) << \
			SPNIC_MSG_HEADER_##field##_SHIFT)

#define IS_TLP_MBX(dst_func) ((dst_func) == SPNIC_MGMT_SRC_ID)

enum spnic_msg_direction_type {
	SPNIC_MSG_DIRECT_SEND	= 0,
	SPNIC_MSG_RESPONSE	= 1
};

enum spnic_msg_segment_type {
	NOT_LAST_SEGMENT = 0,
	LAST_SEGMENT	 = 1
};

enum spnic_msg_ack_type {
	SPNIC_MSG_ACK,
	SPNIC_MSG_NO_ACK
};

enum spnic_data_type {
	SPNIC_DATA_INLINE	= 0,
	SPNIC_DATA_DMA		= 1
};

enum spnic_msg_src_type {
	SPNIC_MSG_FROM_MGMT = 0,
	SPNIC_MSG_FROM_MBOX = 1
};

enum spnic_msg_aeq_type {
	SPNIC_ASYNC_MSG_AEQ = 0,
	/* Indicate dest func or mgmt cpu  which aeq to response mbox message */
	SPNIC_MBOX_RSP_MSG_AEQ	= 1,
	/* Indicate mgmt cpu  which aeq to response api cmd message */
	SPNIC_MGMT_RSP_MSG_AEQ	= 2
};

enum spnic_mbox_seg_errcode {
	MBOX_ERRCODE_NO_ERRORS = 0,
	/* VF sends the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_VF_TO_WRONG_FUNC = 0x100,
	/* PPF sends the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_PPF_TO_WRONG_FUNC = 0x200,
	/* PF sends the mailbox data to the wrong destination functions */
	MBOX_ERRCODE_PF_TO_WRONG_FUNC = 0x300,
	/* The mailbox data size is set to all zero */
	MBOX_ERRCODE_ZERO_DATA_SIZE = 0x400,
	/* The sender function attribute has not been learned by CPI hardware */
	MBOX_ERRCODE_UNKNOWN_SRC_FUNC = 0x500,
	/* The receiver function attr has not been learned by CPI hardware */
	MBOX_ERRCODE_UNKNOWN_DES_FUNC = 0x600
};

struct mbox_msg_info {
	u8 msg_id;
	u8 status; /* Can only use 3 bit */
};

struct spnic_recv_mbox {
	void *mbox;
	void *buf_out;
	u16 cmd;
	u16 mbox_len;
	enum spnic_mod_type mod;
	enum spnic_msg_ack_type ack_type;
	u8 seq_id;
	struct mbox_msg_info msg_info;
};

struct spnic_send_mbox {
	u8 *data;

	u64 *wb_status; /* Write back status */

	const struct rte_memzone *wb_mz;
	void *wb_vaddr;
	rte_iova_t wb_paddr;

	const struct rte_memzone *sbuff_mz;
	void *sbuff_vaddr;
	rte_iova_t sbuff_paddr;
};

enum mbox_event_state {
	EVENT_START = 0,
	EVENT_FAIL,
	EVENT_SUCCESS,
	EVENT_TIMEOUT,
	EVENT_END
};

enum spnic_mbox_cb_state {
	SPNIC_VF_MBOX_CB_REG = 0,
	SPNIC_VF_MBOX_CB_RUNNING,
	SPNIC_PF_MBOX_CB_REG,
	SPNIC_PF_MBOX_CB_RUNNING,
	SPNIC_PPF_MBOX_CB_REG,
	SPNIC_PPF_MBOX_CB_RUNNING,
	SPNIC_PPF_TO_PF_MBOX_CB_REG,
	SPNIC_PPF_TO_PF_MBOX_CB_RUNNING
};

struct spnic_mbox {
	struct spnic_hwdev *hwdev;

	pthread_mutex_t mbox_send_mutex;
	pthread_mutex_t msg_send_mutex;

	struct spnic_send_mbox send_mbox;

	/* Last element for mgmt */
	struct spnic_recv_mbox	mbox_resp[SPNIC_MAX_FUNCTIONS + 1];
	struct spnic_recv_mbox	mbox_send[SPNIC_MAX_FUNCTIONS + 1];

	u8 send_msg_id;
	enum mbox_event_state event_flag;
	/* Lock for mbox event flag */
	rte_spinlock_t mbox_lock;
};

int spnic_mbox_func_aeqe_handler(void *handle, u8 *header, __rte_unused u8 size,
				 void *param);

int spnic_func_to_func_init(struct spnic_hwdev *hwdev);

void spnic_func_to_func_free(struct spnic_hwdev *hwdev);

int spnic_send_mbox_to_mgmt(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
			    u16 cmd, void *buf_in, u16 in_size, void *buf_out,
			    u16 *out_size, u32 timeout);

void spnic_response_mbox_to_mgmt(struct spnic_hwdev *hwdev,
				 enum spnic_mod_type mod, u16 cmd,
				 void *buf_in, u16 in_size, u16 msg_id);

int spnic_send_mbox_to_mgmt_no_ack(struct spnic_hwdev *hwdev,
				   enum spnic_mod_type mod, u16 cmd,
				   void *buf_in, u16 in_size);

int spnic_mbox_to_pf(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
		     u16 cmd, void *buf_in, u16 in_size, void *buf_out,
		     u16 *out_size, u32 timeout);

int spnic_mbox_to_vf(struct spnic_hwdev *hwdev, enum spnic_mod_type mod,
		     u16 vf_id, u16 cmd, void *buf_in, u16 in_size,
		     void *buf_out, u16 *out_size, u32 timeout);

#endif /* _SPNIC_MBOX_H_ */
