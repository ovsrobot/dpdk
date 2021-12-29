/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_MGMT_H_
#define _SPNIC_MGMT_H_

#define SPNIC_MSG_HANDLER_RES	(-1)

/* Structures for l2nic and mag msg to mgmt sync interface */
struct mgmt_msg_head {
	u8 status;
	u8 version;
	u8 rsvd0[6];
};

/* Cmdq module type */
enum spnic_mod_type {
	SPNIC_MOD_COMM = 0, /* HW communication module */
	SPNIC_MOD_L2NIC = 1, /* L2NIC module */
	SPNIC_MOD_ROCE = 2,
	SPNIC_MOD_PLOG = 3,
	SPNIC_MOD_TOE = 4,
	SPNIC_MOD_FLR = 5,
	SPNIC_MOD_FC = 6,
	SPNIC_MOD_CFGM = 7, /* Configuration module */
	SPNIC_MOD_CQM = 8,
	SPNIC_MOD_VSWITCH = 9,
	COMM_MOD_FC = 10,
	SPNIC_MOD_OVS = 11,
	SPNIC_MOD_DSW = 12,
	SPNIC_MOD_MIGRATE = 13,
	SPNIC_MOD_HILINK = 14,
	SPNIC_MOD_CRYPT = 15, /* Secure crypto module */
	SPNIC_MOD_HW_MAX = 16, /* Hardware max module id */

	/* Software module id, for PF/VF and multi-host */
	SPNIC_MOD_SW_FUNC = 17,
	SPNIC_MOD_IOE = 18,
	SPNIC_MOD_MAX
};

typedef enum {
	RES_TYPE_FLUSH_BIT = 0,
	RES_TYPE_MQM,
	RES_TYPE_SMF,

	RES_TYPE_COMM = 10,
	/* clear mbox and aeq, The RES_TYPE_COMM bit must be set */
	RES_TYPE_COMM_MGMT_CH,
	/* clear cmdq, The RES_TYPE_COMM bit must be set */
	RES_TYPE_COMM_CMD_CH,
	RES_TYPE_NIC,
	RES_TYPE_OVS,
	RES_TYPE_MAX = 20,
} func_reset_flag_e;

#define SPNIC_COMM_RES		((1 << RES_TYPE_COMM) | \
				(1 << RES_TYPE_FLUSH_BIT) | \
				(1 << RES_TYPE_MQM) | \
				(1 << RES_TYPE_SMF) | \
				(1 << RES_TYPE_COMM_CMD_CH))
#define SPNIC_NIC_RES		(1 << RES_TYPE_NIC)
#define SPNIC_OVS_RES		(1 << RES_TYPE_OVS)

struct spnic_recv_msg {
	void *msg;

	u16 msg_len;
	enum spnic_mod_type mod;
	u16 cmd;
	u8 seq_id;
	u16 msg_id;
	int async_mgmt_to_pf;
};

enum comm_pf_to_mgmt_event_state {
	SEND_EVENT_UNINIT = 0,
	SEND_EVENT_START,
	SEND_EVENT_SUCCESS,
	SEND_EVENT_FAIL,
	SEND_EVENT_TIMEOUT,
	SEND_EVENT_END
};

struct spnic_msg_pf_to_mgmt {
	struct spnic_hwdev *hwdev;

	/* Mutex for sync message */
	pthread_mutex_t sync_msg_mutex;

	void *mgmt_ack_buf;

	struct spnic_recv_msg recv_msg_from_mgmt;
	struct spnic_recv_msg recv_resp_msg_from_mgmt;

	u16 sync_msg_id;
};

int spnic_mgmt_msg_aeqe_handler(void *hwdev, u8 *header, u8 size, void *param);

int spnic_pf_to_mgmt_init(struct spnic_hwdev *hwdev);

void spnic_pf_to_mgmt_free(struct spnic_hwdev *hwdev);

int spnic_msg_to_mgmt_sync(void *hwdev, enum spnic_mod_type mod, u16 cmd,
			   void *buf_in, u16 in_size, void *buf_out,
			   u16 *out_size, u32 timeout);

#endif /* _SPNIC_MGMT_H_ */
