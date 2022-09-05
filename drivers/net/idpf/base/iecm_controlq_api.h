/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _IECM_CONTROLQ_API_H_
#define _IECM_CONTROLQ_API_H_

#ifdef __KERNEL__
#include "iecm_mem.h"
#else /* !__KERNEL__ */
/* Error Codes */
/* Linux kernel driver can't directly use these. Instead, they are mapped to
 * linux compatible error codes which get translated in the build script.
 */
#define IECM_SUCCESS			0
#define IECM_ERR_PARAM			-53	/* -EBADR */
#define IECM_ERR_NOT_IMPL		-95	/* -EOPNOTSUPP */
#define IECM_ERR_NOT_READY		-16	/* -EBUSY */
#define IECM_ERR_BAD_PTR		-14	/* -EFAULT */
#define IECM_ERR_INVAL_SIZE		-90	/* -EMSGSIZE */
#define IECM_ERR_DEVICE_NOT_SUPPORTED	-19	/* -ENODEV */
#define IECM_ERR_FW_API_VER		-13	/* -EACCESS */
#define IECM_ERR_NO_MEMORY		-12	/* -ENOMEM */
#define IECM_ERR_CFG			-22	/* -EINVAL */
#define IECM_ERR_OUT_OF_RANGE		-34	/* -ERANGE */
#define IECM_ERR_ALREADY_EXISTS		-17	/* -EEXIST */
#define IECM_ERR_DOES_NOT_EXIST		-6	/* -ENXIO */
#define IECM_ERR_IN_USE			-114	/* -EALREADY */
#define IECM_ERR_MAX_LIMIT		-109	/* -ETOOMANYREFS */
#define IECM_ERR_RESET_ONGOING		-104	/* -ECONNRESET */

/* CRQ/CSQ specific error codes */
#define IECM_ERR_CTLQ_ERROR		-74	/* -EBADMSG */
#define IECM_ERR_CTLQ_TIMEOUT		-110	/* -ETIMEDOUT */
#define IECM_ERR_CTLQ_FULL		-28	/* -ENOSPC */
#define IECM_ERR_CTLQ_NO_WORK		-42	/* -ENOMSG */
#define IECM_ERR_CTLQ_EMPTY		-105	/* -ENOBUFS */
#endif /* !__KERNEL__ */

struct iecm_hw;

/* Used for queue init, response and events */
enum iecm_ctlq_type {
	IECM_CTLQ_TYPE_MAILBOX_TX	= 0,
	IECM_CTLQ_TYPE_MAILBOX_RX	= 1,
	IECM_CTLQ_TYPE_CONFIG_TX	= 2,
	IECM_CTLQ_TYPE_CONFIG_RX	= 3,
	IECM_CTLQ_TYPE_EVENT_RX		= 4,
	IECM_CTLQ_TYPE_RDMA_TX		= 5,
	IECM_CTLQ_TYPE_RDMA_RX		= 6,
	IECM_CTLQ_TYPE_RDMA_COMPL	= 7
};

/*
 * Generic Control Queue Structures
 */

struct iecm_ctlq_reg {
	/* used for queue tracking */
	u32 head;
	u32 tail;
	/* Below applies only to default mb (if present) */
	u32 len;
	u32 bah;
	u32 bal;
	u32 len_mask;
	u32 len_ena_mask;
	u32 head_mask;
};

/* Generic queue msg structure */
struct iecm_ctlq_msg {
	u8 vmvf_type; /* represents the source of the message on recv */
#define IECM_VMVF_TYPE_VF 0
#define IECM_VMVF_TYPE_VM 1
#define IECM_VMVF_TYPE_PF 2
	u8 host_id;
	/* 3b field used only when sending a message to peer - to be used in
	 * combination with target func_id to route the message
	 */
#define IECM_HOST_ID_MASK 0x7

	u16 opcode;
	u16 data_len;	/* data_len = 0 when no payload is attached */
	union {
		u16 func_id;	/* when sending a message */
		u16 status;	/* when receiving a message */
	};
	union {
		struct {
			u32 chnl_retval;
			u32 chnl_opcode;
		} mbx;
	} cookie;
	union {
#define IECM_DIRECT_CTX_SIZE	16
#define IECM_INDIRECT_CTX_SIZE	8
		/* 16 bytes of context can be provided or 8 bytes of context
		 * plus the address of a DMA buffer
		 */
		u8 direct[IECM_DIRECT_CTX_SIZE];
		struct {
			u8 context[IECM_INDIRECT_CTX_SIZE];
			struct iecm_dma_mem *payload;
		} indirect;
	} ctx;
};

/* Generic queue info structures */
/* MB, CONFIG and EVENT q do not have extended info */
struct iecm_ctlq_create_info {
	enum iecm_ctlq_type type;
	int id; /* absolute queue offset passed as input
		 * -1 for default mailbox if present
		 */
	u16 len; /* Queue length passed as input */
	u16 buf_size; /* buffer size passed as input */
	u64 base_address; /* output, HPA of the Queue start  */
	struct iecm_ctlq_reg reg; /* registers accessed by ctlqs */

	int ext_info_size;
	void *ext_info; /* Specific to q type */
};

/* Control Queue information */
struct iecm_ctlq_info {
	LIST_ENTRY_TYPE(iecm_ctlq_info) cq_list;

	enum iecm_ctlq_type cq_type;
	int q_id;
	iecm_lock cq_lock;		/* queue lock
					 * iecm_lock is defined in OSdep.h
					 */
	/* used for interrupt processing */
	u16 next_to_use;
	u16 next_to_clean;
	u16 next_to_post;		/* starting descriptor to post buffers
					 * to after recev
					 */

	struct iecm_dma_mem desc_ring;	/* descriptor ring memory
					 * iecm_dma_mem is defined in OSdep.h
					 */
	union {
		struct iecm_dma_mem **rx_buff;
		struct iecm_ctlq_msg **tx_msg;
	} bi;

	u16 buf_size;			/* queue buffer size */
	u16 ring_size;			/* Number of descriptors */
	struct iecm_ctlq_reg reg;	/* registers accessed by ctlqs */
};

/* PF/VF mailbox commands */
enum iecm_mbx_opc {
	/* iecm_mbq_opc_send_msg_to_pf:
	 *	usage: used by PF or VF to send a message to its CPF
	 *	target: RX queue and function ID of parent PF taken from HW
	 */
	iecm_mbq_opc_send_msg_to_pf		= 0x0801,

	/* iecm_mbq_opc_send_msg_to_vf:
	 *	usage: used by PF to send message to a VF
	 *	target: VF control queue ID must be specified in descriptor
	 */
	iecm_mbq_opc_send_msg_to_vf		= 0x0802,

	/* iecm_mbq_opc_send_msg_to_peer_pf:
	 *	usage: used by any function to send message to any peer PF
	 *	target: RX queue and host of parent PF taken from HW
	 */
	iecm_mbq_opc_send_msg_to_peer_pf	= 0x0803,

	/* iecm_mbq_opc_send_msg_to_peer_drv:
	 *	usage: used by any function to send message to any peer driver
	 *	target: RX queue and target host must be specific in descriptor
	 */
	iecm_mbq_opc_send_msg_to_peer_drv	= 0x0804,
};

/*
 * API supported for control queue management
 */

/* Will init all required q including default mb.  "q_info" is an array of
 * create_info structs equal to the number of control queues to be created.
 */
int iecm_ctlq_init(struct iecm_hw *hw, u8 num_q,
		   struct iecm_ctlq_create_info *q_info);

/* Allocate and initialize a single control queue, which will be added to the
 * control queue list; returns a handle to the created control queue
 */
int iecm_ctlq_add(struct iecm_hw *hw,
		  struct iecm_ctlq_create_info *qinfo,
		  struct iecm_ctlq_info **cq);

/* Deinitialize and deallocate a single control queue */
void iecm_ctlq_remove(struct iecm_hw *hw,
		      struct iecm_ctlq_info *cq);

/* Sends messages to HW and will also free the buffer*/
int iecm_ctlq_send(struct iecm_hw *hw,
		   struct iecm_ctlq_info *cq,
		   u16 num_q_msg,
		   struct iecm_ctlq_msg q_msg[]);

/* Receives messages and called by interrupt handler/polling
 * initiated by app/process. Also caller is supposed to free the buffers
 */
int iecm_ctlq_recv(struct iecm_ctlq_info *cq, u16 *num_q_msg,
		   struct iecm_ctlq_msg *q_msg);

/* Reclaims send descriptors on HW write back */
int iecm_ctlq_clean_sq(struct iecm_ctlq_info *cq, u16 *clean_count,
		       struct iecm_ctlq_msg *msg_status[]);

/* Indicate RX buffers are done being processed */
int iecm_ctlq_post_rx_buffs(struct iecm_hw *hw,
			    struct iecm_ctlq_info *cq,
			    u16 *buff_count,
			    struct iecm_dma_mem **buffs);

/* Will destroy all q including the default mb */
int iecm_ctlq_deinit(struct iecm_hw *hw);

#endif /* _IECM_CONTROLQ_API_H_ */
