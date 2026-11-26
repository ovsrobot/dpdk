/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_CHANNEL_H_
#define _NBL_CHANNEL_H_

#include "nbl_ethdev.h"

#define NBL_CHAN_MAX_PAGE_SIZE			(64 * 1024)

#define NBL_CHAN_MGT_TO_COMMON(chan_mgt)	((chan_mgt)->common)
#define NBL_CHAN_MGT_TO_DEV(chan_mgt)		NBL_COMMON_TO_DEV(NBL_CHAN_MGT_TO_COMMON(chan_mgt))
#define NBL_CHAN_MGT_TO_HW_OPS_TBL(chan_mgt)	((chan_mgt)->hw_ops_tbl)
#define NBL_CHAN_MGT_TO_HW_OPS(chan_mgt)	(NBL_CHAN_MGT_TO_HW_OPS_TBL(chan_mgt)->ops)
#define NBL_CHAN_MGT_TO_HW_PRIV(chan_mgt)	(NBL_CHAN_MGT_TO_HW_OPS_TBL(chan_mgt)->priv)
#define NBL_CHAN_MGT_TO_CHAN_INFO(chan_mgt)	((chan_mgt)->chan_info)

#define NBL_CHAN_TX_DESC(tx_ring, i) \
	(&(((union nbl_chan_tx_desc *)((tx_ring)->desc))[i]))
#define NBL_CHAN_RX_DESC(rx_ring, i) \
	(&(((union nbl_chan_rx_desc *)((rx_ring)->desc))[i]))

#define NBL_CHAN_QUEUE_LEN			64
#define NBL_CHAN_BUF_LEN			4096

#define NBL_CHAN_TX_WAIT_US			100
#define NBL_CHAN_TX_REKICK_WAIT_TIMES		2000
#define NBL_CHAN_TX_WAIT_TIMES			10000
#define NBL_CHAN_RETRY_TIMES			20000
#define NBL_CHAN_TX_DESC_EMBEDDED_DATA_LEN	16

#define NBL_CHAN_TX_DESC_AVAIL			BIT(0)
#define NBL_CHAN_TX_DESC_USED			BIT(1)
#define NBL_CHAN_RX_DESC_WRITE			BIT(1)
#define NBL_CHAN_RX_DESC_AVAIL			BIT(3)
#define NBL_CHAN_RX_DESC_USED			BIT(4)

/* These macros require an existing chan_info variable. */
#define DESC_R(desc, field)									\
	({											\
		typeof(desc) _desc = (desc);							\
		chan_info->mailbox.product_type == NBL_LEONIS_TYPE ? _desc->NBL_NAME(field)	\
							   : _desc->draco.NBL_NAME(field##_v2);	\
	})

#define DESC_W(desc, field, val)								\
	({											\
		typeof(val) _val = (val);							\
		typeof(desc) _desc = (desc);							\
		if (chan_info->mailbox.product_type == NBL_LEONIS_TYPE)				\
			_desc->NBL_NAME(field) = _val;						\
		else										\
			_desc->draco.NBL_NAME(field##_v2) = _val;				\
	})

enum {
	NBL_MB_RX_QID = 0,
	NBL_MB_TX_QID = 1,
};

enum {
	NBL_MBX_STATUS_IDLE = 0,
	NBL_MBX_STATUS_WAITING,
	NBL_MBX_STATUS_ACKING,
	NBL_MBX_STATUS_ACKED,
	NBL_MBX_STATUS_TIMEOUT,
};

union nbl_chan_tx_desc {
	struct __rte_packed_begin {
		uint16_t flags;
		uint16_t srcid;
		uint16_t dstid;
		uint16_t data_len;
		uint16_t buf_len;
		uint64_t buf_addr;
		uint16_t msg_type;
		uint8_t data[16];
		uint16_t msgid;
		uint8_t rsv[26];
	} __rte_packed_end;
	struct __rte_packed_begin draco_chan_tx_desc {
		uint16_t flags_v2;
		uint16_t srcid_v2;
		uint16_t dstid_v2;
		uint16_t data_len_v2;
		uint64_t buf_addr_v2;
		uint16_t buf_len_v2;
		uint16_t msg_type_v2;
		uint8_t data_v2[16];
		uint16_t msgid_v2;
		uint8_t rsv_v2[26];
	} __rte_packed_end draco;
};

union nbl_chan_rx_desc {
	struct __rte_packed_begin {
		uint16_t flags;
		uint32_t buf_len;
		uint16_t buf_id;
		uint64_t buf_addr;
	} __rte_packed_end;
	struct __rte_packed_begin draco_chan_rx_desc {
		uint16_t flags_v2;
		uint16_t buf_id_v2;
		uint32_t buf_len_v2;
		uint64_t buf_addr_v2;
	} __rte_packed_end draco;
};

struct nbl_chan_ring {
	struct nbl_dma_mem desc_mem;
	struct nbl_dma_mem buf_mem;
	void *desc;
	void *buf;

	uint16_t next_to_use;
	uint16_t tail_ptr;
	uint16_t next_to_clean;
};

struct nbl_chan_waitqueue_head {
	char *ack_data;
	RTE_ATOMIC(int) status;
	int ack_err;
	uint16_t ack_data_len;
	uint16_t msg_type;
};

union nbl_chan_info {
	struct {
		struct nbl_chan_ring txq;
		struct nbl_chan_ring rxq;
		struct nbl_chan_waitqueue_head *wait;

		rte_spinlock_t txq_lock;
		uint16_t num_txq_entries;
		uint16_t num_rxq_entries;
		uint16_t txq_buf_size;
		uint16_t rxq_buf_size;

		struct nbl_work work;
		void *state_bmp_mem;
		struct rte_bitmap *state_bmp;
		rte_thread_t tid;
		int fd[2];
		enum nbl_product_type product_type;
	} mailbox;

	struct {
		struct rte_intr_handle intr_handle;
		void *shm_msg_ring;
		int eventfd;
	} userdev;
};

struct nbl_chan_msg_handler {
	void (*func)(void *priv, uint16_t srcid, uint16_t msgid, void *data, uint32_t len);
	void *priv;
};

struct nbl_channel_mgt {
	uint32_t mode;
	struct nbl_common_info *common;
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	union nbl_chan_info *chan_info;
	struct nbl_chan_msg_handler msg_handler[NBL_CHAN_MSG_MAX];
	enum nbl_chan_state state;
};

#endif
