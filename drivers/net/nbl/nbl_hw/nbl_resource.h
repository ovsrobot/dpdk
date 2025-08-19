/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_RESOURCE_H_
#define _NBL_RESOURCE_H_

#include "nbl_ethdev.h"
#include "nbl_include.h"
#include <stdint.h>

#define NBL_RES_MGT_TO_HW_OPS_TBL(res_mgt)	((res_mgt)->hw_ops_tbl)
#define NBL_RES_MGT_TO_HW_OPS(res_mgt)		(NBL_RES_MGT_TO_HW_OPS_TBL(res_mgt)->ops)
#define NBL_RES_MGT_TO_HW_PRIV(res_mgt)		(NBL_RES_MGT_TO_HW_OPS_TBL(res_mgt)->priv)
#define NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)	((res_mgt)->chan_ops_tbl)
#define NBL_RES_MGT_TO_CHAN_OPS(res_mgt)	(NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)->ops)
#define NBL_RES_MGT_TO_CHAN_PRIV(res_mgt)	(NBL_RES_MGT_TO_CHAN_OPS_TBL(res_mgt)->priv)
#define NBL_RES_MGT_TO_ETH_DEV(res_mgt)		((res_mgt)->eth_dev)
#define NBL_RES_MGT_TO_COMMON(res_mgt)		((res_mgt)->common)
#define NBL_RES_MGT_TO_TXRX_MGT(res_mgt)	((res_mgt)->txrx_mgt)
#define NBL_RES_MGT_TO_TX_RING(res_mgt, index)	\
	(NBL_RES_MGT_TO_TXRX_MGT(res_mgt)->tx_rings[(index)])
#define NBL_RES_MGT_TO_RX_RING(res_mgt, index)	\
	(NBL_RES_MGT_TO_TXRX_MGT(res_mgt)->rx_rings[(index)])

struct nbl_packed_desc {
	rte_le64_t addr;
	rte_le32_t len;
	rte_le16_t id;
	rte_le16_t flags;
};

struct nbl_tx_entry {
	struct rte_mbuf *mbuf;
	uint16_t first_id;
};

struct nbl_rx_entry {
	struct rte_mbuf *mbuf;
};

struct nbl_res_tx_ring {
	volatile struct nbl_packed_desc *desc;
	struct nbl_tx_entry *tx_entry;
	const struct rte_memzone *net_hdr_mz;
	volatile uint8_t *notify;
	const struct rte_eth_dev *eth_dev;
	struct nbl_common_info *common;
	u64 default_hdr[2];

	enum nbl_product_type product;
	int dma_limit_msb;
	bool dma_set_msb;
	u16 nb_desc;
	u16 next_to_clean;
	u16 next_to_use;

	u16 avail_used_flags;
	bool used_wrap_counter;
	u16 notify_qid;
	u16 exthdr_len;

	u16 vlan_proto;
	u16 vlan_tci;
	u16 lag_id;
	u16 vq_free_cnt;
	/* Start freeing TX buffers if there are less free descriptors than this value */
	u16 tx_free_thresh;
	/* Number of Tx descriptors to use before RS bit is set */
	u16 tx_rs_thresh;

	unsigned int size;

	u16 queue_id;

	u64 offloads;
	u64 ring_phys_addr;

	u16 (*prep_tx_ehdr)(void *priv, struct rte_mbuf *mbuf);
};

struct nbl_res_rx_ring {
	volatile struct nbl_packed_desc *desc;
	struct nbl_rx_entry *rx_entry;
	struct rte_mempool *mempool;
	volatile uint8_t *notify;
	const struct rte_eth_dev *eth_dev;
	struct nbl_common_info *common;
	uint64_t mbuf_initializer; /**< value to init mbufs */
	struct rte_mbuf fake_mbuf;

	enum nbl_product_type product;
	int dma_limit_msb;
	unsigned int size;
	bool dma_set_msb;
	u16 nb_desc;
	u16 next_to_clean;
	u16 next_to_use;

	u16 avail_used_flags;
	bool used_wrap_counter;
	u16 notify_qid;
	u16 exthdr_len;

	u16 vlan_proto;
	u16 vlan_tci;
	u16 vq_free_cnt;
	u16 port_id;

	u16 queue_id;
	u16 buf_length;

	u64 offloads;
	u64 ring_phys_addr;
};

struct nbl_txrx_mgt {
	rte_spinlock_t tx_lock;
	struct nbl_res_tx_ring **tx_rings;
	struct nbl_res_rx_ring **rx_rings;
	u16 queue_offset;
	u8 tx_ring_num;
	u8 rx_ring_num;
};

struct nbl_res_info {
	u16 base_qid;
	u16 lcore_max;
	u16 *pf_qid_to_lcore_id;
	rte_atomic16_t tx_current_queue;
};

struct nbl_resource_mgt {
	const struct rte_eth_dev *eth_dev;
	struct nbl_channel_ops_tbl *chan_ops_tbl;
	struct nbl_hw_ops_tbl *hw_ops_tbl;
	struct nbl_txrx_mgt *txrx_mgt;
	struct nbl_common_info *common;
	struct nbl_res_info res_info;
};

struct nbl_resource_mgt_leonis {
	struct nbl_resource_mgt res_mgt;
};

int nbl_txrx_mgt_start(struct nbl_resource_mgt *res_mgt);
void nbl_txrx_mgt_stop(struct nbl_resource_mgt *res_mgt);
int nbl_txrx_setup_ops(struct nbl_resource_ops *resource_ops);
void nbl_txrx_remove_ops(struct nbl_resource_ops *resource_ops);

#endif
