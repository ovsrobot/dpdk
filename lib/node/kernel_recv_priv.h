/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef __INCLUDE_KERNEL_RECV_PRIV_H__
#define __INCLUDE_KERNEL_RECV_PRIV_H__

#define KERN_RECV_CACHE_COUNT 64

typedef struct kernel_recv_info {
	struct rte_mbuf *rx_bufs[KERN_RECV_CACHE_COUNT];
	uint16_t cls_next;
	uint16_t idx;
	uint16_t cnt;
	int sock;
} kernel_recv_info_t;

/**
 * @internal
 *
 * Kernel Recv node context structure.
 */
typedef struct kernel_recv_node_ctx {
	struct rte_mempool *pktmbuf_pool;
	kernel_recv_info_t *recv_info;
} kernel_recv_node_ctx_t;

/**
 * @internal
 *
 * Kernel Recv node list element structure.
 */
typedef struct kernel_recv_node_elem {
	struct kernel_recv_node_elem *next; /**< Pointer to the next node element. */
	struct kernel_recv_node_ctx ctx;    /**< Kernel Recv node context. */
	rte_node_t nid;			    /**< Node identifier of the Kernel Recv node. */
} kernel_recv_node_elem_t;

enum kernel_recv_next_nodes {
	KERNEL_RECV_NEXT_IP4_LOOKUP,
	KERNEL_RECV_NEXT_PKT_CLS,
	KERNEL_RECV_NEXT_MAX,
};

/**
 * @internal
 *
 * Kernel Recv node main structure.
 */
struct kernel_recv_node_main {
	kernel_recv_node_elem_t *head; /**< Pointer to the head node element. */
};

/**
 * @internal
 *
 * Get the Kernel Recv node data.
 *
 * @return
 *   Pointer to Kernel Recv node data.
 */
struct kernel_recv_node_main *kernel_recv_node_data_get(void);

/**
 * @internal
 *
 * Get the Kernel Recv node.
 *
 * @return
 *   Pointer to the Kernel Recv node.
 */
struct rte_node_register *kernel_recv_node_get(void);

#endif /* __INCLUDE_KERNEL_RECV_PRIV_H__ */
