/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#ifndef __INCLUDE_PUNT_KERNEL_PRIV_H__
#define __INCLUDE_PUNT_KERNEL_PRIV_H__

struct punt_kernel_node_elem;
struct punt_kernel_node_ctx;
typedef struct punt_kernel_node_elem punt_kernel_node_elem_t;

/**
 * @internal
 *
 * PUNT Kernel node context structure.
 */
typedef struct punt_kernel_node_ctx {
	int sock;
} punt_kernel_node_ctx_t;

enum punt_kernel_next_nodes {
	PUNT_KERNEL_NEXT_PKT_DROP,
	PUNT_KERNEL_NEXT_MAX,
};

/**
 * @internal
 *
 * Get the PUNT Kernel node.
 *
 * @return
 *   Pointer to the PUNT Kernel node.
 */
struct rte_node_register *punt_kernel_node_get(void);

#endif /* __INCLUDE_PUNT_KERNEL_PRIV_H__ */
