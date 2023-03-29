/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Intel Corporation
 */

#ifndef _RTE_GRAPH_MODEL_DISPATCH_H_
#define _RTE_GRAPH_MODEL_DISPATCH_H_

/**
 * @file rte_graph_model_dispatch.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * This API allows to set core affinity with the node.
 */
#include <rte_errno.h>
#include <rte_mempool.h>
#include <rte_memzone.h>
#include <rte_ring.h>

#include "rte_graph_worker_common.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GRAPH_SCHED_WQ_SIZE_MULTIPLIER  8
#define GRAPH_SCHED_WQ_SIZE(nb_nodes)   \
	((typeof(nb_nodes))((nb_nodes) * GRAPH_SCHED_WQ_SIZE_MULTIPLIER))

/**
 * @internal
 *
 * Schedule the node to the right graph's work queue.
 *
 * @param node
 *   Pointer to the scheduled node object.
 * @param rq
 *   Pointer to the scheduled run-queue for all graphs.
 *
 * @return
 *   True on success, false otherwise.
 */
bool __rte_graph_sched_node_enqueue(struct rte_node *node,
				    struct rte_graph_rq_head *rq);

/**
 * @internal
 *
 * Process all nodes (streams) in the graph's work queue.
 *
 * @param graph
 *   Pointer to the graph object.
 */
void __rte_noinline __rte_graph_sched_wq_process(struct rte_graph *graph);

/**
 * Set lcore affinity with the node.
 *
 * @param name
 *   Valid node name. In the case of the cloned node, the name will be
 * "parent node name" + "-" + name.
 * @param lcore_id
 *   The lcore ID value.
 *
 * @return
 *   0 on success, error otherwise.
 */
__rte_experimental
int rte_graph_model_dispatch_lcore_affinity_set(const char *name,
						unsigned int lcore_id);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_GRAPH_MODEL_DISPATCH_H_ */
