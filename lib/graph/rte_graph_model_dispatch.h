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
#include "rte_graph_worker_common.h"

#ifdef __cplusplus
extern "C" {
#endif

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
