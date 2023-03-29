/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Intel Corporation
 */

#include "rte_graph_worker_common.h"

RTE_DEFINE_PER_LCORE(enum rte_graph_worker_model, worker_model) = RTE_GRAPH_MODEL_DEFAULT;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 * Set the graph worker model
 *
 * @note This function does not perform any locking, and is only safe to call
 *    before graph running.
 *
 * @param name
 *   Name of the graph worker model.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
inline int
rte_graph_worker_model_set(enum rte_graph_worker_model model)
{
	if (model >= RTE_GRAPH_MODEL_LIST_END)
		goto fail;

	RTE_PER_LCORE(worker_model) = model;
	return 0;

fail:
	RTE_PER_LCORE(worker_model) = RTE_GRAPH_MODEL_DEFAULT;
	return -1;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the graph worker model
 *
 * @param name
 *   Name of the graph worker model.
 *
 * @return
 *   Graph worker model on success.
 */
inline
enum rte_graph_worker_model
rte_graph_worker_model_get(void)
{
	return RTE_PER_LCORE(worker_model);
}
