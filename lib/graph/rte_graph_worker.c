/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Intel Corporation
 */

/**
 * @file graph_worker.c
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * These API enable to set/get graph walking model.
 *
 */

#include "rte_graph_worker_common.h"
#include "graph_private.h"

/**
 * @note This function does not perform any locking, and is only safe to call
 *    before graph running. It will set all graphs the same model.
 *
 * @param name
 *   Name of the graph worker model.
 *
 * @return
 *   0 on success, -1 otherwise.
 */
int
rte_graph_worker_model_set(enum rte_graph_worker_model model)
{
	struct graph_head *graph_head = graph_list_head_get();
	struct graph *graph;
	int ret = 0;

	if (model == RTE_GRAPH_MODEL_DEFAULT || model == RTE_GRAPH_MODEL_RTC ||
	    model == RTE_GRAPH_MODEL_MCORE_DISPATCH)
		STAILQ_FOREACH(graph, graph_head, next)
			graph->graph->model = model;
	else {
		STAILQ_FOREACH(graph, graph_head, next)
			graph->graph->model = RTE_GRAPH_MODEL_DEFAULT;
		ret = -1;
		}

	return ret;
}

/**
 * Get the graph worker model
 *
 * @note All graph will use the same model and this function will get model from the first one
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
	struct graph_head *graph_head = graph_list_head_get();
	struct graph *graph;

	graph = STAILQ_FIRST(graph_head);

	return graph->graph->model;
}
