/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Intel Corporation
 */

#include "rte_graph_worker_common.h"
#include "graph_private.h"

int
rte_graph_worker_model_set(uint32_t model)
{
	struct graph_head *graph_head = graph_list_head_get();
	struct graph *graph;

	if (graph_model_is_valid(model))
		return -EINVAL;

	STAILQ_FOREACH(graph, graph_head, next)
			graph->graph->model = model;

	return 0;
}
