/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 * Copyright(C) 2023 Intel Corporation
 */

#ifndef _RTE_GRAPH_WORKER_H_
#define _RTE_GRAPH_WORKER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "rte_graph_model_rtc.h"
#include "rte_graph_model_dispatch.h"

/**
 * Perform graph walk on the circular buffer and invoke the process function
 * of the nodes and collect the stats.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup function.
 *
 * @see rte_graph_lookup()
 */
__rte_experimental
static inline void
rte_graph_walk(struct rte_graph *graph)
{
	int model = rte_graph_worker_model_get();

	if (model == RTE_GRAPH_MODEL_DEFAULT ||
	    model == RTE_GRAPH_MODEL_RTC)
		rte_graph_walk_rtc(graph);
	else if (model == RTE_GRAPH_MODEL_MCORE_DISPATCH)
		rte_graph_walk_mcore_dispatch(graph);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_GRAPH_WORKER_H_ */
