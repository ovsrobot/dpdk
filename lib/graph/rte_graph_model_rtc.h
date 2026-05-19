/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 * Copyright(C) 2023 Intel Corporation
 */

#include "rte_graph_worker_common.h"

/**
 * Perform graph walk on the pending bitmap and invoke the process function
 * of the nodes and collect the stats.
 *
 * Nodes are visited in scheduling order (lowest priority value first).
 * Source nodes are seeded into the pending bitmap at the start of each walk.
 *
 * @param graph
 *   Graph pointer returned from rte_graph_lookup function.
 *
 * @see rte_graph_lookup()
 */
static inline void
rte_graph_walk_rtc(struct rte_graph *graph)
{
	const uint16_t nwords = graph->nb_sched_words;
	struct rte_node *node;
	uint16_t word, bit;

	/*
	 * Nodes are assigned a bit position (sched_idx) sorted by (priority,
	 * node_id) at graph creation time. Source nodes are forced to INT16_MIN
	 * priority so they always come first.
	 *
	 * sched_table[] maps bit positions to node offsets:
	 *
	 *   pending[]         sched_table[]
	 *   +----------+      +------------------+
	 *   | word 0   | ---> | src_node_0       | bit 0 (prio=INT16_MIN)
	 *   | 1100...1 |      | src_node_1       | bit 1 (prio=INT16_MIN)
	 *   |          |      | mpls_input       | bit 2 (prio=-10)
	 *   |          |      | ipv4_input       | bit 3 (prio=0)
	 *   |          |      | ...              |
	 *   +----------+      +------------------+
	 *   | word 1   | ---> | ip4_rewrite      | bit 64 (prio=10)
	 *   | ...      |      | ...              |
	 *   +----------+      +------------------+
	 *
	 * Walk: for each word, find lowest set bit (rte_ctz64), process that
	 * node, clear the bit, re-read the word (processing may have set new
	 * bits), repeat.
	 *
	 * After each node is processed, restart scanning from word 0 since
	 * processing may set bits in any word, including earlier ones.
	 */

	/* Seed pending bitmap with source nodes */
	for (word = 0; word < nwords; word++)
		graph->pending[word] |= graph->src_pending[word];

	for (;;) {
		/* find first word with any pending bit */
		for (word = 0; word < nwords; word++)
			if (graph->pending[word])
				break;
		if (word == nwords)
			break; /* no more pending nodes */

		bit = rte_ctz64(graph->pending[word]);
		graph->pending[word] &= ~(1ULL << bit);
		node = __rte_graph_pending_node(graph, word, bit);
		__rte_node_process(graph, node);
	}
}
