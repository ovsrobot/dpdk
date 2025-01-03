/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#include <arpa/inet.h>
#include <sys/socket.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph_feature_arc_worker.h>
#include <rte_malloc.h>

#include "rte_node_ip4_api.h"
#include "node_private.h"
#include "interface_tx_feature_priv.h"

#define IF_TX_FEATURE_LAST_NEXT_INDEX(ctx) \
	(((struct if_tx_feature_node_ctx *)ctx)->last_index)
/*
 * @internal array for mapping port to next node index
 */
struct if_tx_feature_node_main  {
	uint16_t next_index[RTE_MAX_ETHPORTS];
};

struct if_tx_feature_node_ctx {
	uint16_t last_index;
};

static struct if_tx_feature_node_main *if_tx_feature_nm;

int
if_tx_feature_node_set_next(uint16_t port_id, uint16_t next_index)
{
	if (if_tx_feature_nm == NULL) {
		if_tx_feature_nm = rte_zmalloc(
			"if_tx_feature_nm", sizeof(struct if_tx_feature_node_main),
			RTE_CACHE_LINE_SIZE);
		if (if_tx_feature_nm == NULL)
			return -ENOMEM;
	}
	if_tx_feature_nm->next_index[port_id] = next_index;

	return 0;
}

static int
if_tx_feature_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	RTE_SET_USED(graph);

	/* pkt_drop */
	IF_TX_FEATURE_LAST_NEXT_INDEX(node->ctx) = 0;

	return 0;
}

static uint16_t
if_tx_feature_node_process(struct rte_graph *graph, struct rte_node *node,
			   void **objs, uint16_t nb_objs)
{
	uint16_t held = 0, next;
	void **to_next, **from;
	uint16_t last_spec = 0;
	rte_edge_t next_index;
	struct rte_mbuf *mbuf;
	int i;

	/* Speculative next */
	next_index = IF_TX_FEATURE_LAST_NEXT_INDEX(node->ctx);

	from = objs;
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	for (i = 0; i < nb_objs; i++) {

		mbuf = (struct rte_mbuf *)objs[i];

		/* port-tx node starts from next edge 1*/
		next = if_tx_feature_nm->next_index[mbuf->port];

		if (unlikely(next_index != next)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}
	/* !!! Home run !!! */
	if (likely(last_spec == nb_objs)) {
		rte_node_next_stream_move(graph, node, next_index);
		return nb_objs;
	}
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	IF_TX_FEATURE_LAST_NEXT_INDEX(node->ctx) = next;

	return nb_objs;
}

static struct rte_node_register if_tx_feature_node = {
	.process = if_tx_feature_node_process,
	.init = if_tx_feature_node_init,
	.name = "interface_tx",
	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
};

struct rte_node_register *
if_tx_feature_node_get(void)
{
	return &if_tx_feature_node;
}

RTE_NODE_REGISTER(if_tx_feature_node);

/* if_tx feature node */
struct rte_graph_feature_register if_tx_feature = {
	.feature_name = RTE_IP4_OUTPUT_END_FEATURE_NAME,
	.arc_name = RTE_IP4_OUTPUT_FEATURE_ARC_NAME,
	.feature_process_fn = if_tx_feature_node_process,
	.feature_node = &if_tx_feature_node,
};
