/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */
#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>
#include <rte_node_mbuf_dynfield.h>
#include <node_private.h>

#define NODE_MBUF_DYNFIELD_MEMZONE_NAME "__rte_node_mbuf_dynfield"

struct node_mbuf_dynfield_mz {
	int dynfield_offset;
};

static const struct rte_mbuf_dynfield node_mbuf_dynfield_desc = {
	.name = "rte_node_mbuf_dynfield",
	.size = sizeof(rte_node_mbuf_dynfield_t),
	.align = alignof(rte_node_mbuf_dynfield_t),
};

int node_mbuf_dynfield_offset = -1;

int rte_node_mbuf_dynfield_register(void)
{
	int dyn_offset;

	RTE_BUILD_BUG_ON(sizeof(rte_node_mbuf_dynfield_t) < RTE_NODE_MBUF_DYNFIELD_SIZE);
	RTE_BUILD_BUG_ON(sizeof(rte_node_mbuf_overload_fields_t) <
			 RTE_NODE_MBUF_OVERLOADABLE_FIELDS_SIZE);

	if (node_mbuf_dynfield_offset == -1) {
		dyn_offset = rte_mbuf_dynfield_register(&node_mbuf_dynfield_desc);
		if (dyn_offset < 0) {
			node_err("node_mbuf_dyn", "rte_mbuf_dynfield_register failed");
			return -1;
		}
		node_mbuf_dynfield_offset = dyn_offset;

		node_dbg("node_mbuf_dyn", "node mbuf dynfield size %zu at offset: %d",
			  sizeof(rte_node_mbuf_dynfield_t), node_mbuf_dynfield_offset);
	} else {
		dyn_offset = node_mbuf_dynfield_offset;
	}
	return dyn_offset;
}
