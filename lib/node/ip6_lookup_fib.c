/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib6.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include "rte_node_ip6_api.h"

#include "node_private.h"

/* IP6 Lookup FIB global data struct */
struct ip6_lookup_fib_node_main {
	struct rte_fib6 *fib6[RTE_MAX_NUMA_NODES];
};

struct ip6_lookup_fib_node_ctx {
	/* Socket's FIB6 */
	struct rte_fib6 *fib6;
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
};

static struct ip6_lookup_fib_node_main ip6_lookup_fib_nm;

#define FIB6_MAX_ROUTES (1 << 16)
#define FIB6_NUM_TBL8   (1 << 15)
#define FIB6_DEFAULT_NH 999

#define IP6_LOOKUP_FIB_NODE(ctx) \
	(((struct ip6_lookup_fib_node_ctx *)ctx)->fib6)

#define IP6_LOOKUP_FIB_NODE_PRIV1_OFF(ctx) \
	(((struct ip6_lookup_fib_node_ctx *)ctx)->mbuf_priv1_off)

static int
setup_fib6(unsigned int socket)
{
	struct ip6_lookup_fib_node_main *nm = &ip6_lookup_fib_nm;
	struct rte_fib6_conf conf;
	char s[RTE_FIB6_NAMESIZE];

	/* One fib6 per socket */
	if (nm->fib6[socket])
		return 0;

	conf.type = RTE_FIB6_TRIE;
	conf.default_nh = FIB6_DEFAULT_NH;
	conf.max_routes = FIB6_MAX_ROUTES;
	conf.rib_ext_sz = 0;
	conf.trie.nh_sz = RTE_FIB6_TRIE_4B;
	conf.trie.num_tbl8 = FIB6_NUM_TBL8;
	snprintf(s, sizeof(s), "IPV6_LOOKUP_FIB_%u", socket);
	nm->fib6[socket] = rte_fib6_create(s, socket, &conf);
	if (nm->fib6[socket] == NULL)
		return -rte_errno;

	return 0;
}

static int
ip6_lookup_fib_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	static uint8_t init_once;
	unsigned int socket;
	uint16_t lcore_id;
	int rc;

	RTE_BUILD_BUG_ON(sizeof(struct ip6_lookup_fib_node_ctx) > RTE_NODE_CTX_SZ);

	if (!init_once) {
		node_mbuf_priv1_dynfield_offset = rte_mbuf_dynfield_register(
				&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_offset < 0)
			return -rte_errno;

		/* Setup FIB6 for all sockets */
		RTE_LCORE_FOREACH(lcore_id)
		{
			socket = rte_lcore_to_socket_id(lcore_id);
			rc = setup_fib6(socket);
			if (rc) {
				node_err("ip6_lookup_fib",
					 "Failed to setup fib6 for sock %u, rc=%d", socket, rc);
				return rc;
			}
		}
		init_once = 1;
	}

	/* Update socket's FIB and mbuf dyn priv1 offset in node ctx */
	IP6_LOOKUP_FIB_NODE(node->ctx) = ip6_lookup_fib_nm.fib6[graph->socket];
	IP6_LOOKUP_FIB_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;

	node_dbg("ip6_lookup_fib", "Initialized ip6_lookup_fib node");

	return 0;
}

static struct rte_node_xstats ip6_lookup_fib_xstats = {
	.nb_xstats = 1,
	.xstat_desc = {
		[0] = "ip6_lookup_fib_error",
	},
};

static struct rte_node_register ip6_lookup_fib_node = {
	.name = "ip6_lookup_fib",

	.init = ip6_lookup_fib_node_init,
	.xstats = &ip6_lookup_fib_xstats,

	.nb_edges = RTE_NODE_IP6_LOOKUP_NEXT_PKT_DROP + 1,
	.next_nodes = {
		[RTE_NODE_IP6_LOOKUP_NEXT_REWRITE] = "ip6_rewrite",
		[RTE_NODE_IP6_LOOKUP_NEXT_PKT_DROP] = "pkt_drop",
	},
};

RTE_NODE_REGISTER(ip6_lookup_fib_node);
