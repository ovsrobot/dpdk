/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell.
 */

#include <arpa/inet.h>

#include <eal_export.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_fib.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>

#include "rte_node_ip4_api.h"

#include "node_private.h"

/* IP4 Lookup global data struct */
struct ip4_lookup_fib_node_main {
	struct rte_fib *fib[RTE_MAX_NUMA_NODES];
};

struct ip4_lookup_fib_node_ctx {
	/* Socket's FIB */
	struct rte_fib *fib;
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
};

static struct ip4_lookup_fib_node_main ip4_lookup_fib_nm;

#define FIB_MAX_ROUTES (1 << 16)
#define FIB_NUM_TBL8   (1 << 15)
#define FIB_DEFAULT_NH 999

#define IP4_LOOKUP_NODE_FIB(ctx) \
	(((struct ip4_lookup_fib_node_ctx *)ctx)->fib)

#define IP4_LOOKUP_NODE_PRIV1_OFF(ctx) \
	(((struct ip4_lookup_fib_node_ctx *)ctx)->mbuf_priv1_off)

static uint16_t
ip4_lookup_fib_node_process(struct rte_graph *graph, struct rte_node *node, void **objs,
			    uint16_t nb_objs)
{
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	struct rte_fib *fib = IP4_LOOKUP_NODE_FIB(node->ctx);
	const int dyn = IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx);
	struct rte_ipv4_hdr *ipv4_hdr;
	uint64_t next_hop[nb_objs];
	uint16_t lookup_err = 0;
	void **to_next, **from;
	uint16_t last_spec = 0;
	rte_edge_t next_index;
	uint16_t n_left_from;
	uint32_t ip[nb_objs];
	uint16_t held = 0;
	uint32_t drop_nh;
	uint16_t next;
	int i, rc;

	/* Speculative next */
	next_index = RTE_NODE_IP4_LOOKUP_NEXT_REWRITE;
	/* Drop node */
	drop_nh = ((uint32_t)RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP) << 16;

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);

	for (i = OBJS_PER_CLINE; i < RTE_GRAPH_BURST_SIZE; i += OBJS_PER_CLINE)
		rte_prefetch0(&objs[i]);

#if RTE_GRAPH_BURST_SIZE > 64
	for (i = 0; i < 4 && i < n_left_from; i++) {
		rte_prefetch0(pkts[i]);
		rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[i], void *,
					sizeof(struct rte_ether_hdr)));
	}
#endif

	i = 0;
	while (n_left_from >= 4) {
#if RTE_GRAPH_BURST_SIZE > 64
		if (likely(n_left_from > 7)) {
			rte_prefetch0(pkts[4]);
			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[4], void *,
					sizeof(struct rte_ether_hdr)));
			rte_prefetch0(pkts[5]);
			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[5], void *,
					sizeof(struct rte_ether_hdr)));
			rte_prefetch0(pkts[6]);
			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[6], void *,
					sizeof(struct rte_ether_hdr)));
			rte_prefetch0(pkts[7]);
			rte_prefetch0(rte_pktmbuf_mtod_offset(pkts[7], void *,
					sizeof(struct rte_ether_hdr)));
		}
#endif

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];
		pkts += 4;
		n_left_from -= 4;
		/* Extract DIP of mbuf0 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf0, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		node_mbuf_priv1(mbuf0, dyn)->cksum = ipv4_hdr->hdr_checksum;
		node_mbuf_priv1(mbuf0, dyn)->ttl = ipv4_hdr->time_to_live;

		ip[i++] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		/* Extract DIP of mbuf1 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf1, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		node_mbuf_priv1(mbuf1, dyn)->cksum = ipv4_hdr->hdr_checksum;
		node_mbuf_priv1(mbuf1, dyn)->ttl = ipv4_hdr->time_to_live;

		ip[i++] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		/* Extract DIP of mbuf2 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf2, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		node_mbuf_priv1(mbuf2, dyn)->cksum = ipv4_hdr->hdr_checksum;
		node_mbuf_priv1(mbuf2, dyn)->ttl = ipv4_hdr->time_to_live;

		ip[i++] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);

		/* Extract DIP of mbuf3 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf3, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));

		/* Extract cksum, ttl as ipv4 hdr is in cache */
		node_mbuf_priv1(mbuf3, dyn)->cksum = ipv4_hdr->hdr_checksum;
		node_mbuf_priv1(mbuf3, dyn)->ttl = ipv4_hdr->time_to_live;

		ip[i++] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	}
	while (n_left_from > 0) {
		mbuf0 = pkts[0];
		pkts += 1;
		n_left_from -= 1;

		/* Extract DIP of mbuf0 */
		ipv4_hdr = rte_pktmbuf_mtod_offset(mbuf0, struct rte_ipv4_hdr *,
				sizeof(struct rte_ether_hdr));
		/* Extract cksum, ttl as ipv4 hdr is in cache */
		node_mbuf_priv1(mbuf0, dyn)->cksum = ipv4_hdr->hdr_checksum;
		node_mbuf_priv1(mbuf0, dyn)->ttl = ipv4_hdr->time_to_live;

		ip[i++] = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	}

	rc = rte_fib_lookup_bulk(fib, ip, next_hop, nb_objs);
	if (unlikely(rc != 0))
		return 0;

	for (i = 0; i < nb_objs; i++) {
		if (unlikely(next_hop[i] == FIB_DEFAULT_NH)) {
			next_hop[i] = drop_nh;
			lookup_err += 1;
		}

		mbuf0 = (struct rte_mbuf *)objs[i];
		node_mbuf_priv1(mbuf0, dyn)->nh = (uint16_t)next_hop[i];
		next = (uint16_t)(next_hop[i] >> 16);

		if (unlikely(next_index ^ next)) {
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

	NODE_INCREMENT_XSTAT_ID(node, 0, lookup_err != 0, lookup_err);
	held += last_spec;
	rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
	rte_node_next_stream_put(graph, node, next_index, held);

	return nb_objs;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_node_ip4_fib_route_add, 25.07)
int
rte_node_ip4_fib_route_add(uint32_t ip, uint8_t depth, uint16_t next_hop,
			   enum rte_node_ip4_lookup_next next_node)
{
	char abuf[INET6_ADDRSTRLEN];
	struct in_addr in;
	uint8_t socket;
	uint32_t val;
	int ret;

	in.s_addr = htonl(ip);
	inet_ntop(AF_INET, &in, abuf, sizeof(abuf));
	/* Embedded next node id into 24 bit next hop */
	val = ((next_node << 16) | next_hop) & ((1ull << 24) - 1);
	node_dbg("ip4_lookup_fib", "FIB: Adding route %s / %d nh (0x%x)", abuf, depth, val);

	for (socket = 0; socket < RTE_MAX_NUMA_NODES; socket++) {
		if (!ip4_lookup_fib_nm.fib[socket])
			continue;

		ret = rte_fib_add(ip4_lookup_fib_nm.fib[socket], ip, depth, val);
		if (ret < 0) {
			node_err("ip4_lookup_fib",
				 "Unable to add entry %s / %d nh (%x) to FIB on sock %d, rc=%d",
				 abuf, depth, val, socket, ret);
			return ret;
		}
	}

	return 0;
}

static int
setup_fib(unsigned int socket)
{
	struct ip4_lookup_fib_node_main *nm = &ip4_lookup_fib_nm;
	struct rte_fib_conf conf;
	char s[RTE_FIB_NAMESIZE];

	/* One fib per socket */
	if (nm->fib[socket])
		return 0;

	conf.type = RTE_FIB_DIR24_8;
	conf.default_nh = FIB_DEFAULT_NH;
	conf.max_routes = FIB_MAX_ROUTES;
	conf.rib_ext_sz = 0;
	conf.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	conf.dir24_8.num_tbl8 = FIB_NUM_TBL8;
	conf.flags = 0;
	snprintf(s, sizeof(s), "IPV4_LOOKUP_FIB_%d", socket);
	nm->fib[socket] = rte_fib_create(s, socket, &conf);
	if (nm->fib[socket] == NULL)
		return -rte_errno;

	return 0;
}

static int
ip4_lookup_fib_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	static uint8_t init_once;
	unsigned int socket;
	uint16_t lcore_id;
	int rc;

	RTE_BUILD_BUG_ON(sizeof(struct ip4_lookup_fib_node_ctx) > RTE_NODE_CTX_SZ);

	if (!init_once) {
		node_mbuf_priv1_dynfield_offset = rte_mbuf_dynfield_register(
				&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_offset < 0)
			return -rte_errno;

		/* Setup FIB for all sockets */
		RTE_LCORE_FOREACH(lcore_id)
		{
			socket = rte_lcore_to_socket_id(lcore_id);
			rc = setup_fib(socket);
			if (rc) {
				node_err("ip4_lookup_fib",
					 "Failed to setup fib for sock %u, rc=%d",
					 socket, rc);
				return rc;
			}
		}
		init_once = 1;
	}

	/* Update socket's FIB and mbuf dyn priv1 offset in node ctx */
	IP4_LOOKUP_NODE_FIB(node->ctx) = ip4_lookup_fib_nm.fib[graph->socket];
	IP4_LOOKUP_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;

	node_dbg("ip4_lookup_fib", "Initialized ip4_lookup_fib node");

	return 0;
}

static struct rte_node_xstats ip4_lookup_fib_xstats = {
	.nb_xstats = 1,
	.xstat_desc = {
		[0] = "ip4_lookup_fib_error",
	},
};

static struct rte_node_register ip4_lookup_fib_node = {
	.process = ip4_lookup_fib_node_process,
	.name = "ip4_lookup_fib",

	.init = ip4_lookup_fib_node_init,
	.xstats = &ip4_lookup_fib_xstats,

	.nb_edges = RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP + 1,
	.next_nodes = {
		[RTE_NODE_IP4_LOOKUP_NEXT_IP4_LOCAL] = "ip4_local",
		[RTE_NODE_IP4_LOOKUP_NEXT_REWRITE] = "ip4_rewrite",
		[RTE_NODE_IP4_LOOKUP_NEXT_PKT_DROP] = "pkt_drop",
	},
};

RTE_NODE_REGISTER(ip4_lookup_fib_node);
