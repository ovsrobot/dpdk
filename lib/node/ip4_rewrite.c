/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_vect.h>

#include "rte_node_ip4_api.h"

#include "ip4_rewrite_priv.h"
#include "node_private.h"

struct ip4_rewrite_node_ctx {
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
	/* Cached next index */
	uint16_t next_index;
	rte_graph_feature_arc_t output_feature_arc;
};

static struct ip4_rewrite_node_main *ip4_rewrite_nm;

#define IP4_REWRITE_NODE_LAST_NEXT(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->next_index)

#define IP4_REWRITE_NODE_PRIV1_OFF(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->mbuf_priv1_off)

#define IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->output_feature_arc)

static uint16_t
ip4_rewrite_node_process(struct rte_graph *graph, struct rte_node *node,
			 void **objs, uint16_t nb_objs)
{
	rte_graph_feature_arc_t out_feature_arc = IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(node->ctx);
	uint16_t next0 = 0, next1 = 0, next2 = 0, next3 = 0, next_index;
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	struct ip4_rewrite_nh_header *nh = ip4_rewrite_nm->nh;
	const int dyn = IP4_REWRITE_NODE_PRIV1_OFF(node->ctx);
	uint16_t n_left_from, held = 0, last_spec = 0;
	struct rte_ipv4_hdr *ip0, *ip1, *ip2, *ip3;
	int b0_feat, b1_feat, b2_feat, b3_feat;
	rte_graph_feature_t f0, f1, f2, f3;
	uint16_t tx0, tx1, tx2, tx3;
	int64_t fd0, fd1, fd2, fd3;
	void *d0, *d1, *d2, *d3;
	void **to_next, **from;
	rte_xmm_t priv01;
	rte_xmm_t priv23;
	int i, has_feat;

	RTE_SET_USED(fd0);
	RTE_SET_USED(fd1);
	RTE_SET_USED(fd2);
	RTE_SET_USED(fd3);

	/* Speculative next as last next */
	next_index = IP4_REWRITE_NODE_LAST_NEXT(node->ctx);
	rte_prefetch0(nh);

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = 0; i < 4 && i < n_left_from; i++)
		rte_prefetch0(pkts[i]);

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);
	/* Update Ethernet header of pkts */
	while (n_left_from >= 4) {
		if (likely(n_left_from > 7)) {
			/* Prefetch only next-mbuf struct and priv area.
			 * Data need not be prefetched as we only write.
			 */
			rte_prefetch0(pkts[4]);
			rte_prefetch0(pkts[5]);
			rte_prefetch0(pkts[6]);
			rte_prefetch0(pkts[7]);
		}

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];

		pkts += 4;
		n_left_from -= 4;
		priv01.u64[0] = node_mbuf_priv1(mbuf0, dyn)->u;
		priv01.u64[1] = node_mbuf_priv1(mbuf1, dyn)->u;
		priv23.u64[0] = node_mbuf_priv1(mbuf2, dyn)->u;
		priv23.u64[1] = node_mbuf_priv1(mbuf3, dyn)->u;

		f0 = nh[priv01.u16[0]].nh_feature;
		f1 = nh[priv01.u16[4]].nh_feature;
		f2 = nh[priv23.u16[0]].nh_feature;
		f3 = nh[priv23.u16[4]].nh_feature;

		tx0 = nh[priv01.u16[0]].tx_node - 1;
		tx1 = nh[priv01.u16[4]].tx_node - 1;
		tx2 = nh[priv23.u16[0]].tx_node - 1;
		tx3 = nh[priv23.u16[4]].tx_node - 1;

		b0_feat = rte_graph_feature_arc_has_feature(out_feature_arc, tx0, &f0);
		b1_feat = rte_graph_feature_arc_has_feature(out_feature_arc, tx1, &f1);
		b2_feat = rte_graph_feature_arc_has_feature(out_feature_arc, tx2, &f2);
		b3_feat = rte_graph_feature_arc_has_feature(out_feature_arc, tx3, &f3);

		has_feat = b0_feat | b1_feat | b2_feat | b3_feat;

		if (unlikely(has_feat)) {
			/* prefetch feature data */
			rte_graph_feature_data_prefetch(out_feature_arc, tx0, f0);
			rte_graph_feature_data_prefetch(out_feature_arc, tx1, f1);
			rte_graph_feature_data_prefetch(out_feature_arc, tx2, f2);
			rte_graph_feature_data_prefetch(out_feature_arc, tx3, f3);

			/* Save feature into mbuf */
			node_mbuf_priv1(mbuf0, dyn)->current_feature = f0;
			node_mbuf_priv1(mbuf1, dyn)->current_feature = f1;
			node_mbuf_priv1(mbuf2, dyn)->current_feature = f2;
			node_mbuf_priv1(mbuf3, dyn)->current_feature = f3;

			/* Save index into mbuf for next feature node */
			node_mbuf_priv1(mbuf0, dyn)->index = tx0;
			node_mbuf_priv1(mbuf1, dyn)->index = tx1;
			node_mbuf_priv1(mbuf2, dyn)->index = tx2;
			node_mbuf_priv1(mbuf3, dyn)->index = tx3;

			/* Does all of them have feature enabled */
			has_feat = b0_feat && b1_feat && b2_feat && b3_feat;
			if (has_feat) {
				rte_graph_feature_arc_feature_data_get(out_feature_arc,
								       f0, tx0, &next0, &fd0);
				rte_graph_feature_arc_feature_data_get(out_feature_arc,
								       f1, tx1, &next1, &fd1);
				rte_graph_feature_arc_feature_data_get(out_feature_arc,
								       f2, tx2, &next2, &fd2);
				rte_graph_feature_arc_feature_data_get(out_feature_arc,
								       f3, tx3, &next3, &fd3);
			} else {
				if (b0_feat) {
					rte_graph_feature_arc_feature_data_get(out_feature_arc, f0,
									       tx0, &next0, &fd0);
				} else {
					priv01.u32[1] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf0 */
					d0 = rte_pktmbuf_mtod(mbuf0, void *);
					rte_memcpy(d0, nh[priv01.u16[0]].rewrite_data,
						   nh[priv01.u16[0]].rewrite_len);

					next0 = tx0 + 1;
					ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
								      sizeof(struct rte_ether_hdr));
					ip0->time_to_live = priv01.u16[1] - 1;
					ip0->hdr_checksum = priv01.u16[2] + priv01.u16[3];
				}
				if (b1_feat) {
					rte_graph_feature_arc_feature_data_get(out_feature_arc, f1,
									       tx1, &next1, &fd1);
				} else {
					priv01.u32[3] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf1 */
					d1 = rte_pktmbuf_mtod(mbuf1, void *);
					rte_memcpy(d1, nh[priv01.u16[4]].rewrite_data,
						   nh[priv01.u16[4]].rewrite_len);

					next1 = tx1 + 1;
					ip1 = (struct rte_ipv4_hdr *)((uint8_t *)d1 +
								      sizeof(struct rte_ether_hdr));
					ip1->time_to_live = priv01.u16[5] - 1;
					ip1->hdr_checksum = priv01.u16[6] + priv01.u16[7];
				}
				if (b2_feat) {
					rte_graph_feature_arc_feature_data_get(out_feature_arc, f2,
									       tx2, &next2, &fd2);
				} else {
					priv23.u32[1] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf2 */
					d2 = rte_pktmbuf_mtod(mbuf2, void *);
					rte_memcpy(d2, nh[priv23.u16[0]].rewrite_data,
						   nh[priv23.u16[0]].rewrite_len);
					next2 = tx2 + 1;
					ip2 = (struct rte_ipv4_hdr *)((uint8_t *)d2 +
								      sizeof(struct rte_ether_hdr));
					ip2->time_to_live = priv23.u16[1] - 1;
					ip2->hdr_checksum = priv23.u16[2] + priv23.u16[3];
				}
				if (b3_feat) {
					rte_graph_feature_arc_feature_data_get(out_feature_arc, f3,
									       tx3, &next1, &fd3);
				} else {
					priv23.u32[3] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf3 */
					d3 = rte_pktmbuf_mtod(mbuf3, void *);
					rte_memcpy(d3, nh[priv23.u16[4]].rewrite_data,
						   nh[priv23.u16[4]].rewrite_len);
					next3 = tx3 + 1;
					ip3 = (struct rte_ipv4_hdr *)((uint8_t *)d3 +
								      sizeof(struct rte_ether_hdr));
					ip3->time_to_live = priv23.u16[5] - 1;
					ip3->hdr_checksum = priv23.u16[6] + priv23.u16[7];
				}
			}
		} else {
			/* Increment checksum by one. */
			priv01.u32[1] += rte_cpu_to_be_16(0x0100);
			priv01.u32[3] += rte_cpu_to_be_16(0x0100);
			priv23.u32[1] += rte_cpu_to_be_16(0x0100);
			priv23.u32[3] += rte_cpu_to_be_16(0x0100);

			/* Update ttl,cksum rewrite ethernet hdr on mbuf0 */
			d0 = rte_pktmbuf_mtod(mbuf0, void *);
			rte_memcpy(d0, nh[priv01.u16[0]].rewrite_data,
				   nh[priv01.u16[0]].rewrite_len);

			next0 = tx0 + 1;
			ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
						      sizeof(struct rte_ether_hdr));
			ip0->time_to_live = priv01.u16[1] - 1;
			ip0->hdr_checksum = priv01.u16[2] + priv01.u16[3];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf1 */
			d1 = rte_pktmbuf_mtod(mbuf1, void *);
			rte_memcpy(d1, nh[priv01.u16[4]].rewrite_data,
				   nh[priv01.u16[4]].rewrite_len);

			next1 = tx1 + 1;
			ip1 = (struct rte_ipv4_hdr *)((uint8_t *)d1 +
						      sizeof(struct rte_ether_hdr));
			ip1->time_to_live = priv01.u16[5] - 1;
			ip1->hdr_checksum = priv01.u16[6] + priv01.u16[7];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf2 */
			d2 = rte_pktmbuf_mtod(mbuf2, void *);
			rte_memcpy(d2, nh[priv23.u16[0]].rewrite_data,
				   nh[priv23.u16[0]].rewrite_len);
			next2 = tx2 + 1;
			ip2 = (struct rte_ipv4_hdr *)((uint8_t *)d2 +
						      sizeof(struct rte_ether_hdr));
			ip2->time_to_live = priv23.u16[1] - 1;
			ip2->hdr_checksum = priv23.u16[2] + priv23.u16[3];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf3 */
			d3 = rte_pktmbuf_mtod(mbuf3, void *);
			rte_memcpy(d3, nh[priv23.u16[4]].rewrite_data,
				   nh[priv23.u16[4]].rewrite_len);

			next3 = tx3 + 1;
			ip3 = (struct rte_ipv4_hdr *)((uint8_t *)d3 +
						      sizeof(struct rte_ether_hdr));
			ip3->time_to_live = priv23.u16[5] - 1;
			ip3->hdr_checksum = priv23.u16[6] + priv23.u16[7];
		}

		/* Enqueue four to next node */
		rte_edge_t fix_spec =
			((next_index == next0) && (next0 == next1) &&
			 (next1 == next2) && (next2 == next3));

		if (unlikely(fix_spec == 0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* next0 */
			if (next_index == next0) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next0,
						    from[0]);
			}

			/* next1 */
			if (next_index == next1) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next1,
						    from[1]);
			}

			/* next2 */
			if (next_index == next2) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next2,
						    from[2]);
			}

			/* next3 */
			if (next_index == next3) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, next3,
						    from[3]);
			}

			from += 4;

			/* Change speculation if last two are same */
			if ((next_index != next3) && (next2 == next3)) {
				/* Put the current speculated node */
				rte_node_next_stream_put(graph, node,
							 next_index, held);
				held = 0;

				/* Get next speculated stream */
				next_index = next3;
				to_next = rte_node_next_stream_get(
					graph, node, next_index, nb_objs);
			}
		} else {
			last_spec += 4;
		}
	}

	while (n_left_from > 0) {
		uint16_t chksum;

		mbuf0 = pkts[0];

		pkts += 1;
		n_left_from -= 1;

		tx0 = nh[node_mbuf_priv1(mbuf0, dyn)->nh].tx_node - 1;
		f0 = nh[node_mbuf_priv1(mbuf0, dyn)->nh].nh_feature;

		if (unlikely(rte_graph_feature_arc_has_feature(out_feature_arc, tx0, &f0))) {
			rte_graph_feature_arc_feature_data_get(out_feature_arc, f0, tx0,
							       &next0, &fd0);
			node_mbuf_priv1(mbuf0, dyn)->current_feature = f0;
			node_mbuf_priv1(mbuf0, dyn)->index = tx0;
		} else {
			d0 = rte_pktmbuf_mtod(mbuf0, void *);
			rte_memcpy(d0, nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_data,
				   nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_len);

			next0 = tx0 + 1;
			ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
						      sizeof(struct rte_ether_hdr));
			chksum = node_mbuf_priv1(mbuf0, dyn)->cksum +
				 rte_cpu_to_be_16(0x0100);
			chksum += chksum >= 0xffff;
			ip0->hdr_checksum = chksum;
			ip0->time_to_live = node_mbuf_priv1(mbuf0, dyn)->ttl - 1;
		}
		if (unlikely(next_index ^ next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, next0, from[0]);
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
	/* Save the last next used */
	IP4_REWRITE_NODE_LAST_NEXT(node->ctx) = next_index;

	return nb_objs;
}

static int
ip4_rewrite_node_init(const struct rte_graph *graph, struct rte_node *node)
{
	rte_graph_feature_arc_t feature_arc = RTE_GRAPH_FEATURE_ARC_INITIALIZER;
	static bool init_once;

	RTE_SET_USED(graph);
	RTE_BUILD_BUG_ON(sizeof(struct ip4_rewrite_node_ctx) > RTE_NODE_CTX_SZ);
	RTE_BUILD_BUG_ON(sizeof(struct ip4_rewrite_nh_header) != RTE_CACHE_LINE_MIN_SIZE);

	if (!init_once) {
		node_mbuf_priv1_dynfield_offset = rte_mbuf_dynfield_register(
				&node_mbuf_priv1_dynfield_desc);
		if (node_mbuf_priv1_dynfield_offset < 0)
			return -rte_errno;

		/* Create ipv4-output feature arc, if not created
		 */
		if (rte_graph_feature_arc_lookup_by_name(RTE_IP4_OUTPUT_FEATURE_ARC_NAME, NULL) &&
		    rte_graph_feature_arc_create(RTE_IP4_OUTPUT_FEATURE_ARC_NAME,
						 RTE_GRAPH_FEATURE_MAX_PER_ARC, /* max features */
						 RTE_MAX_ETHPORTS + 1, /* max output interfaces */
						 ip4_rewrite_node_get(),
						 &feature_arc)) {
			return -rte_errno;
		}

		init_once = true;
	}
	IP4_REWRITE_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;
	IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(node->ctx) = feature_arc;

	node_dbg("ip4_rewrite", "Initialized ip4_rewrite node initialized");

	return 0;
}

int
ip4_rewrite_set_next(uint16_t port_id, uint16_t next_index)
{
	if (ip4_rewrite_nm == NULL) {
		ip4_rewrite_nm = rte_zmalloc(
			"ip4_rewrite", sizeof(struct ip4_rewrite_node_main),
			RTE_CACHE_LINE_SIZE);
		if (ip4_rewrite_nm == NULL)
			return -ENOMEM;
	}
	ip4_rewrite_nm->next_index[port_id] = next_index;

	return 0;
}

int
rte_node_ip4_rewrite_add(uint16_t next_hop, uint8_t *rewrite_data,
			 uint8_t rewrite_len, uint16_t dst_port)
{
	struct ip4_rewrite_nh_header *nh;

	if (next_hop >= RTE_GRAPH_IP4_REWRITE_MAX_NH)
		return -EINVAL;

	if (rewrite_len > RTE_GRAPH_IP4_REWRITE_MAX_LEN)
		return -EINVAL;

	if (ip4_rewrite_nm == NULL) {
		ip4_rewrite_nm = rte_zmalloc(
			"ip4_rewrite", sizeof(struct ip4_rewrite_node_main),
			RTE_CACHE_LINE_SIZE);
		if (ip4_rewrite_nm == NULL)
			return -ENOMEM;
	}

	/* Check if dst port doesn't exist as edge */
	if (!ip4_rewrite_nm->next_index[dst_port])
		return -EINVAL;

	/* Update next hop */
	nh = &ip4_rewrite_nm->nh[next_hop];

	memcpy(nh->rewrite_data, rewrite_data, rewrite_len);
	nh->tx_node = ip4_rewrite_nm->next_index[dst_port];
	nh->rewrite_len = rewrite_len;
	nh->enabled = true;
	nh->nh_feature = RTE_GRAPH_FEATURE_INVALID_VALUE;

	return 0;
}

static struct rte_node_register ip4_rewrite_node = {
	.process = ip4_rewrite_node_process,
	.name = "ip4_rewrite",
	/* Default edge i.e '0' is pkt drop */
	.nb_edges = 1,
	.next_nodes = {
		[0] = "pkt_drop",
	},
	.init = ip4_rewrite_node_init,
};

struct rte_node_register *
ip4_rewrite_node_get(void)
{
	return &ip4_rewrite_node;
}

RTE_NODE_REGISTER(ip4_rewrite_node);
