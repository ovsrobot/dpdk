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

#define ALL_PKT_MASK 0xf

struct ip4_rewrite_node_ctx {
	rte_graph_feature_arc_t output_feature_arc;
	/* Dynamic offset to mbuf priv1 */
	int mbuf_priv1_off;
	/* Cached next index */
	uint16_t next_index;
	uint16_t last_tx;
};

typedef struct rewrite_priv_vars {
	union {
		struct {
			rte_xmm_t xmm1;
		};
		struct __rte_packed {
			uint16_t next0;
			uint16_t next1;
			uint16_t next2;
			uint16_t next3;
			uint16_t last_tx_interface;
			uint16_t last_if_feature;
			uint16_t actual_feat_mask;
			uint16_t speculative_feat_mask;
		};
	};
} rewrite_priv_vars_t;

static struct ip4_rewrite_node_main *ip4_rewrite_nm;

#define IP4_REWRITE_NODE_LAST_NEXT(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->next_index)

#define IP4_REWRITE_NODE_LAST_TX(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->last_tx)

#define IP4_REWRITE_NODE_PRIV1_OFF(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->mbuf_priv1_off)

#define IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(ctx) \
	(((struct ip4_rewrite_node_ctx *)ctx)->output_feature_arc)

static __rte_always_inline void
prefetch_mbuf_and_dynfield(struct rte_mbuf *mbuf)
{
	/* prefetch first cache line required for accessing buf_addr */
	rte_prefetch0((void *)mbuf);
}

static __rte_always_inline void
check_output_feature_x4(struct rte_graph_feature_arc *arc,
			const rte_graph_feature_rt_list_t flist,
			rewrite_priv_vars_t *pvar, struct node_mbuf_priv1 *priv0,
			struct node_mbuf_priv1 *priv1, struct node_mbuf_priv1 *priv2,
			struct node_mbuf_priv1 *priv3)
{
	uint32_t mask = 0;
	uint16_t xor = 0;

	/*
	 * interface edge's start from 1 and not from 0 as "pkt_drop"
	 * is next node at 0th index
	 */
	priv0->if_index = pvar->next0 - 1;
	priv1->if_index = pvar->next1 - 1;
	priv2->if_index = pvar->next2 - 1;
	priv3->if_index = pvar->next3 - 1;

	/* Find out if all packets are sent to last_tx_interface */
	xor = pvar->last_tx_interface ^ priv0->if_index;
	xor += priv0->if_index ^ priv1->if_index;
	xor += priv1->if_index ^ priv2->if_index;
	xor += priv2->if_index ^ priv3->if_index;

	if (likely(!xor)) {
		/* copy last interface feature and feature mask */
		priv0->current_feature = priv1->current_feature =
			priv2->current_feature = priv3->current_feature =
			pvar->last_if_feature;
		pvar->actual_feat_mask = pvar->speculative_feat_mask;
	} else {
		/* create a mask for index which does not have feature
		 * Also override next edge and if feature enabled, get feature
		 */
		mask = rte_graph_feature_arc_feature_set(arc, flist, priv0->if_index,
							 &priv0->current_feature,
							 &pvar->next0);

		mask |= ((rte_graph_feature_arc_feature_set(arc, flist, priv1->if_index,
							     &priv1->current_feature,
							     &pvar->next1)) << 1);

		mask |= ((rte_graph_feature_arc_feature_set(arc, flist, priv2->if_index,
							     &priv2->current_feature,
							     &pvar->next2)) << 2);

		mask |= ((rte_graph_feature_arc_feature_set(arc, flist, priv3->if_index,
							     &priv3->current_feature,
							     &pvar->next3)) << 3);

		/*
		 * add last tx and last feature regardless even if feature is
		 * valid or not
		 */
		pvar->last_tx_interface = priv3->if_index;
		pvar->last_if_feature = priv3->current_feature;
		/* Set 0xf if invalid feature to last packet, else 0 */
		pvar->speculative_feat_mask = (priv3->current_feature ==
					       RTE_GRAPH_FEATURE_INVALID) ? ALL_PKT_MASK : 0x0;
		pvar->actual_feat_mask = mask;
	}
}

static __rte_always_inline uint16_t
__ip4_rewrite_node_process(struct rte_graph *graph, struct rte_node *node,
			   void **objs, uint16_t nb_objs,
			   const int dyn, const int check_enabled_features,
			   struct rte_graph_feature_arc *out_feature_arc,
			   const rte_graph_feature_rt_list_t flist)
{
	struct node_mbuf_priv1 *priv0 = NULL, *priv1 = NULL, *priv2 = NULL, *priv3 = NULL;
	struct rte_mbuf *mbuf0, *mbuf1, *mbuf2, *mbuf3, **pkts;
	struct ip4_rewrite_nh_header *nh = ip4_rewrite_nm->nh;
	uint16_t n_left_from, held = 0, last_spec = 0;
	struct rte_ipv4_hdr *ip0, *ip1, *ip2, *ip3;
	rewrite_priv_vars_t pvar;
	int64_t fd0, fd1, fd2, fd3;
	rte_edge_t fix_spec = 0;
	void *d0, *d1, *d2, *d3;
	void **to_next, **from;
	uint16_t next_index;
	rte_xmm_t priv01;
	rte_xmm_t priv23;
	int i;

	RTE_SET_USED(fd0);
	RTE_SET_USED(fd1);
	RTE_SET_USED(fd2);
	RTE_SET_USED(fd3);

	/* Initialize speculative variables.*/

	/* Last interface */
	pvar.last_tx_interface = IP4_REWRITE_NODE_LAST_TX(node->ctx);
	/*last next from node ctx*/
	next_index = IP4_REWRITE_NODE_LAST_NEXT(node->ctx);
	pvar.speculative_feat_mask = ALL_PKT_MASK;
	pvar.actual_feat_mask = 0;

	rte_prefetch0(nh);

	pkts = (struct rte_mbuf **)objs;
	from = objs;
	n_left_from = nb_objs;

	for (i = 0; i < 4 && i < n_left_from; i++)
		prefetch_mbuf_and_dynfield(pkts[i]);

	/* Get stream for the speculated next node */
	to_next = rte_node_next_stream_get(graph, node, next_index, nb_objs);

	/* prefetch speculative feature and corresponding data */
	if (check_enabled_features) {
		/*
		 * Get first feature enabled, if any, on last_tx_interface
		 */
		if (unlikely(rte_graph_feature_arc_first_feature_get(out_feature_arc,
								     flist,
								     pvar.last_tx_interface,
								     (rte_graph_feature_t *)
								     &pvar.last_if_feature))) {
			/* prefetch feature cache line */
			rte_graph_feature_arc_feature_prefetch(out_feature_arc, flist,
							       pvar.last_if_feature);

			/* prefetch feature data cache line */
			rte_graph_feature_arc_data_prefetch(out_feature_arc, flist,
							    pvar.last_if_feature,
							    pvar.last_tx_interface);
			/*
			 * Set speculativa_feat mask to indicate, all 4 packets
			 * going to feature path
			 */
			pvar.speculative_feat_mask = 0;
		}
	}

	/* Update Ethernet header of pkts */
	while (n_left_from >= 4) {
		if (likely(n_left_from > 7)) {
			/* Prefetch only next-mbuf struct and priv area.
			 * Data need not be prefetched as we only write.
			 */
			prefetch_mbuf_and_dynfield(pkts[4]);
			prefetch_mbuf_and_dynfield(pkts[5]);
			prefetch_mbuf_and_dynfield(pkts[6]);
			prefetch_mbuf_and_dynfield(pkts[7]);
		}

		mbuf0 = pkts[0];
		mbuf1 = pkts[1];
		mbuf2 = pkts[2];
		mbuf3 = pkts[3];

		pkts += 4;
		n_left_from -= 4;

		/* Copy mbuf private data into private variables */
		priv01.u64[0] = node_mbuf_priv1(mbuf0, dyn)->u;
		priv01.u64[1] = node_mbuf_priv1(mbuf1, dyn)->u;
		priv23.u64[0] = node_mbuf_priv1(mbuf2, dyn)->u;
		priv23.u64[1] = node_mbuf_priv1(mbuf3, dyn)->u;

		/* Copy next edge from next hop */
		pvar.next0 = nh[priv01.u16[0]].tx_node;
		pvar.next1 = nh[priv01.u16[4]].tx_node;
		pvar.next2 = nh[priv23.u16[0]].tx_node;
		pvar.next3 = nh[priv23.u16[4]].tx_node;

		if (check_enabled_features) {
			priv0 = node_mbuf_priv1(mbuf0, dyn);
			priv1 = node_mbuf_priv1(mbuf1, dyn);
			priv2 = node_mbuf_priv1(mbuf2, dyn);
			priv3 = node_mbuf_priv1(mbuf3, dyn);

			/* If feature is enabled, override next edge for each mbuf
			 * and set node_mbuf_priv data appropriately
			 */
			check_output_feature_x4(out_feature_arc, flist,
						&pvar, priv0, priv1, priv2, priv3);

			/* check_output_feature_x4() returns bit mask which indicates
			 * which packet is not following feature path, hence normal processing
			 * has to happen on them
			 */
			if (unlikely(pvar.actual_feat_mask)) {
				if (pvar.actual_feat_mask & 0x1) {
					priv01.u32[1] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf0 */
					d0 = rte_pktmbuf_mtod(mbuf0, void *);
					rte_memcpy(d0, nh[priv01.u16[0]].rewrite_data,
						   nh[priv01.u16[0]].rewrite_len);
					ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
								      sizeof(struct rte_ether_hdr));
					ip0->time_to_live = priv01.u16[1] - 1;
					ip0->hdr_checksum = priv01.u16[2] + priv01.u16[3];
				}
				if (pvar.actual_feat_mask & 0x2) {
					priv01.u32[3] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf1 */
					d1 = rte_pktmbuf_mtod(mbuf1, void *);
					rte_memcpy(d1, nh[priv01.u16[4]].rewrite_data,
						   nh[priv01.u16[4]].rewrite_len);

					ip1 = (struct rte_ipv4_hdr *)((uint8_t *)d1 +
								      sizeof(struct rte_ether_hdr));
					ip1->time_to_live = priv01.u16[5] - 1;
					ip1->hdr_checksum = priv01.u16[6] + priv01.u16[7];
				}
				if (pvar.actual_feat_mask & 0x4) {
					priv23.u32[1] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf2 */
					d2 = rte_pktmbuf_mtod(mbuf2, void *);
					rte_memcpy(d2, nh[priv23.u16[0]].rewrite_data,
						   nh[priv23.u16[0]].rewrite_len);
					ip2 = (struct rte_ipv4_hdr *)((uint8_t *)d2 +
								      sizeof(struct rte_ether_hdr));
					ip2->time_to_live = priv23.u16[1] - 1;
					ip2->hdr_checksum = priv23.u16[2] + priv23.u16[3];
				}
				if (pvar.actual_feat_mask & 0x8) {
					priv23.u32[3] += rte_cpu_to_be_16(0x0100);
					/* Update ttl,cksum rewrite ethernet hdr on mbuf3 */
					d3 = rte_pktmbuf_mtod(mbuf3, void *);
					rte_memcpy(d3, nh[priv23.u16[4]].rewrite_data,
						   nh[priv23.u16[4]].rewrite_len);
					ip3 = (struct rte_ipv4_hdr *)((uint8_t *)d3 +
								      sizeof(struct rte_ether_hdr));
					ip3->time_to_live = priv23.u16[5] - 1;
					ip3->hdr_checksum = priv23.u16[6] + priv23.u16[7];
				}
			}
		} else {
			/* Case when no feature is enabled */

			/* Increment checksum by one. */
			priv01.u32[1] += rte_cpu_to_be_16(0x0100);
			priv01.u32[3] += rte_cpu_to_be_16(0x0100);
			priv23.u32[1] += rte_cpu_to_be_16(0x0100);
			priv23.u32[3] += rte_cpu_to_be_16(0x0100);

			/* Update ttl,cksum rewrite ethernet hdr on mbuf0 */
			d0 = rte_pktmbuf_mtod(mbuf0, void *);
			rte_memcpy(d0, nh[priv01.u16[0]].rewrite_data,
				   nh[priv01.u16[0]].rewrite_len);

			ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
						      sizeof(struct rte_ether_hdr));
			ip0->time_to_live = priv01.u16[1] - 1;
			ip0->hdr_checksum = priv01.u16[2] + priv01.u16[3];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf1 */
			d1 = rte_pktmbuf_mtod(mbuf1, void *);
			rte_memcpy(d1, nh[priv01.u16[4]].rewrite_data,
				   nh[priv01.u16[4]].rewrite_len);

			ip1 = (struct rte_ipv4_hdr *)((uint8_t *)d1 +
						      sizeof(struct rte_ether_hdr));
			ip1->time_to_live = priv01.u16[5] - 1;
			ip1->hdr_checksum = priv01.u16[6] + priv01.u16[7];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf2 */
			d2 = rte_pktmbuf_mtod(mbuf2, void *);
			rte_memcpy(d2, nh[priv23.u16[0]].rewrite_data,
				   nh[priv23.u16[0]].rewrite_len);
			ip2 = (struct rte_ipv4_hdr *)((uint8_t *)d2 +
						      sizeof(struct rte_ether_hdr));
			ip2->time_to_live = priv23.u16[1] - 1;
			ip2->hdr_checksum = priv23.u16[2] + priv23.u16[3];

			/* Update ttl,cksum rewrite ethernet hdr on mbuf3 */
			d3 = rte_pktmbuf_mtod(mbuf3, void *);
			rte_memcpy(d3, nh[priv23.u16[4]].rewrite_data,
				   nh[priv23.u16[4]].rewrite_len);

			ip3 = (struct rte_ipv4_hdr *)((uint8_t *)d3 +
						      sizeof(struct rte_ether_hdr));
			ip3->time_to_live = priv23.u16[5] - 1;
			ip3->hdr_checksum = priv23.u16[6] + priv23.u16[7];
		}

		/* Enqueue four to next node */
		fix_spec = next_index ^ pvar.next0;
		fix_spec += next_index ^ pvar.next1;
		fix_spec += next_index ^ pvar.next2;
		fix_spec += next_index ^ pvar.next3;

		if (unlikely(fix_spec != 0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			/* next0 */
			if (next_index == pvar.next0) {
				to_next[0] = from[0];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, pvar.next0,
						    from[0]);
			}

			/* next1 */
			if (next_index == pvar.next1) {
				to_next[0] = from[1];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, pvar.next1,
						    from[1]);
			}

			/* next2 */
			if (next_index == pvar.next2) {
				to_next[0] = from[2];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, pvar.next2,
						    from[2]);
			}

			/* next3 */
			if (next_index == pvar.next3) {
				to_next[0] = from[3];
				to_next++;
				held++;
			} else {
				rte_node_enqueue_x1(graph, node, pvar.next3,
						    from[3]);
			}

			from += 4;

			/* Change speculation if last two are same */
			if ((next_index != pvar.next3) && (pvar.next2 == pvar.next3)) {
				/* Put the current speculated node */
				rte_node_next_stream_put(graph, node,
							 next_index, held);
				held = 0;

				/* Get next speculated stream */
				next_index = pvar.next3;
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

		pvar.next0 = nh[node_mbuf_priv1(mbuf0, dyn)->nh].tx_node;
		if (check_enabled_features) {
			priv0 = node_mbuf_priv1(mbuf0, dyn);
			if (pvar.next0 != (pvar.last_tx_interface + 1)) {
				priv0->if_index = pvar.next0 - 1;
				rte_graph_feature_arc_feature_set(out_feature_arc, flist,
								  priv0->if_index,
								  &priv0->current_feature,
								  &pvar.next0);
				pvar.last_tx_interface = priv0->if_index;
				pvar.last_if_feature = priv0->current_feature;
			} else {
				/* current mbuf index is same as last_tx_interface */
				priv0->if_index = pvar.last_tx_interface;
				priv0->current_feature = pvar.last_if_feature;
			}
		}
		/* Do the needful if either feature arc is disabled OR
		 * Invalid feature is present
		 */
		if (!check_enabled_features ||
		    (priv0->current_feature == RTE_GRAPH_FEATURE_INVALID)) {
			d0 = rte_pktmbuf_mtod(mbuf0, void *);
			rte_memcpy(d0, nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_data,
				   nh[node_mbuf_priv1(mbuf0, dyn)->nh].rewrite_len);

			ip0 = (struct rte_ipv4_hdr *)((uint8_t *)d0 +
						      sizeof(struct rte_ether_hdr));
			chksum = node_mbuf_priv1(mbuf0, dyn)->cksum +
				 rte_cpu_to_be_16(0x0100);
			chksum += chksum >= 0xffff;
			ip0->hdr_checksum = chksum;
			ip0->time_to_live = node_mbuf_priv1(mbuf0, dyn)->ttl - 1;
		}
		if (unlikely(next_index ^ pvar.next0)) {
			/* Copy things successfully speculated till now */
			rte_memcpy(to_next, from, last_spec * sizeof(from[0]));
			from += last_spec;
			to_next += last_spec;
			held += last_spec;
			last_spec = 0;

			rte_node_enqueue_x1(graph, node, pvar.next0, from[0]);
			from += 1;
		} else {
			last_spec += 1;
		}
	}

	IP4_REWRITE_NODE_LAST_TX(node->ctx) = pvar.last_tx_interface;

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

static uint16_t
ip4_rewrite_feature_node_process(struct rte_graph *graph, struct rte_node *node,
				 void **objs, uint16_t nb_objs)
{
	struct rte_graph_feature_arc *arc =
		rte_graph_feature_arc_get(IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(node->ctx));
	const int dyn = IP4_REWRITE_NODE_PRIV1_OFF(node->ctx);
	rte_graph_feature_rt_list_t flist;

	/* If any feature is enabled on this arc */
	if (unlikely(rte_graph_feature_arc_has_any_feature(arc, &flist))) {
		if (flist)
			return __ip4_rewrite_node_process(graph, node, objs, nb_objs,
							  dyn,
							  1 /* check features */, arc,
							  (rte_graph_feature_rt_list_t)1);
		else
			return __ip4_rewrite_node_process(graph, node, objs, nb_objs,
							  dyn,
							  1 /* check features */, arc,
							  (rte_graph_feature_rt_list_t)0);
	} else {
		return __ip4_rewrite_node_process(graph, node, objs, nb_objs, dyn,
						  0/* don't check features*/, NULL,
						  0/* don't care */);
	}
	return 0;
}

static uint16_t
ip4_rewrite_node_process(struct rte_graph *graph, struct rte_node *node,
			 void **objs, uint16_t nb_objs)
{
	const int dyn = IP4_REWRITE_NODE_PRIV1_OFF(node->ctx);

	return __ip4_rewrite_node_process(graph, node, objs, nb_objs, dyn,
					  0/* don't check features*/, NULL,
					  0/* don't care */);
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
		if (rte_graph_feature_arc_lookup_by_name(RTE_IP4_OUTPUT_FEATURE_ARC_NAME,
							 NULL) < 0) {
			if (rte_graph_feature_arc_create(RTE_IP4_OUTPUT_FEATURE_ARC_NAME,
							 RTE_GRAPH_FEATURE_MAX_PER_ARC,
							 RTE_MAX_ETHPORTS,
							 ip4_rewrite_node_get(), &feature_arc)) {
				return -rte_errno;
			}
			init_once = true;
		}
	}
	IP4_REWRITE_NODE_PRIV1_OFF(node->ctx) = node_mbuf_priv1_dynfield_offset;
	IP4_REWRITE_NODE_OUTPUT_FEATURE_ARC(node->ctx) = feature_arc;
	IP4_REWRITE_NODE_LAST_TX(node->ctx) = UINT16_MAX;

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

	return 0;
}

static struct rte_node_register ip4_rewrite_node = {
	.process = ip4_rewrite_node_process,
	.feat_arc_proc = ip4_rewrite_feature_node_process,
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
