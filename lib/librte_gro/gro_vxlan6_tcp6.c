/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Inspur Corporation
 */

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_udp.h>

#include "gro_vxlan6_tcp6.h"

void *
gro_vxlan6_tcp6_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow)
{
	struct gro_vxlan6_tcp6_tbl *tbl;
	size_t size;
	uint32_t entries_num, i;

	entries_num = max_flow_num * max_item_per_flow;
	entries_num = RTE_MIN(entries_num, GRO_VXLAN6_TCP6_TBL_MAX_ITEM_NUM);

	if (entries_num == 0)
		return NULL;

	tbl = rte_zmalloc_socket(__func__,
			sizeof(struct gro_vxlan6_tcp6_tbl),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl == NULL)
		return NULL;

	size = sizeof(struct gro_vxlan6_tcp6_item) * entries_num;
	tbl->items = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->items == NULL) {
		rte_free(tbl);
		return NULL;
	}
	tbl->max_item_num = entries_num;

	size = sizeof(struct gro_vxlan6_tcp6_flow) * entries_num;
	tbl->flows = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->flows == NULL) {
		rte_free(tbl->items);
		rte_free(tbl);
		return NULL;
	}

	for (i = 0; i < entries_num; i++)
		tbl->flows[i].start_index = INVALID_ARRAY_INDEX;
	tbl->max_flow_num = entries_num;

	return tbl;
}

void
gro_vxlan6_tcp6_tbl_destroy(void *tbl)
{
	struct gro_vxlan6_tcp6_tbl *vxlan6_tbl = tbl;

	if (vxlan6_tbl) {
		rte_free(vxlan6_tbl->items);
		rte_free(vxlan6_tbl->flows);
	}
	rte_free(vxlan6_tbl);
}

static inline uint32_t
find_an_empty_item(struct gro_vxlan6_tcp6_tbl *tbl)
{
	uint32_t max_item_num = tbl->max_item_num, i;

	for (i = 0; i < max_item_num; i++)
		if (tbl->items[i].inner_item.firstseg == NULL)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
find_an_empty_flow(struct gro_vxlan6_tcp6_tbl *tbl)
{
	uint32_t max_flow_num = tbl->max_flow_num, i;

	for (i = 0; i < max_flow_num; i++)
		if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
insert_new_item(struct gro_vxlan6_tcp6_tbl *tbl,
		struct rte_mbuf *pkt,
		uint64_t start_time,
		uint32_t prev_idx,
		uint32_t sent_seq)
{
	uint32_t item_idx;

	item_idx = find_an_empty_item(tbl);
	if (unlikely(item_idx == INVALID_ARRAY_INDEX))
		return INVALID_ARRAY_INDEX;

	tbl->items[item_idx].inner_item.firstseg = pkt;
	tbl->items[item_idx].inner_item.lastseg = rte_pktmbuf_lastseg(pkt);
	tbl->items[item_idx].inner_item.start_time = start_time;
	tbl->items[item_idx].inner_item.next_pkt_idx = INVALID_ARRAY_INDEX;
	tbl->items[item_idx].inner_item.sent_seq = sent_seq;
	tbl->items[item_idx].inner_item.nb_merged = 1;
	tbl->item_num++;

	/* If the previous packet exists, chain the new one with it. */
	if (prev_idx != INVALID_ARRAY_INDEX) {
		tbl->items[item_idx].inner_item.next_pkt_idx =
			tbl->items[prev_idx].inner_item.next_pkt_idx;
		tbl->items[prev_idx].inner_item.next_pkt_idx = item_idx;
	}

	return item_idx;
}

static inline uint32_t
delete_item(struct gro_vxlan6_tcp6_tbl *tbl,
		uint32_t item_idx,
		uint32_t prev_item_idx)
{
	uint32_t next_idx = tbl->items[item_idx].inner_item.next_pkt_idx;

	/* NULL indicates an empty item. */
	tbl->items[item_idx].inner_item.firstseg = NULL;
	tbl->item_num--;
	if (prev_item_idx != INVALID_ARRAY_INDEX)
		tbl->items[prev_item_idx].inner_item.next_pkt_idx = next_idx;

	return next_idx;
}

static inline uint32_t
insert_new_flow(struct gro_vxlan6_tcp6_tbl *tbl,
		struct vxlan6_tcp6_flow_key *src,
		uint32_t item_idx)
{
	struct vxlan6_tcp6_flow_key *dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
	if (unlikely(flow_idx == INVALID_ARRAY_INDEX))
		return INVALID_ARRAY_INDEX;

	dst = &(tbl->flows[flow_idx].key);

	rte_ether_addr_copy(&(src->inner_key.eth_saddr),
			&(dst->inner_key.eth_saddr));
	rte_ether_addr_copy(&(src->inner_key.eth_daddr),
			&(dst->inner_key.eth_daddr));
	gro_ipv6_addr_copy(src->inner_key.ip_saddr, dst->inner_key.ip_saddr);
	gro_ipv6_addr_copy(src->inner_key.ip_daddr, dst->inner_key.ip_daddr);
	dst->inner_key.recv_ack = src->inner_key.recv_ack;
	dst->inner_key.src_port = src->inner_key.src_port;
	dst->inner_key.dst_port = src->inner_key.dst_port;

	dst->vxlan_hdr.vx_flags = src->vxlan_hdr.vx_flags;
	dst->vxlan_hdr.vx_vni = src->vxlan_hdr.vx_vni;
	rte_ether_addr_copy(&(src->outer_eth_saddr), &(dst->outer_eth_saddr));
	rte_ether_addr_copy(&(src->outer_eth_daddr), &(dst->outer_eth_daddr));
	gro_ipv6_addr_copy(src->outer_ip_saddr, dst->outer_ip_saddr);
	gro_ipv6_addr_copy(src->outer_ip_daddr, dst->outer_ip_daddr);
	dst->outer_src_port = src->outer_src_port;
	dst->outer_dst_port = src->outer_dst_port;

	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flow_num++;

	return flow_idx;
}

static inline int
is_same_vxlan6_tcp6_flow(struct vxlan6_tcp6_flow_key k1,
		struct vxlan6_tcp6_flow_key k2)
{
	return (rte_is_same_ether_addr(&k1.outer_eth_saddr,
					&k2.outer_eth_saddr) &&
			rte_is_same_ether_addr(&k1.outer_eth_daddr,
				&k2.outer_eth_daddr) &&
			rte_is_same_ipv6_addr(k1.outer_ip_saddr,
					      k2.outer_ip_saddr) &&
			rte_is_same_ipv6_addr(k1.outer_ip_daddr,
					      k2.outer_ip_daddr) &&
			(k1.outer_src_port == k2.outer_src_port) &&
			(k1.outer_dst_port == k2.outer_dst_port) &&
			(k1.vxlan_hdr.vx_flags == k2.vxlan_hdr.vx_flags) &&
			(k1.vxlan_hdr.vx_vni == k2.vxlan_hdr.vx_vni) &&
			is_same_tcp6_flow(k1.inner_key, k2.inner_key));
}

static inline int
check_vxlan_seq_option_v6(struct gro_vxlan6_tcp6_item *item,
		struct rte_tcp_hdr *tcp_hdr,
		uint32_t sent_seq,
		uint16_t tcp_hl,
		uint16_t tcp_dl)
{
	struct rte_mbuf *pkt = item->inner_item.firstseg;
	int cmp;
	uint16_t l2_offset;

	l2_offset = pkt->outer_l2_len + pkt->outer_l3_len;
	cmp = check_seq_option_v6(&item->inner_item, tcp_hdr, sent_seq,
			tcp_hl, tcp_dl, l2_offset);
	if (cmp > 0)
		/* Append the new packet. */
		return 1;
	else if (cmp < 0)
		/* Prepend the new packet. */
		return -1;

	return 0;
}

static inline int
merge_two_vxlan6_tcp6_packets(struct gro_vxlan6_tcp6_item *item,
		struct rte_mbuf *pkt,
		int cmp,
		uint32_t sent_seq)
{
	if (merge_two_tcp6_packets(&item->inner_item, pkt, cmp, sent_seq,
				pkt->outer_l2_len +
				pkt->outer_l3_len))
		return 1;

	return 0;
}

static inline void
update_vxlan6_header(struct gro_vxlan6_tcp6_item *item)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_mbuf *pkt = item->inner_item.firstseg;
	uint16_t len;

	/* Update the outer IPv6 header. */
	len = pkt->pkt_len - pkt->outer_l2_len;
	ipv6_hdr = (struct rte_ipv6_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			pkt->outer_l2_len);
	ipv6_hdr->payload_len = rte_cpu_to_be_16(len - pkt->outer_l3_len);

	/* Update the outer UDP header. */
	len -= pkt->outer_l3_len;
	udp_hdr = (struct rte_udp_hdr *)((char *)ipv6_hdr + pkt->outer_l3_len);
	udp_hdr->dgram_len = rte_cpu_to_be_16(len);

	/* Update the inner IPv6 header. */
	len -= pkt->l2_len;
	ipv6_hdr = (struct rte_ipv6_hdr *)((char *)udp_hdr + pkt->l2_len);
	/* IPv6 payload_len does not include IPv6 header. */
	ipv6_hdr->payload_len = rte_cpu_to_be_16(len - pkt->l3_len);
}

int32_t
gro_vxlan6_tcp6_reassemble(struct rte_mbuf *pkt,
		struct gro_vxlan6_tcp6_tbl *tbl,
		uint64_t start_time)
{
	struct rte_ether_hdr *outer_eth_hdr, *eth_hdr;
	struct rte_ipv6_hdr *outer_ipv6_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	struct rte_vxlan_hdr *vxlan_hdr;
	uint32_t sent_seq;
	int32_t tcp_dl;

	struct vxlan6_tcp6_flow_key key;
	uint32_t cur_idx, prev_idx, item_idx;
	uint32_t i, max_flow_num, remaining_flow_num;
	int cmp;
	uint16_t hdr_len;
	uint8_t find;

	/*
	 * Don't process the packet whose TCP header length is greater
	 * than 60 bytes or less than 20 bytes.
	 */
	if (unlikely(INVALID_TCP_HDRLEN(pkt->l4_len)))
		return -1;

	outer_eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	outer_ipv6_hdr = (struct rte_ipv6_hdr *)((char *)outer_eth_hdr +
			pkt->outer_l2_len);
	udp_hdr = (struct rte_udp_hdr *)((char *)outer_ipv6_hdr +
			pkt->outer_l3_len);
	vxlan_hdr = (struct rte_vxlan_hdr *)((char *)udp_hdr +
			sizeof(struct rte_udp_hdr));
	eth_hdr = (struct rte_ether_hdr *)((char *)vxlan_hdr +
			sizeof(struct rte_vxlan_hdr));
	ipv6_hdr = (struct rte_ipv6_hdr *)((char *)udp_hdr + pkt->l2_len);
	tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv6_hdr + pkt->l3_len);

	/*
	 * Don't process the packet which has FIN, SYN, RST, PSH, URG,
	 * ECE or CWR set.
	 */
	if (tcp_hdr->tcp_flags != RTE_TCP_ACK_FLAG)
		return -1;

	hdr_len = pkt->outer_l2_len + pkt->outer_l3_len + pkt->l2_len +
		pkt->l3_len + pkt->l4_len;
	/*
	 * Don't process the packet whose payload length is less than or
	 * equal to 0.
	 */
	if (pkt->pkt_len <= hdr_len)
		return -1;
	tcp_dl = pkt->pkt_len - hdr_len;

	sent_seq = rte_be_to_cpu_32(tcp_hdr->sent_seq);

	rte_ether_addr_copy(&(eth_hdr->s_addr), &(key.inner_key.eth_saddr));
	rte_ether_addr_copy(&(eth_hdr->d_addr), &(key.inner_key.eth_daddr));
	gro_ipv6_addr_copy(ipv6_hdr->src_addr, key.inner_key.ip_saddr);
	gro_ipv6_addr_copy(ipv6_hdr->dst_addr, key.inner_key.ip_daddr);
	key.inner_key.recv_ack = tcp_hdr->recv_ack;
	key.inner_key.src_port = tcp_hdr->src_port;
	key.inner_key.dst_port = tcp_hdr->dst_port;

	key.vxlan_hdr.vx_flags = vxlan_hdr->vx_flags;
	key.vxlan_hdr.vx_vni = vxlan_hdr->vx_vni;
	rte_ether_addr_copy(&(outer_eth_hdr->s_addr), &(key.outer_eth_saddr));
	rte_ether_addr_copy(&(outer_eth_hdr->d_addr), &(key.outer_eth_daddr));
	gro_ipv6_addr_copy(outer_ipv6_hdr->src_addr, key.outer_ip_saddr);
	gro_ipv6_addr_copy(outer_ipv6_hdr->dst_addr, key.outer_ip_daddr);
	key.outer_src_port = udp_hdr->src_port;
	key.outer_dst_port = udp_hdr->dst_port;

	/* Search for a matched flow. */
	max_flow_num = tbl->max_flow_num;
	remaining_flow_num = tbl->flow_num;
	find = 0;
	for (i = 0; i < max_flow_num && remaining_flow_num; i++) {
		if (tbl->flows[i].start_index != INVALID_ARRAY_INDEX) {
			if (is_same_vxlan6_tcp6_flow(tbl->flows[i].key, key)) {
				find = 1;
				break;
			}
			remaining_flow_num--;
		}
	}

	/*
	 * Can't find a matched flow. Insert a new flow and store the
	 * packet into the flow.
	 */
	if (find == 0) {
		item_idx = insert_new_item(tbl, pkt, start_time,
				INVALID_ARRAY_INDEX, sent_seq);
		if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		if (insert_new_flow(tbl, &key, item_idx) ==
				INVALID_ARRAY_INDEX) {
			/*
			 * Fail to insert a new flow, so
			 * delete the inserted packet.
			 */
			delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
			return -1;
		}
		return 0;
	}

	/* Check all packets in the flow and try to find a neighbor. */
	cur_idx = tbl->flows[i].start_index;
	prev_idx = cur_idx;
	do {
		cmp = check_vxlan_seq_option_v6(&(tbl->items[cur_idx]), tcp_hdr,
				sent_seq, pkt->l4_len, tcp_dl);
		if (cmp) {
			if (merge_two_vxlan6_tcp6_packets(
						&(tbl->items[cur_idx]),
						pkt, cmp, sent_seq))
				return 1;
			/*
			 * Can't merge two packets, as the packet
			 * length will be greater than the max value.
			 * Insert the packet into the flow.
			 */
			if (insert_new_item(tbl, pkt, start_time, prev_idx,
						sent_seq) ==
					INVALID_ARRAY_INDEX)
				return -1;
			return 0;
		}
		prev_idx = cur_idx;
		cur_idx = tbl->items[cur_idx].inner_item.next_pkt_idx;
	} while (cur_idx != INVALID_ARRAY_INDEX);

	/* Can't find neighbor. Insert the packet into the flow. */
	if (insert_new_item(tbl, pkt, start_time, prev_idx, sent_seq
				) == INVALID_ARRAY_INDEX)
		return -1;

	return 0;
}

uint16_t
gro_vxlan6_tcp6_tbl_timeout_flush(struct gro_vxlan6_tcp6_tbl *tbl,
		uint64_t flush_timestamp,
		struct rte_mbuf **out,
		uint16_t nb_out)
{
	uint16_t k = 0;
	uint32_t i, j;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++) {
		if (unlikely(tbl->flow_num == 0))
			return k;

		j = tbl->flows[i].start_index;
		while (j != INVALID_ARRAY_INDEX) {
			if (tbl->items[j].inner_item.start_time <=
					flush_timestamp) {
				out[k++] = tbl->items[j].inner_item.firstseg;
				if (tbl->items[j].inner_item.nb_merged > 1)
					update_vxlan6_header(&(tbl->items[j]));
				/*
				 * Delete the item and get the next packet
				 * index.
				 */
				j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
				tbl->flows[i].start_index = j;
				if (j == INVALID_ARRAY_INDEX)
					tbl->flow_num--;

				if (unlikely(k == nb_out))
					return k;
			} else
				/*
				 * The left packets in the flow won't be
				 * timeout. Go to check other flows.
				 */
				break;
		}
	}
	return k;
}

uint32_t
gro_vxlan6_tcp6_tbl_pkt_count(void *tbl)
{
	struct gro_vxlan6_tcp6_tbl *gro_tbl = tbl;

	if (gro_tbl)
		return gro_tbl->item_num;

	return 0;
}
