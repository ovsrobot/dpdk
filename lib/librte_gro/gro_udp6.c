/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Inspur Corporation
 */

#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ip.h>

#include "gro_udp6.h"

void *
gro_udp6_tbl_create(uint16_t socket_id,
		uint16_t max_flow_num,
		uint16_t max_item_per_flow)
{
	struct gro_udp6_tbl *tbl;
	size_t size;
	uint32_t entries_num, i;

	entries_num = max_flow_num * max_item_per_flow;
	entries_num = RTE_MIN(entries_num, GRO_UDP6_TBL_MAX_ITEM_NUM);

	if (entries_num == 0)
		return NULL;

	tbl = rte_zmalloc_socket(__func__,
			sizeof(struct gro_udp6_tbl),
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl == NULL)
		return NULL;

	size = sizeof(struct gro_udp6_item) * entries_num;
	tbl->items = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->items == NULL) {
		rte_free(tbl);
		return NULL;
	}
	tbl->max_item_num = entries_num;

	size = sizeof(struct gro_udp6_flow) * entries_num;
	tbl->flows = rte_zmalloc_socket(__func__,
			size,
			RTE_CACHE_LINE_SIZE,
			socket_id);
	if (tbl->flows == NULL) {
		rte_free(tbl->items);
		rte_free(tbl);
		return NULL;
	}
	/* INVALID_ARRAY_INDEX indicates an empty flow */
	for (i = 0; i < entries_num; i++)
		tbl->flows[i].start_index = INVALID_ARRAY_INDEX;
	tbl->max_flow_num = entries_num;

	return tbl;
}

void
gro_udp6_tbl_destroy(void *tbl)
{
	struct gro_udp6_tbl *udp6_tbl = tbl;

	if (udp6_tbl) {
		rte_free(udp6_tbl->items);
		rte_free(udp6_tbl->flows);
	}
	rte_free(udp6_tbl);
}

static inline uint32_t
find_an_empty_item(struct gro_udp6_tbl *tbl)
{
	uint32_t i;
	uint32_t max_item_num = tbl->max_item_num;

	for (i = 0; i < max_item_num; i++)
		if (tbl->items[i].firstseg == NULL)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
find_an_empty_flow(struct gro_udp6_tbl *tbl)
{
	uint32_t i;
	uint32_t max_flow_num = tbl->max_flow_num;

	for (i = 0; i < max_flow_num; i++)
		if (tbl->flows[i].start_index == INVALID_ARRAY_INDEX)
			return i;
	return INVALID_ARRAY_INDEX;
}

static inline uint32_t
insert_new_item(struct gro_udp6_tbl *tbl,
		struct rte_mbuf *pkt,
		uint64_t start_time,
		uint32_t prev_idx,
		uint16_t frag_offset,
		uint8_t is_last_frag)
{
	uint32_t item_idx;

	item_idx = find_an_empty_item(tbl);
	if (item_idx == INVALID_ARRAY_INDEX)
		return INVALID_ARRAY_INDEX;

	tbl->items[item_idx].firstseg = pkt;
	tbl->items[item_idx].lastseg = rte_pktmbuf_lastseg(pkt);
	tbl->items[item_idx].start_time = start_time;
	tbl->items[item_idx].next_pkt_idx = INVALID_ARRAY_INDEX;
	tbl->items[item_idx].frag_offset = frag_offset;
	tbl->items[item_idx].is_last_frag = is_last_frag;
	tbl->items[item_idx].nb_merged = 1;
	tbl->item_num++;

	/* if the previous packet exists, chain them together. */
	if (prev_idx != INVALID_ARRAY_INDEX) {
		tbl->items[item_idx].next_pkt_idx =
			tbl->items[prev_idx].next_pkt_idx;
		tbl->items[prev_idx].next_pkt_idx = item_idx;
	}

	return item_idx;
}

static inline uint32_t
delete_item(struct gro_udp6_tbl *tbl, uint32_t item_idx,
		uint32_t prev_item_idx)
{
	uint32_t next_idx = tbl->items[item_idx].next_pkt_idx;

	/* NULL indicates an empty item */
	tbl->items[item_idx].firstseg = NULL;
	tbl->item_num--;
	if (prev_item_idx != INVALID_ARRAY_INDEX)
		tbl->items[prev_item_idx].next_pkt_idx = next_idx;

	return next_idx;
}

/* Copy IPv6 addr */
static inline void gro_ipv6_addr_copy(const uint8_t *ipv6_from,
				      uint8_t *ipv6_to)
{
	const uint64_t *from_words = (const uint64_t *)ipv6_from;
	uint64_t *to_words   = (uint64_t *)ipv6_to;

	to_words[0] = from_words[0];
	to_words[1] = from_words[1];
}

static inline uint32_t
insert_new_flow(struct gro_udp6_tbl *tbl,
		struct udp6_flow_key *src,
		uint32_t item_idx)
{
	struct udp6_flow_key *dst;
	uint32_t flow_idx;

	flow_idx = find_an_empty_flow(tbl);
	if (unlikely(flow_idx == INVALID_ARRAY_INDEX))
		return INVALID_ARRAY_INDEX;

	dst = &(tbl->flows[flow_idx].key);

	rte_ether_addr_copy(&(src->eth_saddr), &(dst->eth_saddr));
	rte_ether_addr_copy(&(src->eth_daddr), &(dst->eth_daddr));
	gro_ipv6_addr_copy(src->ip_saddr, dst->ip_saddr);
	gro_ipv6_addr_copy(src->ip_daddr, dst->ip_daddr);
	dst->ip_id = src->ip_id;

	tbl->flows[flow_idx].start_index = item_idx;
	tbl->flow_num++;

	return flow_idx;
}

static inline uint16_t
get_ipv6_frag_offset(struct rte_ipv6_fragment_ext *ipv6_frag_hdr)
{
	return ((rte_be_to_cpu_16(ipv6_frag_hdr->frag_data) >> 3) * 8);
}

static inline uint8_t
is_last_ipv6_frag(struct rte_ipv6_fragment_ext *ipv6_frag_hdr)
{
	return (rte_be_to_cpu_16(ipv6_frag_hdr->frag_data) & 0x0001);
}

/*
 * update the packet length for the flushed packet.
 */
static inline void
update_header(struct gro_udp6_item *item)
{
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_mbuf *pkt = item->firstseg;
	struct rte_ipv6_fragment_ext *ipv6_frag_hdr;
	size_t fh_len = sizeof(*ipv6_frag_hdr);

	ipv6_hdr = (struct rte_ipv6_hdr *)(rte_pktmbuf_mtod(pkt, char *) +
			pkt->l2_len);
	/* Note: payload_len includes extension headers and upper layers
	 * data, but l3_len also includes extension headers, so need to
	 * add length of extension headers if they exist.
	 */
	ipv6_hdr->payload_len = rte_cpu_to_be_16(pkt->pkt_len -
			pkt->l2_len - pkt->l3_len);

	/* Remove fragment extension header or clear MF flag */
	if (item->is_last_frag && (ipv6_hdr->proto == IPPROTO_FRAGMENT)) {
		uint16_t ip_ofs;

		ipv6_frag_hdr = (struct rte_ipv6_fragment_ext *)(ipv6_hdr + 1);
		ip_ofs = get_ipv6_frag_offset(ipv6_frag_hdr);
		if (ip_ofs == 0) {
			ipv6_hdr->proto = ipv6_frag_hdr->next_header;
			pkt->l3_len -= fh_len;

			/* Remove IPv6 fragment extension header */
			memmove(rte_pktmbuf_mtod_offset(pkt, char *, fh_len),
				rte_pktmbuf_mtod(pkt, char*),
				pkt->outer_l2_len + pkt->outer_l3_len +
					pkt->l2_len + pkt->l3_len);
			rte_pktmbuf_adj(pkt, fh_len);
		} else {
			/* clear MF flag */
			ipv6_frag_hdr->frag_data = rte_cpu_to_be_16(
				(rte_be_to_cpu_16(ipv6_frag_hdr->frag_data) &
					0xFFFE));
			ipv6_hdr->payload_len += fh_len;
		}
	}
}

int32_t
gro_udp6_reassemble(struct rte_mbuf *pkt,
		struct gro_udp6_tbl *tbl,
		uint64_t start_time)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ipv6_fragment_ext *ipv6_frag_hdr;
	uint16_t fh_len = sizeof(*ipv6_frag_hdr);
	uint16_t ip_dl;
	uint32_t ip_id;
	uint16_t hdr_len;
	uint16_t frag_offset = 0;
	uint8_t is_last_frag;

	struct udp6_flow_key key;
	uint32_t cur_idx, prev_idx, item_idx;
	uint32_t i, max_flow_num, remaining_flow_num;
	int cmp;
	uint8_t find;

	/*
	 * Don't process the packet whose UDP header length is not equal
	 * to 20.
	 */
	if (unlikely(pkt->l4_len != UDP_HDRLEN))
		return -1;

	eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr *);
	ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr + pkt->l2_len);

	/* Note: l3_len includes length of extension headers */
	hdr_len = pkt->l2_len + pkt->l3_len;

	/*
	 * Don't process non-fragment packet.
	 */
	if (ipv6_hdr->proto != IPPROTO_FRAGMENT)
		return -1;

	/*
	 * Don't process the packet whose payload length is less than or
	 * equal to 0.
	 */
	if (pkt->pkt_len <= hdr_len)
		return -1;

	ipv6_frag_hdr = (struct rte_ipv6_fragment_ext *)(ipv6_hdr + 1);
	ip_dl = rte_be_to_cpu_16(ipv6_hdr->payload_len) - fh_len;
	ip_id = rte_be_to_cpu_32(ipv6_frag_hdr->id);
	frag_offset = get_ipv6_frag_offset(ipv6_frag_hdr);
	is_last_frag = is_last_ipv6_frag(ipv6_frag_hdr);

	rte_ether_addr_copy(&(eth_hdr->s_addr), &(key.eth_saddr));
	rte_ether_addr_copy(&(eth_hdr->d_addr), &(key.eth_daddr));
	gro_ipv6_addr_copy(ipv6_hdr->src_addr, key.ip_saddr);
	gro_ipv6_addr_copy(ipv6_hdr->dst_addr, key.ip_daddr);
	key.ip_id = ip_id;

	/* Search for a matched flow. */
	max_flow_num = tbl->max_flow_num;
	remaining_flow_num = tbl->flow_num;
	find = 0;
	for (i = 0; i < max_flow_num && remaining_flow_num; i++) {
		if (tbl->flows[i].start_index != INVALID_ARRAY_INDEX) {
			if (is_same_udp6_flow(tbl->flows[i].key, key)) {
				find = 1;
				break;
			}
			remaining_flow_num--;
		}
	}

	/*
	 * Fail to find a matched flow. Insert a new flow and store the
	 * packet into the flow.
	 */
	if (find == 0) {
		item_idx = insert_new_item(tbl, pkt, start_time,
				INVALID_ARRAY_INDEX, frag_offset,
				is_last_frag);
		if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		if (insert_new_flow(tbl, &key, item_idx) ==
				INVALID_ARRAY_INDEX) {
			/*
			 * Fail to insert a new flow, so delete the
			 * stored packet.
			 */
			delete_item(tbl, item_idx, INVALID_ARRAY_INDEX);
			return -1;
		}
		return 0;
	}

	/*
	 * Check all packets in the flow and try to find a neighbor for
	 * the input packet.
	 */
	cur_idx = tbl->flows[i].start_index;
	prev_idx = cur_idx;
	do {
		cmp = udp6_check_neighbor(&(tbl->items[cur_idx]),
				frag_offset, ip_dl, 0);
		if (cmp) {
			if (merge_two_udp6_packets(&(tbl->items[cur_idx]),
						pkt, cmp, frag_offset,
						is_last_frag, 0))
				return 1;
			/*
			 * Fail to merge the two packets, as the packet
			 * length is greater than the max value. Store
			 * the packet into the flow.
			 */
			if (insert_new_item(tbl, pkt, start_time, prev_idx,
						frag_offset, is_last_frag) ==
					INVALID_ARRAY_INDEX)
				return -1;
			return 0;
		}

		/* Ensure inserted items are ordered by frag_offset */
		if (frag_offset
			< tbl->items[cur_idx].frag_offset) {
			break;
		}

		prev_idx = cur_idx;
		cur_idx = tbl->items[cur_idx].next_pkt_idx;
	} while (cur_idx != INVALID_ARRAY_INDEX);

	/* Fail to find a neighbor, so store the packet into the flow. */
	if (cur_idx == tbl->flows[i].start_index) {
		/* Insert it before the first packet of the flow */
		item_idx = insert_new_item(tbl, pkt, start_time,
				INVALID_ARRAY_INDEX, frag_offset,
				is_last_frag);
		if (item_idx == INVALID_ARRAY_INDEX)
			return -1;
		tbl->items[item_idx].next_pkt_idx = cur_idx;
		tbl->flows[i].start_index = item_idx;
	} else {
		if (insert_new_item(tbl, pkt, start_time, prev_idx,
			frag_offset, is_last_frag) == INVALID_ARRAY_INDEX)
			return -1;
	}

	return 0;
}

static int
gro_udp6_merge_items(struct gro_udp6_tbl *tbl,
			   uint32_t start_idx)
{
	uint16_t frag_offset;
	uint8_t is_last_frag;
	int16_t ip_dl;
	struct rte_mbuf *pkt;
	int cmp;
	uint32_t item_idx;
	uint16_t hdr_len;

	item_idx = tbl->items[start_idx].next_pkt_idx;
	while (item_idx != INVALID_ARRAY_INDEX) {
		pkt = tbl->items[item_idx].firstseg;
		hdr_len = pkt->outer_l2_len + pkt->outer_l3_len + pkt->l2_len +
			pkt->l3_len;
		ip_dl = pkt->pkt_len - hdr_len;
		frag_offset = tbl->items[item_idx].frag_offset;
		is_last_frag = tbl->items[item_idx].is_last_frag;
		cmp = udp6_check_neighbor(&(tbl->items[start_idx]),
					frag_offset, ip_dl, 0);
		if (cmp) {
			if (merge_two_udp6_packets(
					&(tbl->items[start_idx]),
					pkt, cmp, frag_offset,
					is_last_frag, 0)) {
				item_idx = delete_item(tbl, item_idx,
							INVALID_ARRAY_INDEX);
				tbl->items[start_idx].next_pkt_idx
					= item_idx;
			} else {
				return 0;
			}
		} else {
			return 0;
		}
	}

	return 0;
}

uint16_t
gro_udp6_tbl_timeout_flush(struct gro_udp6_tbl *tbl,
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
			if (tbl->items[j].start_time <= flush_timestamp) {
				gro_udp6_merge_items(tbl, j);
				out[k++] = tbl->items[j].firstseg;
				if (tbl->items[j].nb_merged > 1)
					update_header(&(tbl->items[j]));
				/*
				 * Delete the packet and get the next
				 * packet in the flow.
				 */
				j = delete_item(tbl, j, INVALID_ARRAY_INDEX);
				tbl->flows[i].start_index = j;
				if (j == INVALID_ARRAY_INDEX)
					tbl->flow_num--;

				if (unlikely(k == nb_out))
					return k;
			} else
				/*
				 * The left packets in this flow won't be
				 * timeout. Go to check other flows.
				 */
				break;
		}
	}
	return k;
}

uint32_t
gro_udp6_tbl_pkt_count(void *tbl)
{
	struct gro_udp6_tbl *gro_tbl = tbl;

	if (gro_tbl)
		return gro_tbl->item_num;

	return 0;
}
