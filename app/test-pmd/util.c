/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <stdio.h>

#include <rte_bitops.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_dissect.h>
#include <rte_ether.h>
#include <rte_vxlan.h>
#include <rte_ethdev.h>
#include <rte_flow.h>

#include "testpmd.h"

#define MAX_STRING_LEN 8192
#define MAX_DUMP_LEN   1024

#define MKDUMPSTR(buf, buf_size, cur_len, ...) \
do { \
	if (cur_len >= buf_size) \
		break; \
	cur_len += snprintf(buf + cur_len, buf_size - cur_len, __VA_ARGS__); \
} while (0)

static inline void
print_ether_addr(const char *what, const struct rte_ether_addr *eth_addr,
		 char print_buf[], size_t buf_size, size_t *cur_len)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];

	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	MKDUMPSTR(print_buf, buf_size, *cur_len, "%s%s", what, buf);
}

static inline bool
is_timestamp_enabled(const struct rte_mbuf *mbuf)
{
	static uint64_t timestamp_rx_dynflag;
	int timestamp_rx_dynflag_offset;

	if (timestamp_rx_dynflag == 0) {
		timestamp_rx_dynflag_offset = rte_mbuf_dynflag_lookup(
				RTE_MBUF_DYNFLAG_RX_TIMESTAMP_NAME, NULL);
		if (timestamp_rx_dynflag_offset < 0)
			return false;
		timestamp_rx_dynflag = RTE_BIT64(timestamp_rx_dynflag_offset);
	}

	return (mbuf->ol_flags & timestamp_rx_dynflag) != 0;
}

static inline rte_mbuf_timestamp_t
get_timestamp(const struct rte_mbuf *mbuf)
{
	static int timestamp_dynfield_offset = -1;

	if (timestamp_dynfield_offset < 0) {
		timestamp_dynfield_offset = rte_mbuf_dynfield_lookup(
				RTE_MBUF_DYNFIELD_TIMESTAMP_NAME, NULL);
		if (timestamp_dynfield_offset < 0)
			return 0;
	}

	return *RTE_MBUF_DYNFIELD(mbuf,
			timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

static void
dump_pkt_verbose(FILE *outf, uint16_t port_id, uint16_t queue,
		 struct rte_mbuf *pkts[], uint16_t nb_pkts, int is_rx)
{
	struct rte_mbuf  *mb;
	const struct rte_ether_hdr *eth_hdr;
	struct rte_ether_hdr _eth_hdr;
	uint16_t eth_type;
	uint64_t ol_flags;
	uint16_t i, packet_type;
	uint16_t is_encapsulation;
	char buf[256];
	struct rte_net_hdr_lens hdr_lens;
	uint32_t sw_packet_type;
	uint16_t udp_port;
	uint32_t vx_vni;
	const char *reason;
	int dynf_index;
	char print_buf[MAX_STRING_LEN];
	size_t buf_size = MAX_STRING_LEN;
	size_t cur_len = 0;
	uint64_t restore_info_dynflag;

	restore_info_dynflag = rte_flow_restore_info_dynflag();
	MKDUMPSTR(print_buf, buf_size, cur_len,
		  "port %u/queue %u: %s %u packets\n", port_id, queue,
		  is_rx ? "received" : "sent", (unsigned int) nb_pkts);
	for (i = 0; i < nb_pkts; i++) {
		struct rte_flow_error error;
		struct rte_flow_restore_info info = { 0, };

		mb = pkts[i];
		ol_flags = mb->ol_flags;
		if (rxq_share > 0)
			MKDUMPSTR(print_buf, buf_size, cur_len, "port %u, ",
				  mb->port);
		eth_hdr = rte_pktmbuf_read(mb, 0, sizeof(_eth_hdr), &_eth_hdr);
		eth_type = RTE_BE_TO_CPU_16(eth_hdr->ether_type);
		packet_type = mb->packet_type;
		is_encapsulation = RTE_ETH_IS_TUNNEL_PKT(packet_type);
		if ((ol_flags & restore_info_dynflag) != 0 &&
				rte_flow_get_restore_info(port_id, mb, &info, &error) == 0) {
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  "restore info:");
			if (info.flags & RTE_FLOW_RESTORE_INFO_TUNNEL) {
				struct port_flow_tunnel *port_tunnel;

				port_tunnel = port_flow_locate_tunnel
					      (port_id, &info.tunnel);
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - tunnel");
				if (port_tunnel)
					MKDUMPSTR(print_buf, buf_size, cur_len,
						  " #%u", port_tunnel->id);
				else
					MKDUMPSTR(print_buf, buf_size, cur_len,
						  " %s", "-none-");
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " type %s", port_flow_tunnel_type
					  (&info.tunnel));
			} else {
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - no tunnel info");
			}
			if (info.flags & RTE_FLOW_RESTORE_INFO_ENCAPSULATED)
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - outer header present");
			else
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - no outer header");
			if (info.flags & RTE_FLOW_RESTORE_INFO_GROUP_ID)
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - miss group %u", info.group_id);
			else
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - no miss group");
			MKDUMPSTR(print_buf, buf_size, cur_len, "\n");
		}
		print_ether_addr("  src=", &eth_hdr->src_addr,
				 print_buf, buf_size, &cur_len);
		print_ether_addr(" - dst=", &eth_hdr->dst_addr,
				 print_buf, buf_size, &cur_len);
		MKDUMPSTR(print_buf, buf_size, cur_len,
			  " - pool=%s - type=0x%04x - length=%u - nb_segs=%d",
			  mb->pool->name, eth_type, (unsigned int) mb->pkt_len,
			  (int)mb->nb_segs);
		if (ol_flags & RTE_MBUF_F_RX_RSS_HASH) {
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - RSS hash=0x%x",
				  (unsigned int) mb->hash.rss);
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - RSS queue=0x%x", (unsigned int) queue);
		}
		if (ol_flags & RTE_MBUF_F_RX_FDIR) {
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - FDIR matched ");
			if (ol_flags & RTE_MBUF_F_RX_FDIR_ID)
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  "ID=0x%x", mb->hash.fdir.hi);
			else if (ol_flags & RTE_MBUF_F_RX_FDIR_FLX)
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  "flex bytes=0x%08x %08x",
					  mb->hash.fdir.hi, mb->hash.fdir.lo);
			else
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  "hash=0x%x ID=0x%x ",
					  mb->hash.fdir.hash, mb->hash.fdir.id);
		}
		if (is_timestamp_enabled(mb))
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - timestamp %"PRIu64" ", get_timestamp(mb));
		if ((is_rx && (ol_flags & RTE_MBUF_F_RX_QINQ) != 0) ||
				(!is_rx && (ol_flags & RTE_MBUF_F_TX_QINQ) != 0))
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - QinQ VLAN tci=0x%x, VLAN tci outer=0x%x",
				  mb->vlan_tci, mb->vlan_tci_outer);
		else if ((is_rx && (ol_flags & RTE_MBUF_F_RX_VLAN) != 0) ||
				(!is_rx && (ol_flags & RTE_MBUF_F_TX_VLAN) != 0))
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - VLAN tci=0x%x", mb->vlan_tci);
		if (!is_rx && (ol_flags & RTE_MBUF_DYNFLAG_TX_METADATA))
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - Tx metadata: 0x%x",
				  *RTE_FLOW_DYNF_METADATA(mb));
		if (is_rx && (ol_flags & RTE_MBUF_DYNFLAG_RX_METADATA))
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - Rx metadata: 0x%x",
				  *RTE_FLOW_DYNF_METADATA(mb));
		for (dynf_index = 0; dynf_index < 64; dynf_index++) {
			if (dynf_names[dynf_index][0] != '\0')
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - dynf %s: %d",
					  dynf_names[dynf_index],
					  !!(ol_flags & (1UL << dynf_index)));
		}
		if (mb->packet_type) {
			rte_get_ptype_name(mb->packet_type, buf, sizeof(buf));
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - hw ptype: %s", buf);
		}
		sw_packet_type = rte_net_get_ptype(mb, &hdr_lens,
					RTE_PTYPE_ALL_MASK);
		rte_get_ptype_name(sw_packet_type, buf, sizeof(buf));
		MKDUMPSTR(print_buf, buf_size, cur_len, " - sw ptype: %s", buf);
		if (sw_packet_type & RTE_PTYPE_L2_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len, " - l2_len=%d",
				  hdr_lens.l2_len);
		if (sw_packet_type & RTE_PTYPE_L3_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len, " - l3_len=%d",
				  hdr_lens.l3_len);
		if (sw_packet_type & RTE_PTYPE_L4_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len, " - l4_len=%d",
				  hdr_lens.l4_len);
		if (sw_packet_type & RTE_PTYPE_TUNNEL_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - tunnel_len=%d", hdr_lens.tunnel_len);
		if (sw_packet_type & RTE_PTYPE_INNER_L2_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - inner_l2_len=%d", hdr_lens.inner_l2_len);
		if (sw_packet_type & RTE_PTYPE_INNER_L3_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - inner_l3_len=%d", hdr_lens.inner_l3_len);
		if (sw_packet_type & RTE_PTYPE_INNER_L4_MASK)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - inner_l4_len=%d", hdr_lens.inner_l4_len);
		if (is_encapsulation) {
			struct rte_ipv4_hdr *ipv4_hdr;
			struct rte_ipv6_hdr *ipv6_hdr;
			struct rte_udp_hdr *udp_hdr;
			uint8_t l2_len;
			uint8_t l3_len;
			uint8_t l4_len;
			uint8_t l4_proto;
			struct  rte_vxlan_hdr *vxlan_hdr;

			l2_len  = sizeof(struct rte_ether_hdr);

			/* Do not support ipv4 option field */
			if (RTE_ETH_IS_IPV4_HDR(packet_type)) {
				l3_len = sizeof(struct rte_ipv4_hdr);
				ipv4_hdr = rte_pktmbuf_mtod_offset(mb,
				struct rte_ipv4_hdr *,
				l2_len);
				l4_proto = ipv4_hdr->next_proto_id;
			} else {
				l3_len = sizeof(struct rte_ipv6_hdr);
				ipv6_hdr = rte_pktmbuf_mtod_offset(mb,
				struct rte_ipv6_hdr *,
				l2_len);
				l4_proto = ipv6_hdr->proto;
			}
			if (l4_proto == IPPROTO_UDP) {
				udp_hdr = rte_pktmbuf_mtod_offset(mb,
				struct rte_udp_hdr *,
				l2_len + l3_len);
				l4_len = sizeof(struct rte_udp_hdr);
				vxlan_hdr = rte_pktmbuf_mtod_offset(mb,
				struct rte_vxlan_hdr *,
				l2_len + l3_len + l4_len);
				udp_port = RTE_BE_TO_CPU_16(udp_hdr->dst_port);
				vx_vni = rte_be_to_cpu_32(vxlan_hdr->vx_vni);
				MKDUMPSTR(print_buf, buf_size, cur_len,
					  " - VXLAN packet: packet type =%d, "
					  "Destination UDP port =%d, VNI = %d, "
					  "last_rsvd = %d", packet_type,
					  udp_port, vx_vni >> 8, vx_vni & 0xff);
			}
		}
		MKDUMPSTR(print_buf, buf_size, cur_len,
			  " - %s queue=0x%x", is_rx ? "Receive" : "Send",
			  (unsigned int) queue);
		MKDUMPSTR(print_buf, buf_size, cur_len, "\n");
		if (is_rx)
			rte_get_rx_ol_flag_list(mb->ol_flags, buf, sizeof(buf));
		else
			rte_get_tx_ol_flag_list(mb->ol_flags, buf, sizeof(buf));

		MKDUMPSTR(print_buf, buf_size, cur_len,
			  "  ol_flags: %s\n", buf);
		if (rte_mbuf_check(mb, 1, &reason) < 0)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  "INVALID mbuf: %s\n", reason);
		if (cur_len >= buf_size)
			fprintf(outf, "%s ...\n", print_buf);
		else
			fprintf(outf, "%s", print_buf);
		cur_len = 0;
	}
}

#ifdef RTE_HAS_JANSSON

/* Encode offload flags as JSON array */
static json_t *
encode_ol_flags(uint64_t flags, int is_rx)
{
	json_t *ol_array = json_array();
	unsigned int i;

	if (is_rx)
		flags &= ~RTE_MBUF_F_TX_OFFLOAD_MASK;
	else
		flags &= RTE_MBUF_F_TX_OFFLOAD_MASK;

	for (i = 0; i < 64; i++) {
		uint64_t mask = (uint64_t)1 << i;
		const char *name;

		if (!(mask & flags))
			continue;

		if (is_rx)
			name = rte_get_rx_ol_flag_name(mask);
		else
			name = rte_get_tx_ol_flag_name(mask);
		json_array_append_new(ol_array, json_string(name));
	}
	return ol_array;
}

/* Encode packet type fields as JSON object */
static json_t *
encode_ptype(uint32_t ptype)
{
	if ((ptype & RTE_PTYPE_ALL_MASK) == RTE_PTYPE_UNKNOWN)
		return json_string("UNKNOWN");

	json_t *ptypes = json_array();
	if (ptype & RTE_PTYPE_L2_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_l2_name(ptype)));
	if (ptype & RTE_PTYPE_L3_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_l3_name(ptype)));
	if (ptype & RTE_PTYPE_L4_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_l4_name(ptype)));
	if (ptype & RTE_PTYPE_TUNNEL_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_tunnel_name(ptype)));
	if (ptype & RTE_PTYPE_INNER_L2_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_inner_l2_name(ptype)));
	if (ptype & RTE_PTYPE_INNER_L3_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_inner_l3_name(ptype)));
	if (ptype & RTE_PTYPE_INNER_L4_MASK)
		json_array_append(ptypes, json_string(rte_get_ptype_inner_l4_name(ptype)));

	return ptypes;
}

static void
dump_pkt_json(FILE *outf, uint16_t port_id, uint16_t queue,
	      struct rte_mbuf *pkts[], uint16_t nb_pkts, int is_rx)
{
	char buf[256];

	for (uint16_t i = 0; i < nb_pkts; i++) {
		const struct rte_mbuf *mb = pkts[i];
		struct rte_net_hdr_lens hdr_lens;
		const struct rte_ether_hdr *eth_hdr;
		struct rte_ether_hdr _eth_hdr;
		uint16_t eth_type;
		uint64_t ol_flags = mb->ol_flags;
		const char *reason = NULL;
		json_t *jobj;

		jobj = json_object();
		json_object_set_new(jobj, "port", json_integer(port_id));
		json_object_set_new(jobj, "queue", json_integer(queue));
		json_object_set_new(jobj, "is_rx", json_boolean(is_rx));

		if (rte_mbuf_check(mb, 1, &reason) < 0) {
			json_object_set_new(jobj, "invalid", json_string(reason));
			continue;
		}

		eth_hdr = rte_pktmbuf_read(mb, 0, sizeof(_eth_hdr), &_eth_hdr);
		eth_type = RTE_BE_TO_CPU_16(eth_hdr->ether_type);

		rte_ether_format_addr(buf, sizeof(buf), &eth_hdr->dst_addr);
		json_object_set_new(jobj, "dst", json_string(buf));
		rte_ether_format_addr(buf, sizeof(buf), &eth_hdr->src_addr);
		json_object_set_new(jobj, "src", json_string(buf));

		snprintf(buf, sizeof(buf), "0x%04x", eth_type);
		json_object_set_new(jobj, "type", json_string(buf));

		json_object_set_new(jobj, "length", json_integer(mb->pkt_len));
		json_object_set_new(jobj, "nb_segs", json_integer(mb->nb_segs));

		if (ol_flags & RTE_MBUF_F_RX_RSS_HASH)
			json_object_set_new(jobj, "rss_hash", json_integer(mb->hash.rss));

		if (ol_flags & RTE_MBUF_F_RX_FDIR) {
			json_t *fdir = json_object();

			if (ol_flags & RTE_MBUF_F_RX_FDIR_ID)
				json_object_set_new(fdir, "id",
						    json_integer(mb->hash.fdir.hi));
			else if (ol_flags & RTE_MBUF_F_RX_FDIR_FLX) {
				json_t *bytes = json_array();

				json_array_append(bytes, json_integer(mb->hash.fdir.hi));
				json_array_append(bytes, json_integer(mb->hash.fdir.lo));
				json_object_set_new(fdir, "flex", bytes);
			} else {
				json_object_set_new(fdir, "hash", json_integer(mb->hash.fdir.hash));
				json_object_set_new(fdir, "id",  json_integer(mb->hash.fdir.id));
			}
		}

		if (is_timestamp_enabled(mb))
			json_object_set_new(jobj, "timestamp", json_integer(get_timestamp(mb)));

		if ((is_rx && (ol_flags & RTE_MBUF_F_RX_QINQ) != 0) ||
		    (!is_rx && (ol_flags & RTE_MBUF_F_TX_QINQ) != 0)) {
			json_object_set_new(jobj, "vlan_tci", json_integer(mb->vlan_tci));
			json_object_set_new(jobj, "vlan_outer_tci",
					    json_integer(mb->vlan_tci_outer));
		} else if ((is_rx && (ol_flags & RTE_MBUF_F_RX_VLAN) != 0) ||
			   (!is_rx && (ol_flags & RTE_MBUF_F_TX_VLAN) != 0)) {
			json_object_set_new(jobj, "vlan_tci", json_integer(mb->vlan_tci));
		}

		if (mb->packet_type)
			json_object_set_new(jobj, "hw_ptype", encode_ptype(mb->packet_type));

		uint32_t sw_packet_type = rte_net_get_ptype(mb, &hdr_lens, RTE_PTYPE_ALL_MASK);
		json_object_set_new(jobj, "sw_ptype", encode_ptype(sw_packet_type));

		if (sw_packet_type & RTE_PTYPE_L2_MASK)
			json_object_set_new(jobj, "l2_len", json_integer(hdr_lens.l2_len));
		if (sw_packet_type & RTE_PTYPE_L3_MASK)
			json_object_set_new(jobj, "l3_len", json_integer(hdr_lens.l3_len));
		if (sw_packet_type & RTE_PTYPE_L4_MASK)
			json_object_set_new(jobj, "l4_len", json_integer(hdr_lens.l4_len));
		if (sw_packet_type & RTE_PTYPE_TUNNEL_MASK)
			json_object_set_new(jobj, "tunnel_len", json_integer(hdr_lens.tunnel_len));
		if (sw_packet_type & RTE_PTYPE_INNER_L2_MASK)
			json_object_set_new(jobj, "inner_l2_len",
					    json_integer(hdr_lens.inner_l2_len));
		if (sw_packet_type & RTE_PTYPE_INNER_L3_MASK)
			json_object_set_new(jobj, "inner_l3_len",
					    json_integer(hdr_lens.inner_l3_len));
		if (sw_packet_type & RTE_PTYPE_INNER_L4_MASK)
			json_object_set_new(jobj, "inner_l4_len",
					    json_integer(hdr_lens.inner_l4_len));

		json_object_set_new(jobj, "ol_flags", encode_ol_flags(mb->ol_flags, is_rx));

		json_dumpf(jobj, outf, JSON_INDENT(4));
		json_decref(jobj);
	}
}
#endif

static void
dump_pkt_hex(FILE *outf, uint16_t port_id, uint16_t queue,
	     struct rte_mbuf *pkts[], uint16_t nb_pkts, int is_rx)
{
	fprintf(outf, "port %u/queue %u: %s %u packets\n", port_id, queue,
		  is_rx ? "received" : "sent", (unsigned int) nb_pkts);

	for (uint16_t i = 0; i < nb_pkts; i++) {
		rte_pktmbuf_dump(outf, pkts[i], MAX_DUMP_LEN);
		fprintf(outf, "\n");
	}
}

/* Brief tshark style one line output which is
 * number time_delta Source Destination Protocol len info
 */
static void
dump_pkt_brief(FILE *outf, uint16_t port, uint16_t queue,
	       struct rte_mbuf *pkts[], uint16_t nb_pkts, int is_rx)
{
	static uint64_t start_cycles;
	static RTE_ATOMIC(uint64_t) packet_count = 1;
	uint64_t now, count;
	double interval;

	/* Compute time interval from the first packet received */
	now = rte_rdtsc();
	if (start_cycles == 0) {
		start_cycles = now;
		printf("Seq#   Time        Port:Que R Description\n");
	}
	interval = (double)(now - start_cycles) / (double)rte_get_tsc_hz();

	/* Packet counter needs to be thread safe */
	count = rte_atomic_fetch_add_explicit(&packet_count, nb_pkts, rte_memory_order_relaxed);

	for (uint16_t i = 0; i < nb_pkts; i++) {
		const struct rte_mbuf *mb = pkts[i];
		char str[256];

		rte_dissect_mbuf(str, sizeof(str), mb, 0);
		fprintf(outf, "%6"PRIu64" %11.9f %4u:%-3u %c %s\n",
		       count + i, interval, port, queue, is_rx ? 'R' : 'T', str);
	}
}

static void
dump_pkt_burst(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
	      uint16_t nb_pkts, int is_rx)
{
	FILE *outf;

	if (!nb_pkts)
		return;

	outf = rte_atomic_load_explicit(&output_file, rte_memory_order_relaxed);
	if (unlikely(!outf))
		return;

	switch (output_format) {
	case OUTPUT_MODE_VERBOSE:
		dump_pkt_verbose(outf, port_id, queue, pkts, nb_pkts, is_rx);
		return;
	case OUTPUT_MODE_HEX:
		dump_pkt_hex(outf, port_id, queue, pkts, nb_pkts, is_rx);
		break;
	case OUTPUT_MODE_DISSECT:
		dump_pkt_brief(outf, port_id, queue, pkts, nb_pkts, is_rx);
		break;
#ifdef RTE_HAS_JANSSON
	case OUTPUT_MODE_JSON:
		dump_pkt_json(outf, port_id, queue, pkts, nb_pkts, is_rx);
		break;
#endif
	default:
		return;
	}
	fflush(outf);
}

uint16_t
dump_rx_pkts(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
	     uint16_t nb_pkts, __rte_unused uint16_t max_pkts,
	     __rte_unused void *user_param)
{
	dump_pkt_burst(port_id, queue, pkts, nb_pkts, 1);
	return nb_pkts;
}

uint16_t
dump_tx_pkts(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
	     uint16_t nb_pkts, __rte_unused void *user_param)
{
	dump_pkt_burst(port_id, queue, pkts, nb_pkts, 0);
	return nb_pkts;
}

uint16_t
tx_pkt_set_md(uint16_t port_id, __rte_unused uint16_t queue,
	      struct rte_mbuf *pkts[], uint16_t nb_pkts,
	      __rte_unused void *user_param)
{
	uint16_t i = 0;

	/*
	 * Add metadata value to every Tx packet,
	 * and set ol_flags accordingly.
	 */
	if (rte_flow_dynf_metadata_avail())
		for (i = 0; i < nb_pkts; i++) {
			*RTE_FLOW_DYNF_METADATA(pkts[i]) =
						ports[port_id].tx_metadata;
			pkts[i]->ol_flags |= RTE_MBUF_DYNFLAG_TX_METADATA;
		}
	return nb_pkts;
}

void
add_tx_md_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (!ports[portid].tx_set_md_cb[queue])
			ports[portid].tx_set_md_cb[queue] =
				rte_eth_add_tx_callback(portid, queue,
							tx_pkt_set_md, NULL);
}

void
remove_tx_md_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (ports[portid].tx_set_md_cb[queue]) {
			rte_eth_remove_tx_callback(portid, queue,
				ports[portid].tx_set_md_cb[queue]);
			ports[portid].tx_set_md_cb[queue] = NULL;
		}
}

uint16_t
tx_pkt_set_dynf(uint16_t port_id, __rte_unused uint16_t queue,
		struct rte_mbuf *pkts[], uint16_t nb_pkts,
		__rte_unused void *user_param)
{
	uint16_t i = 0;

	if (ports[port_id].mbuf_dynf)
		for (i = 0; i < nb_pkts; i++)
			pkts[i]->ol_flags |= ports[port_id].mbuf_dynf;
	return nb_pkts;
}

void
add_tx_dynf_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (!ports[portid].tx_set_dynf_cb[queue])
			ports[portid].tx_set_dynf_cb[queue] =
				rte_eth_add_tx_callback(portid, queue,
							tx_pkt_set_dynf, NULL);
}

void
remove_tx_dynf_callback(portid_t portid)
{
	struct rte_eth_dev_info dev_info;
	uint16_t queue;
	int ret;

	if (port_id_is_invalid(portid, ENABLED_WARN))
		return;

	ret = eth_dev_info_get_print_err(portid, &dev_info);
	if (ret != 0)
		return;

	for (queue = 0; queue < dev_info.nb_tx_queues; queue++)
		if (ports[portid].tx_set_dynf_cb[queue]) {
			rte_eth_remove_tx_callback(portid, queue,
				ports[portid].tx_set_dynf_cb[queue]);
			ports[portid].tx_set_dynf_cb[queue] = NULL;
		}
}

int
eth_dev_info_get_print_err(uint16_t port_id,
					struct rte_eth_dev_info *dev_info)
{
	int ret;

	ret = rte_eth_dev_info_get(port_id, dev_info);
	if (ret != 0)
		fprintf(stderr,
			"Error during getting device (port %u) info: %s\n",
			port_id, strerror(-ret));

	return ret;
}

int
eth_dev_conf_get_print_err(uint16_t port_id, struct rte_eth_conf *dev_conf)
{
	int ret;

	ret = rte_eth_dev_conf_get(port_id, dev_conf);
	if (ret != 0)
		fprintf(stderr,
			"Error during getting device configuration (port %u): %s\n",
			port_id, strerror(-ret));

	return ret;
}

void
eth_set_promisc_mode(uint16_t port, int enable)
{
	int ret;

	if (enable)
		ret = rte_eth_promiscuous_enable(port);
	else
		ret = rte_eth_promiscuous_disable(port);

	if (ret != 0)
		fprintf(stderr,
			"Error during %s promiscuous mode for port %u: %s\n",
			enable ? "enabling" : "disabling",
			port, rte_strerror(-ret));
}

void
eth_set_allmulticast_mode(uint16_t port, int enable)
{
	int ret;

	if (enable)
		ret = rte_eth_allmulticast_enable(port);
	else
		ret = rte_eth_allmulticast_disable(port);

	if (ret != 0)
		fprintf(stderr,
			"Error during %s all-multicast mode for port %u: %s\n",
			enable ? "enabling" : "disabling",
			port, rte_strerror(-ret));
}

int
eth_link_get_nowait_print_err(uint16_t port_id, struct rte_eth_link *link)
{
	int ret;

	ret = rte_eth_link_get_nowait(port_id, link);
	if (ret < 0)
		fprintf(stderr,
			"Device (port %u) link get (without wait) failed: %s\n",
			port_id, rte_strerror(-ret));

	return ret;
}

int
eth_macaddr_get_print_err(uint16_t port_id, struct rte_ether_addr *mac_addr)
{
	int ret;

	ret = rte_eth_macaddr_get(port_id, mac_addr);
	if (ret != 0)
		fprintf(stderr,
			"Error getting device (port %u) mac address: %s\n",
			port_id, rte_strerror(-ret));

	return ret;
}
