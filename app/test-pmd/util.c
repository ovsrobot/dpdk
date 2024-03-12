/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright 2018 Mellanox Technologies, Ltd
 */

#include <stdio.h>

#include <rte_bitops.h>
#include <rte_net.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
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

/* More verbose older style packet decode */
static void
dump_pkt_verbose(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
		 uint16_t nb_pkts, int is_rx)
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

	if (!nb_pkts)
		return;
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
		if (ol_flags & RTE_MBUF_F_RX_QINQ)
			MKDUMPSTR(print_buf, buf_size, cur_len,
				  " - QinQ VLAN tci=0x%x, VLAN tci outer=0x%x",
				  mb->vlan_tci, mb->vlan_tci_outer);
		else if (ol_flags & RTE_MBUF_F_RX_VLAN)
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
			printf("%s ...\n", print_buf);
		else
			printf("%s", print_buf);
		cur_len = 0;
	}
}

static void
dissect_arp(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_arp_hdr *arp;
	struct rte_arp_hdr _arp;
	uint16_t ar_op;
	char buf[128];

	arp = rte_pktmbuf_read(mb, offset, sizeof(*arp), &_arp);
	if (unlikely(arp == NULL)) {
		printf("truncated ARP! ");
		return;
	}

	ar_op = RTE_BE_TO_CPU_16(arp->arp_opcode);
	switch (ar_op) {
	case RTE_ARP_OP_REQUEST:
		inet_ntop(AF_INET, &arp->arp_data.arp_tip, buf, sizeof(buf));
		printf("Who has %s? ", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		printf("Tell %s ", buf);
		break;
	case RTE_ARP_OP_REPLY:
		inet_ntop(AF_INET, &arp->arp_data.arp_sip, buf, sizeof(buf));
		printf("%s is at", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		printf("%s ", buf);
		break;
	case RTE_ARP_OP_INVREQUEST:
		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_tha);
		printf("Who is %s? ", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		printf("Tell %s ", buf);
		break;

	case RTE_ARP_OP_INVREPLY:
		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		printf("%s is at ", buf);

		inet_ntop(AF_INET, &arp->arp_data.arp_sip, buf, sizeof(buf));
		printf("%s ", buf);
		break;
	default:
		printf("Unknown ARP %#x ", ar_op);
		break;
	}
}

static void
dissect_udp(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_udp_hdr *udph;
	struct rte_udp_hdr _udp;
	uint16_t src_port, dst_port;

	udph = rte_pktmbuf_read(mb, offset, sizeof(*udph), &_udp);
	if (unlikely(udph == NULL)) {
		printf("truncated UDP! ");
		return;
	}

	src_port = RTE_BE_TO_CPU_16(udph->src_port);
	dst_port = RTE_BE_TO_CPU_16(udph->dst_port);

	/* TODO handle vxlan */

	printf("UDP %u %u → %u ",
		  RTE_BE_TO_CPU_16(udph->dgram_len),
		  src_port, dst_port);

}

static void
dissect_tcp(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_tcp_hdr *tcph;
	struct rte_tcp_hdr _tcp;
	uint16_t src_port, dst_port;

	tcph = rte_pktmbuf_read(mb, offset, sizeof(*tcph), &_tcp);
	if (unlikely(tcph == NULL)) {
		printf("truncated TCP! ");
		return;
	}

	src_port = RTE_BE_TO_CPU_16(tcph->src_port);
	dst_port = RTE_BE_TO_CPU_16(tcph->dst_port);

	printf("TCP %u → %u",
		  src_port, dst_port);
#define PRINT_TCP_FLAG(flag) \
	if (tcph->tcp_flags & RTE_TCP_ ## flag ## _FLAG) \
		printf(" [" #flag" ]")

	PRINT_TCP_FLAG(URG);
	PRINT_TCP_FLAG(ACK);
	PRINT_TCP_FLAG(RST);
	PRINT_TCP_FLAG(SYN);
	PRINT_TCP_FLAG(FIN);
#undef PRINT_TCP_FLAG

	printf("Seq=%u Ack=%u Win=%u ",
		  RTE_BE_TO_CPU_16(tcph->sent_seq),
		  RTE_BE_TO_CPU_16(tcph->recv_ack),
		  RTE_BE_TO_CPU_16(tcph->rx_win));
}

static void
dissect_icmp(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_icmp_hdr *icmp;
	struct rte_icmp_hdr _icmp;
	static const char * const icmp_types[256] = {
		[RTE_IP_ICMP_ECHO_REPLY]   = "ICMP Reply",
		[RTE_IP_ICMP_ECHO_REQUEST] = "ICMP Request",
		[RTE_ICMP6_ECHO_REPLY]     = "ICMPv6 Reply",
		[RTE_ICMP6_ECHO_REQUEST]   = "ICMPv6 Request",
		[133]                      = "ICMPv6 Router Solicitation",
		[134]                      = "ICMPv6 Router Solicitation",
	};


	icmp = rte_pktmbuf_read(mb, offset, sizeof(*icmp), &_icmp);
	if (unlikely(icmp == NULL)) {
		printf("truncated ICMP! ");
	} else {
		const char *name = icmp_types[icmp->icmp_type];

		if (name != NULL)
			printf("%s ", name);
		else
			printf("ICMP type %u ", icmp->icmp_type);
	}
}

static void
dissect_ipv4(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_ipv4_hdr *ip_hdr;
	struct rte_ipv4_hdr _ip_hdr;
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

	ip_hdr = rte_pktmbuf_read(mb, offset, sizeof(*ip_hdr), &_ip_hdr);
	if (unlikely(ip_hdr == NULL)) {
		printf("truncated IP! ");
		return;
	}

	inet_ntop(AF_INET, &ip_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET, &ip_hdr->dst_addr, dbuf, sizeof(dbuf));
	printf("%s → %s ", sbuf, dbuf);

	offset += ip_hdr->ihl * 4;
	switch (ip_hdr->next_proto_id) {
	case IPPROTO_UDP:
		return dissect_udp(mb, offset);
	case IPPROTO_TCP:
		return dissect_tcp(mb, offset);
	case IPPROTO_ICMP:
		return dissect_icmp(mb, offset);
	default:
		/* TODO dissect tunnels */
		printf("IP proto %#x ", ip_hdr->next_proto_id);
	}
}

static void
dissect_ipv6(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_hdr _ip6_hdr;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	uint16_t proto;
	unsigned int i;

	ip6_hdr = rte_pktmbuf_read(mb, offset, sizeof(*ip6_hdr), &_ip6_hdr);
	if (unlikely(ip6_hdr == NULL)) {
		printf("truncated IPv6! ");
		return;
	}
	offset += sizeof(*ip6_hdr);

	inet_ntop(AF_INET6, ip6_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET6, ip6_hdr->dst_addr, dbuf, sizeof(dbuf));
	printf("%s → %s ", sbuf, dbuf);

#define MAX_EXT_HDRS 5
	proto = ip6_hdr->proto;
	for (i = 0; i < MAX_EXT_HDRS; i++) {
		switch (proto) {
		case IPPROTO_UDP:
			return dissect_udp(mb, offset);
		case IPPROTO_TCP:
			return dissect_tcp(mb, offset);
		case IPPROTO_ICMPV6:
			return dissect_icmp(mb, offset);

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			const struct rte_ipv6_routing_ext *xh;
			struct rte_ipv6_routing_ext _xh;

			xh = rte_pktmbuf_read(mb, offset, sizeof(*xh), &_xh);
			if (unlikely(xh == NULL)) {
				printf("truncated IPV6 option! ");
				return;
			}
			offset += (xh->hdr_len + 1) * 8;
			proto = xh->next_hdr;
			continue;
		}

		case IPPROTO_FRAGMENT:
			printf("FRAG ");
			return;

		case IPPROTO_NONE:
			printf("NONE ");
			return;

		default:
			printf("IPv6 proto %u ", proto);
			return;
		}
	}

	printf("Too many extensions! ");
}

static void
dissect_eth(const struct rte_mbuf *mb, uint16_t offset)
{
	const struct rte_ether_hdr *eth_hdr;
	struct rte_ether_hdr _eth_hdr;
	uint16_t eth_type;
	char sbuf[RTE_ETHER_ADDR_FMT_SIZE], dbuf[RTE_ETHER_ADDR_FMT_SIZE];

	eth_hdr = rte_pktmbuf_read(mb, offset, sizeof(struct rte_ether_hdr), &_eth_hdr);
	if (unlikely(eth_hdr == NULL)) {
		printf("missing Eth header! offset=%u", offset);
		return;
	}

	offset += sizeof(*eth_hdr);
	eth_type = RTE_BE_TO_CPU_16(eth_hdr->ether_type);
	if (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vh
			= (const struct rte_vlan_hdr *)(eth_hdr + 1);
		eth_type = vh->eth_proto;
		offset += sizeof(*vh);

		printf("%s %#x ", eth_type == RTE_ETHER_TYPE_VLAN ? "VLAN" : "QINQ",
		       RTE_BE_TO_CPU_16(vh->vlan_tci));
	}

	switch (eth_type) {
	case RTE_ETHER_TYPE_ARP:
		rte_ether_format_addr(sbuf, sizeof(sbuf), &eth_hdr->src_addr);
		rte_ether_format_addr(sbuf, sizeof(dbuf), &eth_hdr->dst_addr);
		printf("%s → %s ARP ", sbuf, dbuf);

		dissect_arp(mb, offset);
		break;
	case RTE_ETHER_TYPE_IPV4:
		dissect_ipv4(mb, offset);
		break;

	case RTE_ETHER_TYPE_IPV6:
		dissect_ipv6(mb, offset);
		break;
	default:
		printf("Ethernet proto %#x ", eth_type);
	}
}

/* Brief tshark style one line output which is
 * number time_delta Source Destination Protocol len info
 */
static void
dump_pkt_brief(uint16_t queue, struct rte_mbuf *pkts[], uint16_t nb_pkts)
{
	static uint64_t start_cycles;
	static uint64_t packet_count;
	uint64_t now;
	uint64_t count;
	double interval;
	uint16_t i;

	if (!nb_pkts)
		return;

	now = rte_rdtsc();
	if (start_cycles == 0)
		start_cycles = now;
	interval = (double)(now - start_cycles) / (double)rte_get_tsc_hz();

	count = __atomic_fetch_add(&packet_count, nb_pkts, __ATOMIC_RELAXED);

	for (i = 0; i < nb_pkts; i++) {
		const struct rte_mbuf *mb = pkts[i];

		printf("%6"PRIu64" %11.9f %4u:%-3u ", count + i, interval, mb->port, queue);
		dissect_eth(mb, 0);
		putchar('\n');
	}
	fflush(stdout);
}

/* Hex dump of packet data */
static void
dump_pkt_hex(struct rte_mbuf *pkts[], uint16_t nb_pkts)
{
	uint16_t i;

	for (i = 0; i < nb_pkts; i++)
		rte_pktmbuf_dump(stdout, pkts[i], MAX_DUMP_LEN);

	fflush(stdout);
}

static uint16_t
dump_pkt_burst(uint16_t port_id, uint16_t queue, struct rte_mbuf *pkts[],
	      uint16_t nb_pkts, int is_rx)
{
	switch (verbose_level) {
	case VERBOSE_RX ... VERBOSE_BOTH:
		dump_pkt_verbose(port_id, queue, pkts, nb_pkts, is_rx);
		break;
	case VERBOSE_DISSECT:
		dump_pkt_brief(queue, pkts, nb_pkts);
		break;
	case VERBOSE_HEX:
		dump_pkt_hex(pkts, nb_pkts);
	}
	return nb_pkts;
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
