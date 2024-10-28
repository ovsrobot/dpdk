/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Stephen Hemminger <stephen@networkplumber.org>
 *
 * Print packets in format similar to tshark.
 * Output should be one line per mbuf
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>

#include <rte_arp.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_dissect.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

/* Forward declaration - Ethernet can be nested */
static int
dissect_eth(char *buf, size_t size, const struct rte_mbuf *mb,
	    uint32_t offset, uint32_t dump_len);

/*
 * Read data from segmented mbuf and put it into buf , but stop if would go past max length
 * See rte_pktmbuf_read()
 */
static const void *
dissect_read(const struct rte_mbuf *m, uint32_t offset, uint32_t len,
	     void *buf, uint32_t dump_len)
{

	/* If this header would be past the requested length */
	if (dump_len > 0 && offset + len > dump_len)
		return NULL;

	return rte_pktmbuf_read(m, offset, len, buf);
}

/*
 * Print to string buffer and adjust result
 * Returns true on success, false if buffer is exhausted.
 */
static __rte_format_printf(3, 4) int
dissect_print(char **buf, size_t *sz, const char *fmt, ...)
{
	va_list ap;
	int count;

	va_start(ap, fmt);
	count = vsnprintf(*buf, *sz, fmt, ap);
	va_end(ap);

	/* error or string is full */
	if (count < 0 || count >= (int)*sz) {
		*sz = 0;
	} else {
		*buf += count;
		*sz -= count;
	}
	return count;
}

static int
dissect_arp(char *buf, size_t size, const struct rte_mbuf *mb,
	    uint32_t offset, uint32_t dump_len)
{
	const struct rte_arp_hdr *arp;
	struct rte_arp_hdr _arp;
	int count = 0;
	char abuf[64];

	arp = dissect_read(mb, offset, sizeof(_arp), &_arp, dump_len);
	if (arp == NULL)
		return snprintf(buf, size, "Missing ARP header");

	offset += sizeof(_arp);

	uint16_t ar_op = rte_be_to_cpu_16(arp->arp_opcode);
	switch (ar_op) {
	case RTE_ARP_OP_REQUEST:
		inet_ntop(AF_INET, &arp->arp_data.arp_tip, abuf, sizeof(abuf));
		count += dissect_print(&buf, &size, "Who has %s? ", abuf);

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		count += dissect_print(&buf, &size, "Tell %s ", abuf);
		break;

	case RTE_ARP_OP_REPLY:
		inet_ntop(AF_INET, &arp->arp_data.arp_sip, abuf, sizeof(abuf));
		count += dissect_print(&buf, &size, "%s is at", abuf);

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		count += dissect_print(&buf, &size, "%s ", abuf);
		break;

	case RTE_ARP_OP_INVREQUEST:
		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_tha);
		count += dissect_print(&buf, &size, "Who is %s? ", abuf);

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		count += dissect_print(&buf, &size, "Tell %s ", abuf);
		break;

	case RTE_ARP_OP_INVREPLY:
		rte_ether_format_addr(abuf, sizeof(buf), &arp->arp_data.arp_sha);
		count += dissect_print(&buf, &size, "%s is at ", abuf);

		inet_ntop(AF_INET, &arp->arp_data.arp_sip, abuf, sizeof(abuf));
		count += dissect_print(&buf, &size, "%s ", abuf);
		break;

	default:
		count += dissect_print(&buf, &size, "Unknown ARP %#x ", ar_op);
		break;
	}

	return count;
}

static int
dissect_vxlan(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_vxlan_hdr *vxlan;
	struct rte_vxlan_hdr _vxlan;
	int count = 0;

	vxlan = dissect_read(mb, offset, sizeof(_vxlan), &_vxlan, dump_len);
	if (vxlan == NULL)
		return snprintf(buf, size, "Missing VXLAN header");

	offset += sizeof(_vxlan);

	if (vxlan->flag_i) {
		uint32_t vni = rte_be_to_cpu_32(vxlan->vx_vni);

		count += dissect_print(&buf, &size, "%#x ", vni >> 8);
	}

	count += dissect_eth(buf, size, mb, offset, dump_len);
	return count;
}

static int
dissect_udp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_udp_hdr *udph;
	struct rte_udp_hdr _udp;
	uint16_t src_port, dst_port, len;

	udph = dissect_read(mb, offset, sizeof(_udp), &_udp, dump_len);
	if (udph == NULL)
		return snprintf(buf, size, "Missing UDP header");

	offset += sizeof(_udp);
	src_port = rte_be_to_cpu_16(udph->src_port);
	dst_port = rte_be_to_cpu_16(udph->dst_port);
	len = rte_be_to_cpu_16(udph->dgram_len);

	switch (dst_port) {
	case RTE_VXLAN_DEFAULT_PORT:
		return dissect_vxlan(buf, size, mb, offset, dump_len);
	default:
		return dissect_print(&buf, &size, "UDP %u %u → %u ", len, src_port, dst_port);
	}
}

static int
dissect_tcp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_tcp_hdr *tcph;
	struct rte_tcp_hdr _tcp;
	uint16_t src_port, dst_port;
	int count;

	tcph = dissect_read(mb, offset, sizeof(_tcp), &_tcp, dump_len);
	if (tcph == NULL)
		return snprintf(buf, size, "Missing TCP header");

	offset += sizeof(_tcp);
	src_port = rte_be_to_cpu_16(tcph->src_port);
	dst_port = rte_be_to_cpu_16(tcph->dst_port);

	count = dissect_print(&buf, &size, "TCP %u → %u", src_port, dst_port);

#define PRINT_TCP_FLAG(flag) do {					\
	if (tcph->tcp_flags & RTE_TCP_ ## flag ## _FLAG)		\
		count += dissect_print(&buf, &size, " [ " #flag " ]");	\
	} while (0)

	PRINT_TCP_FLAG(URG);
	PRINT_TCP_FLAG(ACK);
	PRINT_TCP_FLAG(RST);
	PRINT_TCP_FLAG(SYN);
	PRINT_TCP_FLAG(FIN);
#undef PRINT_TCP_FLAG

	count += dissect_print(&buf, &size, "Seq=%u Ack=%u Win=%u ",
			       rte_be_to_cpu_16(tcph->sent_seq),
			       rte_be_to_cpu_16(tcph->recv_ack),
			       rte_be_to_cpu_16(tcph->rx_win));
	return count;
}

static int
dissect_icmp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_icmp_hdr *icmp;
	struct rte_icmp_hdr _icmp;
	static const char * const icmp_types[256] = {
		[RTE_ICMP_TYPE_ECHO_REPLY]     = "ICMP Echo Reply",
		[RTE_ICMP_TYPE_DEST_UNREACHABLE]  = "ICMP Destination Unreachable",
		[RTE_ICMP_TYPE_SOURCE_QUENCH]  = "ICMP Source Quench",
		[RTE_ICMP_TYPE_REDIRECT]       = "ICMP Redirect",
		[RTE_ICMP_TYPE_ECHO_REQUEST]   = "ICMP Echo Request",
		[RTE_ICMP_TYPE_TTL_EXCEEDED]        = "ICMP TTL Exceeded",
		[RTE_ICMP_TYPE_PARAM_PROBLEM]  = "ICMP Parameter Problem",
		[RTE_ICMP_TYPE_TIMESTAMP_REQUEST] = "ICMP Timestamp Request",
		[RTE_ICMP_TYPE_TIMESTAMP_REPLY] = "ICMP Timestamp Reply",
		[RTE_ICMP_TYPE_INFO_REQUEST]   = "ICMP Info Request",
		[RTE_ICMP_TYPE_INFO_REPLY]     = "ICMP Info Reply",

		[RTE_ICMP6_ECHO_REPLY]     = "ICMPv6 Echo Reply",
		[RTE_ICMP6_ECHO_REQUEST]   = "ICMPv6 Echo Request",

		[RTE_ND_ROUTER_SOLICIT]    = "ICMPv6 Router Solicitation",
		[RTE_ND_ROUTER_ADVERT]     = "ICMPv6 Router Advertisement",
		[RTE_ND_NEIGHBOR_SOLICIT]  = "ICMPv6 Neighbor Solicitation",
		[RTE_ND_NEIGHBOR_ADVERT]   = "ICMPv6 Neighbor Advertisement",
	};

	icmp = dissect_read(mb, offset, sizeof(_icmp), &_icmp, dump_len);
	if (icmp == NULL)
		return snprintf(buf, size, "Missing ICMP header");

	offset += sizeof(_icmp);
	const char *name = icmp_types[icmp->icmp_type];
	if (name != NULL)
		return dissect_print(&buf, &size, "%s ", name);
	else
		return dissect_print(&buf, &size, "ICMP %u ", icmp->icmp_type);
}

static int
dissect_ipv4(char *buf, size_t size, const struct rte_mbuf *mb,
	     uint32_t offset, uint32_t dump_len)
{
	const struct rte_ipv4_hdr *ip_hdr;
	struct rte_ipv4_hdr _ip_hdr;
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];
	int count;

	ip_hdr = dissect_read(mb, offset, sizeof(_ip_hdr), &_ip_hdr, dump_len);
	if (ip_hdr == NULL)
		return snprintf(buf, size, "Missing IP header");

	inet_ntop(AF_INET, &ip_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET, &ip_hdr->dst_addr, dbuf, sizeof(dbuf));
	count = dissect_print(&buf, &size, "%s → %s ", sbuf, dbuf);

	offset += ip_hdr->ihl * 4;
	switch (ip_hdr->next_proto_id) {
	case IPPROTO_UDP:
		count += dissect_udp(buf, size, mb, offset, dump_len);
		break;
	case IPPROTO_TCP:
		count += dissect_tcp(buf, size, mb, offset, dump_len);
		break;
	case IPPROTO_ICMP:
		count += dissect_icmp(buf, size, mb, offset, dump_len);
		break;
	default:
		/* TODO dissect tunnels */
		count += dissect_print(&buf, &size, "IP %#x ", ip_hdr->next_proto_id);
	}
	return count;
}

static int
dissect_ipv6(char *buf, size_t size, const struct rte_mbuf *mb,
	     uint32_t offset, uint32_t dump_len)
{
	const struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_hdr _ip6_hdr;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	uint16_t proto;
	unsigned int i;
	int count;

	ip6_hdr = dissect_read(mb, offset, sizeof(_ip6_hdr), &_ip6_hdr, dump_len);
	if (ip6_hdr == NULL)
		return snprintf(buf, size, "Missing IPv6 header");

	offset += sizeof(*ip6_hdr);
	inet_ntop(AF_INET6, &ip6_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET6, &ip6_hdr->dst_addr, dbuf, sizeof(dbuf));
	count = dissect_print(&buf, &size, "%s → %s ", sbuf, dbuf);

#define MAX_EXT_HDRS 5
	proto = ip6_hdr->proto;
	for (i = 0; i < MAX_EXT_HDRS; i++) {
		switch (proto) {
		case IPPROTO_UDP:
			count += dissect_udp(buf, size, mb, offset, dump_len);
			return count;

		case IPPROTO_TCP:
			count += dissect_tcp(buf, size, mb, offset, dump_len);
			return count;

		case IPPROTO_ICMPV6:
			count += dissect_icmp(buf, size, mb, offset, dump_len);
			return count;

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			const struct rte_ipv6_routing_ext *xh;
			struct rte_ipv6_routing_ext _xh;

			xh = dissect_read(mb, offset, sizeof(xh), &_xh, dump_len);
			if (xh == NULL)
				return count;

			offset += (xh->hdr_len + 1) * 8;
			proto = xh->next_hdr;
			continue;
		}

		case IPPROTO_FRAGMENT:
			count += dissect_print(&buf, &size, "%s", "FRAG ");
			return count;

		case IPPROTO_NONE:
			count += dissect_print(&buf, &size, "%s", "NONE ");
			return count;

		default:
			count += dissect_print(&buf, &size, "IPv6 %#x ", proto);
			return count;
		}
	}
	return count;
}

/*
 * Format up a string describing contents of packet in tshark like style.
 */
static int
dissect_eth(char *buf, size_t size, const struct rte_mbuf *mb,
	    uint32_t offset, uint32_t dump_len)
{
	const struct rte_ether_hdr *eth_hdr;
	struct rte_ether_hdr _eth_hdr;
	uint16_t eth_type;
	int count = 0;
	char sbuf[RTE_ETHER_ADDR_FMT_SIZE], dbuf[RTE_ETHER_ADDR_FMT_SIZE];

	eth_hdr = dissect_read(mb, offset, sizeof(_eth_hdr), &_eth_hdr, dump_len);
	if (unlikely(eth_hdr == NULL))
		return snprintf(buf, size, "Missing ETH header");

	offset += sizeof(*eth_hdr);
	eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	if (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vh;
		struct rte_vlan_hdr _vh;

		vh = dissect_read(mb, offset, sizeof(_vh), &_vh, dump_len);
		if (unlikely(vh == NULL))
			return snprintf(buf, size, "Missing VLAN header");

		eth_type = vh->eth_proto;
		offset += sizeof(*vh);

		count += dissect_print(&buf, &size, "%s %#x ",
				       (eth_type == RTE_ETHER_TYPE_VLAN) ? "VLAN" : "QINQ",
				       rte_be_to_cpu_16(vh->vlan_tci));
	}

	switch (eth_type) {
	case RTE_ETHER_TYPE_ARP:
		rte_ether_format_addr(sbuf, sizeof(sbuf), &eth_hdr->src_addr);
		rte_ether_format_addr(dbuf, sizeof(dbuf), &eth_hdr->dst_addr);
		count += dissect_print(&buf, &size, "%s → %s ARP ", sbuf, dbuf);
		count += dissect_arp(buf, size,  mb, offset, dump_len);
		break;

	case RTE_ETHER_TYPE_IPV4:
		count += dissect_ipv4(buf, size, mb, offset, dump_len);
		break;

	case RTE_ETHER_TYPE_IPV6:
		count += dissect_ipv6(buf, size, mb, offset, dump_len);
		break;

	default:
		count += dissect_print(&buf, &size, "ETH %#x ", eth_type);
	}

	return count;
}

int
rte_dissect_mbuf(char *buf, size_t size, const struct rte_mbuf *m, uint32_t dump_len)
{
	int count;

	count = dissect_eth(buf, size, m, 0, dump_len);
	if (count <= 0)
		return count;

	/* output was truncated, but redact the trailing blank */
	if (count >= (int)size)
		return count - 1;

	if (buf[count] == ' ')
		buf[count--] = '\0';

	return count;
}
