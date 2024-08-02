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
static void
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
	/* If this header would be past the requested length
	 * then unwind back to end the string.
	 */
	if (dump_len > 0 && offset + len > dump_len)
		return NULL;

	return rte_pktmbuf_read(m, offset, len, buf);
}

/*
 * Print to string buffer and adjust result
 * Returns true on success, false if buffer is exhausted.
 */
static __rte_format_printf(3, 4) bool
dissect_print(char **buf, size_t *sz, const char *fmt, ...)
{
	va_list ap;
	int cnt;

	va_start(ap, fmt);
	cnt = vsnprintf(*buf, *sz, fmt, ap);
	va_end(ap);

	/* error or string is full */
	if (cnt < 0 || cnt >= (int)*sz) {
		*sz = 0;
		return false;
	}

	*buf += cnt;
	*sz -= cnt;
	return true;
}

static void
dissect_arp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_arp_hdr *arp;
	struct rte_arp_hdr _arp;
	char abuf[64];

	arp = dissect_read(mb, offset, sizeof(_arp), &_arp, dump_len);
	if (arp == NULL)
		return;
	offset += sizeof(_arp);

	uint16_t ar_op = rte_be_to_cpu_16(arp->arp_opcode);
	switch (ar_op) {
	case RTE_ARP_OP_REQUEST:
		inet_ntop(AF_INET, &arp->arp_data.arp_tip, abuf, sizeof(abuf));
		if (!dissect_print(&buf, &size, "Who has %s? ", abuf))
			return;

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		if (!dissect_print(&buf, &size, "Tell %s ", abuf))
			return;

		break;
	case RTE_ARP_OP_REPLY:
		inet_ntop(AF_INET, &arp->arp_data.arp_sip, abuf, sizeof(abuf));
		if (!dissect_print(&buf, &size, "%s is at", abuf))
			return;

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		if (!dissect_print(&buf, &size, "%s ", abuf))
			return;
		break;
	case RTE_ARP_OP_INVREQUEST:
		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_tha);
		if (!dissect_print(&buf, &size, "Who is %s? ", abuf))
			return;

		rte_ether_format_addr(abuf, sizeof(abuf), &arp->arp_data.arp_sha);
		if (!dissect_print(&buf, &size, "Tell %s ", abuf))
			return;
		break;

	case RTE_ARP_OP_INVREPLY:
		rte_ether_format_addr(abuf, sizeof(buf), &arp->arp_data.arp_sha);
		if (!dissect_print(&buf, &size, "%s is at ", abuf))
			return;

		inet_ntop(AF_INET, &arp->arp_data.arp_sip, abuf, sizeof(abuf));
		if (!dissect_print(&buf, &size, "%s ", abuf))
			return;
		break;
	default:
		if (!dissect_print(&buf, &size, "Unknown ARP %#x ", ar_op))
			return;
		break;
	}
}

static void
dissect_vxlan(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_vxlan_hdr *vxlan;
	struct rte_vxlan_hdr _vxlan;

	vxlan = dissect_read(mb, offset, sizeof(_vxlan), &_vxlan, dump_len);
	if (vxlan == NULL)
		return;
	offset += sizeof(_vxlan);

	if (!dissect_print(&buf, &size, "VXLAN "))
		return;

	if (vxlan->flag_i) {
		uint32_t vni = rte_be_to_cpu_32(vxlan->vx_vni);

		if (!dissect_print(&buf, &size, "%#x ", vni >> 8))
			return;
	}

	dissect_eth(buf, size, mb, offset, dump_len);
}

static void
dissect_udp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_udp_hdr *udph;
	struct rte_udp_hdr _udp;
	uint16_t src_port, dst_port, len;

	udph = dissect_read(mb, offset, sizeof(_udp), &_udp, dump_len);
	if (udph == NULL)
		return;
	offset += sizeof(_udp);

	src_port = rte_be_to_cpu_16(udph->src_port);
	dst_port = rte_be_to_cpu_16(udph->dst_port);
	len = rte_be_to_cpu_16(udph->dgram_len);

	switch (dst_port) {
	case RTE_VXLAN_DEFAULT_PORT:
		dissect_vxlan(buf, size, mb, offset, dump_len);
		break;
	default:
		if (!dissect_print(&buf, &size, "UDP %u %u → %u ", len, src_port, dst_port))
			return;
	}
}

static void
dissect_tcp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_tcp_hdr *tcph;
	struct rte_tcp_hdr _tcp;
	uint16_t src_port, dst_port;

	tcph = dissect_read(mb, offset, sizeof(_tcp), &_tcp, dump_len);
	if (tcph == NULL)
		return;
	offset += sizeof(_tcp);

	src_port = rte_be_to_cpu_16(tcph->src_port);
	dst_port = rte_be_to_cpu_16(tcph->dst_port);

	if (!dissect_print(&buf, &size, "TCP %u → %u", src_port, dst_port))
		return;

#define PRINT_TCP_FLAG(flag) {					   \
	if (tcph->tcp_flags & RTE_TCP_ ## flag ## _FLAG)	   \
		if (!dissect_print(&buf, &size, " [ " #flag " ]")) \
			return;					   \
	}

	PRINT_TCP_FLAG(URG);
	PRINT_TCP_FLAG(ACK);
	PRINT_TCP_FLAG(RST);
	PRINT_TCP_FLAG(SYN);
	PRINT_TCP_FLAG(FIN);
#undef PRINT_TCP_FLAG

	dissect_print(&buf, &size, "Seq=%u Ack=%u Win=%u ",
		      rte_be_to_cpu_16(tcph->sent_seq),
		      rte_be_to_cpu_16(tcph->recv_ack),
		      rte_be_to_cpu_16(tcph->rx_win));
}

static void
dissect_icmp(char *buf, size_t size, const struct rte_mbuf *mb, uint32_t offset, uint32_t dump_len)
{
	const struct rte_icmp_hdr *icmp;
	struct rte_icmp_hdr _icmp;
	static const char * const icmp_types[256] = {
		[RTE_IP_ICMP_ECHO_REPLY]     = "ICMP Echo Reply",
		[RTE_IP_ICMP_DEST_UNREACH]   = "ICMP Destination Unreachable",
		[RTE_IP_ICMP_SOURCE_QUENCH]  = "ICMP Source Quench",
		[RTE_IP_ICMP_REDIRECT]       = "ICMP Redirect",
		[RTE_IP_ICMP_ECHO_REQUEST]   = "ICMP Echo Request",
		[RTE_IP_ICMP_TIME_EXCEEDED]  = "ICMP Time Exceeded",
		[RTE_IP_ICMP_PARAMETERPROB]  = "ICMP Parameter Problem",
		[RTE_IP_ICMP_TIMESTAMP]      = "ICMP Timestamp Request",
		[RTE_IP_ICMP_TIMESTAMPREPLY] = "ICMP Timestamp Reply",
		[RTE_IP_ICMP_INFO_REQUEST]   = "ICMP Info Request",
		[RTE_IP_ICMP_INFO_REPLY]     = "ICMP Info Reply",

		[RTE_ICMP6_ECHO_REPLY]     = "ICMPv6 Echo Reply",
		[RTE_ICMP6_ECHO_REQUEST]   = "ICMPv6 Echo Request",
		[RTE_ND_ROUTER_SOLICIT]    = "ICMPv6 Router Solicitation",
		[RTE_ND_ROUTER_ADVERT]     = "ICMPv6 Router Advertisement",
		[RTE_ND_NEIGHBOR_SOLICIT]  = "ICMPv6 Neighbor Solicitation",
		[RTE_ND_NEIGHBOR_ADVERT]   = "ICMPv6 Neighbor Advertisement",
	};

	icmp = dissect_read(mb, offset, sizeof(_icmp), &_icmp, dump_len);
	if (icmp == NULL)
		return;
	offset += sizeof(_icmp);

	const char *name = icmp_types[icmp->icmp_type];
	if (name != NULL)
		dissect_print(&buf, &size, "%s ", name);
	else
		dissect_print(&buf, &size, "ICMP %u ", icmp->icmp_type);
}

static void
dissect_ipv4(char *buf, size_t size, const struct rte_mbuf *mb,
	     uint32_t offset, uint32_t dump_len)
{
	const struct rte_ipv4_hdr *ip_hdr;
	struct rte_ipv4_hdr _ip_hdr;
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

	ip_hdr = dissect_read(mb, offset, sizeof(_ip_hdr), &_ip_hdr, dump_len);
	if (ip_hdr == NULL)
		return;

	inet_ntop(AF_INET, &ip_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET, &ip_hdr->dst_addr, dbuf, sizeof(dbuf));
	if (!dissect_print(&buf, &size, "%s → %s ", sbuf, dbuf))
		return;

	offset += ip_hdr->ihl * 4;
	switch (ip_hdr->next_proto_id) {
	case IPPROTO_UDP:
		return dissect_udp(buf, size, mb, offset, dump_len);
	case IPPROTO_TCP:
		return dissect_tcp(buf, size, mb, offset, dump_len);
	case IPPROTO_ICMP:
		return dissect_icmp(buf, size, mb, offset, dump_len);
	default:
		/* TODO dissect tunnels */
		dissect_print(&buf, &size, "IP %#x ", ip_hdr->next_proto_id);
	}
}

static void
dissect_ipv6(char *buf, size_t size, const struct rte_mbuf *mb,
	     uint32_t offset, uint32_t dump_len)
{
	const struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_hdr _ip6_hdr;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	uint16_t proto;
	unsigned int i;

	ip6_hdr = dissect_read(mb, offset, sizeof(_ip6_hdr), &_ip6_hdr, dump_len);
	if (ip6_hdr == NULL)
		return;

	offset += sizeof(*ip6_hdr);
	inet_ntop(AF_INET6, ip6_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET6, ip6_hdr->dst_addr, dbuf, sizeof(dbuf));
	if (!dissect_print(&buf, &size, "%s → %s ", sbuf, dbuf))
		return;

#define MAX_EXT_HDRS 5
	proto = ip6_hdr->proto;
	for (i = 0; i < MAX_EXT_HDRS; i++) {
		switch (proto) {
		case IPPROTO_UDP:
			return dissect_udp(buf, size, mb, offset, dump_len);
		case IPPROTO_TCP:
			return dissect_tcp(buf, size, mb, offset, dump_len);
		case IPPROTO_ICMPV6:
			return dissect_icmp(buf, size, mb, offset, dump_len);

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			const struct rte_ipv6_routing_ext *xh;
			struct rte_ipv6_routing_ext _xh;

			xh = dissect_read(mb, offset, sizeof(xh), &_xh, dump_len);
			if (xh == NULL)
				return;

			offset += (xh->hdr_len + 1) * 8;
			proto = xh->next_hdr;
			continue;
		}

		case IPPROTO_FRAGMENT:
			dissect_print(&buf, &size, "%s", "FRAG ");
			return;

		case IPPROTO_NONE:
			dissect_print(&buf, &size, "%s", "NONE ");
			return;

		default:
			dissect_print(&buf, &size, "IPv6 %#x ", proto);
			return;
		}
	}
}

/*
 * Format up a string describing contents of packet in tshark like style.
 */
static void
dissect_eth(char *buf, size_t size, const struct rte_mbuf *mb,
	    uint32_t offset, uint32_t dump_len)
{
	const struct rte_ether_hdr *eth_hdr;
	struct rte_ether_hdr _eth_hdr;
	uint16_t eth_type;
	char sbuf[RTE_ETHER_ADDR_FMT_SIZE], dbuf[RTE_ETHER_ADDR_FMT_SIZE];

	eth_hdr = dissect_read(mb, offset, sizeof(_eth_hdr), &_eth_hdr, dump_len);
	if (unlikely(eth_hdr == NULL))
		return;

	offset += sizeof(*eth_hdr);
	eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	if (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vh
			= (const struct rte_vlan_hdr *)(eth_hdr + 1);
		eth_type = vh->eth_proto;
		offset += sizeof(*vh);

		const char *vs = (eth_type == RTE_ETHER_TYPE_VLAN) ? "VLAN" : "QINQ";
		uint16_t tci = rte_be_to_cpu_16(vh->vlan_tci);

		if (!dissect_print(&buf, &size, "%s %#x ", vs, tci))
			return;
	}

	switch (eth_type) {
	case RTE_ETHER_TYPE_ARP:
		rte_ether_format_addr(sbuf, sizeof(sbuf), &eth_hdr->src_addr);
		rte_ether_format_addr(dbuf, sizeof(dbuf), &eth_hdr->dst_addr);
		if (!dissect_print(&buf, &size, "%s → %s ARP ", sbuf, dbuf))
			return;

		dissect_arp(buf, size,  mb, offset, dump_len);
		break;

	case RTE_ETHER_TYPE_IPV4:
		dissect_ipv4(buf, size, mb, offset, dump_len);
		break;

	case RTE_ETHER_TYPE_IPV6:
		dissect_ipv6(buf, size, mb, offset, dump_len);
		break;

	default:
		dissect_print(&buf, &size, "ETH %#x ", eth_type);
	}
}

void
rte_dissect_mbuf(char *buf, size_t size, const struct rte_mbuf *m, uint32_t dump_len)
{
	dissect_eth(buf, size, m, 0, dump_len);

	/* trim off trailing spaces */
	char *cp;
	while ((cp = strrchr(buf, ' ')) != NULL) {
		if (cp[1] != '\0')
			break;
		*cp = '\0';
	}
}
