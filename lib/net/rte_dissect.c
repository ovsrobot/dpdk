/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Stephen Hemminger <stephen@networkplumber.org>
 *
 * Print packets in format similar to tshark.
 * Output should be one line per mbuf
 */

#include <setjmp.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <rte_arp.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_dissect.h>
#include <rte_ether.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_mbuf.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

typedef struct dissect_ctx {
	jmp_buf jmpenv;		/* unwind when dump_len is reached */
	uint32_t offset;	/* current offset */
	uint32_t dump_len;	/* maximum depth in packet to look at */
} dissect_ctx_t;

static void
dissect_eth(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb);

/* Read data from segmented mbuf, but stop if would go past max length */
static const void *
dissect_read(dissect_ctx_t *ctx, const struct rte_mbuf *m,
	     void *buf, size_t len)
{
	/* If this header would be past the requested length
	 * then unwind back to end the string.
	 */
	if (ctx->dump_len != 0 && ctx->offset + len > ctx->dump_len)
		longjmp(ctx->jmpenv, 1);

	return rte_pktmbuf_read(m, ctx->offset, len, buf);
}

static void
dissect_arp(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_arp_hdr *arp;
	struct rte_arp_hdr _arp;
	uint16_t ar_op;
	char buf[128];

	arp = dissect_read(ctx, mb, &_arp, sizeof(_arp));
	if (unlikely(arp == NULL)) {
		fprintf(f, "truncated ARP! ");
		return;
	}

	ar_op = rte_be_to_cpu_16(arp->arp_opcode);
	switch (ar_op) {
	case RTE_ARP_OP_REQUEST:
		inet_ntop(AF_INET, &arp->arp_data.arp_tip, buf, sizeof(buf));
		fprintf(f, "Who has %s? ", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		fprintf(f, "Tell %s ", buf);
		break;
	case RTE_ARP_OP_REPLY:
		inet_ntop(AF_INET, &arp->arp_data.arp_sip, buf, sizeof(buf));
		fprintf(f, "%s is at", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		fprintf(f, "%s ", buf);
		break;
	case RTE_ARP_OP_INVREQUEST:
		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_tha);
		fprintf(f, "Who is %s? ", buf);

		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		fprintf(f, "Tell %s ", buf);
		break;

	case RTE_ARP_OP_INVREPLY:
		rte_ether_format_addr(buf, sizeof(buf), &arp->arp_data.arp_sha);
		fprintf(f, "%s is at ", buf);

		inet_ntop(AF_INET, &arp->arp_data.arp_sip, buf, sizeof(buf));
		fprintf(f, "%s ", buf);
		break;
	default:
		fprintf(f, "Unknown ARP %#x ", ar_op);
		break;
	}
}

static void
dissect_vxlan(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_vxlan_hdr *vxlan;
	struct rte_vxlan_hdr _vxlan;

	vxlan = dissect_read(ctx, mb, &_vxlan, sizeof(_vxlan));
	fprintf(f, "VXLAN ");
	if (vxlan->flag_i) {
		uint32_t vni = rte_be_to_cpu_32(vxlan->vx_vni);

		fprintf(f, "%#x ", vni >> 8);
	}
	dissect_eth(ctx, f, mb);
}

static void
dissect_udp(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_udp_hdr *udph;
	struct rte_udp_hdr _udp;
	uint16_t src_port, dst_port;

	udph = dissect_read(ctx, mb, &_udp, sizeof(_udp));
	if (unlikely(udph == NULL)) {
		fprintf(f, "truncated UDP! ");
		return;
	}

	src_port = rte_be_to_cpu_16(udph->src_port);
	dst_port = rte_be_to_cpu_16(udph->dst_port);

	switch (dst_port) {
	case RTE_VXLAN_DEFAULT_PORT:
		dissect_vxlan(ctx, f, mb);
		break;
	default:
		fprintf(f, "UDP %u %u → %u ", rte_be_to_cpu_16(udph->dgram_len), src_port, dst_port);
	}
}

static void
dissect_tcp(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_tcp_hdr *tcph;
	struct rte_tcp_hdr _tcp;
	uint16_t src_port, dst_port;

	tcph = dissect_read(ctx, mb, &_tcp, sizeof(_tcp));
	if (unlikely(tcph == NULL)) {
		fprintf(f, "truncated TCP! ");
		return;
	}

	src_port = rte_be_to_cpu_16(tcph->src_port);
	dst_port = rte_be_to_cpu_16(tcph->dst_port);

	fprintf(f, "TCP %u → %u",
		  src_port, dst_port);
#define PRINT_TCP_FLAG(flag) \
	if (tcph->tcp_flags & RTE_TCP_ ## flag ## _FLAG) \
		fprintf(f, " [" #flag" ]")

	PRINT_TCP_FLAG(URG);
	PRINT_TCP_FLAG(ACK);
	PRINT_TCP_FLAG(RST);
	PRINT_TCP_FLAG(SYN);
	PRINT_TCP_FLAG(FIN);
#undef PRINT_TCP_FLAG

	fprintf(f, "Seq=%u Ack=%u Win=%u ",
		  rte_be_to_cpu_16(tcph->sent_seq),
		  rte_be_to_cpu_16(tcph->recv_ack),
		  rte_be_to_cpu_16(tcph->rx_win));
}

static void
dissect_icmp(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
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

	icmp = dissect_read(ctx, mb, &_icmp, sizeof(_icmp));
	if (unlikely(icmp == NULL)) {
		fprintf(f, "truncated ICMP! ");
	} else {
		const char *name = icmp_types[icmp->icmp_type];

		if (name != NULL)
			fprintf(f, "%s ", name);
		else
			fprintf(f, "ICMP type %u ", icmp->icmp_type);
	}
}

static void
dissect_ipv4(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_ipv4_hdr *ip_hdr;
	struct rte_ipv4_hdr _ip_hdr;
	char sbuf[INET_ADDRSTRLEN], dbuf[INET_ADDRSTRLEN];

	ip_hdr = dissect_read(ctx, mb, &_ip_hdr, sizeof(_ip_hdr));
	if (unlikely(ip_hdr == NULL)) {
		fprintf(f, "truncated IP! ");
		return;
	}

	inet_ntop(AF_INET, &ip_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET, &ip_hdr->dst_addr, dbuf, sizeof(dbuf));
	fprintf(f, "%s → %s ", sbuf, dbuf);

	ctx->offset += ip_hdr->ihl * 4;
	switch (ip_hdr->next_proto_id) {
	case IPPROTO_UDP:
		return dissect_udp(ctx, f, mb);
	case IPPROTO_TCP:
		return dissect_tcp(ctx, f, mb);
	case IPPROTO_ICMP:
		return dissect_icmp(ctx, f, mb);
	default:
		/* TODO dissect tunnels */
		fprintf(f, "IP proto %#x ", ip_hdr->next_proto_id);
	}
}

static void
dissect_ipv6(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_ipv6_hdr *ip6_hdr;
	struct rte_ipv6_hdr _ip6_hdr;
	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];
	uint16_t proto;
	unsigned int i;

	ip6_hdr = dissect_read(ctx, mb, &_ip6_hdr, sizeof(_ip6_hdr));
	if (unlikely(ip6_hdr == NULL)) {
		fprintf(f, "truncated IPv6! ");
		return;
	}
	ctx->offset += sizeof(*ip6_hdr);

	inet_ntop(AF_INET6, ip6_hdr->src_addr, sbuf, sizeof(sbuf));
	inet_ntop(AF_INET6, ip6_hdr->dst_addr, dbuf, sizeof(dbuf));
	fprintf(f, "%s → %s ", sbuf, dbuf);

#define MAX_EXT_HDRS 5
	proto = ip6_hdr->proto;
	for (i = 0; i < MAX_EXT_HDRS; i++) {
		switch (proto) {
		case IPPROTO_UDP:
			return dissect_udp(ctx, f, mb);
		case IPPROTO_TCP:
			return dissect_tcp(ctx, f, mb);
		case IPPROTO_ICMPV6:
			return dissect_icmp(ctx, f, mb);

		case IPPROTO_HOPOPTS:
		case IPPROTO_ROUTING:
		case IPPROTO_DSTOPTS:
		{
			const struct rte_ipv6_routing_ext *xh;
			struct rte_ipv6_routing_ext _xh;

			xh = dissect_read(ctx, mb, &_xh, sizeof(xh));
			if (unlikely(xh == NULL)) {
				fprintf(f, "truncated IPV6 option! ");
				return;
			}
			ctx->offset += (xh->hdr_len + 1) * 8;
			proto = xh->next_hdr;
			continue;
		}

		case IPPROTO_FRAGMENT:
			fprintf(f, "FRAG ");
			return;

		case IPPROTO_NONE:
			fprintf(f, "NONE ");
			return;

		default:
			fprintf(f, "IPv6 proto %u ", proto);
			return;
		}
	}

	fprintf(f, "Too many extensions!");
}

static void
dissect_eth(dissect_ctx_t *ctx, FILE *f, const struct rte_mbuf *mb)
{
	const struct rte_ether_hdr *eth_hdr;
	struct rte_ether_hdr _eth_hdr;
	uint16_t eth_type;
	char sbuf[RTE_ETHER_ADDR_FMT_SIZE], dbuf[RTE_ETHER_ADDR_FMT_SIZE];

	eth_hdr = dissect_read(ctx, mb, &_eth_hdr, sizeof(_eth_hdr));
	if (unlikely(eth_hdr == NULL)) {
		fprintf(f, "missing Eth header!");
		return;
	}

	ctx->offset += sizeof(*eth_hdr);
	eth_type = rte_be_to_cpu_16(eth_hdr->ether_type);
	if (eth_type == RTE_ETHER_TYPE_VLAN || eth_type == RTE_ETHER_TYPE_QINQ) {
		const struct rte_vlan_hdr *vh
			= (const struct rte_vlan_hdr *)(eth_hdr + 1);
		eth_type = vh->eth_proto;
		ctx->offset += sizeof(*vh);

		fprintf(f, "%s %#x ", eth_type == RTE_ETHER_TYPE_VLAN ? "VLAN" : "QINQ",
			rte_be_to_cpu_16(vh->vlan_tci));
	}

	switch (eth_type) {
	case RTE_ETHER_TYPE_ARP:
		rte_ether_format_addr(sbuf, sizeof(sbuf), &eth_hdr->src_addr);
		rte_ether_format_addr(sbuf, sizeof(dbuf), &eth_hdr->dst_addr);
		fprintf(f, "%s → %s ARP ", sbuf, dbuf);

		dissect_arp(ctx, f, mb);
		break;
	case RTE_ETHER_TYPE_IPV4:
		dissect_ipv4(ctx, f, mb);
		break;

	case RTE_ETHER_TYPE_IPV6:
		dissect_ipv6(ctx, f, mb);
		break;
	default:
		fprintf(f, "Ethernet proto %#x ", eth_type);
	}
}

void
rte_dissect_mbuf(FILE *f, const struct rte_mbuf *m, uint32_t dump_len)
{
	dissect_ctx_t ctx = {
		.dump_len = dump_len,
	};

	if (setjmp(ctx.jmpenv) == 0)
		dissect_eth(&ctx, f, m);

	putc('\n', f);
}
