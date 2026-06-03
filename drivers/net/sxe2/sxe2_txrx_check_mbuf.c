/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include <rte_common.h>
#include <rte_net.h>
#include <rte_vect.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <ethdev_driver.h>
#include <rte_geneve.h>

#include "sxe2_txrx_check_mbuf.h"
#include "sxe2_common_log.h"

#define TX_IPPROTO_IPIP 4
#define TX_IPPROTO_GRE  47
#define GRE_CHECKSUM_PRESENT 0x8000
#define GRE_KEY_PRESENT 0x2000
#define GRE_SEQUENCE_PRESENT 0x1000
#define GRE_EXT_LEN 4
#define GRE_SUPPORTED_FIELDS (GRE_CHECKSUM_PRESENT | GRE_KEY_PRESENT | GRE_SEQUENCE_PRESENT)


static uint16_t vxlan_gpe_udp_port = RTE_VXLAN_GPE_DEFAULT_PORT;
static uint16_t geneve_udp_port = RTE_GENEVE_DEFAULT_PORT;

static inline int32_t check_mbuf_len(struct offload_info *info, struct rte_mbuf *m)
{
	int32_t ret = 0;
	if (m->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
		if (info->outer_l2_len != m->outer_l2_len) {
			PMD_LOG_ERR(TX, "outer_l2_len error in mbuf. Original "
				    "length:%u calculated length:%u", m->outer_l2_len,
				    info->outer_l2_len);
			ret = -1;
			goto end;
		}
		if (info->outer_l3_len != m->outer_l3_len) {
			PMD_LOG_ERR(TX, "outer_l3_len error in mbuf. Original "
				    "length:%u calculated length:%u", m->outer_l3_len,
				    info->outer_l3_len);
			ret = -1;
			goto end;
		}
	}

	if (info->l2_len != m->l2_len) {
		PMD_LOG_ERR(TX, "l2_len error in mbuf. Original "
			"length:%u calculated length:%u", m->l2_len, info->l2_len);
		ret = -1;
		goto end;
	}
	if (info->l3_len != m->l3_len) {
		PMD_LOG_ERR(TX, "l3_len error in mbuf. Original "
			"length:%u calculated length:%u", m->l3_len, info->l3_len);
		ret = -1;
		goto end;
	}
	if (info->l4_len != m->l4_len) {
		PMD_LOG_ERR(TX, "l4_len error in mbuf. Original "
			"length:%u calculated length:%u", m->l4_len, info->l4_len);
		ret = -1;
		goto end;
	}
	ret = 0;

end:
	return ret;
}

static inline int32_t check_ether_type(struct offload_info *info, struct rte_mbuf *m)
{
	int32_t ret = 0;

	if (m->ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK) {
		if (info->outer_ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
			if (!(m->ol_flags & RTE_MBUF_F_TX_OUTER_IPV4)) {
				PMD_LOG_ERR(TX, "Outer ethernet type is ipv4, "
					"tx offload missing `RTE_MBUF_F_TX_OUTER_IPV4` flag");
				ret = -1;
				goto end;
			}
			if (m->ol_flags & RTE_MBUF_F_TX_OUTER_IPV6) {
				PMD_LOG_ERR(TX, "Outer ethernet type is ipv4, tx "
					"offload contains wrong `RTE_MBUF_F_TX_OUTER_IPV6` flag");
				ret = -1;
				goto end;
			}
		} else if (info->outer_ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
			if (!(m->ol_flags & RTE_MBUF_F_TX_OUTER_IPV6)) {
				PMD_LOG_ERR(TX, "Outer ethernet type is ipv6, "
					"tx offload missing `RTE_MBUF_F_TX_OUTER_IPV6` flag");
				ret = -1;
				goto end;
			}
			if (m->ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) {
				PMD_LOG_ERR(TX, "Outer ethernet type is ipv6, tx "
					"offload contains wrong `RTE_MBUF_F_TX_OUTER_IPV4` flag");
				ret = -1;
				goto end;
			}
		}
	}

	if (info->ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		if (!(m->ol_flags & RTE_MBUF_F_TX_IPV4)) {
			PMD_LOG_ERR(TX, "Ethernet type is ipv4, tx offload "
				"missing `RTE_MBUF_F_TX_IPV4` flag.");
			ret = -1;
			goto end;
		}
		if (m->ol_flags & RTE_MBUF_F_TX_IPV6) {
			PMD_LOG_ERR(TX, "Ethernet type is ipv4, tx "
				"offload contains wrong `RTE_MBUF_F_TX_IPV6` flag");
			ret = -1;
			goto end;
		}
	} else if (info->ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		if (!(m->ol_flags & RTE_MBUF_F_TX_IPV6)) {
			PMD_LOG_ERR(TX, "Ethernet type is ipv6, tx offload "
				"missing `RTE_MBUF_F_TX_IPV6` flag.");
			ret = -1;
			goto end;
		}
		if (m->ol_flags & RTE_MBUF_F_TX_IPV4) {
			PMD_LOG_ERR(TX, "Ethernet type is ipv6, tx offload "
				"contains wrong `RTE_MBUF_F_TX_IPV4` flag");
			ret = -1;
			goto end;
		}
	}
	ret = 0;

end:
	return ret;
}

static inline void parse_ipv4(struct rte_ipv4_hdr *ipv4_hdr, struct offload_info *info)
{
	struct rte_tcp_hdr *tcp_hdr;

	info->l3_len   = rte_ipv4_hdr_len(ipv4_hdr);
	info->l4_proto = ipv4_hdr->next_proto_id;

	if (info->l4_proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + info->l3_len);
		info->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
	} else if (info->l4_proto == IPPROTO_UDP) {
		info->l4_len = sizeof(struct rte_udp_hdr);
	} else {
		info->l4_len = 0;
	}
}

static inline void parse_ipv6(struct rte_ipv6_hdr *ipv6_hdr, struct offload_info *info)
{
	struct rte_tcp_hdr *tcp_hdr;

	info->l3_len   = sizeof(struct rte_ipv6_hdr);
	info->l4_proto = ipv6_hdr->proto;

	if (info->l4_proto == IPPROTO_TCP) {
		tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv6_hdr + info->l3_len);
		info->l4_len = (tcp_hdr->data_off & 0xf0) >> 2;
	} else if (info->l4_proto == IPPROTO_UDP) {
		info->l4_len = sizeof(struct rte_udp_hdr);
	} else {
		info->l4_len = 0;
	}
}

static inline void parse_ethernet(struct rte_ether_hdr *eth_hdr, struct offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vlan_hdr *vlan_hdr;

	info->l2_len = sizeof(struct rte_ether_hdr);
	info->ethertype = eth_hdr->ether_type;

	while (info->ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
		   info->ethertype == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
		vlan_hdr = (struct rte_vlan_hdr *)
			((char *)eth_hdr + info->l2_len);
		info->l2_len   += sizeof(struct rte_vlan_hdr);
		info->ethertype = vlan_hdr->eth_proto;
	}

	switch (info->ethertype) {
	case RTE_STATIC_BSWAP16(RTE_ETHER_TYPE_IPV4):
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)eth_hdr + info->l2_len);
		parse_ipv4(ipv4_hdr, info);
		break;
	case RTE_STATIC_BSWAP16(RTE_ETHER_TYPE_IPV6):
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)eth_hdr + info->l2_len);
		parse_ipv6(ipv6_hdr, info);
		break;
	default:
		info->l4_len = 0;
		info->l3_len = 0;
		info->l4_proto = 0;
		break;
	}
}

static inline void update_tunnel_outer(struct offload_info *info)
{
	info->is_tunnel       = 1;
	info->outer_ethertype = info->ethertype;
	info->outer_l2_len    = info->l2_len;
	info->outer_l3_len    = info->l3_len;
	info->outer_l4_proto  = info->l4_proto;
}

static inline void parse_gtp(struct rte_udp_hdr *udp_hdr, struct offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_gtp_hdr *gtp_hdr;
	uint8_t gtp_len = sizeof(*gtp_hdr);
	uint8_t ip_ver;

	if (udp_hdr->dst_port != rte_cpu_to_be_16(RTE_GTPC_UDP_PORT) &&
		udp_hdr->src_port != rte_cpu_to_be_16(RTE_GTPC_UDP_PORT) &&
		udp_hdr->dst_port != rte_cpu_to_be_16(RTE_GTPU_UDP_PORT))
		goto end;

	update_tunnel_outer(info);
	info->l2_len = 0;

	gtp_hdr = (struct rte_gtp_hdr *)((char *)udp_hdr + sizeof(*udp_hdr));

	if (gtp_hdr->msg_type == 0xff) {
		ip_ver = *(uint8_t *)((char *)udp_hdr + sizeof(*udp_hdr) + sizeof(*gtp_hdr));
		ip_ver = (ip_ver) & 0xf0;

		if (ip_ver == RTE_GTP_TYPE_IPV4) {
			ipv4_hdr = (struct rte_ipv4_hdr *)((char *)gtp_hdr + gtp_len);
			info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
			parse_ipv4(ipv4_hdr, info);
		} else if (ip_ver == RTE_GTP_TYPE_IPV6) {
			ipv6_hdr = (struct rte_ipv6_hdr *)((char *)gtp_hdr + gtp_len);
			info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
			parse_ipv6(ipv6_hdr, info);
		}
	} else {
		info->ethertype = 0;
		info->l4_len    = 0;
		info->l3_len    = 0;
		info->l4_proto  = 0;
	}

	info->l2_len += RTE_ETHER_GTP_HLEN;

end:
	return;
}

static inline void parse_vxlan(struct rte_udp_hdr *udp_hdr, struct offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;

	if (udp_hdr->dst_port != rte_cpu_to_be_16(RTE_VXLAN_DEFAULT_PORT))
		goto end;

	update_tunnel_outer(info);

	eth_hdr = (struct rte_ether_hdr *)((char *)udp_hdr +
		sizeof(struct rte_udp_hdr) + sizeof(struct rte_vxlan_hdr));

	parse_ethernet(eth_hdr, info);
	info->l2_len += RTE_ETHER_VXLAN_HLEN;

end:
	return;
}

static inline void parse_vxlan_gpe(struct rte_udp_hdr *udp_hdr, struct offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_vxlan_gpe_hdr *vxlan_gpe_hdr;
	uint8_t vxlan_gpe_len = sizeof(*vxlan_gpe_hdr);

	if (udp_hdr->dst_port != rte_cpu_to_be_16(vxlan_gpe_udp_port))
		goto end;

	vxlan_gpe_hdr = (struct rte_vxlan_gpe_hdr *)((char *)udp_hdr + sizeof(struct rte_udp_hdr));

	if (!vxlan_gpe_hdr->proto || vxlan_gpe_hdr->proto == RTE_VXLAN_GPE_TYPE_IPV4) {
		update_tunnel_outer(info);

		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)vxlan_gpe_hdr + vxlan_gpe_len);

		parse_ipv4(ipv4_hdr, info);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;

	} else if (vxlan_gpe_hdr->proto == RTE_VXLAN_GPE_TYPE_IPV6) {
		update_tunnel_outer(info);

		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)vxlan_gpe_hdr + vxlan_gpe_len);

		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (vxlan_gpe_hdr->proto == RTE_VXLAN_GPE_TYPE_ETH) {
		update_tunnel_outer(info);

		eth_hdr = (struct rte_ether_hdr *)((char *)vxlan_gpe_hdr + vxlan_gpe_len);

		parse_ethernet(eth_hdr, info);
	} else {
		goto end;
	}

	info->l2_len += RTE_ETHER_VXLAN_GPE_HLEN;

end:
	return;
}

static inline void parse_geneve(struct rte_udp_hdr *udp_hdr, struct offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_geneve_hdr *geneve_hdr;
	uint16_t geneve_len;

	if (udp_hdr->dst_port != rte_cpu_to_be_16(geneve_udp_port))
		goto end;

	geneve_hdr = (struct rte_geneve_hdr *)((char *)udp_hdr + sizeof(struct rte_udp_hdr));
	geneve_len = sizeof(struct rte_geneve_hdr) + geneve_hdr->opt_len * 4;
	if (!geneve_hdr->proto || geneve_hdr->proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		update_tunnel_outer(info);
		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)geneve_hdr + geneve_len);
		parse_ipv4(ipv4_hdr, info);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;
	} else if (geneve_hdr->proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		update_tunnel_outer(info);
		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)geneve_hdr + geneve_len);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (geneve_hdr->proto == rte_cpu_to_be_16(RTE_GENEVE_TYPE_ETH)) {
		update_tunnel_outer(info);
		eth_hdr = (struct rte_ether_hdr *)((char *)geneve_hdr + geneve_len);
		parse_ethernet(eth_hdr, info);
	} else {
		goto end;
	}

	info->l2_len += (sizeof(struct rte_udp_hdr) + sizeof(struct rte_geneve_hdr) +
		((struct rte_geneve_hdr *)geneve_hdr)->opt_len * 4);

end:
	return;
}

static inline void parse_gre(struct simple_gre_hdr *gre_hdr, struct offload_info *info)
{
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_ipv6_hdr *ipv6_hdr;
	uint8_t gre_len = 0;

	gre_len += sizeof(struct simple_gre_hdr);

	if (gre_hdr->flags & rte_cpu_to_be_16(GRE_KEY_PRESENT))
		gre_len += GRE_EXT_LEN;
	if (gre_hdr->flags & rte_cpu_to_be_16(GRE_SEQUENCE_PRESENT))
		gre_len += GRE_EXT_LEN;
	if (gre_hdr->flags & rte_cpu_to_be_16(GRE_CHECKSUM_PRESENT))
		gre_len += GRE_EXT_LEN;

	if (gre_hdr->proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
		update_tunnel_outer(info);

		ipv4_hdr = (struct rte_ipv4_hdr *)((char *)gre_hdr + gre_len);

		parse_ipv4(ipv4_hdr, info);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
		info->l2_len = 0;

	} else if (gre_hdr->proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6)) {
		update_tunnel_outer(info);

		ipv6_hdr = (struct rte_ipv6_hdr *)((char *)gre_hdr + gre_len);

		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
		parse_ipv6(ipv6_hdr, info);
		info->l2_len = 0;

	} else if (gre_hdr->proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_TEB)) {
		update_tunnel_outer(info);

		eth_hdr = (struct rte_ether_hdr *)((char *)gre_hdr + gre_len);

		parse_ethernet(eth_hdr, info);
	} else {
		goto end;
	}

	info->l2_len += gre_len;

end:
	return;
}

static inline void parse_encap_ip(void *encap_ip, struct offload_info *info)
{
	struct rte_ipv4_hdr *ipv4_hdr = encap_ip;
	struct rte_ipv6_hdr *ipv6_hdr = encap_ip;
	uint8_t ip_version;

	ip_version = ((ipv4_hdr->version_ihl & 0xf0) >> 4);

	if (ip_version != 4 && ip_version != 6)
		goto end;

	info->is_tunnel = 1;
	info->outer_ethertype = info->ethertype;
	info->outer_l2_len = info->l2_len;
	info->outer_l3_len = info->l3_len;

	if (ip_version == 4) {
		parse_ipv4(ipv4_hdr, info);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
	} else {
		parse_ipv6(ipv6_hdr, info);
		info->ethertype = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6);
	}
	info->l2_len = 0;

end:
	return;
}

__rte_unused int32_t sxe2_txrx_check_mbuf(struct rte_mbuf *m)
{
	int32_t ret = 0;
	struct rte_ether_hdr *eth_hdr;
	void *l3_hdr = NULL;
	struct offload_info info = {0};
	uint64_t ol_flags = m->ol_flags;
	uint64_t tunnel_type = ol_flags & RTE_MBUF_F_TX_TUNNEL_MASK;

	eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	parse_ethernet(eth_hdr, &info);
	l3_hdr = (char *)eth_hdr + info.l2_len;
	if (info.l4_proto == IPPROTO_UDP) {
		struct rte_udp_hdr *udp_hdr;

		udp_hdr = (struct rte_udp_hdr *)((char *)l3_hdr + info.l3_len);
		if ((info.l2_len + info.l3_len + sizeof(struct rte_udp_hdr)) > m->data_len) {
			PMD_LOG_ERR(TX, "UDP header exceeds mbuf data length");
			ret = -1;
			goto end;
		}
		parse_gtp(udp_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "gtp tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_GTP` flag");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_GTP) {
				PMD_LOG_ERR(TX, "gtp tunnel packet, tx offload has wrong "
					"`%s` flag correct is `RTE_MBUF_F_TX_TUNNEL_GTP` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}
		parse_vxlan_gpe(udp_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "vxlan gpe tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE` flag");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE) {
				PMD_LOG_ERR(TX, "vxlan gpe tunnel packet, tx offload has "
					"wrong `%s` flag correct is `RTE_MBUF_F_TX_TUNNEL_VXLAN_GPE` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}
		parse_vxlan(udp_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "vxlan tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_VXLAN` flag");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_VXLAN) {
				PMD_LOG_ERR(TX, "vxlan tunnel packet, tx offload has "
					"wrong `%s` flag correct is `RTE_MBUF_F_TX_TUNNEL_VXLAN` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}
		parse_geneve(udp_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "geneve tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_GENEVE` flag");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_GENEVE) {
				PMD_LOG_ERR(TX, "geneve tunnel packet, tx offload has "
					"wrong `%s` flag correct is `RTE_MBUF_F_TX_TUNNEL_GENEVE` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}

		if (unlikely(RTE_ETH_IS_TUNNEL_PKT(m->packet_type) != 0)) {
			PMD_LOG_ERR(TX, "Unknown tunnel packet UDP dst port:%u",
				    udp_hdr->dst_port);
			ret = -1;
			goto end;
		}
	} else if (info.l4_proto == TX_IPPROTO_GRE) {
		struct simple_gre_hdr *gre_hdr;

		gre_hdr = (struct simple_gre_hdr *)((char *)l3_hdr + info.l3_len);
		parse_gre(gre_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "gre tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_GRE` flag.");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_GRE) {
				PMD_LOG_ERR(TX, "gre tunnel packet, tx offload has "
					"wrong `%s` flag, correct is `RTE_MBUF_F_TX_TUNNEL_GRE` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}
	} else if (info.l4_proto == TX_IPPROTO_IPIP) {
		void *encap_ip_hdr;

		encap_ip_hdr = (char *)l3_hdr + info.l3_len;
		parse_encap_ip(encap_ip_hdr, &info);
		if (info.is_tunnel) {
			if (!tunnel_type) {
				PMD_LOG_ERR(TX, "Ipip tunnel packet missing tx "
					"offload missing `RTE_MBUF_F_TX_TUNNEL_IPIP` flag");
				ret = -1;
				goto end;
			}
			if (tunnel_type != RTE_MBUF_F_TX_TUNNEL_IPIP) {
				PMD_LOG_ERR(TX, "Ipip tunnel packet, tx offload has "
					"wrong `%s` flag, correct is `RTE_MBUF_F_TX_TUNNEL_IPIP` flag",
				rte_get_tx_ol_flag_name(tunnel_type));
				ret = -1;
				goto end;
			}
			goto check_len;
		}
	}

check_len:
	if (check_mbuf_len(&info, m) != 0) {
		ret = -1;
		goto end;
	}
	ret = check_ether_type(&info, m);

end:
	return ret;
}
