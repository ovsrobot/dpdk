/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 *
 * IEEE 1588 / PTP Protocol Library — Implementation
 */

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_udp.h>

#include "rte_ptp.h"

#include <eal_export.h>

/*
 * Internal: find PTP header offset within a packet.
 * Returns pointer to PTP header or NULL.
 */
static struct rte_ptp_hdr *
ptp_hdr_find(const struct rte_mbuf *m)
{
	const struct rte_ether_hdr *eth;
	uint16_t ether_type;
	const uint8_t *p;
	uint32_t offset;

	if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr))
		return NULL;

	eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
	ether_type = rte_be_to_cpu_16(eth->ether_type);
	offset = sizeof(struct rte_ether_hdr);

	/* L2 PTP: EtherType 0x88F7 */
	if (ether_type == RTE_PTP_ETHERTYPE) {
		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ptp_hdr))
			return NULL;
		p = (const uint8_t *)eth + offset;
		return (struct rte_ptp_hdr *)(uintptr_t)p;
	}

	/* VLAN-tagged L2 PTP */
	if (ether_type == RTE_ETHER_TYPE_VLAN) {
		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_vlan_hdr))
			return NULL;
		const struct rte_vlan_hdr *vlan =
			(const struct rte_vlan_hdr *)((const uint8_t *)eth + offset);
		ether_type = rte_be_to_cpu_16(vlan->eth_proto);
		offset += sizeof(struct rte_vlan_hdr);

		if (ether_type == RTE_PTP_ETHERTYPE) {
			if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ptp_hdr))
				return NULL;
			p = (const uint8_t *)eth + offset;
			return (struct rte_ptp_hdr *)(uintptr_t)p;
		}

		/* Double-tagged VLAN (QinQ) */
		if (ether_type == RTE_ETHER_TYPE_QINQ ||
		    ether_type == RTE_ETHER_TYPE_VLAN) {
			if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_vlan_hdr))
				return NULL;
			vlan = (const struct rte_vlan_hdr *)
				((const uint8_t *)eth + offset);
			ether_type = rte_be_to_cpu_16(vlan->eth_proto);
			offset += sizeof(struct rte_vlan_hdr);

			if (ether_type == RTE_PTP_ETHERTYPE) {
				if (rte_pktmbuf_data_len(m) <
				    offset + sizeof(struct rte_ptp_hdr))
					return NULL;
				p = (const uint8_t *)eth + offset;
				return (struct rte_ptp_hdr *)(uintptr_t)p;
			}
		}
	}

	/* PTP over UDP/IPv4 */
	if (ether_type == RTE_ETHER_TYPE_IPV4) {
		const struct rte_ipv4_hdr *iph;
		uint16_t ihl;

		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ipv4_hdr))
			return NULL;

		iph = (const struct rte_ipv4_hdr *)((const uint8_t *)eth + offset);
		if (iph->next_proto_id != IPPROTO_UDP)
			return NULL;

		ihl = (iph->version_ihl & 0x0F) * 4;
		offset += ihl;

		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_udp_hdr))
			return NULL;

		const struct rte_udp_hdr *udp =
			(const struct rte_udp_hdr *)((const uint8_t *)eth + offset);
		uint16_t dst_port = rte_be_to_cpu_16(udp->dst_port);

		if (dst_port != RTE_PTP_EVENT_PORT &&
		    dst_port != RTE_PTP_GENERAL_PORT)
			return NULL;

		offset += sizeof(struct rte_udp_hdr);
		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ptp_hdr))
			return NULL;

		p = (const uint8_t *)eth + offset;
		return (struct rte_ptp_hdr *)(uintptr_t)p;
	}

	/* PTP over UDP/IPv6 */
	if (ether_type == RTE_ETHER_TYPE_IPV6) {
		const struct rte_ipv6_hdr *ip6h;

		if (rte_pktmbuf_data_len(m) <
		    offset + sizeof(struct rte_ipv6_hdr))
			return NULL;

		ip6h = (const struct rte_ipv6_hdr *)
			((const uint8_t *)eth + offset);
		if (ip6h->proto != IPPROTO_UDP)
			return NULL;

		offset += sizeof(struct rte_ipv6_hdr);

		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_udp_hdr))
			return NULL;

		const struct rte_udp_hdr *udp =
			(const struct rte_udp_hdr *)
			((const uint8_t *)eth + offset);
		uint16_t dst_port = rte_be_to_cpu_16(udp->dst_port);

		if (dst_port != RTE_PTP_EVENT_PORT &&
		    dst_port != RTE_PTP_GENERAL_PORT)
			return NULL;

		offset += sizeof(struct rte_udp_hdr);
		if (rte_pktmbuf_data_len(m) < offset + sizeof(struct rte_ptp_hdr))
			return NULL;

		p = (const uint8_t *)eth + offset;
		return (struct rte_ptp_hdr *)(uintptr_t)p;
	}

	return NULL;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_ptp_classify, 26.07)
int
rte_ptp_classify(const struct rte_mbuf *m)
{
	struct rte_ptp_hdr *hdr = ptp_hdr_find(m);

	if (hdr == NULL)
		return RTE_PTP_MSGTYPE_INVALID;

	return rte_ptp_msg_type(hdr);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_ptp_hdr_get, 26.07)
struct rte_ptp_hdr *
rte_ptp_hdr_get(const struct rte_mbuf *m)
{
	return ptp_hdr_find(m);
}

static const char * const ptp_msg_names[] = {
	[RTE_PTP_MSGTYPE_SYNC]           = "Sync",
	[RTE_PTP_MSGTYPE_DELAY_REQ]      = "Delay_Req",
	[RTE_PTP_MSGTYPE_PDELAY_REQ]     = "PDelay_Req",
	[RTE_PTP_MSGTYPE_PDELAY_RESP]    = "PDelay_Resp",
	[0x4]                            = "Reserved_4",
	[0x5]                            = "Reserved_5",
	[0x6]                            = "Reserved_6",
	[0x7]                            = "Reserved_7",
	[RTE_PTP_MSGTYPE_FOLLOW_UP]      = "Follow_Up",
	[RTE_PTP_MSGTYPE_DELAY_RESP]     = "Delay_Resp",
	[RTE_PTP_MSGTYPE_PDELAY_RESP_FU] = "PDelay_Resp_Follow_Up",
	[RTE_PTP_MSGTYPE_ANNOUNCE]       = "Announce",
	[RTE_PTP_MSGTYPE_SIGNALING]      = "Signaling",
	[RTE_PTP_MSGTYPE_MANAGEMENT]     = "Management",
	[0xE]                            = "Reserved_E",
	[0xF]                            = "Reserved_F",
};

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_ptp_msg_type_str, 26.07)
const char *
rte_ptp_msg_type_str(int msg_type)
{
	if (msg_type < 0 || msg_type > 0xF)
		return "Not_PTP";
	return ptp_msg_names[msg_type];
}
