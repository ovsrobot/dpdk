/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#ifndef __L3FWD_ACL_SCALAR_H__
#define __L3FWD_ACL_SCALAR_H__

#include "l3fwd.h"

/* ethernet addresses of ports */
static struct rte_ether_hdr port_l2hdr[RTE_MAX_ETHPORTS];

#ifdef DO_RFC_1812_CHECKS
static inline void
l3fwd_acl_prepare_one_packet(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
	int index)
{
	struct rte_ipv4_hdr *ipv4_hdr;
	struct rte_mbuf *pkt = pkts_in[index];

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr *,
						sizeof(struct rte_ether_hdr));

		/* Check to make sure the packet is valid (RFC1812) */
		if (is_valid_ipv4_pkt(ipv4_hdr, pkt->pkt_len) >= 0) {

			/* Update time to live and header checksum */
			--(ipv4_hdr->time_to_live);
			++(ipv4_hdr->hdr_checksum);

			/* Fill acl structure */
			acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
			acl->m_ipv4[(acl->num_ipv4)++] = pkt;

		} else {
			/* Not a valid IPv4 packet */
			rte_pktmbuf_free(pkt);
		}
	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = MBUF_IPV6_2PROTO(pkt);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;

	} else {
		/* Unknown type, drop the packet */
		rte_pktmbuf_free(pkt);
	}
}

#else
static inline void
l3fwd_acl_prepare_one_packet(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
	int index)
{
	struct rte_mbuf *pkt = pkts_in[index];

	if (RTE_ETH_IS_IPV4_HDR(pkt->packet_type)) {
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;

	} else if (RTE_ETH_IS_IPV6_HDR(pkt->packet_type)) {
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = MBUF_IPV6_2PROTO(pkt);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	} else {
		/* Unknown type, drop the packet */
		rte_pktmbuf_free(pkt);
	}
}
#endif /* DO_RFC_1812_CHECKS */

/* Enqueue a single packet, and send burst if queue is filled */
static inline void
l3fwd_acl_send_single_packet(struct rte_mbuf *m, uint16_t port)
{
	uint32_t lcore_id;
	struct lcore_conf *qconf;
	struct rte_ether_hdr *eh;

	lcore_id = rte_lcore_id();

	/* update src and dst mac*/
	eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	memcpy(eh, &port_l2hdr[port],
			sizeof(eh->dst_addr) + sizeof(eh->src_addr));

	qconf = &lcore_conf[lcore_id];
	rte_eth_tx_buffer(port, qconf->tx_queue_id[port],
			qconf->tx_buffer[port], m);
}

static inline void
l3fwd_acl_prepare_acl_parameter(struct rte_mbuf **pkts_in, struct acl_search_t *acl,
	int nb_rx)
{
	int i;

	acl->num_ipv4 = 0;
	acl->num_ipv6 = 0;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < nb_rx; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(
				pkts_in[i], void *));
	}

	for (i = 0; i < (nb_rx - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod(pkts_in[
				i + PREFETCH_OFFSET], void *));
		l3fwd_acl_prepare_one_packet(pkts_in, acl, i);
	}

	/* Process left packets */
	for (; i < nb_rx; i++)
		l3fwd_acl_prepare_one_packet(pkts_in, acl, i);
}

static inline void
l3fwd_acl_send_one_packet(struct rte_mbuf *m, uint32_t res)
{
	if (likely((res & ACL_DENY_SIGNATURE) == 0 && res != 0)) {
		/* forward packets */
		l3fwd_acl_send_single_packet(m,
			(uint8_t)(res - FWD_PORT_SHIFT));
	} else {
		/* in the ACL list, drop it */
#ifdef L3FWDACL_DEBUG
		if ((res & ACL_DENY_SIGNATURE) != 0) {
			if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
				dump_acl4_rule(m, res);
			else if (RTE_ETH_IS_IPV6_HDR(m->packet_type))
				dump_acl6_rule(m, res);
		}
#endif
		rte_pktmbuf_free(m);
	}
}

static inline void
l3fwd_acl_send_packets(struct rte_mbuf **m, uint32_t *res, int num)
{
	int i;

	/* Prefetch first packets */
	for (i = 0; i < PREFETCH_OFFSET && i < num; i++) {
		rte_prefetch0(rte_pktmbuf_mtod(
				m[i], void *));
	}

	for (i = 0; i < (num - PREFETCH_OFFSET); i++) {
		rte_prefetch0(rte_pktmbuf_mtod(m[
				i + PREFETCH_OFFSET], void *));
		l3fwd_acl_send_one_packet(m[i], res[i]);
	}

	/* Process left packets */
	for (; i < num; i++)
		l3fwd_acl_send_one_packet(m[i], res[i]);
}

#endif /* __L3FWD_ACL_SCALAR_H__ */
