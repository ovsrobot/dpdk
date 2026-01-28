/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 */

#ifndef _RTE_NET_PTYPE_H_
#define _RTE_NET_PTYPE_H_

#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Structure containing header lengths associated to a packet, filled
 * by rte_net_get_ptype().
 */
struct rte_net_hdr_lens {
	uint8_t l2_len;
	/* Outer_L4_len + ... + inner L2_len for tunneling pkt. */
	uint8_t inner_l2_len;
	uint16_t l3_len;
	uint16_t inner_l3_len;
	/* Protocol header of tunnel packets */
	uint16_t tunnel_len;
	uint8_t l4_len;
	uint8_t inner_l4_len;
};

/**
 * Skip IPv6 header extensions.
 *
 * This function skips all IPv6 extensions, returning size of
 * complete header including options and final protocol value.
 *
 * @param proto
 *   Protocol field of IPv6 header.
 * @param m
 *   The packet mbuf to be parsed.
 * @param off
 *   On input, must contain the offset to the first byte following
 *   IPv6 header, on output, contains offset to the first byte
 *   of next layer (after any IPv6 extension header)
 * @param frag
 *   Contains 1 in output if packet is an IPv6 fragment.
 * @return
 *   Protocol that follows IPv6 header.
 *   -1 if an error occurs during mbuf parsing.
 */
int
rte_net_skip_ip6_ext(uint16_t proto, const struct rte_mbuf *m, uint32_t *off,
	int *frag);

/**
 * Parse an Ethernet packet to get its packet type.
 *
 * This function parses the network headers in mbuf data and return its
 * packet type.
 *
 * If it is provided by the user, it also fills a rte_net_hdr_lens
 * structure that contains the lengths of the parsed network
 * headers. Each length field is valid only if the associated packet
 * type is set. For instance, hdr_lens->l2_len is valid only if
 * (retval & RTE_PTYPE_L2_MASK) != RTE_PTYPE_UNKNOWN.
 *
 * Supported packet types are:
 *   L2: Ether, Vlan, QinQ
 *   L3: IPv4, IPv6
 *   L4: TCP, UDP, SCTP
 *   Tunnels: IPv4, IPv6, Gre, Nvgre
 *
 * @param m
 *   The packet mbuf to be parsed.
 * @param hdr_lens
 *   A pointer to a structure where the header lengths will be returned,
 *   or NULL.
 * @param layers
 *   List of layers to parse. The function will stop at the first
 *   empty layer. Examples:
 *   - To parse all known layers, use RTE_PTYPE_ALL_MASK.
 *   - To parse only L2 and L3, use RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK
 * @return
 *   The packet type of the packet.
 */
uint32_t rte_net_get_ptype(const struct rte_mbuf *m,
	struct rte_net_hdr_lens *hdr_lens, uint32_t layers);

/**
 * Prepare pseudo header checksum
 *
 * This function prepares pseudo header checksum for TSO and non-TSO tcp/udp in
 * provided mbufs packet data and based on the requested offload flags.
 *
 * - for non-TSO tcp/udp packets full pseudo-header checksum is counted and set
 *   in packet data,
 * - for TSO the IP payload length is not included in pseudo header.
 *
 * This function expects that used headers are in the first data segment of
 * mbuf, are not fragmented and can be safely modified.
 *
 * @param m
 *   The packet mbuf to be fixed.
 * @param ol_flags
 *   TX offloads flags to use with this packet.
 * @return
 *   0 if checksum is initialized properly
 */
static inline int
rte_net_intel_cksum_flags_prepare(struct rte_mbuf *m, uint64_t ol_flags)
{
	const uint64_t inner_requests = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_L4_MASK |
		RTE_MBUF_F_TX_TCP_SEG | RTE_MBUF_F_TX_UDP_SEG;
	const uint64_t outer_requests = RTE_MBUF_F_TX_OUTER_IP_CKSUM |
		RTE_MBUF_F_TX_OUTER_UDP_CKSUM;
	/* Initialise ipv4_hdr to avoid false positive compiler warnings. */
	struct rte_ipv4_hdr *ipv4_hdr = NULL;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_tcp_hdr *tcp_hdr;
	struct rte_udp_hdr *udp_hdr;
	uint64_t inner_l3_offset = m->l2_len;

	/*
	 * Does packet set any of available offloads?
	 * Mainly it is required to avoid fragmented headers check if
	 * no offloads are requested.
	 */
	if (!(ol_flags & (inner_requests | outer_requests)))
		return 0;

	if (ol_flags & (RTE_MBUF_F_TX_OUTER_IPV4 | RTE_MBUF_F_TX_OUTER_IPV6)) {
		inner_l3_offset += m->outer_l2_len + m->outer_l3_len;
		/*
		 * prepare outer IPv4 header checksum by setting it to 0,
		 * in order to be computed by hardware NICs.
		 */
		if (ol_flags & RTE_MBUF_F_TX_OUTER_IP_CKSUM) {
			ipv4_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_ipv4_hdr *, m->outer_l2_len);
			ipv4_hdr->hdr_checksum = 0;
		}
		if (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM || ol_flags & inner_requests) {
			if (ol_flags & RTE_MBUF_F_TX_OUTER_IPV4) {
				ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
					m->outer_l2_len);
				udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr +
					m->outer_l3_len);
				if (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM)
					udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
						m->ol_flags);
				else if (ipv4_hdr->next_proto_id == IPPROTO_UDP)
					udp_hdr->dgram_cksum = 0;
			} else {
				ipv6_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv6_hdr *,
					m->outer_l2_len);
				udp_hdr = rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *,
					 m->outer_l2_len + m->outer_l3_len);
				if (ol_flags & RTE_MBUF_F_TX_OUTER_UDP_CKSUM)
					udp_hdr->dgram_cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
						m->ol_flags);
				else if (ipv6_hdr->proto == IPPROTO_UDP)
					udp_hdr->dgram_cksum = 0;
			}
		}
	}

	/*
	 * Check if headers are fragmented.
	 * The check could be less strict depending on which offloads are
	 * requested and headers to be used, but let's keep it simple.
	 */
	if (unlikely(rte_pktmbuf_data_len(m) <
		     inner_l3_offset + m->l3_len + m->l4_len))
		return -ENOTSUP;

	if (ol_flags & RTE_MBUF_F_TX_IPV4) {
		ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *,
				inner_l3_offset);

		if (ol_flags & RTE_MBUF_F_TX_IP_CKSUM)
			ipv4_hdr->hdr_checksum = 0;
	}

	if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_UDP_CKSUM ||
			(ol_flags & RTE_MBUF_F_TX_UDP_SEG)) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr +
					m->l3_len);
			udp_hdr->dgram_cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
					ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
				struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO udp */
			udp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_udp_hdr *,
					inner_l3_offset + m->l3_len);
			udp_hdr->dgram_cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
					ol_flags);
		}
	} else if ((ol_flags & RTE_MBUF_F_TX_L4_MASK) == RTE_MBUF_F_TX_TCP_CKSUM ||
			(ol_flags & RTE_MBUF_F_TX_TCP_SEG)) {
		if (ol_flags & RTE_MBUF_F_TX_IPV4) {
			/* non-TSO tcp or TSO */
			tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr +
					m->l3_len);
			tcp_hdr->cksum = rte_ipv4_phdr_cksum(ipv4_hdr,
					ol_flags);
		} else {
			ipv6_hdr = rte_pktmbuf_mtod_offset(m,
				struct rte_ipv6_hdr *, inner_l3_offset);
			/* non-TSO tcp or TSO */
			tcp_hdr = rte_pktmbuf_mtod_offset(m,
					struct rte_tcp_hdr *,
					inner_l3_offset + m->l3_len);
			tcp_hdr->cksum = rte_ipv6_phdr_cksum(ipv6_hdr,
					ol_flags);
		}
	}

	return 0;
}

/**
 * Prepare pseudo header checksum
 *
 * This function prepares pseudo header checksum for TSO and non-TSO tcp/udp in
 * provided mbufs packet data.
 *
 * - for non-TSO tcp/udp packets full pseudo-header checksum is counted and set
 *   in packet data,
 * - for TSO the IP payload length is not included in pseudo header.
 *
 * This function expects that used headers are in the first data segment of
 * mbuf, are not fragmented and can be safely modified.
 *
 * @param m
 *   The packet mbuf to be fixed.
 * @return
 *   0 if checksum is initialized properly
 */
static inline int
rte_net_intel_cksum_prepare(struct rte_mbuf *m)
{
	return rte_net_intel_cksum_flags_prepare(m, m->ol_flags);
}

/**
 * Compute IPv4 header and UDP/TCP checksums in software.
 *
 * Computes checksums based on mbuf offload flags:
 * - RTE_MBUF_F_TX_IP_CKSUM: Compute IPv4 header checksum
 * - RTE_MBUF_F_TX_UDP_CKSUM: Compute UDP checksum (IPv4 or IPv6)
 * - RTE_MBUF_F_TX_TCP_CKSUM: Compute TCP checksum (IPv4 or IPv6)
 *
 * @param mbuf
 *   The packet mbuf. Must have l2_len and l3_len set correctly.
 * @param copy
 *   If true, copy L2/L3/L4 headers to a new segment before computing
 *   checksums. This is safe for indirect mbufs but has overhead.
 *   If false, compute checksums in place. This is only safe if the
 *   mbuf will be copied afterward (e.g., to a device ring buffer).
 * @return
 *   - On success: Returns mbuf (new segment if copy=true, original if copy=false)
 *   - On error: Returns NULL (allocation failed or malformed packet)
 */
static inline struct rte_mbuf *
rte_net_ip_udptcp_cksum_mbuf(struct rte_mbuf *mbuf, bool copy)
{
	const uint64_t l4_ol_flags = mbuf->ol_flags & RTE_MBUF_F_TX_L4_MASK;
	const uint64_t l4_offset = mbuf->l2_len + mbuf->l3_len;
	uint32_t hdrlens = l4_offset;

	/* Determine total header length needed */
	if (l4_ol_flags == RTE_MBUF_F_TX_UDP_CKSUM)
		hdrlens += sizeof(struct rte_udp_hdr);
	else if (l4_ol_flags == RTE_MBUF_F_TX_TCP_CKSUM)
		hdrlens += sizeof(struct rte_tcp_hdr);
	else if (l4_ol_flags != RTE_MBUF_F_TX_L4_NO_CKSUM)
		return NULL; /* Unsupported L4 checksum type */
	else if (!(mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM))
		return mbuf; /* Nothing to do */

	/* Validate we at least have L2+L3 headers before doing any work */
	if (unlikely(rte_pktmbuf_data_len(mbuf) < l4_offset))
		return NULL;

	if (copy) {
		/*
		 * Copy headers to new segment to handle indirect mbufs.
		 * This ensures we can safely modify checksums without
		 * corrupting shared/read-only data.
		 */
		struct rte_mbuf *seg = rte_pktmbuf_copy(mbuf, mbuf->pool, 0, hdrlens);
		if (!seg)
			return NULL;

		rte_pktmbuf_adj(mbuf, hdrlens);
		rte_pktmbuf_chain(seg, mbuf);
		mbuf = seg;
	} else if (unlikely(!RTE_MBUF_DIRECT(mbuf) || rte_mbuf_refcnt_read(mbuf) > 1))
		return NULL;

	void *l3_hdr = rte_pktmbuf_mtod_offset(mbuf, void *, mbuf->l2_len);

	/* IPv4 header checksum */
	if (mbuf->ol_flags & RTE_MBUF_F_TX_IP_CKSUM) {
		struct rte_ipv4_hdr *iph = l3_hdr;
		iph->hdr_checksum = 0;
		iph->hdr_checksum = rte_ipv4_cksum(iph);
	}

	/* L4 checksum (UDP or TCP) - skip if headers not in first segment */
	if (l4_ol_flags == RTE_MBUF_F_TX_UDP_CKSUM && rte_pktmbuf_data_len(mbuf) >= hdrlens) {
		struct rte_udp_hdr *udp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_udp_hdr *,
				l4_offset);
		udp_hdr->dgram_cksum = 0;
		udp_hdr->dgram_cksum = (mbuf->ol_flags & RTE_MBUF_F_TX_IPV4) ?
			rte_ipv4_udptcp_cksum_mbuf(mbuf, (const struct rte_ipv4_hdr *)l3_hdr,
					l4_offset) :
			rte_ipv6_udptcp_cksum_mbuf(mbuf, (const struct rte_ipv6_hdr *)l3_hdr,
					l4_offset);
	} else if (l4_ol_flags == RTE_MBUF_F_TX_TCP_CKSUM &&
			rte_pktmbuf_data_len(mbuf) >= hdrlens) {
		struct rte_tcp_hdr *tcp_hdr = rte_pktmbuf_mtod_offset(mbuf, struct rte_tcp_hdr *,
				l4_offset);
		tcp_hdr->cksum = 0;
		tcp_hdr->cksum = (mbuf->ol_flags & RTE_MBUF_F_TX_IPV4) ?
			rte_ipv4_udptcp_cksum_mbuf(mbuf,  (const struct rte_ipv4_hdr *)l3_hdr,
					l4_offset) :
			rte_ipv6_udptcp_cksum_mbuf(mbuf, (const struct rte_ipv6_hdr *)l3_hdr,
					l4_offset);
	}

	return mbuf;
}

#ifdef __cplusplus
}
#endif


#endif /* _RTE_NET_PTYPE_H_ */
