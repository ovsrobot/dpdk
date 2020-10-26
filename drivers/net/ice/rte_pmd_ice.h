/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _RTE_PMD_ICE_H_
#define _RTE_PMD_ICE_H_

/**
 * @file rte_pmd_ice.h
 *
 * ice PMD specific functions.
 *
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __INTEL_RX_FLEX_DESC_METADATA__
#define __INTEL_RX_FLEX_DESC_METADATA__

/**
 * The supported network protocol extraction metadata format.
 */
union rte_pmd_proto_xtr_metadata {
	uint32_t metadata;

	struct {
		uint16_t data0;
		uint16_t data1;
	} raw;

	struct {
		uint16_t stag_vid:12,
			 stag_dei:1,
			 stag_pcp:3;
		uint16_t ctag_vid:12,
			 ctag_dei:1,
			 ctag_pcp:3;
	} vlan;

	struct {
		uint16_t protocol:8,
			 ttl:8;
		uint16_t tos:8,
			 ihl:4,
			 version:4;
	} ipv4;

	struct {
		uint16_t hoplimit:8,
			 nexthdr:8;
		uint16_t flowhi4:4,
			 tc:8,
			 version:4;
	} ipv6;

	struct {
		uint16_t flowlo16;
		uint16_t flowhi4:4,
			 tc:8,
			 version:4;
	} ipv6_flow;

	struct {
		uint16_t fin:1,
			 syn:1,
			 rst:1,
			 psh:1,
			 ack:1,
			 urg:1,
			 ece:1,
			 cwr:1,
			 res1:4,
			 doff:4;
		uint16_t rsvd;
	} tcp;

	uint32_t ip_ofs;
};

/**
 * The mbuf dynamic field metadata for protocol extraction from hardware:
 *
 *  a). Extract one word from the defined location of the specified
 *      protocol in the packet.
 *  b). Report the offset to the selected protocol type.
 *
 *  And the metadata can hold two of the above defined fields (in word), these
 *  words are in host endian order.
 */
#define RTE_PMD_DYNFIELD_PROTO_XTR_METADATA_NAME \
	"rte_pmd_dynfield_proto_xtr_metadata"

/**
 * The mbuf dynamic flag for VLAN protocol extraction metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_VLAN_NAME \
	"rte_pmd_dynflag_proto_xtr_vlan"

/**
 * The mbuf dynamic flag for IPv4 protocol extraction metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_IPV4_NAME \
	"rte_pmd_dynflag_proto_xtr_ipv4"

/**
 * The mbuf dynamic flag for IPv6 protocol extraction metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_IPV6_NAME \
	"rte_pmd_dynflag_proto_xtr_ipv6"

/**
 * The mbuf dynamic flag for IPv6 with flow protocol extraction metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_IPV6_FLOW_NAME \
	"rte_pmd_dynflag_proto_xtr_ipv6_flow"

/**
 * The mbuf dynamic flag for TCP protocol extraction metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_TCP_NAME \
	"rte_pmd_dynflag_proto_xtr_tcp"

/**
 * The mbuf dynamic flag for IPv4 or IPv6 header offset report metadata type.
 */
#define RTE_PMD_DYNFLAG_PROTO_XTR_IP_OFFSET_NAME \
	"rte_pmd_dynflag_proto_xtr_ip_offset"

#endif /* __INTEL_RX_FLEX_DESC_METADATA__ */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMD_ICE_H_ */
