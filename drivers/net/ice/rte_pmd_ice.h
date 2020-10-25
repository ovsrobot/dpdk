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

#include <stdio.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __INTEL_FXP_RX_DESC_METADATA__
#define __INTEL_FXP_RX_DESC_METADATA__

/**
 * The mbuf dynamic field for metadata extraction from NIC:
 *  a). Extract 16b (2 Bytes) from the defined offset location of the specified
 *      protocol in the packet.
 *  b). Report the offset to the selected protocol.
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

#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMD_ICE_H_ */
