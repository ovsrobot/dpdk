/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Intel Corporation
 */

#ifndef _RTE_VXLAN_H_
#define _RTE_VXLAN_H_

/**
 * @file
 *
 * VXLAN-related definitions
 */

#include <stdint.h>

#include <rte_byteorder.h>
#include <rte_udp.h>


#ifdef __cplusplus
extern "C" {
#endif

/** VXLAN default port. */
#define RTE_VXLAN_DEFAULT_PORT 4789
#define RTE_VXLAN_GPE_DEFAULT_PORT 4790

/**
 * VXLAN protocol header.
 * Contains the 8-bit flag, 24-bit VXLAN Network Identifier and
 * Reserved fields (24 bits and 8 bits)
 */
__extension__ /* no named member in struct */
struct rte_vxlan_hdr {
	union {
		struct {
			rte_be32_t vx_flags; /**< flags (8) + Reserved (24). */
			rte_be32_t vx_vni;   /**< VNI (24) + Reserved (8). */
		};
		struct {
			union {
				uint8_t    flags;    /**< Should be 8 (I flag). */
				/* Flag bits defined by GPE */
				struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
					uint8_t flag_o:1,
						flag_b:1,
						flag_p:1,
						flag_i_gpe:1,
						flag_ver:2,
						rsvd_gpe:2;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
					uint8_t rsvd_gpe:2,
						flag_ver:2,
						flag_i_gpe:1,
						flag_p:1,
						flag_b:1,
						flag_o:1;
#endif
				} __rte_packed;
				/* Flag bits defined by GBP */
				struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
					uint8_t rsvd_gbp2:3,
						flag_i_gbp:1,
						rsvd_gbp1:3,
						flag_g:1;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
					uint8_t flag_g:1,
						rsvd_gbp1:3,
						flag_i_gbp:1,
						rsvd_gbp2:3;
#endif
				} __rte_packed;
			};
			union {
				uint8_t    rsvd0[3]; /**< Reserved. */
				/* Overlap with rte_vxlan_gpe_hdr which is deprecated.*/
				struct {
					uint8_t rsvd0_gpe[2]; /**< Reserved. */
					uint8_t proto;	   /**< Next protocol. */
				} __rte_packed;
				struct {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
					uint8_t rsvd0_gbp3:3,
						flag_a:1,
						rsvd0_gbp2:2,
						flag_d:1,
						rsvd0_gbp1:1;
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
					uint8_t rsvd0_gbp1:1,
						flag_d:1,
						rsvd0_gbp2:2,
						flag_a:1,
						rsvd0_gbp3:3;
#endif
					uint16_t policy_id;
				} __rte_packed;
			} __rte_packed;
			uint8_t    vni[3];   /**< VXLAN identifier. */
			uint8_t    rsvd1;    /**< Reserved. */
		} __rte_packed;
	};
} __rte_packed;

/** VXLAN tunnel header length. */
#define RTE_ETHER_VXLAN_HLEN \
	(sizeof(struct rte_udp_hdr) + sizeof(struct rte_vxlan_hdr))


/**
 * @deprecated Replaced with ``rte_vxlan_hdr``.
 * VXLAN-GPE protocol header (draft-ietf-nvo3-vxlan-gpe-05).
 * Contains the 8-bit flag, 8-bit next-protocol, 24-bit VXLAN Network
 * Identifier and Reserved fields (16 bits and 8 bits).
 */
__extension__ /* no named member in struct */
struct rte_vxlan_gpe_hdr {
	union {
		struct {
			uint8_t vx_flags;    /**< flag (8). */
			uint8_t reserved[2]; /**< Reserved (16). */
			uint8_t protocol;    /**< next-protocol (8). */
			rte_be32_t vx_vni;   /**< VNI (24) + Reserved (8). */
		};
		struct {
			uint8_t flags;    /**< Flags. */
			uint8_t rsvd0[2]; /**< Reserved. */
			uint8_t proto;    /**< Next protocol. */
			uint8_t vni[3];   /**< VXLAN identifier. */
			uint8_t rsvd1;    /**< Reserved. */
		};
	};
} __rte_packed;

/**
 * @deprecated Replaced with ``RTE_ETHER_VXLAN_HLEN``.
 * VXLAN-GPE tunnel header length.
 */
#define RTE_ETHER_VXLAN_GPE_HLEN (sizeof(struct rte_udp_hdr) + \
		sizeof(struct rte_vxlan_gpe_hdr))

/* VXLAN-GPE next protocol types */
#define RTE_VXLAN_GPE_TYPE_IPV4 1 /**< IPv4 Protocol. */
#define RTE_VXLAN_GPE_TYPE_IPV6 2 /**< IPv6 Protocol. */
#define RTE_VXLAN_GPE_TYPE_ETH  3 /**< Ethernet Protocol. */
#define RTE_VXLAN_GPE_TYPE_NSH  4 /**< NSH Protocol. */
#define RTE_VXLAN_GPE_TYPE_MPLS 5 /**< MPLS Protocol. */
#define RTE_VXLAN_GPE_TYPE_GBP  6 /**< GBP Protocol. */
#define RTE_VXLAN_GPE_TYPE_VBNG 7 /**< vBNG Protocol. */


#ifdef __cplusplus
}
#endif

#endif /* RTE_VXLAN_H_ */
