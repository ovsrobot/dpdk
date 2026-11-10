/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 6WIND S.A.
 * Copyright(c) 2026 SmartShare Systems
 */

#ifndef _RTE_MPLS_H_
#define _RTE_MPLS_H_

/**
 * @file
 *
 * MPLS-related defines
 */

#include <stdint.h>
#include <rte_byteorder.h>

/*
 * Special-Purpose MPLS Label Values
 * https://www.iana.org/assignments/mpls-label-values
 */
#define RTE_MPLS_LABEL_IPV4         0   /**< IPv4 Explicit NULL Label (RFC 3032). */
#define RTE_MPLS_LABEL_ROUTER_ALERT 1   /**< Router Alert Label (RFC 3032). */
#define RTE_MPLS_LABEL_IPV6         2   /**< IPv6 Explicit NULL Label (RFC 3032). */
#define RTE_MPLS_LABEL_NULL         3   /**< Implicit NULL Label (RFC 3032). */
#define RTE_MPLS_LABEL_MNA          4   /**< MPLS Network Actions (RFC 9994). */
#define RTE_MPLS_LABEL_ELI          7   /**< Entropy Label Indicator (ELI) (RFC 6790). */
#define RTE_MPLS_LABEL_GAL          13  /**< Generic Associated Channel Label (GAL) (RFC 5586). */
#define RTE_MPLS_LABEL_OAM_ALERT    14  /**< OAM Alert Label (RFC 3429). */
#define RTE_MPLS_LABEL_XL           15  /**< Extension Label (XL) (RFC 7274; RFC 9017). */
/* Extended Special-Purpose MPLS Label Values (valid when following an Extension Label) */
#define RTE_MPLS_LABEL_MLI          16  /**< Metadata Label Indicator (MLI) (RFC 8595). */
#define RTE_MPLS_LABEL_MPI          17  /**< Metadata Present Indicator (MPI) (RFC 8595). */
#define RTE_MPLS_LABEL_FLI          18  /**< Flow-ID Label Indicator (FLI) (RFC 9714). */

/**
 * MPLS header.
 */
__extension__
struct __rte_packed_begin rte_mpls_hdr {
	rte_be16_t tag_msb; /**< Label(msb). */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint8_t tag_lsb:4;  /**< Label(lsb). */
	uint8_t tc:3;       /**< Traffic class. */
	uint8_t bs:1;       /**< Bottom of stack. */
#else
	uint8_t bs:1;       /**< Bottom of stack. */
	uint8_t tc:3;       /**< Traffic class. */
	uint8_t tag_lsb:4;  /**< label(lsb) */
#endif
	uint8_t  ttl;       /**< Time to live. */
} __rte_packed_end;

#endif /* RTE_MPLS_H_ */
