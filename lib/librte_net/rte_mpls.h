/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 6WIND S.A.
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

#ifdef __cplusplus
extern "C" {
#endif

/**
 * MPLS header.
 */
struct rte_mpls_hdr {
	uint16_t tag_msb;   /**< Label(msb). */
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint32_t tag_lsb:4;  /**< Label(lsb). */
	uint32_t tc:3;       /**< Traffic class. */
	uint32_t bs:1;       /**< Bottom of stack. */
#else
	uint32_t bs:1;       /**< Bottom of stack. */
	uint32_t tc:3;       /**< Traffic class. */
	uint32_t tag_lsb:4;  /**< label(lsb) */
#endif
	uint8_t  ttl;       /**< Time to live. */
} __rte_packed;

#ifdef __cplusplus
}
#endif

#endif /* RTE_MPLS_H_ */
