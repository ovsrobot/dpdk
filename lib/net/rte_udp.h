/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright(c) 2010-2014 Intel Corporation.
 * All rights reserved.
 */

#ifndef _RTE_UDP_H_
#define _RTE_UDP_H_

/**
 * @file
 *
 * UDP-related defines
 */

#include <assert.h>
#include <stdalign.h>
#include <stdint.h>

#include <rte_byteorder.h>

/**
 * UDP Header
 */
struct /* native alignment: __rte_aligned(2) */ rte_udp_hdr {
	rte_be16_t src_port;    /**< UDP source port. */
	rte_be16_t dst_port;    /**< UDP destination port. */
	rte_be16_t dgram_len;   /**< UDP datagram length */
	rte_be16_t dgram_cksum; /**< UDP datagram checksum */
};

static_assert(sizeof(struct rte_udp_hdr) == 8,
		"sizeof(struct rte_udp_hdr) == 8");
static_assert(alignof(struct rte_udp_hdr) == 2,
		"alignof(struct rte_udp_hdr) == 2");

#endif /* RTE_UDP_H_ */
