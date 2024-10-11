/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 1982, 1986, 1990, 1993
 *      The Regents of the University of California.
 * Copyright(c) 2013 6WIND S.A.
 * All rights reserved.
 */

#ifndef _RTE_ICMP_H_
#define _RTE_ICMP_H_

/**
 * @file
 *
 * ICMP-related defines
 */

#include <stdint.h>

#include <rte_byteorder.h>

/**
 * ICMP base header
 */
struct /* native alignment: __rte_aligned(2) */ rte_icmp_base_hdr {
	uint8_t type;
	uint8_t code;
	rte_be16_t checksum;
};

/**
 * ICMP echo header
 */
struct /* native alignment: __rte_aligned(2) */ rte_icmp_echo_hdr {
	struct rte_icmp_base_hdr base;
	rte_be16_t identifier;
	rte_be16_t sequence;
};

/**
 * ICMP Header
 *
 * @see rte_icmp_echo_hdr which is similar.
 */
struct /* native alignment: __rte_aligned(2) */ rte_icmp_hdr {
	uint8_t  icmp_type;     /* ICMP packet type. */
	uint8_t  icmp_code;     /* ICMP packet code. */
	rte_be16_t icmp_cksum;  /* ICMP packet checksum. */
	rte_be16_t icmp_ident;  /* ICMP packet identifier. */
	rte_be16_t icmp_seq_nb; /* ICMP packet sequence number. */
};

/* ICMP packet types */
#define RTE_IP_ICMP_ECHO_REPLY   0
#define RTE_IP_ICMP_ECHO_REQUEST 8
#define RTE_ICMP6_ECHO_REQUEST 128
#define RTE_ICMP6_ECHO_REPLY   129

#endif /* RTE_ICMP_H_ */
