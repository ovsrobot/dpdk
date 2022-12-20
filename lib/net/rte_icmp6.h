/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef _RTE_ICMP6_H_
#define _RTE_ICMP6_H_

/**
 * @file
 *
 * ICMP6-related defines
 */

#include <stdint.h>

#include <rte_byteorder.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * ICMP6 header
 */
struct rte_icmp6_hdr {
	uint8_t type;
	uint8_t code;
	rte_be16_t checksum;
} __rte_packed;

/**
 * ICMP6 echo
 */
struct rte_icmp6_echo {
	struct rte_icmp6_hdr hdr;
	rte_be16_t identifier;
	rte_be16_t sequence;
} __rte_packed;

/* ICMP6 packet types */
#define RTE_ICMP6_ECHO_REQUEST 128
#define RTE_ICMP6_ECHO_REPLY   129

#ifdef __cplusplus
}
#endif

#endif /* RTE_ICMP6_H_ */
