/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_NET_DISSECT_H_
#define _RTE_NET_DISSECT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>

#include <rte_compat.h>

struct rte_mbuf;

/**
 *
 * Print packets in format (single line) similar to tshark to a file.
 *
 * @param f
 *   A pointer to a file for output
 * @param m
 *   The packet mbuf.
 * @param dump_len
 *   Maximum offset in packet to examine.
 *   If is zero then dump the whole packet.
 */
__rte_experimental
void
rte_dissect_mbuf(FILE *f, const struct rte_mbuf *m, uint32_t dump_len);

#ifdef __cplusplus
}
#endif


#endif /* _RTE_NET_DISSECT_H_ */
