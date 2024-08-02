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
 * Format description of packet to a string buffer
 *
 * @param buf
 *   A pointer to buffer for the resulting line.
 * @param size
 *   The format buffer size.
 * @param m
 *   The packet mbuf.
 * @param dump_len
 *   Maximum offset in packet to examine.
 *   If is zero then dump the whole packet.
 * @return
 *   Returns the number of bytes printed (excluding null byte at end of string).
 *   if output was truncated returns the number of bytes that would have been printed.
 */
__rte_experimental
int
rte_dissect_mbuf(char *buf, size_t size, const struct rte_mbuf *m, uint32_t dump_len);

#ifdef __cplusplus
}
#endif


#endif /* _RTE_NET_DISSECT_H_ */
