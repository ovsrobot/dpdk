/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Maxime Leroy, Free Mobile
 */

#ifndef _RIB6_INTERNAL_H_
#define _RIB6_INTERNAL_H_

#include <stdint.h>

#include <rte_compat.h>
#include <rte_ip6.h>

struct rte_rib6;

/**
 * @internal
 * Count byte boundaries L in {24, 32, 40, ..., RTE_ALIGN_CEIL(depth, 8) - 8}
 * for which the supernet of ip at level L has no valid descendant with
 * depth > L. Used by lib/fib to maintain tbl8 reservation accounting in
 * a single descent of the binary tree.
 *
 * @param rib
 *  RIB object handle
 * @param ip
 *  IPv6 prefix address
 * @param depth
 *  prefix length
 * @return
 *  number of empty byte boundaries (0 if all levels have descendants
 *  or depth <= 24)
 */
__rte_internal
uint8_t
rte_rib6_count_empty_supernets(struct rte_rib6 *rib,
	const struct rte_ipv6_addr *ip, uint8_t depth);

#endif /* _RIB6_INTERNAL_H_ */
