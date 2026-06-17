/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Maxime Leroy, Free Mobile
 */

#ifndef _RIB6_INTERNAL_H_
#define _RIB6_INTERNAL_H_

#include <stdbool.h>

#include <rte_compat.h>

struct rte_rib6_node;

__rte_internal
bool
rte_rib6_node_has_children(const struct rte_rib6_node *node);

__rte_internal
struct rte_rib6_node *
rte_rib6_get_parent(const struct rte_rib6_node *node);

#endif /* _RIB6_INTERNAL_H_ */
