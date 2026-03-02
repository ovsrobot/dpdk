/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 *
 * This file contains the items related methods
 */

#ifndef FLOW_PERF_ITEMS_GEN
#define FLOW_PERF_ITEMS_GEN

#include <stdint.h>
#include <rte_flow.h>

#include "config.h"

void fill_items(struct rte_flow_item *items, uint64_t *flow_items,
	uint32_t outer_ip_src, uint8_t core_idx);

/* Fill items template for async flow API (masks only, no spec values).
 * If spec_sizes is non-NULL, populates per-item spec sizes and n_items_out.
 */
void fill_items_template(struct rte_flow_item *items, uint64_t *flow_items, uint32_t outer_ip_src,
			 uint8_t core_idx, size_t *spec_sizes, uint32_t *n_items_out);

#endif /* FLOW_PERF_ITEMS_GEN */
