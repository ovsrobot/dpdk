/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Intel Corporation
 */

#include <stdlib.h>

#include <rte_common.h>

#include "ixgbe_osdep.h"

void *
ixgbe_calloc(struct ixgbe_hw __rte_unused *hw, size_t count, size_t size)
{
	return malloc(count * size);
}

void *
ixgbe_malloc(struct ixgbe_hw __rte_unused *hw, size_t size)
{
	return malloc(size);
}

void
ixgbe_free(struct ixgbe_hw __rte_unused *hw, void *addr)
{
	free(addr);
}
