/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <inttypes.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_log.h>

#include <rte_lcore_var.h>

#include "eal_private.h"

#define WARN_THRESHOLD 75

/*
 * Avoid using offset zero, since it would result in a NULL-value
 * "handle" (offset) pointer, which in principle and per the API
 * definition shouldn't be an issue, but may confuse some tools and
 * users.
 */
#define INITIAL_OFFSET 1

char rte_lcore_var[RTE_MAX_LCORE][RTE_MAX_LCORE_VAR] __rte_cache_aligned;

static uintptr_t allocated = INITIAL_OFFSET;

static void
verify_allocation(uintptr_t new_allocated)
{
	static bool has_warned;

	RTE_VERIFY(new_allocated < RTE_MAX_LCORE_VAR);

	if (new_allocated > (WARN_THRESHOLD * RTE_MAX_LCORE_VAR) / 100 &&
	    !has_warned) {
		EAL_LOG(WARNING, "Per-lcore data usage has exceeded %d%% "
			"of the maximum capacity (%d bytes)", WARN_THRESHOLD,
			RTE_MAX_LCORE_VAR);
		has_warned = true;
	}
}

static void *
lcore_var_alloc(size_t size, size_t align)
{
	uintptr_t new_allocated = RTE_ALIGN_CEIL(allocated, align);

	void *offset = (void *)new_allocated;

	new_allocated += size;

	verify_allocation(new_allocated);

	allocated = new_allocated;

	EAL_LOG(DEBUG, "Allocated %"PRIuPTR" bytes of per-lcore data with a "
		"%"PRIuPTR"-byte alignment", size, align);

	return offset;
}

void *
rte_lcore_var_alloc(size_t size, size_t align)
{
	/* Having the per-lcore buffer size aligned on cache lines
	 * assures as well as having the base pointer aligned on cache
	 * size assures that aligned offsets also translate to aligned
	 * pointers across all values.
	 */
	RTE_BUILD_BUG_ON(RTE_MAX_LCORE_VAR % RTE_CACHE_LINE_SIZE != 0);
	RTE_ASSERT(align <= RTE_CACHE_LINE_SIZE);

	/* '0' means asking for worst-case alignment requirements */
	if (align == 0)
		align = alignof(max_align_t);

	RTE_ASSERT(rte_is_power_of_2(align));

	return lcore_var_alloc(size, align);
}
