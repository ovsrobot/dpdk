/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

/* XXX: should this file be called eal_common_ldata.c or rte_ldata.c? */

#include <inttypes.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_log.h>

#include <rte_lcore_var.h>

#include "eal_private.h"

#define WARN_THRESHOLD 75
#define MAX_AUTO_ALIGNMENT 16U

/*
 * Avoid using offset zero, since it would result in a NULL-value
 * "handle" (offset) pointer, which in principle and per the API
 * definition shouldn't be an issue, but may confuse some tools and
 * users.
 */
#define INITIAL_OFFSET MAX_AUTO_ALIGNMENT

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
lcore_var_alloc(size_t size, size_t alignment)
{
	uintptr_t new_allocated = RTE_ALIGN_CEIL(allocated, alignment);

	void *offset = (void *)new_allocated;

	new_allocated += size;

	verify_allocation(new_allocated);

	allocated = new_allocated;

	EAL_LOG(DEBUG, "Allocated %"PRIuPTR" bytes of per-lcore data with a "
		"%"PRIuPTR"-byte alignment", size, alignment);

	return offset;
}

void *
rte_lcore_var_alloc(size_t size)
{
	RTE_BUILD_BUG_ON(RTE_MAX_LCORE_VAR % RTE_CACHE_LINE_SIZE != 0);

	/* Allocations are naturally aligned (i.e., the same alignment
	 * as the object size, up to a maximum of 16 bytes, which
	 * should satisify alignment requirements of any kind of
	 * object.
	 */
	size_t alignment = RTE_MIN(size, MAX_AUTO_ALIGNMENT);

	return lcore_var_alloc(size, alignment);
}
