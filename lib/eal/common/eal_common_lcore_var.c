/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <inttypes.h>
#include <stdlib.h>

#ifdef RTE_EXEC_ENV_WINDOWS
#include <malloc.h>
#endif

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_log.h>

#include <rte_lcore_var.h>

#include "eal_private.h"

#define LCORE_BUFFER_SIZE (RTE_MAX_LCORE_VAR * RTE_MAX_LCORE)

static void *lcore_buffer;
static size_t offset = RTE_MAX_LCORE_VAR;

static void *
lcore_var_alloc(size_t size, size_t align)
{
	void *handle;
	void *value;

	offset = RTE_ALIGN_CEIL(offset, align);

	if (offset + size > RTE_MAX_LCORE_VAR) {
#ifdef RTE_EXEC_ENV_WINDOWS
		lcore_buffer = _aligned_malloc(LCORE_BUFFER_SIZE,
					       RTE_CACHE_LINE_SIZE);
#else
		lcore_buffer = aligned_alloc(RTE_CACHE_LINE_SIZE,
					     LCORE_BUFFER_SIZE);
#endif
		RTE_VERIFY(lcore_buffer != NULL);

		offset = 0;
	}

	handle = RTE_PTR_ADD(lcore_buffer, offset);

	offset += size;

	RTE_LCORE_VAR_FOREACH_VALUE(value, handle)
		memset(value, 0, size);

	EAL_LOG(DEBUG, "Allocated %"PRIuPTR" bytes of per-lcore data with a "
		"%"PRIuPTR"-byte alignment", size, align);

	return handle;
}

void *
rte_lcore_var_alloc(size_t size, size_t align)
{
	/* Having the per-lcore buffer size aligned on cache lines
	 * assures as well as having the base pointer aligned on cache
	 * size assures that aligned offsets also translate to alipgned
	 * pointers across all values.
	 */
	RTE_BUILD_BUG_ON(RTE_MAX_LCORE_VAR % RTE_CACHE_LINE_SIZE != 0);
	RTE_ASSERT(align <= RTE_CACHE_LINE_SIZE);
	RTE_ASSERT(size <= RTE_MAX_LCORE_VAR);

	/* '0' means asking for worst-case alignment requirements */
	if (align == 0)
		align = alignof(max_align_t);

	RTE_ASSERT(rte_is_power_of_2(align));

	return lcore_var_alloc(size, align);
}
