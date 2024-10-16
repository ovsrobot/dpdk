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
#include "eal_lcore_var.h"

/*
 * An lcore var buffer stores at a minimum one, but usually many,
 * lcore variables. The value instances for all lcore ids are stored
 * in the same buffer.
 *
 * The address of the value of a particular lcore variable associated
 * with a particular lcore id is:
 * buffer->data + offset + lcore_id * RTE_MAX_LCORE_VAR.
 *
 * In this way, the values associated with a particular lcore id are
 * grouped spatially close (in the data array), and no padding is
 * required to prevent false sharing.
 *
 * The (buffer->data + offset) base pointer is what is being returned
 * to the API user as an opaque handle. The handle is a pointer to the
 * value for lcore id 0, for that lcore variable.
 *
 * The implementation maintains a current lcore var buffer (being
 * allocated from), and an offset representing the amount of data
 * already allocated (in bytes) in that buffer.
 *
 * The offset is progressively incremented (by the size of the
 * just-allocated lcore variable), as lcore variables are being
 * allocated.
 *
 * When one lcore var buffer is full, a new is allocated off the heap.
 *
 * The lcore var buffers are arranged in a single-link list, to allow
 * freeing them at the point of rte_eal_cleanup(), and thereby avoid
 * false positives from tools like valgrind memcheck.
 */
struct lcore_var_buffer {
	char data[RTE_MAX_LCORE_VAR * RTE_MAX_LCORE];
	struct lcore_var_buffer *prev;
};

static struct lcore_var_buffer *current_buffer;

/* initialized to trigger buffer allocation on first allocation */
static size_t offset = RTE_MAX_LCORE_VAR;

static void *
lcore_var_alloc(size_t size, size_t align)
{
	void *handle;
	unsigned int lcore_id;
	void *value;

	offset = RTE_ALIGN_CEIL(offset, align);

	if (offset + size > RTE_MAX_LCORE_VAR) {
		struct lcore_var_buffer *prev = current_buffer;
		size_t alloc_size =
			RTE_ALIGN_CEIL(sizeof(struct lcore_var_buffer),
				       RTE_CACHE_LINE_SIZE);
#ifdef RTE_EXEC_ENV_WINDOWS
		current_buffer = _aligned_malloc(alloc_size, RTE_CACHE_LINE_SIZE);
#else
		current_buffer = aligned_alloc(RTE_CACHE_LINE_SIZE, alloc_size);

#endif
		RTE_VERIFY(current_buffer != NULL);

		current_buffer->prev = prev;

		offset = 0;
	}

	handle = &current_buffer->data[offset];

	offset += size;

	RTE_LCORE_VAR_FOREACH(lcore_id, value, handle)
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
	RTE_VERIFY(align <= RTE_CACHE_LINE_SIZE);
	RTE_VERIFY(size <= RTE_MAX_LCORE_VAR);

	/* '0' means asking for worst-case alignment requirements */
	if (align == 0)
#ifdef RTE_TOOLCHAIN_MSVC
		/* MSVC <stddef.h> is missing the max_align_t typedef */
		align = alignof(double);
#else
		align = alignof(max_align_t);
#endif

	RTE_VERIFY(rte_is_power_of_2(align));

	return lcore_var_alloc(size, align);
}

void
eal_lcore_var_cleanup(void)
{
	while (current_buffer != NULL) {
		struct lcore_var_buffer *prev = current_buffer->prev;

		free(current_buffer);

		current_buffer = prev;
	}
}
