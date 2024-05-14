/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_COUNTER_H_
#define _RTE_COUNTER_H_

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 * RTE Counter
 *
 * A counter is 64 bit value that is safe from split read/write
 * on 32 bit platforms. It assumes that only one cpu at a time
 * will update the counter, and another CPU may want to read it.
 *
 * This is a much weaker guarantee than full atomic variables
 * but is faster since no locked operations are required for update.
 */

#include <stdatomic.h>

#ifdef RTE_ARCH_64
/*
 * On a platform that can support native 64 bit type, no special handling.
 * These are just wrapper around 64 bit value.
 */
typedef uint64_t rte_counter64_t;

/**
 * Add value to counter.
 */
__rte_experimental
static inline void
rte_counter64_add(rte_counter64_t *counter, uint32_t val)
{
	*counter += val;
}

__rte_experimental
static inline uint64_t
rte_counter64_fetch(const rte_counter64_t *counter)
{
	return *counter;
}

__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	*counter = 0;
}

#else
/*
 * On a 32 bit platform need to use atomic to force the compler to not
 * split 64 bit read/write.
 */
typedef RTE_ATOMIC(uint64_t) rte_counter64_t;

__rte_experimental
static inline void
rte_counter64_add(rte_counter64_t *counter, uint32_t val)
{
	rte_atomic_fetch_add_explicit(counter, val, rte_memory_order_relaxed);
}

__rte_experimental
static inline uint64_t
rte_counter64_fetch(const rte_counter64_t *counter)
{
	return rte_atomic_load_explicit(counter, rte_memory_order_relaxed);
}

__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	rte_atomic_store_explicit(counter, 0, rte_memory_order_relaxed);
}
#endif


#ifdef __cplusplus
}
#endif

#endif /* _RTE_COUNTER_H_ */
