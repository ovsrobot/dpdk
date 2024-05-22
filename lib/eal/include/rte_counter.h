/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_COUNTER_H_
#define _RTE_COUNTER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_compat.h>
#include <rte_common.h>
#include <rte_stdatomic.h>

/**
 * @file
 * RTE Counter
 *
 * A counter is 64 bit value that is safe from split read/write.
 * It assumes that only one CPU at a time  will update the counter,
 * and another CPU may want to read it.
 *
 * This is a weaker subset of full atomic variables.
 *
 * The counters are subject to the restrictions of atomic variables
 * in packed structures or unaligned.
 */

#ifndef RTE_ARCH_I686

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * On platforms where 64 bit values are not split by compiler, the counter
 * is implemented as basic 64 bit unsigned integer that only increases.
 * The counter is reset by changing zero offset.
 */
typedef struct {
	uint64_t current; /**< Monotonically increasing value. */
	uint64_t offset;  /**< Offset of zero value. */
} rte_counter64_t;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Add value to counter.
 * Assumes this operation is only done by one thread on the object.
 *
 * @param counter
 *    A pointer to the counter.
 * @param val
 *    The value to add to the counter.
 */
static inline void
rte_counter64_add(rte_counter64_t *counter, uint32_t val)
{
	counter->current += val;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reads the value of the current which is current value adjusted by the zero offset.
 * This operation can be done by any thread.
 *
 * @param counter
 *    A pointer to the counter.
 * @return
 *    The value of the counter.
 */
__rte_experimental
static inline uint64_t
rte_counter64_read(const rte_counter64_t *counter)
{
	uint64_t cur, offs;

	cur = rte_atomic_load_explicit(&counter->current, rte_memory_order_consume);
	offs = rte_atomic_load_explicit(&counter->offset, rte_memory_order_relaxed);

	return cur - offs;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reset a counter to zero by recording current value and making it the new zero offset.
 * This operation can be done by any thread.
 *
 * @param counter
 *    A pointer to the counter.
 */
__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	uint64_t cur;

	cur = rte_atomic_load_explicit(&counter->current, rte_memory_order_consume);
	rte_atomic_store_explicit(&counter->offset, cur, rte_memory_order_relaxed);
}

#else

/* On x86 32 bit need to use atomic to avoid load/store tearing */
typedef RTE_ATOMIC(uint64_t) rte_counter64_t;

__rte_experimental
static inline void
rte_counter64_add(rte_counter64_t *counter, uint32_t val)
{
	rte_atomic_fetch_add_explicit(counter, val, rte_memory_order_relaxed);
}

__rte_experimental
static inline uint64_t
rte_counter64_read(const rte_counter64_t *counter)
{
	return rte_atomic_load_explicit(counter, rte_memory_order_relaxed);
}

__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	rte_atomic_store_explicit(counter, 0, rte_memory_order_relaxed);
}

#endif /* RTE_ARCH_64 */


#ifdef __cplusplus
}
#endif

#endif /* _RTE_COUNTER_H_ */
