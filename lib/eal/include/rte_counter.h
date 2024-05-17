/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) Stephen Hemminger <stephen@networkplumber.org>
 */

#ifndef _RTE_COUNTER_H_
#define _RTE_COUNTER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <rte_common.h>
#include <rte_stdatomic.h>

/**
 * @file
 * RTE Counter
 *
 * A counter is 64 bit value that is safe from split read/write.
 * It assumes that only one cpu at a time  will update the counter,
 * and another CPU may want to read it.
 *
 * This is a weaker subset of full atomic variables.
 *
 * The counters are subject to the restrictions of atomic variables
 * in packed structures or unaligned.
 */

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * The RTE counter type.
 */
typedef RTE_ATOMIC(uint64_t) rte_counter64_t;

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
__rte_experimental
static inline void
rte_counter64_add(rte_counter64_t *counter, uint32_t val)
{
	rte_atomic_fetch_add_explicit(counter, val, rte_memory_order_relaxed);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Read a counter.
 * This operation can be done by any thread.
 *
 * @param counter
 *    A pointer to the counter.
 * @return
 *  The current value of the counter.
 */
__rte_experimental
static inline uint64_t
rte_counter64_fetch(const rte_counter64_t *counter)
{
	return rte_atomic_load_explicit(counter, rte_memory_order_consume);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Set a counter.
 * This operation can be done by any thread.
 *
 * @param counter
 *    A pointer to the counter.
 * @param val
 *    Value to set counter to.
 */
__rte_experimental
static inline void
rte_counter64_set(rte_counter64_t *counter, uint64_t val)
{
	rte_atomic_store_explicit(counter, val, rte_memory_order_release);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Reset a counter to zero.
 * This operation can be done by any thread.
 *
 * @param counter
 *    A pointer to the counter.
 */
__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	rte_counter64_set(counter, 0);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_COUNTER_H_ */
