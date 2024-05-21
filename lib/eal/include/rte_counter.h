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

#ifdef RTE_ARCH_64

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * On native 64 bit platform, counter is implemented as basic
 * 64 bit unsigned integer that only increases.
 */
typedef struct {
	uint64_t current;
	uint64_t offset;
} rte_counter64_t;

/**
 * @internal
 * Macro to implement read once (compiler barrier) using stdatomic.
 * This is compiler barrier only.
 */
#define __rte_read_once(var)						\
	rte_atomic_load_explicit((__rte_atomic typeof(&(var)))&(var),	\
		rte_memory_order_consume)

/**
 * @internal
 * Macro to implement write once (compiler barrier) using stdatomic.
 * This is compiler barrier only.
 */
#define __rte_write_once(var, val)					    \
	rte_atomic_store_explicit((__rte_atomic typeof(&(var)))&(var), val, \
		rte_memory_order_release)

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
rte_counter64_read(const rte_counter64_t *counter)
{
	return __rte_read_once(counter->current) - __rte_read_once(counter->offset);
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
	__rte_write_once(counter->offset, __rte_read_once(counter->current));
}

#else

/* On 32 bit platform, need to use atomic to avoid load/store tearing */
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
	return rte_atomic_load_explicit(counter, rte_memory_order_consume);
}

__rte_experimental
static inline void
rte_counter64_reset(rte_counter64_t *counter)
{
	rte_atomic_store_explicit(counter, 0, rte_memory_order_release);
}

#endif /* RTE_ARCH_64 */


#ifdef __cplusplus
}
#endif

#endif /* _RTE_COUNTER_H_ */
