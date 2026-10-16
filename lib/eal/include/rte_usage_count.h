/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef _RTE_USAGE_COUNT_H_
#define _RTE_USAGE_COUNT_H_

/**
 * @file
 * RTE Usage Counter
 *
 * Trivial usage (reference) counters intended to express increment/decrement
 * sequences with first/last user edge detection, for example "do X on first Y,
 * undo X on last Y".
 *
 * The counters are neither thread-safe nor atomic; callers must provide their
 * own serialization.
 */

#include <stdbool.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_debug.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Usage counter type.
 */
typedef uint32_t rte_usage_count_t;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Claim a usage.
 *
 * @param counter
 *   Usage counter to claim.
 * @return
 *   true if this is the first usage, false otherwise.
 */
__rte_experimental
static inline bool
rte_usage_count_claim(rte_usage_count_t *counter)
{
	RTE_ASSERT(*counter != UINT32_MAX);
	return (*counter)++ == 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a usage.
 *
 * @param counter
 *   Usage counter to release. Must have at least one usage.
 * @return
 *   true if this was the last usage, false otherwise.
 */
__rte_experimental
static inline bool
rte_usage_count_release(rte_usage_count_t *counter)
{
	RTE_ASSERT(*counter != 0);
	return --(*counter) == 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Test whether the currently claimed usage is the last one,
 * i.e. whether a subsequent release would return true.
 *
 * @param counter
 *   Usage counter to test.
 * @return
 *   true if exactly one usage is currently claimed, false otherwise.
 */
__rte_experimental
static inline bool
rte_usage_count_is_last(const rte_usage_count_t *counter)
{
	return *counter == 1;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_USAGE_COUNT_H_ */
