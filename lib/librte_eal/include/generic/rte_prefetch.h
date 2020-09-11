/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _RTE_PREFETCH_H_
#define _RTE_PREFETCH_H_

/**
 * @file
 *
 * Prefetch operations.
 *
 * This file defines an API for prefetch macros / inline-functions,
 * which are architecture-dependent. Prefetching occurs when a
 * processor requests an instruction or data from memory to cache
 * before it is actually needed, potentially speeding up the execution of the
 * program.
 */

/**
 * Prefetch a cache line into all cache levels.
 * @param p
 *   Address to prefetch
 */
static inline void rte_prefetch0(const volatile void *p);

/**
 * Prefetch a cache line into all cache levels except the 0th cache level.
 * @param p
 *   Address to prefetch
 */
static inline void rte_prefetch1(const volatile void *p);

/**
 * Prefetch a cache line into all cache levels except the 0th and 1th cache
 * levels.
 * @param p
 *   Address to prefetch
 */
static inline void rte_prefetch2(const volatile void *p);

/**
 * Prefetch a cache line into all cache levels (non-temporal/transient version)
 *
 * The non-temporal prefetch is intended as a prefetch hint that processor will
 * use the prefetched data only once or short period, unlike the
 * rte_prefetch0() function which imply that prefetched data to use repeatedly.
 *
 * @param p
 *   Address to prefetch
 */
static inline void rte_prefetch_non_temporal(const volatile void *p);

/**
 * Demote a cache line to a more distant level of cache from the processor.
 *
 * CLDEMOTE hints to hardware to move (demote) a cache line from the closest to
 * the processor to a level more distant from the processor. It is a hint and
 * not guarantee. rte_cldemote is intended to speed up things at the producer,
 * in the producer-consumer case.
 *
 * @param p
 *   Address to demote
 */
static inline void rte_cldemote(const volatile void *p);

#endif /* _RTE_PREFETCH_H_ */
