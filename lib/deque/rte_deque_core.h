/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#ifndef _RTE_DEQUE_CORE_H_
#define _RTE_DEQUE_CORE_H_

/**
 * @file
 * This file contains definition of RTE deque structure, init flags and
 * some related macros. This file should not be included directly,
 * include rte_deque.h instead.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memzone.h>
#include <rte_pause.h>
#include <rte_debug.h>

extern int rte_deque_log_type;

#define RTE_DEQUE_MZ_PREFIX "DEQUE_"
/** The maximum length of a deque name. */
#define RTE_DEQUE_NAMESIZE (RTE_MEMZONE_NAMESIZE - \
			   sizeof(RTE_DEQUE_MZ_PREFIX) + 1)

/**
 * Double ended queue (deque) structure.
 *
 * The producer and the consumer have a head and a tail index. These indices
 * are not between 0 and size(deque)-1. These indices are between 0 and
 * 2^32 -1. Their value is masked while accessing the objects in deque.
 * These indices are unsigned 32bits. Hence the result of the subtraction is
 * always a modulo of 2^32 and it is between 0 and capacity.
 */
struct rte_deque {
	alignas(RTE_CACHE_LINE_SIZE) char name[RTE_DEQUE_NAMESIZE];
	/**< Name of the deque */
	int flags;
	/**< Flags supplied at creation. */
	const struct rte_memzone *memzone;
	/**< Memzone, if any, containing the rte_deque */

	alignas(RTE_CACHE_LINE_SIZE) char pad0; /**< empty cache line */

	uint32_t size;           /**< Size of deque. */
	uint32_t mask;           /**< Mask (size-1) of deque. */
	uint32_t capacity;       /**< Usable size of deque */
	/** Ring head and tail pointers. */
	volatile uint32_t head;
	volatile uint32_t tail;
};

/**
 * Deque is to hold exactly requested number of entries.
 * Without this flag set, the deque size requested must be a power of 2, and the
 * usable space will be that size - 1. With the flag, the requested size will
 * be rounded up to the next power of two, but the usable space will be exactly
 * that requested. Worst case, if a power-of-2 size is requested, half the
 * deque space will be wasted.
 */
#define RTE_DEQUE_F_EXACT_SZ 0x0004
#define RTE_DEQUE_SZ_MASK  (0x7fffffffU) /**< Ring size mask */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_DEQUE_CORE_H_ */
