/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 NVIDIA Corporation & Affiliates
 */

#ifndef _RTE_MBUF_HISTORY_H_
#define _RTE_MBUF_HISTORY_H_

/**
 * @file
 * MBUF History
 *
 * This module provides history tracking for mbuf objects using dynamic fields.
 * It tracks the lifecycle of mbuf objects through the system with a fixed set
 * of predefined events to maintain performance.
 *
 * The history is stored as a 64-bit value in the mbuf dynamic field area,
 * with each event encoded in 4 bits, allowing up to 16 events to be tracked.
 */

#include <stdint.h>
#include <rte_mbuf_dyn.h>
#include <rte_common.h>
#include <rte_branch_prediction.h>
#include "mbuf_log.h"

/* Forward declaration to avoid circular dependency */
struct rte_mbuf;

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Number of bits for each history operation
 */
#define RTE_MBUF_HISTORY_BITS          4

/**
 * Maximum number of history operations that can be stored
 */
#define RTE_MBUF_HISTORY_MAX_OPS       16

/**
 * Mask for extracting the most recent operation from history
 */
#define RTE_MBUF_HISTORY_MASK          ((1ULL << RTE_MBUF_HISTORY_BITS) - 1)

/**
 * History operation types
 */
enum rte_mbuf_history_op {
	RTE_MBUF_NEVER = 0,        /* Initial state - never allocated */
	RTE_MBUF_FREE = 1,         /* Freed back to pool */
	RTE_MBUF_PMD_FREE = 2,     /* Freed by PMD back to pool*/
	RTE_MBUF_PMD_TX = 3,       /* Sent to PMD for Tx */
	RTE_MBUF_APP_RX = 4,       /* Returned to application on Rx */
	RTE_MBUF_PMD_ALLOC = 5,    /* Allocated by PMD for Rx */
	RTE_MBUF_ALLOC = 6,        /* Allocated by application */
	RTE_MBUF_BUSY_TX = 7,      /* Returned to app due to Tx busy */
	RTE_MBUF_USR3 = 13,        /* Application-defined event 3 */
	RTE_MBUF_USR2 = 14,        /* Application-defined event 2 */
	RTE_MBUF_USR1 = 15,        /* Application-defined event 1 */
	RTE_MBUF_MAX = 16,          /* Maximum trace operation value */
};


/**
 * Global offset for the history field (set during initialization)
 */
extern int rte_mbuf_history_field_offset;

/**
 * Initialize the mbuf history system
 *
 * This function registers the dynamic field for mbuf history tracking.
 * It should be called once during application initialization.
 *
 * Note: This function is called by rte_pktmbuf_pool_create,
 * so explicit invocation is usually not required unless initializing manually.
 *
 * @return
 *   0 on success, -1 on failure with rte_errno set
 */
int rte_mbuf_history_init(void);

#if RTE_MBUF_HISTORY_DEBUG
/**
 * Get the history value from an mbuf
 *
 * @param m
 *   Pointer to the mbuf
 * @return
 *   The history value, or 0 if history is not available
 */
static inline uint64_t rte_mbuf_history_get(const struct rte_mbuf *m)
{
	if (unlikely(m == NULL || rte_mbuf_history_field_offset == -1))
		return 0;

	return *RTE_MBUF_DYNFIELD(m, rte_mbuf_history_field_offset, uint64_t *);
}

/**
 * Mark an mbuf with a history event
 *
 * @param m
 *   Pointer to the mbuf
 * @param op
 *   The operation to record
 */
static inline void rte_mbuf_history_mark(struct rte_mbuf *m, uint32_t op)
{
	if (unlikely(m == NULL || op >= RTE_MBUF_MAX || rte_mbuf_history_field_offset == -1))
		return;

	uint64_t *history = RTE_MBUF_DYNFIELD(m, rte_mbuf_history_field_offset, uint64_t *);
	*history = (*history << RTE_MBUF_HISTORY_BITS) | op;
}

/**
 * Mark multiple mbufs with a history event
 *
 * @param mbufs
 *   Array of mbuf pointers
 * @param n
 *   Number of mbufs to mark
 * @param op
 *   The operation to record
 */
static inline void rte_mbuf_history_bulk(struct rte_mbuf * const *mbufs,
					uint32_t n, uint32_t op)
{
	if (unlikely(mbufs == NULL || op >= RTE_MBUF_MAX || rte_mbuf_history_field_offset == -1))
		return;

	while (n--)
		rte_mbuf_history_mark(*mbufs++, op);
}
#endif

/**
 * Dump mbuf history statistics for all mempools to a file
 *
 * @param f
 *   File pointer to write the history statistics to
 */
__rte_experimental
void rte_mbuf_history_dump(FILE *f);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MBUF_HISTORY_H_ */
