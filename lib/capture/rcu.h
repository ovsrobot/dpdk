/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */
#ifndef CAPTURE_RCU_H
#define CAPTURE_RCU_H

/*
 * Read-side protection for the capture callbacks.
 *
 * Each thread that runs the callbacks owns a slot. On entry it stores the
 * current writer token into its slot, on exit it stores 0. Plain stores to a
 * cache line nobody else writes; no atomic read-modify-write and no fence.
 * The fence is supplied by the writer: capture_rcu_sync() uses membarrier()
 * to run a full barrier on every CPU executing a thread of this process.
 *
 * This is the memb flavor of liburcu, with thread registration replaced by
 * fixed slots indexed by lcore id. Private to lib/capture for now.
 */

#include <stdalign.h>
#include <stdbool.h>
#include <stdint.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_lcore.h>
#include <rte_stdatomic.h>

/* one slot per lcore, plus one for the EAL interrupt thread */
#define CAPTURE_RCU_SLOTS	(RTE_MAX_LCORE + 1)
#define CAPTURE_RCU_INTR_SLOT	RTE_MAX_LCORE
#define CAPTURE_RCU_NO_SLOT	UINT32_MAX

struct capture_rcu_reader {
	alignas(RTE_CACHE_LINE_SIZE) RTE_ATOMIC(uint64_t) ctr; /* 0 idle, else token at entry */
	uint32_t depth;			/* nesting, owner only */
};

struct capture_rcu {
	alignas(RTE_CACHE_LINE_SIZE) RTE_ATOMIC(uint64_t) token;
	struct capture_rcu_reader reader[CAPTURE_RCU_SLOTS];
};

/* How long to sleep when the OS barrier call fails unexpectedly. */
#define CAPTURE_RCU_MB_FAIL_US	1000

extern struct capture_rcu capture_rcu;

/* Returns false if the OS barrier does not work; register nothing then. */
bool capture_rcu_init(void);

/*
 * Slot for the calling thread.
 *
 * Lcores and registered threads use the lcore id. Alarm and interrupt
 * callbacks run on the EAL interrupt thread, which has no lcore id but is
 * the one such thread allowed to do Rx/Tx (bonding mode 4 does). Any other
 * unregistered thread has no slot and is not captured.
 */
static inline unsigned int
capture_rcu_slot(void)
{
	unsigned int id = rte_lcore_id();

	if (likely(id != LCORE_ID_ANY))
		return id;
	if (rte_thread_is_intr())
		return CAPTURE_RCU_INTR_SLOT;
	return CAPTURE_RCU_NO_SLOT;
}

static inline void
capture_rcu_enter(unsigned int slot)
{
	struct capture_rcu_reader *r = &capture_rcu.reader[slot];
	uint64_t t;

	if (r->depth++ != 0)
		return;

	t = rte_atomic_load_explicit(&capture_rcu.token, rte_memory_order_relaxed);
	rte_atomic_store_explicit(&r->ctr, t, rte_memory_order_relaxed);

	/*
	 * The loads that follow must not move above the store of ctr. The
	 * writer forces that on every CPU with membarrier, so no fence is
	 * needed here; capture is refused if membarrier does not work.
	 */
	rte_compiler_barrier();
}

static inline void
capture_rcu_exit(unsigned int slot)
{
	struct capture_rcu_reader *r = &capture_rcu.reader[slot];

	if (--r->depth != 0)
		return;

	/* release: prior loads complete before the slot reads idle */
	rte_atomic_store_explicit(&r->ctr, 0, rte_memory_order_release);
}

/*
 * Wait until no reader that entered before this call is still inside.
 * The caller must have unpublished the object first, and must not be inside
 * a read section itself.
 */
void capture_rcu_sync(void);

#endif /* CAPTURE_RCU_H */
