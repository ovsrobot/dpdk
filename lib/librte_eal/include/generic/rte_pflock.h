/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corp.
 * Copyright 2011-2015 Samy Al Bahra.
 * All rights reserved.
 */

#ifndef _RTE_PFLOCK_H_
#define _RTE_PFLOCK_H_

/**
 * @file
 *
 * Phase-fair locks
 *
 * This file defines an API for Phase Fair reader writer locks,
 * which is a variant of typical reader-writer locks that prevent
 * starvation. In this type of lock, readers and writers alternate.
 * This significantly reduces the worst-case blocking for readers and writers.
 *
 * This is an implementation derived from FreeBSD
 * based on the work described in:
 *    Brandenburg, B. and Anderson, J. 2010. Spin-Based
 *    Reader-Writer Synchronization for Multiprocessor Real-Time Systems
 *
 * All locks must be initialised before use, and only initialised once.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_pause.h>

/**
 * The rte_pflock_t type.
 */
struct rte_pflock {
	union rte_pflock_ticket {
		uint32_t tickets;
		struct {
			uint16_t in;
			uint16_t out;
		};
	} rd, wr;
};
typedef struct rte_pflock rte_pflock_t;

/**
 * Constants used to map the bits in reader counter
 *
 * +-----------------+-+-+
 * |     Readers     |W|P|
 * |                 |R|H|
 * +-----------------+-+-+
 */

#define RTE_PFLOCK_LSB   0xFFF0
#define RTE_PFLOCK_RINC  0x100		/* Reader increment value. */
#define RTE_PFLOCK_WBITS 0x3		/* Writer bits in reader. */
#define RTE_PFLOCK_PRES  0x2		/* Writer present bit. */
#define RTE_PFLOCK_PHID  0x1		/* Phase ID bit. */

/**
 * A static pflock initializer.
 */
#define RTE_PFLOCK_INITIALIZER {  }

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Initialize the pflock to an unlocked state.
 *
 * @param pf
 *   A pointer to the pflock.
 */
__rte_experimental
static inline void
rte_pflock_init(struct rte_pflock *pf)
{
	pf->rd.tickets = 0;
	pf->wr.tickets = 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Take a pflock for read.
 *
 * @param pf
 *   A pointer to a pflock structure.
 */
__rte_experimental
static inline void
rte_pflock_read_lock(rte_pflock_t *pf)
{
	uint32_t w;

	/*
	 * If no writer is present, then the operation has completed
	 * successfully.
	 */
	w = __atomic_fetch_add(&pf->rd.in, RTE_PFLOCK_RINC, __ATOMIC_ACQ_REL) & RTE_PFLOCK_WBITS;
	if (w == 0)
		return;

	/* Wait for current write phase to complete. */
	while ((__atomic_load_n(&pf->rd.in, __ATOMIC_ACQUIRE) & RTE_PFLOCK_WBITS) == w)
		rte_pause();
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a pflock locked for reading.
 *
 * @param pf
 *   A pointer to the pflock structure.
 */
__rte_experimental
static inline void
rte_pflock_read_unlock(rte_pflock_t *pf)
{
	__atomic_fetch_add(&pf->rd.out, RTE_PFLOCK_RINC, __ATOMIC_RELEASE);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Try to take a pflock for reading
 *
 * @param pf
 *   A pointer to a pflock structure.
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for reading because a
 *     writer holds the lock
 */
__rte_experimental
static inline int
rte_pflock_read_trylock(rte_pflock_t *pf)
{
	union rte_pflock_ticket old, new;

	/* Get current state of the lock */
	old.tickets = __atomic_load_n(&pf->rd.tickets, __ATOMIC_RELAXED);

	/* loop until writer shows up */
	while ((old.in & RTE_PFLOCK_WBITS) == 0) {
		new.out = old.out;
		new.in = old.in + RTE_PFLOCK_RINC;
		if (__atomic_compare_exchange_n(&pf->rd.tickets, &old.tickets, new.tickets,
						0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
			return 0;	/* got it */

		/* either new reader got in (so retry) or a writer */
	}

	/* If writer is present then we are busy */
	return -EBUSY;
}


/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Take the pflock for write.
 *
 * @param pf
 *   A pointer to the ticketlock.
 */
__rte_experimental
static inline void
rte_pflock_write_lock(rte_pflock_t *pf)
{
	uint16_t ticket;

	/* Acquire ownership of write-phase. */
	ticket = __atomic_fetch_add(&pf->wr.in, 1, __ATOMIC_ACQUIRE);
	rte_wait_until_equal_16(&pf->wr.out, ticket, __ATOMIC_RELAXED);

	/*
	 * Acquire ticket on read-side in order to allow them
	 * to flush. Indicates to any incoming reader that a
	 * write-phase is pending.
	 *
	 * Need ACQUIRE to prevent speculative execution of the wait loop
	 */
	ticket = __atomic_fetch_add(&pf->rd.in,
				    (ticket & RTE_PFLOCK_PHID) | RTE_PFLOCK_PRES,
				    __ATOMIC_ACQUIRE);

	/* Wait for any pending readers to flush. */
	rte_wait_until_equal_16(&pf->rd.out, ticket, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a pflock held for writing.
 *
 * @param pf
 *   A pointer to a pflock structure.
 */
__rte_experimental
static inline void
rte_pflock_write_unlock(rte_pflock_t *pf)
{
	/* Migrate from write phase to read phase. */
	__atomic_fetch_and(&pf->rd.in, RTE_PFLOCK_LSB, __ATOMIC_RELEASE);

	/* Allow other writers to continue. */
	__atomic_fetch_add(&pf->wr.out, 1, __ATOMIC_RELEASE);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Try to take the pflock for write.
 *
 * @param pf
 *   A pointer to the pflock.
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for writing because
 *     another writer holds the lock
 */
__rte_experimental
static inline int
rte_pflock_write_trylock(rte_pflock_t *pf)
{
	union rte_pflock_ticket old, new;
	uint16_t ticket;

	/* Get current state of the lock */
	old.tickets = __atomic_load_n(&pf->wr.tickets, __ATOMIC_RELAXED);
	new.out = old.out;
	new.in  = old.in + 1;
	ticket = new.in;

	/* if writer is already present then too busy */
	if (old.out != new.in ||
	    !__atomic_compare_exchange_n(&pf->wr.tickets, &old.tickets, new.tickets,
					 0, __ATOMIC_ACQ_REL, __ATOMIC_RELAXED))
		return -EBUSY; /* another writer is present already */

	/*
	 * We now own the write phase, but still need to tell
	 * readers and wait for them.
	 *
	 * Need ACQUIRE semantics to avoid speculative execution of wait loop
	 */
	ticket  = __atomic_fetch_add(&pf->rd.in,
				 (ticket & RTE_PFLOCK_PHID) | RTE_PFLOCK_PRES,
				 __ATOMIC_ACQUIRE);

	/* Wait for any pending readers to flush. */
	rte_wait_until_equal_16(&pf->rd.out, ticket, __ATOMIC_RELAXED);
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* RTE_PFLOCK_H */
