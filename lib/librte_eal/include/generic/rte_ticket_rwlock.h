/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_TICKET_RWLOCK_H_
#define _RTE_TICKET_RWLOCK_H_

/**
 * @file
 *
 * Ticket based reader/writer lock
 *
 * This file defines an API for ticket style read-write locks.
 * This types of lock act like rte_rwlock but provide fairness
 * and requests are handled first come, first serviced.
 *
 * All locks must be initialized before use, and only initialized once.
 *
 * References:
 *  "Spinlocks and Read-Write Locks"
 *     http://locklessinc.com/articles/locks/
 *  "Scalable Read-Writer Synchronization for Shared-Memory Multiprocessors"
 *     https://www.cs.rochester.edu/research/synchronization/pseudocode/rw.html
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef union {
	uint64_t tickets;
	struct {
		union {
			struct {
				uint16_t write; /* current writer */
				uint16_t read;	/* current reader */
			};
			uint32_t readwrite;	/* atomic for both read and write */
		};
		uint16_t next;	/* next ticket */
	};
} rte_rwticketlock_t;

/**
 * A static rwticket initializer.
 */
#define RTE_RWTICKETLOCK_INITIALIZER { 0 }

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Initialize the rwticketlock to an unlocked state.
 *
 * @param rwl
 *   A pointer to the rwticketlock structure.
 */
__rte_experimental
static inline void
rte_rwticketlock_init(rte_rwticketlock_t *rwl)
{
	rwl->tickets = 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 * Take a write lock. Loop until the lock is held.
 *
 * @param rwl
 *   A pointer to a rwticketlock structure.
 */
__rte_experimental
static inline void
rte_rwticket_write_lock(rte_rwticketlock_t *rwl)
{
	uint16_t me;

	me = __atomic_fetch_add(&rwl->next, 1, __ATOMIC_RELAXED);
	rte_wait_until_equal_16(&rwl->write, me, __ATOMIC_ACQUIRE);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Try to take a write lock.
 *
 * @param rwl
 *   A pointer to a rwticketlock structure.
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for writing because
 *     it was already locked for reading or writing
 */
__rte_experimental
static inline int
rte_rwticket_write_trylock(rte_rwticketlock_t *rwl)
{
	rte_rwticketlock_t old, new;

	old.tickets = __atomic_load_n(&rwl->tickets, __ATOMIC_RELAXED);
	if (old.write != old.next)
		return -EBUSY;

	new.tickets = old.tickets;
	new.next = old.next + 1;
	if (__atomic_compare_exchange_n(&rwl->tickets, &old.tickets, new.tickets,
					0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED))
		return 0;
	else
		return -EBUSY;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a write lock.
 *
 * @param rwl
 *   A pointer to a rwticketlock structure.
 */
__rte_experimental
static inline void
rte_rwticket_write_unlock(rte_rwticketlock_t *rwl)
{
	rte_rwticketlock_t t;

	t.tickets = __atomic_load_n(&rwl->tickets, __ATOMIC_RELAXED);
	t.write++;
	t.read++;
	__atomic_store_n(&rwl->readwrite, t.readwrite, __ATOMIC_RELEASE);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 *
 * Take a read lock. Loop until the lock is held.
 *
 * @param l
 *   A pointer to a rwticketlock structure.
 */
__rte_experimental
static inline void
rte_rwticket_read_lock(rte_rwticketlock_t *rwl)
{
	uint16_t me;

	me = __atomic_fetch_add(&rwl->next, 1, __ATOMIC_RELAXED);
	rte_wait_until_equal_16(&rwl->read, me, __ATOMIC_ACQUIRE);
	__atomic_fetch_add(&rwl->read, 1, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Try to take a read lock.
 *
 * @param rwl
 *   A pointer to a rwticketlock structure.
 *
 * @return
 *   - zero if the lock is successfully taken
 *   - -EBUSY if lock could not be acquired for reading because a
 *     writer holds the lock
 */
__rte_experimental
static inline int
rte_rwticket_read_trylock(rte_rwticketlock_t *rwl)
{
	rte_rwticketlock_t old, new;
	int success;

	old.tickets = __atomic_load_n(&rwl->tickets, __ATOMIC_RELAXED);

	do {
		uint16_t me = old.next; /* this is our ticket */

		/* does writer have the lock now? */
		if (old.read != me && old.write != me)
			return -EBUSY;

		/* expect to be the next reader */
		new.tickets = old.tickets;
		old.read = me;
		new.read = new.next = me + 1;
		success = __atomic_compare_exchange_n(&rwl->tickets, &old.tickets, new.tickets,
						      0, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED);
	} while (!success);

	return 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Release a read lock.
 *
 * @param rwl
 *   A pointer to the rwticketlock structure.
 */
__rte_experimental
static inline void
rte_rwticket_read_unlock(rte_rwticketlock_t *rwl)
{
	__atomic_add_fetch(&rwl->write, 1, __ATOMIC_RELEASE);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_TICKET_RWLOCK_H_ */
