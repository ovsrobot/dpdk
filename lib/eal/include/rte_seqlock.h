/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ericsson AB
 */

#ifndef _RTE_SEQLOCK_H_
#define _RTE_SEQLOCK_H_

/**
 * @file
 * RTE Seqlock
 *
 * A sequence lock (seqlock) is a synchronization primitive allowing
 * multiple, parallel, readers to efficiently and safely (i.e., in a
 * data-race free manner) access the lock-protected data. The RTE
 * seqlock permits multiple writers as well. A spinlock is used for
 * writer-writer synchronization.
 *
 * A reader never blocks a writer. Very high frequency writes may
 * prevent readers from making progress.
 *
 * A seqlock is not preemption-safe on the writer side. If a writer is
 * preempted, it may block readers until the writer thread is again
 * allowed to execute. Heavy computations should be kept out of the
 * writer-side critical section, to avoid delaying readers.
 *
 * Seqlocks are useful for data which are read by many cores, at a
 * high frequency, and relatively infrequently written to.
 *
 * One way to think about seqlocks is that they provide means to
 * perform atomic operations on objects larger than what the native
 * machine instructions allow for.
 *
 * To avoid resource reclamation issues, the data protected by a
 * seqlock should typically be kept self-contained (e.g., no pointers
 * to mutable, dynamically allocated data).
 *
 * Example usage:
 * @code{.c}
 * #define MAX_Y_LEN (16)
 * // Application-defined example data structure, protected by a seqlock.
 * struct config {
 *         rte_seqlock_t lock;
 *         int param_x;
 *         char param_y[MAX_Y_LEN];
 * };
 *
 * // Accessor function for reading config fields.
 * void
 * config_read(const struct config *config, int *param_x, char *param_y)
 * {
 *         // Temporary variables, just to improve readability.
 *         int tentative_x;
 *         char tentative_y[MAX_Y_LEN];
 *
 *         do {
 *                 rte_seqlock_read(&config->lock);
 *                 // Loads may be atomic or non-atomic, as in this example.
 *                 tentative_x = config->param_x;
 *                 strcpy(tentative_y, config->param_y);
 *         } while (rte_seqlock_read_retry(&config->lock));
 *         // An application could skip retrying, and try again later, if
 *         // it can make progress without the data.
 *
 *         *param_x = tentative_x;
 *         strcpy(param_y, tentative_y);
 * }
 *
 * // Accessor function for writing config fields.
 * void
 * config_update(struct config *config, int param_x, const char *param_y)
 * {
 *         rte_seqlock_write_begin(&config->lock);
 *         // Stores may be atomic or non-atomic, as in this example.
 *         config->param_x = param_x;
 *         strcpy(config->param_y, param_y);
 *         rte_seqlock_write_end(&config->lock);
 * }
 * @endcode
 *
 * @see
 * https://en.wikipedia.org/wiki/Seqlock.
 */

#include <stdbool.h>
#include <stdint.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_spinlock.h>

/**
 * The RTE seqlock type.
 */
typedef struct {
	uint32_t sn; /**< A sequence number for the protected data. */
	rte_spinlock_t lock; /**< Spinlock used to serialize writers.  */
} rte_seqlock_t;

/**
 * A static seqlock initializer.
 */
#define RTE_SEQLOCK_INITIALIZER { 0, RTE_SPINLOCK_INITIALIZER }

/**
 * Initialize the seqlock.
 *
 * This function initializes the seqlock, and leaves the writer-side
 * spinlock unlocked.
 *
 * @param seqlock
 *   A pointer to the seqlock.
 */
__rte_experimental
void
rte_seqlock_init(rte_seqlock_t *seqlock);

/**
 * Begin a read-side critical section.
 *
 * A call to this function marks the beginning of a read-side critical
 * section, for @p seqlock.
 *
 * rte_seqlock_read_begin() returns a sequence number, which is later
 * used in rte_seqlock_read_retry() to check if the protected data
 * underwent any modifications during the read transaction.
 *
 * After (in program order) rte_seqlock_read_begin() has been called,
 * the calling thread may read and copy the protected data. The
 * protected data read *must* be copied (either in pristine form, or
 * in the form of some derivative). A copy is required since the
 * application only may read the data in the read-side critical
 * section (i.e., after rte_seqlock_read_begin() and before
 * rte_seqlock_read_retry()), but must not act upon the retrieved data
 * while in the critical section, since it does not yet know if it is
 * consistent.
 *
 * The data may be accessed with both atomic and/or non-atomic loads.
 *
 * After (in program order) all required data loads have been
 * performed, rte_seqlock_read_retry() must be called, marking the end
 * of the read-side critical section.
 *
 * If rte_seqlock_read_retry() returns true, the just-read data is
 * inconsistent and should be discarded. If rte_seqlock_read_retry()
 * returns false, the data was read atomically and the copied data is
 * consistent.
 *
 * If rte_seqlock_read_retry() returns false, the application has the
 * option to immediately restart the whole procedure (e.g., calling
 * rte_seqlock_read_being() again), or do the same at some later time.
 *
 * @param seqlock
 *   A pointer to the seqlock.
 * @return
 *   The seqlock sequence number for this critical section, to
 *   later be passed to rte_seqlock_read_retry().
 *
 * @see rte_seqlock_read_retry()
 */
__rte_experimental
static inline uint32_t
rte_seqlock_read_begin(const rte_seqlock_t *seqlock)
{
	/* __ATOMIC_ACQUIRE to prevent loads after (in program order)
	 * from happening before the sn load. Synchronizes-with the
	 * store release in rte_seqlock_end().
	 */
	return __atomic_load_n(&seqlock->sn, __ATOMIC_ACQUIRE);
}

/**
 * End a read-side critical section.
 *
 * A call to this function marks the end of a read-side critical
 * section, for @p seqlock. The application must supply the sequence
 * number returned from the corresponding rte_seqlock_read_begin()
 * call.
 *
 * After this function has been called, the caller should not access
 * the protected data.
 *
 * In case this function returns false, the just-read data was
 * consistent and the set of atomic and non-atomic load operations
 * performed between rte_seqlock_read_begin() and
 * rte_seqlock_read_retry() were atomic, as a whole.
 *
 * In case rte_seqlock_read_retry() returns true, the data was
 * modified as it was being read and may be inconsistent, and thus
 * should be discarded.
 *
 * @param seqlock
 *   A pointer to the seqlock.
 * @param begin_sn
 *   The seqlock sequence number that was returned by
 *   rte_seqlock_read_begin() for this critical section.
 * @return
 *   true or false, if the just-read seqlock-protected data is inconsistent
 *   or consistent, respectively.
 *
 * @see rte_seqlock_read_begin()
 */
__rte_experimental
static inline bool
rte_seqlock_read_retry(const rte_seqlock_t *seqlock, uint32_t begin_sn)
{
	uint32_t end_sn;

	/* make sure the data loads happens before the sn load */
	rte_atomic_thread_fence(__ATOMIC_ACQUIRE);

	end_sn = __atomic_load_n(&seqlock->sn, __ATOMIC_RELAXED);

	return unlikely(begin_sn & 1 || begin_sn != end_sn);
}

/**
 * Begin write-side critical section.
 *
 * A call to this function acquires the write lock associated @p
 * seqlock, and marks the beginning of a write-side critical section.
 *
 * After having called this function, the caller may go on to modify
 * the protected data, in an atomic or non-atomic manner.
 *
 * After the necessary updates have been performed, the application
 * calls rte_seqlock_write_end().
 *
 * This function is not preemption-safe in the sense that preemption
 * of the calling thread may block reader progress until the writer
 * thread is rescheduled.
 *
 * @param seqlock
 *   A pointer to the seqlock.
 *
 * @see rte_seqlock_write_end()
 */
__rte_experimental
static inline void
rte_seqlock_write_begin(rte_seqlock_t *seqlock)
{
	uint32_t sn;

	/* to synchronize with other writers */
	rte_spinlock_lock(&seqlock->lock);

	sn = seqlock->sn + 1;

	__atomic_store_n(&seqlock->sn, sn, __ATOMIC_RELAXED);

	/* __ATOMIC_RELEASE to prevent stores after (in program order)
	 * from happening before the sn store.
	 */
	rte_atomic_thread_fence(__ATOMIC_RELEASE);
}

/**
 * End write-side critical section.
 *
 * A call to this function marks the end of the write-side critical
 * section, for @p seqlock. After this call has been made, the protected
 * data may no longer be modified.
 *
 * @param seqlock
 *   A pointer to the seqlock.
 *
 * @see rte_seqlock_write_begin()
 */
__rte_experimental
static inline void
rte_seqlock_write_end(rte_seqlock_t *seqlock)
{
	uint32_t sn;

	sn = seqlock->sn + 1;

	/* synchronizes-with the load acquire in rte_seqlock_begin() */
	__atomic_store_n(&seqlock->sn, sn, __ATOMIC_RELEASE);

	rte_spinlock_unlock(&seqlock->lock);
}

#endif  /* _RTE_SEQLOCK_H_ */
