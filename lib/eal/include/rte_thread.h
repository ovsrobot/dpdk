/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */
#include <stdint.h>

#include <rte_os.h>
#include <rte_compat.h>

#ifndef _RTE_THREAD_H_
#define _RTE_THREAD_H_

/**
 * @file
 *
 * Threading functions
 *
 * Simple threads functionality supplied by EAL.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sched.h>

/**
 * Thread id descriptor.
 */
typedef struct rte_thread_tag {
	uintptr_t opaque_id; /**< thread identifier */
} rte_thread_t;

typedef void* (*rte_thread_func) (void *);
/**
 * Thread priority values.
 */
enum rte_thread_priority {
	RTE_THREAD_PRIORITY_NORMAL            = 0,
	/**< normal thread priority, the default */
	RTE_THREAD_PRIORITY_REALTIME_CRITICAL = 1,
	/**< highest thread priority allowed */
};

#ifdef RTE_HAS_CPUSET

/**
 * Representation for thread attributes.
 */
typedef struct {
	enum rte_thread_priority priority; /**< thread priority */
	rte_cpuset_t cpuset; /**< thread affinity */
} rte_thread_attr_t;

#endif /* RTE_HAS_CPUSET */

#define RTE_DECLARE_MUTEX(private_lock)          rte_thread_mutex private_lock

#define RTE_DEFINE_MUTEX(private_lock)\
RTE_INIT(__rte_ ## private_lock ## _init)\
{\
	RTE_VERIFY(rte_thread_mutex_init(&private_lock) == 0);\
}

#define RTE_INIT_MUTEX(private_lock)\
static RTE_DECLARE_MUTEX(private_lock);\
RTE_DEFINE_MUTEX(private_lock)

/**
 * Thread mutex representation.
 */
typedef struct rte_thread_mutex_tag {
	void *mutex_id;  /**< mutex identifier */
} rte_thread_mutex;

/**
 * Returned by rte_thread_barrier_wait() when call is successful.
 */
#define RTE_THREAD_BARRIER_SERIAL_THREAD -1

/**
 * Thread barrier representation.
 */
typedef struct rte_thread_barrier_tag {
	void *barrier_id;  /**< barrrier identifier */
} rte_thread_barrier;

/**
 * TLS key type, an opaque pointer.
 */
typedef struct eal_tls_key *rte_thread_key;

/**
 * Get the id of the calling thread.
 *
 * @return
 *   Return the thread id of the calling thread.
 */
__rte_experimental
rte_thread_t rte_thread_self(void);

/**
 * Check if 2 thread ids are equal.
 *
 * @param t1
 *   First thread id.
 *
 * @param t2
 *   Second thread id.
 *
 * @return
 *   If the ids are equal, return nonzero.
 *   Otherwise, return 0.
 */
__rte_experimental
int rte_thread_equal(rte_thread_t t1, rte_thread_t t2);

#ifdef RTE_HAS_CPUSET

/**
 * Set the affinity of thread 'thread_id' to the cpu set
 * specified by 'cpuset'.
 *
 * @param thread_id
 *    Id of the thread for which to set the affinity.
 *
 * @param cpuset
 *   Pointer to CPU affinity to set.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_set_affinity_by_id(rte_thread_t thread_id,
		const rte_cpuset_t *cpuset);

/**
 * Get the affinity of thread 'thread_id' and store it
 * in 'cpuset'.
 *
 * @param thread_id
 *    Id of the thread for which to get the affinity.
 *
 * @param cpuset
 *   Pointer for storing the affinity value.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_get_affinity_by_id(rte_thread_t thread_id,
		rte_cpuset_t *cpuset);

/**
 * Initialize the attributes of a thread.
 * These attributes can be passed to the rte_thread_create() function
 * that will create a new thread and set its attributes according to attr.
 *
 * @param attr
 *   Thread attributes to initialize.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_attr_init(rte_thread_attr_t *attr);

/**
 * Set the CPU affinity value in the thread attributes pointed to
 * by 'thread_attr'.
 *
 * @param thread_attr
 *   Points to the thread attributes in which affinity will be updated.
 *
 * @param cpuset
 *   Points to the value of the affinity to be set.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset);

/**
 * Get the value of CPU affinity that is set in the thread attributes pointed
 * to by 'thread_attr'.
 *
 * @param thread_attr
 *   Points to the thread attributes from which affinity will be retrieved.
 *
 * @param cpuset
 *   Pointer to the memory that will store the affinity.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset);

/**
 * Set the thread priority value in the thread attributes pointed to
 * by 'thread_attr'.
 *
 * @param thread_attr
 *   Points to the thread attributes in which priority will be updated.
 *
 * @param priority
 *   Points to the value of the priority to be set.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
		enum rte_thread_priority priority);

/**
 * Set core affinity of the current thread.
 * Support both EAL and non-EAL thread and update TLS.
 *
 * @param cpusetp
 *   Pointer to CPU affinity to set.
 * @return
 *   On success, return 0; otherwise return -1;
 */
int rte_thread_set_affinity(rte_cpuset_t *cpusetp);

/**
 * Get core affinity of the current thread.
 *
 * @param cpusetp
 *   Pointer to CPU affinity of current thread.
 *   It presumes input is not NULL, otherwise it causes panic.
 *
 */
void rte_thread_get_affinity(rte_cpuset_t *cpusetp);

/**
 * Create a new thread that will invoke the 'thread_func' routine.
 *
 * @param thread_id
 *    A pointer that will store the id of the newly created thread.
 *
 * @param thread_attr
 *    Attributes that are used at the creation of the new thread.
 *
 * @param thread_func
 *    The routine that the new thread will invoke when starting execution.
 *
 * @param args
 *    Arguments to be passed to the 'thread_func' routine.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_create(rte_thread_t *thread_id,
		const rte_thread_attr_t *thread_attr,
		rte_thread_func thread_func, void *args);

/**
 * Waits for the thread identified by 'thread_id' to terminate
 *
 * @param thread_id
 *    The identifier of the thread.
 *
 * @param value_ptr
 *    Stores the exit status of the thread.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_join(rte_thread_t thread_id, unsigned long *value_ptr);

/**
 * Indicate that the return value of the thread is not needed and
 * all thread resources should be release when the thread terminates.
 *
 * @param thread_id
 *    The id of the thread to be detached.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_detach(rte_thread_t thread_id);

#endif /* RTE_HAS_CPUSET */

/**
 * Get the priority of a thread.
 *
 * @param thread_id
 *    Id of the thread for which to get priority.
 *
 * @param priority
 *   Location to store the retrieved priority.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_get_priority(rte_thread_t thread_id,
		enum rte_thread_priority *priority);

/**
 * Set the priority of a thread.
 *
 * @param thread_id
 *    Id of the thread for which to set priority.
 *
 * @param priority
 *   Priority value to be set.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_set_priority(rte_thread_t thread_id,
		enum rte_thread_priority priority);

/**
 * Initializes a mutex.
 *
 * @param mutex
 *    The mutex to be initialized.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_mutex_init(rte_thread_mutex *mutex);

/**
 * Locks a mutex.
 *
 * @param mutex
 *    The mutex to be locked.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_mutex_lock(rte_thread_mutex *mutex);

/**
 * Unlocks a mutex.
 *
 * @param mutex
 *    The mutex to be unlocked.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_mutex_unlock(rte_thread_mutex *mutex);

/**
 * Tries to lock a mutex.If the mutex is already held by a different thread,
 * the function returns without blocking.
 *
 * @param mutex
 *    The mutex that will be acquired, if not already locked.
 *
 * @return
 *   On success, if the mutex is acquired, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_mutex_try_lock(rte_thread_mutex *mutex);

/**
 * Releases all resources associated with a mutex.
 *
 * @param mutex
 *    The mutex to be uninitialized.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_mutex_destroy(rte_thread_mutex *mutex);

/**
 * Initializes a synchronization barrier.
 *
 * @param barrier
 *    A pointer that references the newly created 'barrier' object.
 *
 * @param count
 *    The number of threads that must enter the barrier before
 *    the threads can continue execution.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_barrier_init(rte_thread_barrier *barrier, int count);

/**
 * Causes the calling thread to wait at the synchronization barrier 'barrier'.
 *
 * @param barrier
 *    The barrier used for synchronizing the threads.
 *
 * @return
 *   Return RTE_THREAD_BARRIER_SERIAL_THREAD for the thread synchronized
 *      at the barrier.
 *   Return 0 for all other threads.
 *   Return a positive errno-style error number, in case of failure.
 */
__rte_experimental
int rte_thread_barrier_wait(rte_thread_barrier *barrier);

/**
 * Releases all resources used by a synchronization barrier
 * and uninitializes it.
 *
 * @param barrier
 *    The barrier to be destroyed.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_barrier_destroy(rte_thread_barrier *barrier);

/**
 * Create a TLS data key visible to all threads in the process.
 * the created key is later used to get/set a value.
 * and optional destructor can be set to be called when a thread exits.
 *
 * @param key
 *   Pointer to store the allocated key.
 * @param destructor
 *   The function to be called when the thread exits.
 *   Ignored on Windows OS.
 *
 * @return
 *   On success, zero.
 *   On failure, return a positive errno-style error number.
 */

__rte_experimental
int rte_thread_key_create(rte_thread_key *key,
			void (*destructor)(void *));

/**
 * Delete a TLS data key visible to all threads in the process.
 *
 * @param key
 *   The key allocated by rte_thread_key_create().
 *
 * @return
 *   On success, zero.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_key_delete(rte_thread_key key);

/**
 * Set value bound to the TLS key on behalf of the calling thread.
 *
 * @param key
 *   The key allocated by rte_thread_key_create().
 * @param value
 *   The value bound to the rte_thread_key key for the calling thread.
 *
 * @return
 *   On success, zero.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_value_set(rte_thread_key key, const void *value);

/**
 * Get value bound to the TLS key on behalf of the calling thread.
 *
 * @param key
 *   The key allocated by rte_thread_key_create().
 *
 * @return
 *   On success, value data pointer (can also be NULL).
 *   On failure, NULL and a positive error number is set in rte_errno.
 *
 */
__rte_experimental
void *rte_thread_value_get(rte_thread_key key);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_THREAD_H_ */
