/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

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
#if defined(RTE_USE_WINDOWS_THREAD_TYPES)
#include <rte_windows_thread_types.h>
#else
#include <rte_thread_types.h>
#endif

enum rte_thread_priority {
	RTE_THREAD_PRIORITY_NORMAL            = EAL_THREAD_PRIORITY_NORMAL,
	RTE_THREAD_PRIORITY_REALTIME_CRITICAL = EAL_THREAD_PRIORITY_REALTIME_CIRTICAL,
	/*
	 * This enum can be extended to allow more priority levels.
	 */
};

typedef struct {
	enum rte_thread_priority priority;
	rte_cpuset_t cpuset;
} rte_thread_attr_t;

/**
 * TLS key type, an opaque pointer.
 */
typedef struct eal_tls_key *rte_tls_key;

#ifdef RTE_HAS_CPUSET

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

/**
 * Set the affinity of thread 'thread_id' to the cpu set
 * specified by 'cpuset'.
 *
 * @param thread_id
 *    Id of the thread for which to set the affinity.
 *
 * @param cpuset_size
 *
 * @param cpuset
 *   Pointer to CPU affinity to set.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_set_affinity_by_id(rte_thread_t thread_id, size_t cpuset_size,
				  const rte_cpuset_t *cpuset);

/**
 * Get the affinity of thread 'thread_id' and store it
 * in 'cpuset'.
 *
 * @param thread_id
 *    Id of the thread for which to get the affinity.
 *
 * @param cpuset_size
 *    Size of the cpu set.
 *
 * @param cpuset
 *   Pointer for storing the affinity value.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_get_affinity_by_id(rte_thread_t thread_id, size_t cpuset_size,
				  rte_cpuset_t *cpuset);

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
 * Initialize the attributes of a thread.
 * These attributes can be passed to the rte_thread_create() function
 * that will create a new thread and set its attributes according to attr;
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
		      void *(*thread_func)(void *), void *args);

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
int rte_thread_join(rte_thread_t thread_id, int *value_ptr);

/**
 * Terminates a thread.
 *
 * @param thread_id
 *    The id of the thread to be cancelled.
 *
 * @return
 *   On success, return 0.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_cancel(rte_thread_t thread_id);

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

#endif /* RTE_HAS_CPUSET */

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
int rte_thread_tls_key_create(rte_tls_key *key, void (*destructor)(void *));

/**
 * Delete a TLS data key visible to all threads in the process.
 *
 * @param key
 *   The key allocated by rte_thread_tls_key_create().
 *
 * @return
 *   On success, zero.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_tls_key_delete(rte_tls_key key);

/**
 * Set value bound to the TLS key on behalf of the calling thread.
 *
 * @param key
 *   The key allocated by rte_thread_tls_key_create().
 * @param value
 *   The value bound to the rte_tls_key key for the calling thread.
 *
 * @return
 *   On success, zero.
 *   On failure, return a positive errno-style error number.
 */
__rte_experimental
int rte_thread_tls_value_set(rte_tls_key key, const void *value);

/**
 * Get value bound to the TLS key on behalf of the calling thread.
 *
 * @param key
 *   The key allocated by rte_thread_tls_key_create().
 *
 * @return
 *   On success, value data pointer (can also be NULL).
 *   On failure, NULL and an error number is set in rte_errno.
 */
__rte_experimental
void *rte_thread_tls_value_get(rte_tls_key key);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_THREAD_H_ */
