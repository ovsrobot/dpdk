/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Mellanox Technologies, Ltd
 */

#include <rte_os.h>

#ifndef _RTE_THREAD_H_
#define _RTE_THREAD_H_

/**
 * @file
 *
 * Threading functions
 *
 * Simple threads functionality supplied by EAL.
 */

/**
 * Opaque pointer for TLS key.
 */
typedef struct eal_tls_key *rte_tls_key;

/**
 * Set core affinity of the current thread.
 * Support both EAL and non-EAL thread and update TLS.
 *
 * @param cpusetp
 *   Point to cpu_set_t for setting current thread affinity.
 * @return
 *   On success, return 0; otherwise return -1;
 */
int rte_thread_set_affinity(rte_cpuset_t *cpusetp);

/**
 * Get core affinity of the current thread.
 *
 * @param cpusetp
 *   Point to cpu_set_t for getting current thread cpu affinity.
 *   It presumes input is not NULL, otherwise it causes panic.
 *
 */
void rte_thread_get_affinity(rte_cpuset_t *cpusetp);

/**
 * Function to create a TLS data key visible to all threads in the process
 * function need to be called once to create a key usable by all threads.
 * rte_tls_key is an opaque pointer used to store the allocated key.
 * which is later used to get/set a value.
 * and optional destructor can be set to be called when a thread expires.
 *
 * @param key
 *   Pointer to store the allocated rte_tls_key
 * @param destructor
 *   The function to be called when the thread expires.
 *   Ignored on Windows OS.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */

__rte_experimental
int rte_thread_tls_key_create(rte_tls_key *key, void (*destructor)(void *));

/**
 * Function to delete a TLS data key visible to all threads in the process
 * rte_tls_key is the opaque pointer allocated by rte_thread_tls_key_create.
 *
 * @param key
 *   The rte_tls_key will contain the allocated key
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */
__rte_experimental
int rte_thread_tls_key_delete(rte_tls_key key);

/**
 * Function to set value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key key allocated by rte_thread_tls_key_create.
 * @param value
 *   The value bound to the rte_tls_key key for the calling thread.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */
__rte_experimental
int rte_thread_tls_value_set(rte_tls_key key, const void *value);

/**
 * Function to get value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key key allocated by rte_thread_tls_key_create.
 *
 * @return
 *   On success, value data pointer (can also be NULL).
 *   On failure, NULL and an error number is set in rte_errno.
 */
__rte_experimental
void *rte_thread_tls_value_get(rte_tls_key key);

#endif /* _RTE_THREAD_H_ */
