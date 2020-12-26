/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Technologies, Ltd
 */

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

/**
 * Opaque pointer for TLS key.
 */
typedef struct eal_tls_key *rte_tls_key;

/**
 * Function to create a TLS data key visible to all threads in the process
 * function need to be called once to create a key usable by all threads.
 * rte_tls_key is an opaque pointer used to store the allocated key.
 * and optional destructor can be set to be called when a thread expires.
 *
 * @param key
 *   Pointer to store the allocated rte_tls_key
 * @param destructor
 *   The function to be called when the thread expires.
 *   Not supported on Windows OS.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */
__rte_experimental
int
rte_thread_tls_create_key(rte_tls_key *key, void (*destructor)(void *));

/**
 * Function to delete a TLS data key visible to all threads in the process
 * rte_tls_key is the opaque pointer allocated by rte_thread_tls_create_key.
 *
 * @param key
 *   The rte_tls_key will contain the allocated key
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */
__rte_experimental
int
rte_thread_tls_delete_key(rte_tls_key key);

/**
 * Function to set value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key key allocated by rte_thread_tls_create_key.
 * @param value
 *   The value bound to the rte_tls_key key for the calling thread.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative number.
 */
__rte_experimental
int
rte_thread_tls_set_value(rte_tls_key key, const void *value);

/**
 * Function to get value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key key allocated by rte_thread_tls_create_key.
 *
 * @return
 *   On success, value data pointer (can also be NULL).
 *   On failure, NULL and an error number is set in rte_errno.
 */
__rte_experimental
void *
rte_thread_tls_get_value(rte_tls_key key);

#endif /* _RTE_THREAD_H_ */
