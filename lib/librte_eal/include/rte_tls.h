/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Technologies, Ltd
 */

#include <rte_compat.h>

#ifndef _RTE_TLS_H_
#define _RTE_TLS_H_

/**
 * @file
 *
 * TLS functions
 *
 * Simple TLS functionality supplied by eal.
 */

/**
 * Opaque pointer for tls key.
 */
typedef struct eal_tls_key *rte_tls_key_t;

/**
 * Function to create a tls data key visible to all threads in the process
 * function need to be called once to create a key usable by all threads.
 * rte_tls_key_t is an opaque pointer used to store the allocated key.
 * and optional destructor can be set to be called when a thread expires.
 *
 * @param key
 *   The rte_tls_key_t will cantain the allocated key
 * @param destructor
 *   The function to be called when the thread expires
 *   Not supported on Windows OS.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative error number -ENOMEM or -ENOEXEC
 */
__rte_experimental
int
rte_tls_create_key(rte_tls_key_t *key, void (*destructor)(void *));

/**
 * Function to delete a tls data key visible to all threads in the process
 * rte_tls_key_t is an opaque pointer used to allocated the key.
 *
 * @param key
 *   The rte_tls_key_t will cantain the allocated key
 *
 * @return
 *   On success, zero.
 *   On failure, a negative error number -ENOMEM or -ENOEXEC
 */
__rte_experimental
int
rte_tls_delete_key(rte_tls_key_t key);

/**
 * Function to set value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key_t key
 * @param value
 *   The value bound to the rte_tls_key_t key for the calling thread.
 *
 * @return
 *   On success, zero.
 *   On failure, a negative error number -ENOMEM or -ENOEXEC
 */
__rte_experimental
int
rte_tls_set_thread_value(rte_tls_key_t key, const void *value);

/**
 * Function to get value bound to the tls key on behalf of the calling thread
 *
 * @param key
 *   The rte_tls_key_t key
 *
 * @return
 *   On success, value data pointer.
 *   On failure, a negative error number is set in rte_errno.
 */
__rte_experimental
void *
rte_tls_get_thread_value(rte_tls_key_t key);

#endif /* _RTE_TLS_H_ */
