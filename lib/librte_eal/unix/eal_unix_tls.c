/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_tls.h>

struct eal_tls_key {
	pthread_key_t thread_index;
};

int
rte_tls_create_key(rte_tls_key_t *key, void (*destructor)(void *))
{
	int err;

	*key = malloc(sizeof(struct eal_tls_key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate tls key.");
		return -ENOMEM;
	}
	err = pthread_key_create(&((*key)->thread_index), destructor);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_key_create failed: %s\n",
			 rte_strerror(err));
		free(*key);
		return -ENOEXEC;
	}
	return 0;
}

int
rte_tls_delete_key(rte_tls_key_t key)
{
	int err;

	if (!key)
		return -EINVAL;
	err = pthread_key_delete(key->thread_index);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_key_delete failed: %s\n",
			 rte_strerror(err));
		free(key);
		return -ENOEXEC;
	}
	free(key);
	return 0;
}

int
rte_tls_set_thread_value(rte_tls_key_t key, const void *value)
{
	int err;

	if (!key)
		return -EINVAL;
	err = pthread_setspecific(key->thread_index, value);
	if (err) {
		RTE_LOG(DEBUG, EAL, "pthread_setspecific failed: %s\n",
			 rte_strerror(err));
		free(key);
		return -ENOEXEC;
	}
	return 0;
}

void *
rte_tls_get_thread_value(rte_tls_key_t key)
{
	if (!key)
		rte_errno = EINVAL;
	return pthread_getspecific(key->thread_index);
}
