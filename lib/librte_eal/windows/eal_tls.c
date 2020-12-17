/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_tls.h>
#include <rte_windows.h>

struct eal_tls_key {
	DWORD thread_index;
};

int
rte_tls_create_key(rte_tls_key_t *key,
		__rte_unused void (*destructor)(void *))
{
	*key = malloc(sizeof(struct eal_tls_key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate tls key.");
		return -ENOMEM;
	}
	(*key)->thread_index = TlsAlloc();
	if ((*key)->thread_index == TLS_OUT_OF_INDEXES) {
		RTE_LOG_WIN32_ERR("TlsAlloc()");
		free(*key);
		return -ENOEXEC;
	}
	return 0;
}

int
rte_tls_delete_key(rte_tls_key_t key)
{
	if (!key)
		return -EINVAL;
	if (!TlsFree(key->thread_index)) {
		RTE_LOG_WIN32_ERR("TlsFree()");
		free(key);
		return -ENOEXEC;
	}
	free(key);
	return 0;
}

int
rte_tls_set_thread_value(rte_tls_key_t key, const void *value)
{
	if (!key)
		return -EINVAL;
	/* discard const qualifier */
	char *p = (char *) (uintptr_t) value;

	if (!TlsSetValue(key->thread_index, p)) {
		RTE_LOG_WIN32_ERR("TlsSetValue()");
		return -ENOEXEC;
	}
	return 0;
}

void *
rte_tls_get_thread_value(rte_tls_key_t key)
{
	if (!key)
		rte_errno = EINVAL;
	void *output = TlsGetValue(key->thread_index);
	if (GetLastError() != ERROR_SUCCESS) {
		RTE_LOG_WIN32_ERR("TlsGetValue()");
		rte_errno = ENOEXEC;
		return NULL;
	}
	return output;
}
