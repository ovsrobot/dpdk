/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_thread.h>
#include <rte_windows.h>

struct eal_tls_key {
	DWORD thread_index;
};

int
rte_thread_tls_create_key(rte_tls_key *key,
		__rte_unused void (*destructor)(void *))
{
	*key = malloc(sizeof(struct eal_tls_key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate tls key.");
		return -1;
	}
	(*key)->thread_index = TlsAlloc();
	if ((*key)->thread_index == TLS_OUT_OF_INDEXES) {
		RTE_LOG_WIN32_ERR("TlsAlloc()");
		free(*key);
		return -1;
	}
	return 0;
}

int
rte_thread_tls_delete_key(rte_tls_key key)
{
	if (!key) {
		RTE_LOG(DEBUG, EAL, "invalid tls key passed to function.\n");
		return -1;
	}
	if (!TlsFree(key->thread_index)) {
		RTE_LOG_WIN32_ERR("TlsFree()");
		free(key);
		return -1;
	}
	free(key);
	return 0;
}

int
rte_thread_tls_set_value(rte_tls_key key, const void *value)
{
	char *p;

	if (!key) {
		RTE_LOG(DEBUG, EAL, "invalid tls key passed to function.\n");
		return -1;
	}
	/* discard const qualifier */
	p = (char *) (uintptr_t) value;
	if (!TlsSetValue(key->thread_index, p)) {
		RTE_LOG_WIN32_ERR("TlsSetValue()");
		return -1;
	}
	return 0;
}

void *
rte_thread_tls_get_value(rte_tls_key key)
{
	void *output;

	if (!key) {
		RTE_LOG(DEBUG, EAL, "invalid tls key passed to function.\n");
		rte_errno = EINVAL;
		return NULL;
	}
	output = TlsGetValue(key->thread_index);
	if (GetLastError() != ERROR_SUCCESS) {
		RTE_LOG_WIN32_ERR("TlsGetValue()");
		rte_errno = ENOEXEC;
		return NULL;
	}
	return output;
}
