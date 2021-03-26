/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_thread.h>
#include <rte_windows.h>

struct eal_tls_key {
	DWORD thread_index;
};

/* Translates the most common error codes related to threads */
static int rte_thread_translate_win32_error(DWORD error)
{
	switch (error) {
	case ERROR_SUCCESS:
		return 0;

	case ERROR_INVALID_PARAMETER:
		return EINVAL;

	case ERROR_INVALID_HANDLE:
		return EFAULT;

	case ERROR_NOT_ENOUGH_MEMORY:
	/* FALLTHROUGH */
	case ERROR_NO_SYSTEM_RESOURCES:
		return ENOMEM;

	case ERROR_PRIVILEGE_NOT_HELD:
	/* FALLTHROUGH */
	case ERROR_ACCESS_DENIED:
		return EACCES;

	case ERROR_ALREADY_EXISTS:
		return EEXIST;

	case ERROR_POSSIBLE_DEADLOCK:
		return EDEADLK;

	case ERROR_INVALID_FUNCTION:
	/* FALLTHROUGH */
	case ERROR_CALL_NOT_IMPLEMENTED:
		return ENOSYS;

	default:
		return EINVAL;
	}

	return EINVAL;
}

rte_thread_t
rte_thread_self(void)
{
	return GetCurrentThreadId();
}

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return t1 == t2 ? 1 : 0;
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	if (attr == NULL) {
		RTE_LOG(DEBUG, EAL,
		"Unable to init thread attributes, invalid parameter\n");
		return EINVAL;
	}

	attr->priority = RTE_THREAD_PRIORITY_NORMAL;
	CPU_ZERO(&attr->cpuset);
	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
			     rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL) {
		RTE_LOG(DEBUG, EAL,
		"Unable to set affinity attribute, invalid parameter\n");
		return EINVAL;
	}

	thread_attr->cpuset = *cpuset;
	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
			     rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL) {
		RTE_LOG(DEBUG, EAL,
		"Unable to set affinity attribute, invalid parameter\n");
		return EINVAL;
	}

	*cpuset = thread_attr->cpuset;
	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
			     enum rte_thread_priority priority)
{
	if (thread_attr == NULL) {
		RTE_LOG(DEBUG, EAL,
		"Unable to set priority attribute, invalid parameter\n");
		return EINVAL;
	}

	thread_attr->priority = priority;
	return 0;
}

int
rte_thread_key_create(rte_thread_key *key,
		__rte_unused void (*destructor)(void *))
{
	*key = malloc(sizeof(**key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate TLS key.\n");
		return ENOMEM;
	}
	(*key)->thread_index = TlsAlloc();
	if ((*key)->thread_index == TLS_OUT_OF_INDEXES) {
		RTE_LOG_WIN32_ERR("TlsAlloc()");
		free(*key);
		return rte_thread_translate_win32_error(GetLastError());
	}
	return 0;
}

int
rte_thread_key_delete(rte_thread_key key)
{
	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		return EINVAL;
	}
	if (!TlsFree(key->thread_index)) {
		RTE_LOG_WIN32_ERR("TlsFree()");
		free(key);
		return rte_thread_translate_win32_error(GetLastError());
	}
	free(key);
	return 0;
}

int
rte_thread_value_set(rte_thread_key key, const void *value)
{
	char *p;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		return EINVAL;
	}
	/* discard const qualifier */
	p = (char *) (uintptr_t) value;
	if (!TlsSetValue(key->thread_index, p)) {
		RTE_LOG_WIN32_ERR("TlsSetValue()");
		return rte_thread_translate_win32_error(GetLastError());
	}
	return 0;
}

void *
rte_thread_value_get(rte_thread_key key)
{
	void *output;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
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
