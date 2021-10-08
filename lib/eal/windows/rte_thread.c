/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_thread.h>

#include "eal_windows.h"

struct eal_tls_key {
	DWORD thread_index;
};

/* Translates the most common error codes related to threads */
static int
thread_translate_win32_error(DWORD error)
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
	}

	return EINVAL;
}

static int
thread_log_last_error(const char *message)
{
	DWORD error = GetLastError();
	RTE_LOG(DEBUG, EAL, "GetLastError()=%lu: %s\n", error, message);

	return thread_translate_win32_error(error);
}

rte_thread_t
rte_thread_self(void)
{
	rte_thread_t thread_id;

	thread_id.opaque_id = GetCurrentThreadId();

	return thread_id;
}

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return t1.opaque_id == t2.opaque_id;
}

static int
rte_convert_cpuset_to_affinity(const rte_cpuset_t *cpuset,
		PGROUP_AFFINITY affinity)
{
	int ret = 0;
	PGROUP_AFFINITY cpu_affinity = NULL;
	unsigned int cpu_idx;

	memset(affinity, 0, sizeof(GROUP_AFFINITY));
	affinity->Group = (USHORT)-1;

	/* Check that all cpus of the set belong to the same processor group and
	 * accumulate thread affinity to be applied.
	 */
	for (cpu_idx = 0; cpu_idx < CPU_SETSIZE; cpu_idx++) {
		if (!CPU_ISSET(cpu_idx, cpuset))
			continue;

		cpu_affinity = eal_get_cpu_affinity(cpu_idx);

		if (affinity->Group == (USHORT)-1) {
			affinity->Group = cpu_affinity->Group;
		} else if (affinity->Group != cpu_affinity->Group) {
			ret = EINVAL;
			goto cleanup;
		}

		affinity->Mask |= cpu_affinity->Mask;
	}

	if (affinity->Mask == 0) {
		ret = EINVAL;
		goto cleanup;
	}

cleanup:
	return ret;
}

int
rte_thread_set_affinity_by_id(rte_thread_t thread_id,
		const rte_cpuset_t *cpuset)
{
	int ret = 0;
	GROUP_AFFINITY thread_affinity;
	HANDLE thread_handle = NULL;

	RTE_VERIFY(cpuset != NULL);

	ret = rte_convert_cpuset_to_affinity(cpuset, &thread_affinity);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "Unable to convert cpuset to thread affinity\n");
		goto cleanup;
	}

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE,
		thread_id.opaque_id);
	if (thread_handle == NULL) {
		ret = thread_log_last_error("OpenThread()");
		goto cleanup;
	}

	if (!SetThreadGroupAffinity(thread_handle, &thread_affinity, NULL)) {
		ret = thread_log_last_error("SetThreadGroupAffinity()");
		goto cleanup;
	}

cleanup:
	if (thread_handle != NULL) {
		CloseHandle(thread_handle);
		thread_handle = NULL;
	}

	return ret;
}

int
rte_thread_get_affinity_by_id(rte_thread_t thread_id,
		rte_cpuset_t *cpuset)
{
	HANDLE thread_handle = NULL;
	PGROUP_AFFINITY cpu_affinity;
	GROUP_AFFINITY thread_affinity;
	unsigned int cpu_idx;
	int ret = 0;

	RTE_VERIFY(cpuset != NULL);

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE,
		thread_id.opaque_id);
	if (thread_handle == NULL) {
		ret = thread_log_last_error("OpenThread()");
		goto cleanup;
	}

	/* obtain previous thread affinity */
	if (!GetThreadGroupAffinity(thread_handle, &thread_affinity)) {
		ret = thread_log_last_error("GetThreadGroupAffinity()");
		goto cleanup;
	}

	CPU_ZERO(cpuset);

	/* Convert affinity to DPDK cpu set */
	for (cpu_idx = 0; cpu_idx < CPU_SETSIZE; cpu_idx++) {

		cpu_affinity = eal_get_cpu_affinity(cpu_idx);

		if ((cpu_affinity->Group == thread_affinity.Group) &&
		   ((cpu_affinity->Mask & thread_affinity.Mask) != 0)) {
			CPU_SET(cpu_idx, cpuset);
		}
	}

cleanup:
	if (thread_handle != NULL) {
		CloseHandle(thread_handle);
		thread_handle = NULL;
	}
	return ret;
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	RTE_VERIFY(attr != NULL);

	attr->priority = RTE_THREAD_PRIORITY_NORMAL;
	CPU_ZERO(&attr->cpuset);

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);
	thread_attr->cpuset = *cpuset;

	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);

	*cpuset = thread_attr->cpuset;

	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
		enum rte_thread_priority priority)
{
	RTE_VERIFY(thread_attr != NULL);

	thread_attr->priority = priority;

	return 0;
}

int
rte_thread_key_create(rte_thread_key *key,
		__rte_unused void (*destructor)(void *))
{
	int ret;

	*key = malloc(sizeof(**key));
	if ((*key) == NULL) {
		RTE_LOG(DEBUG, EAL, "Cannot allocate TLS key.\n");
		return ENOMEM;
	}
	(*key)->thread_index = TlsAlloc();
	if ((*key)->thread_index == TLS_OUT_OF_INDEXES) {
		ret = thread_log_last_error("TlsAlloc()");
		free(*key);
		return ret;
	}
	return 0;
}

int
rte_thread_key_delete(rte_thread_key key)
{
	int ret;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		return EINVAL;
	}
	if (!TlsFree(key->thread_index)) {
		ret = thread_log_last_error("TlsFree()");
		free(key);
		return ret;
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
		return thread_log_last_error("TlsSetValue()");
	}
	return 0;
}

void *
rte_thread_value_get(rte_thread_key key)
{
	void *output;
	DWORD ret = 0;

	if (key == NULL) {
		RTE_LOG(DEBUG, EAL, "Invalid TLS key.\n");
		rte_errno = EINVAL;
		return NULL;
	}
	output = TlsGetValue(key->thread_index);
	ret = GetLastError();
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "GetLastError()=%lu: TlsGetValue()\n", ret);
		rte_errno = thread_translate_win32_error(ret);
		return NULL;
	}
	return output;
}
