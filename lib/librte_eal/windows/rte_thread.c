/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 * Copyright(c) 2021 Microsoft Corporation
 */

#include <rte_common.h>
#include <rte_thread.h>

#include "eal_windows.h"

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

static int
rte_convert_cpuset_to_affinity(const rte_cpuset_t *cpuset,
			       PGROUP_AFFINITY affinity)
{
	int ret = 0;
	PGROUP_AFFINITY cpu_affinity = NULL;

	memset(affinity, 0, sizeof(GROUP_AFFINITY));
	affinity->Group = (USHORT)-1;

	/* Check that all cpus of the set belong to the same processor group and
	 * accumulate thread affinity to be applied.
	 */
	for (unsigned int cpu_idx = 0; cpu_idx < CPU_SETSIZE; cpu_idx++) {
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

int rte_thread_set_affinity_by_id(rte_thread_t thread_id,
			    size_t cpuset_size,
			    const rte_cpuset_t *cpuset)
{
	int ret = 0;
	GROUP_AFFINITY thread_affinity;
	HANDLE thread_handle = NULL;

	if (cpuset == NULL || cpuset_size < sizeof(*cpuset)) {
		ret = EINVAL;
		goto cleanup;
	}

	ret = rte_convert_cpuset_to_affinity(cpuset, &thread_affinity);
	if (ret != 0) {
		RTE_LOG(DEBUG, EAL, "Unable to convert cpuset to thread affinity\n");
		goto cleanup;
	}

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("OpenThread()");
		goto cleanup;
	}

	if (!SetThreadGroupAffinity(thread_handle, &thread_affinity, NULL)) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("SetThreadGroupAffinity()");
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
rte_thread_get_affinity_by_id(rte_thread_t thread_id, size_t cpuset_size,
			rte_cpuset_t *cpuset)
{
	HANDLE thread_handle = NULL;
	PGROUP_AFFINITY cpu_affinity;
	GROUP_AFFINITY thread_affinity;
	int ret = 0;

	if (cpuset == NULL || cpuset_size < sizeof(*cpuset)) {
		ret = EINVAL;
		goto cleanup;
	}

	thread_handle = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("OpenThread()");
		goto cleanup;
	}

	/* obtain previous thread affinity */
	if (!GetThreadGroupAffinity(thread_handle, &thread_affinity)) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("GetThreadGroupAffinity()");
		goto cleanup;
	}

	CPU_ZERO(cpuset);

	/* Convert affinity to DPDK cpu set */
	for (unsigned int cpu_idx = 0; cpu_idx < CPU_SETSIZE; cpu_idx++) {

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

static HANDLE
get_process_handle_from_thread_handle(HANDLE thread_handle)
{
	DWORD process_id = 0;

	process_id = GetProcessIdOfThread(thread_handle);
	if (process_id == 0) {
		RTE_LOG_WIN32_ERR("GetProcessIdOfThread()");
		return NULL;
	}

	return OpenProcess(PROCESS_SET_INFORMATION, FALSE, process_id);
}

int
rte_thread_set_priority(rte_thread_t thread_id,
			enum rte_thread_priority priority)
{
	HANDLE thread_handle = NULL;
	HANDLE process_handle = NULL;
	DWORD priority_class = NORMAL_PRIORITY_CLASS;
	int ret = 0;

	thread_handle = OpenThread(THREAD_SET_INFORMATION |
				   THREAD_QUERY_INFORMATION, FALSE, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("OpenThread()");
		goto cleanup;
	}

	switch (priority) {

	case RTE_THREAD_PRIORITY_REALTIME_CRITICAL:
		priority_class = REALTIME_PRIORITY_CLASS;
		break;

	case RTE_THREAD_PRIORITY_NORMAL:
	/* FALLTHROUGH */
	default:
		priority_class = NORMAL_PRIORITY_CLASS;
		priority = RTE_THREAD_PRIORITY_NORMAL;
		break;
	}

	process_handle = get_process_handle_from_thread_handle(thread_handle);
	if (process_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("get_process_handle_from_thread_handle()");
		goto cleanup;
	}

	if (!SetPriorityClass(process_handle, priority_class)) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("SetPriorityClass()");
		goto cleanup;
	}

	if (!SetThreadPriority(thread_handle, priority)) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("SetThreadPriority()");
		goto cleanup;
	}

cleanup:
	if (thread_handle != NULL) {
		CloseHandle(thread_handle);
		thread_handle = NULL;
	}
	if (process_handle != NULL) {
		CloseHandle(process_handle);
		process_handle = NULL;
	}
	return ret;
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
rte_thread_create(rte_thread_t *thread_id,
		  const rte_thread_attr_t *thread_attr,
		  void *(*thread_func)(void *), void *args)
{
	int ret = 0;
	HANDLE thread_handle = NULL;
	GROUP_AFFINITY thread_affinity;

	thread_handle = CreateThread(NULL, 0,
				(LPTHREAD_START_ROUTINE)(ULONG_PTR)thread_func,
				args, 0, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("CreateThread()");
		goto cleanup;
	}

	if (thread_attr != NULL) {
		if (CPU_COUNT(&thread_attr->cpuset) > 0) {
			ret = rte_convert_cpuset_to_affinity(&thread_attr->cpuset, &thread_affinity);
			if (ret != 0) {
				RTE_LOG(DEBUG, EAL, "Unable to convert cpuset to thread affinity\n");
				goto cleanup;
			}

			if (!SetThreadGroupAffinity(thread_handle, &thread_affinity, NULL)) {
				ret = rte_thread_translate_win32_error(GetLastError());
				RTE_LOG_WIN32_ERR("SetThreadGroupAffinity()");
				goto cleanup;
			}
		}
		ret = rte_thread_set_priority(*thread_id, thread_attr->priority);
		if (ret != 0) {
			RTE_LOG(DEBUG, EAL, "Unable to set thread priority\n");
			goto cleanup;
		}
	}

	return 0;

cleanup:
	if (thread_handle != NULL) {
		CloseHandle(thread_handle);
		thread_handle = NULL;
	}
	return ret;
}

int
rte_thread_join(rte_thread_t thread_id, int *value_ptr)
{
	HANDLE thread_handle = NULL;
	DWORD result = 0;
	DWORD exit_code = 0;
	BOOL err = 0;
	int ret = 0;

	thread_handle = OpenThread(SYNCHRONIZE | THREAD_QUERY_INFORMATION,
				   FALSE, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("OpenThread()");
		goto cleanup;
	}

	result = WaitForSingleObject(thread_handle, INFINITE);
	if (result != WAIT_OBJECT_0) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("WaitForSingleObject()");
		goto cleanup;
	}

	if (value_ptr != NULL) {
		err = GetExitCodeThread(thread_handle, &exit_code);
		if (err == 0) {
			ret = rte_thread_translate_win32_error(GetLastError());
			RTE_LOG_WIN32_ERR("GetExitCodeThread()");
			goto cleanup;
		}
		*value_ptr = exit_code;
	}

cleanup:
	if (thread_handle != NULL) {
		CloseHandle(thread_handle);
		thread_handle = NULL;
	}

	return ret;
}

int
rte_thread_cancel(rte_thread_t thread_id)
{
	int ret = 0;
	HANDLE thread_handle = NULL;

	thread_handle = OpenThread(THREAD_TERMINATE, FALSE, thread_id);
	if (thread_handle == NULL) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("OpenThread()");
		goto cleanup;
	}

	/*
	 * TODO: Behavior is different between POSIX and Windows threads.
	 * POSIX threads wait for a cancellation point.
	 * Current Windows emulation kills thread at any point.
	 */
	ret = TerminateThread(thread_handle, 0);
	if (ret != 0) {
		ret = rte_thread_translate_win32_error(GetLastError());
		RTE_LOG_WIN32_ERR("TerminateThread()");
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
