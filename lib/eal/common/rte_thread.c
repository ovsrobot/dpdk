/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <errno.h>

#include <rte_debug.h>
#include <rte_thread.h>

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	if (attr == NULL)
		return EINVAL;

	CPU_ZERO(&attr->cpuset);
	attr->priority = RTE_THREAD_PRIORITY_NORMAL;

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL)
		return EINVAL;

	if (cpuset == NULL)
		return EINVAL;

	thread_attr->cpuset = *cpuset;

	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	if (thread_attr == NULL)
		return EINVAL;

	if (cpuset == NULL)
		return EINVAL;

	*cpuset = thread_attr->cpuset;

	return 0;
}

int
rte_thread_attr_set_priority(rte_thread_attr_t *thread_attr,
		enum rte_thread_priority priority)
{
	if (thread_attr == NULL)
		return EINVAL;

	thread_attr->priority = priority;

	return 0;
}
