/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Microsoft Corporation
 */

#include <rte_debug.h>
#include <rte_thread.h>

int
rte_thread_equal(rte_thread_t t1, rte_thread_t t2)
{
	return t1.opaque_id == t2.opaque_id;
}

int
rte_thread_attr_init(rte_thread_attr_t *attr)
{
	RTE_VERIFY(attr != NULL);

	CPU_ZERO(&attr->cpuset);
	attr->priority = RTE_THREAD_PRIORITY_NORMAL;

	return 0;
}

int
rte_thread_attr_set_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);
	RTE_VERIFY(cpuset != NULL);

	thread_attr->cpuset = *cpuset;

	return 0;
}

int
rte_thread_attr_get_affinity(rte_thread_attr_t *thread_attr,
		rte_cpuset_t *cpuset)
{
	RTE_VERIFY(thread_attr != NULL);
	RTE_VERIFY(cpuset != NULL);

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
