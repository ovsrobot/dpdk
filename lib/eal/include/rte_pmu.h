/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell
 */

#ifndef _RTE_PMU_H_
#define _RTE_PMU_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include <rte_compat.h>

#ifdef RTE_EXEC_ENV_LINUX

#include <linux/perf_event.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_lcore.h>
#include <rte_log.h>

/**
 * @file
 *
 * PMU event tracing operations
 *
 * This file defines generic API and types necessary to setup PMU and
 * read selected counters in runtime.
 */

/** Maximum number of events in a group */
#define MAX_NUM_GROUP_EVENTS 16

/**
 * A structure describing a group of events.
 */
struct rte_pmu_event_group {
	int fds[MAX_NUM_GROUP_EVENTS]; /**< array of event descriptors */
	struct perf_event_mmap_page *mmap_pages[MAX_NUM_GROUP_EVENTS]; /**< array of user pages */
	bool enabled; /**< true if group was enabled on particular lcore */
};

/**
 * A structure describing an event.
 */
struct rte_pmu_event {
	char *name; /** name of an event */
	unsigned int index; /** event index into fds/mmap_pages */
	TAILQ_ENTRY(rte_pmu_event) next; /** list entry */
};

/**
 * A PMU state container.
 */
struct rte_pmu {
	char *name; /** name of core PMU listed under /sys/bus/event_source/devices */
	struct rte_pmu_event_group group[RTE_MAX_LCORE]; /**< per lcore event group data */
	unsigned int num_group_events; /**< number of events in a group */
	TAILQ_HEAD(, rte_pmu_event) event_list; /**< list of matching events */
};

/** Pointer to the PMU state container */
extern struct rte_pmu rte_pmu;

/** Each architecture supporting PMU needs to provide its own version */
#ifndef rte_pmu_pmc_read
#define rte_pmu_pmc_read(index) ({ 0; })
#endif

/**
 * @internal
 *
 * Read PMU counter.
 *
 * @param pc
 *   Pointer to the mmapped user page.
 * @return
 *   Counter value read from hardware.
 */
__rte_internal
static __rte_always_inline uint64_t
rte_pmu_read_userpage(struct perf_event_mmap_page *pc)
{
	uint64_t width, offset;
	uint32_t seq, index;
	int64_t pmc;

	for (;;) {
		seq = pc->lock;
		rte_compiler_barrier();
		index = pc->index;
		offset = pc->offset;
		width = pc->pmc_width;

		if (likely(pc->cap_user_rdpmc && index)) {
			pmc = rte_pmu_pmc_read(index - 1);
			pmc <<= 64 - width;
			pmc >>= 64 - width;
			offset += pmc;
		}

		rte_compiler_barrier();

		if (likely(pc->lock == seq))
			return offset;
	}

	return 0;
}

/**
 * @internal
 *
 * Enable group of events for a given lcore.
 *
 * @param lcore_id
 *   The identifier of the lcore.
 * @return
 *   0 in case of success, negative value otherwise.
 */
__rte_internal
int
rte_pmu_enable_group(unsigned int lcore_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Add event to the group of enabled events.
 *
 * @param name
 *   Name of an event listed under /sys/bus/event_source/devices/pmu/events.
 * @return
 *   Event index in case of success, negative value otherwise.
 */
__rte_experimental
int
rte_pmu_add_event(const char *name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Read hardware counter configured to count occurrences of an event.
 *
 * @param index
 *   Index of an event to be read.
 * @return
 *   Event value read from register. In case of errors or lack of support
 *   0 is returned. In other words, stream of zeros in a trace file
 *   indicates problem with reading particular PMU event register.
 */
__rte_experimental
static __rte_always_inline uint64_t
rte_pmu_read(unsigned int index)
{
	struct rte_pmu_event_group *group;
	int ret, lcore_id = rte_lcore_id();

	group = &rte_pmu.group[lcore_id];
	if (unlikely(!group->enabled)) {
		ret = rte_pmu_enable_group(lcore_id);
		if (ret)
			return 0;

		group->enabled = true;
	}

	if (unlikely(index >= rte_pmu.num_group_events))
		return 0;

	return rte_pmu_read_userpage(group->mmap_pages[index]);
}

#else /* !RTE_EXEC_ENV_LINUX */

__rte_experimental
static int __rte_unused
rte_pmu_add_event(__rte_unused const char *name)
{
	return -1;
}

__rte_experimental
static __rte_always_inline uint64_t
rte_pmu_read(__rte_unused unsigned int index)
{
	return 0;
}

#endif /* RTE_EXEC_ENV_LINUX */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMU_H_ */
