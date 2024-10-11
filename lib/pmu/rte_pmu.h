/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Marvell
 */

#ifndef _RTE_PMU_H_
#define _RTE_PMU_H_

/**
 * @file
 *
 * PMU event tracing operations
 *
 * This file defines generic API and types necessary to setup PMU and
 * read selected counters in runtime.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>

#include <rte_common.h>
#include <rte_compat.h>

#ifdef RTE_EXEC_ENV_LINUX

#include <linux/perf_event.h>

#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_spinlock.h>

#if defined(RTE_ARCH_ARM64)
#include "rte_pmu_pmc_arm64.h"
#endif

/** Maximum number of events in a group */
#define RTE_MAX_NUM_GROUP_EVENTS 8

/**
 * A structure describing a group of events.
 */
struct __rte_cache_aligned rte_pmu_event_group {
	/** array of user pages */
	struct perf_event_mmap_page *mmap_pages[RTE_MAX_NUM_GROUP_EVENTS];
	int fds[RTE_MAX_NUM_GROUP_EVENTS]; /**< array of event descriptors */
	bool enabled; /**< true if group was enabled on particular lcore */
	TAILQ_ENTRY(rte_pmu_event_group) next; /**< list entry */
};

/**
 * A PMU state container.
 */
struct rte_pmu {
	char *name; /**< name of core PMU listed under /sys/bus/event_source/devices */
	rte_spinlock_t lock; /**< serialize access to event group list */
	TAILQ_HEAD(, rte_pmu_event_group) event_group_list; /**< list of event groups */
	unsigned int num_group_events; /**< number of events in a group */
	TAILQ_HEAD(, rte_pmu_event) event_list; /**< list of matching events */
	unsigned int initialized; /**< initialization counter */
};

/** lcore event group */
RTE_DECLARE_PER_LCORE(struct rte_pmu_event_group, _event_group);

/** PMU state container */
extern struct rte_pmu rte_pmu;

/** Each architecture supporting PMU needs to provide its own version */
#ifndef rte_pmu_pmc_read
#define rte_pmu_pmc_read(index) ({ (void)(index); 0; })
#endif

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Read PMU counter.
 *
 * @warning This should be not called directly.
 *
 * @param pc
 *   Pointer to the mmapped user page.
 * @return
 *   Counter value read from hardware.
 */
__rte_experimental
static __rte_always_inline uint64_t
__rte_pmu_read_userpage(struct perf_event_mmap_page *pc)
{
#define __RTE_PMU_READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
	uint64_t width, offset;
	uint32_t seq, index;
	int64_t pmc;

	for (;;) {
		seq = __RTE_PMU_READ_ONCE(pc->lock);
		rte_compiler_barrier();
		index = __RTE_PMU_READ_ONCE(pc->index);
		offset = __RTE_PMU_READ_ONCE(pc->offset);
		width = __RTE_PMU_READ_ONCE(pc->pmc_width);

		/* index set to 0 means that particular counter cannot be used */
		if (likely(pc->cap_user_rdpmc && index)) {
			pmc = rte_pmu_pmc_read(index - 1);
			pmc <<= 64 - width;
			pmc >>= 64 - width;
			offset += pmc;
		}

		rte_compiler_barrier();

		if (likely(__RTE_PMU_READ_ONCE(pc->lock) == seq))
			return offset;
	}

	return 0;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Enable group of events on the calling lcore.
 *
 * @warning This should be not called directly.
 *
 * @return
 *   0 in case of success, negative value otherwise.
 */
__rte_experimental
int
__rte_pmu_enable_group(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Initialize PMU library.
 *
 * @warning This should be not called directly.
 *
 * @return
 *   0 in case of success, negative value otherwise.
 */
__rte_experimental
int
rte_pmu_init(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Finalize PMU library. This should be called after PMU counters are no longer being read.
 */
__rte_experimental
void
rte_pmu_fini(void);

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
	struct rte_pmu_event_group *group = &RTE_PER_LCORE(_event_group);
	int ret;

	if (unlikely(!rte_pmu.initialized))
		return 0;

	if (unlikely(!group->enabled)) {
		ret = __rte_pmu_enable_group();
		if (ret)
			return 0;
	}

	if (unlikely(index >= rte_pmu.num_group_events))
		return 0;

	return __rte_pmu_read_userpage(group->mmap_pages[index]);
}

#else /* !RTE_EXEC_ENV_LINUX */

__rte_experimental
static inline int rte_pmu_init(void) { return -ENOTSUP; }

__rte_experimental
static inline void rte_pmu_fini(void) { }

__rte_experimental
static inline int rte_pmu_add_event(const char *name __rte_unused) { return -ENOTSUP; }

__rte_experimental
static inline uint64_t rte_pmu_read(unsigned int index __rte_unused) { return UINT64_MAX; }

#endif /* RTE_EXEC_ENV_LINUX */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PMU_H_ */
