/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell International Ltd.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <rte_eal_paging.h>
#include <rte_malloc.h>
#include <rte_pmu.h>
#include <rte_tailq.h>

#include "pmu_private.h"

#define EVENT_SOURCE_DEVICES_PATH "/sys/bus/event_source/devices"

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) ((~0ULL - (1ULL << (l)) + 1) & (~0ULL >> ((64 - 1 - (h)))))
#endif

#ifndef FIELD_PREP
#define FIELD_PREP(m, v) (((uint64_t)(v) << (__builtin_ffsll(m) - 1)) & (m))
#endif

struct rte_pmu *pmu;

/*
 * Following __rte_weak functions provide default no-op. Architectures should override them if
 * necessary.
 */

int
__rte_weak pmu_arch_init(void)
{
	return 0;
}

void
__rte_weak pmu_arch_fini(void)
{
}

void
__rte_weak pmu_arch_fixup_config(uint64_t config[3])
{
	RTE_SET_USED(config);
}

static int
get_term_format(const char *name, int *num, uint64_t *mask)
{
	char *config = NULL;
	char path[PATH_MAX];
	int high, low, ret;
	FILE *fp;

	/* quiesce -Wmaybe-uninitialized warning */
	*num = 0;
	*mask = 0;

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/format/%s", pmu->name, name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	errno = 0;
	ret = fscanf(fp, "%m[^:]:%d-%d", &config, &low, &high);
	if (ret < 2) {
		ret = -ENODATA;
		goto out;
	}
	if (errno) {
		ret = -errno;
		goto out;
	}

	if (ret == 2)
		high = low;

	*mask = GENMASK_ULL(high, low);
	/* Last digit should be [012]. If last digit is missing 0 is implied. */
	*num = config[strlen(config) - 1];
	*num = isdigit(*num) ? *num - '0' : 0;

	ret = 0;
out:
	free(config);
	fclose(fp);

	return ret;
}

static int
parse_event(char *buf, uint64_t config[3])
{
	char *token, *term;
	int num, ret, val;
	uint64_t mask;

	config[0] = config[1] = config[2] = 0;

	token = strtok(buf, ",");
	while (token) {
		errno = 0;
		/* <term>=<value> */
		ret = sscanf(token, "%m[^=]=%i", &term, &val);
		if (ret < 1)
			return -ENODATA;
		if (errno)
			return -errno;
		if (ret == 1)
			val = 1;

		ret = get_term_format(term, &num, &mask);
		free(term);
		if (ret)
			return ret;

		config[num] |= FIELD_PREP(mask, val);
		token = strtok(NULL, ",");
	}

	return 0;
}

static int
get_event_config(const char *name, uint64_t config[3])
{
	char path[PATH_MAX], buf[BUFSIZ];
	FILE *fp;
	int ret;

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/events/%s", pmu->name, name);
	fp = fopen(path, "r");
	if (!fp)
		return -errno;

	ret = fread(buf, 1, sizeof(buf), fp);
	if (ret == 0) {
		fclose(fp);

		return -EINVAL;
	}
	fclose(fp);
	buf[ret] = '\0';

	return parse_event(buf, config);
}

static int
do_perf_event_open(uint64_t config[3], int lcore_id, int group_fd)
{
	struct perf_event_attr attr = {
		.size = sizeof(struct perf_event_attr),
		.type = PERF_TYPE_RAW,
		.exclude_kernel = 1,
		.exclude_hv = 1,
		.disabled = 1,
	};

	pmu_arch_fixup_config(config);

	attr.config = config[0];
	attr.config1 = config[1];
	attr.config2 = config[2];

	return syscall(SYS_perf_event_open, &attr, rte_gettid(), rte_lcore_to_cpu_id(lcore_id),
		       group_fd, 0);
}

static int
open_events(int lcore_id)
{
	struct rte_pmu_event_group *group = &pmu->group[lcore_id];
	struct rte_pmu_event *event;
	uint64_t config[3];
	int num = 0, ret;

	/* group leader gets created first, with fd = -1 */
	group->fds[0] = -1;

	TAILQ_FOREACH(event, &pmu->event_list, next) {
		ret = get_event_config(event->name, config);
		if (ret) {
			RTE_LOG(ERR, EAL, "failed to get %s event config\n", event->name);
			continue;
		}

		ret = do_perf_event_open(config, lcore_id, group->fds[0]);
		if (ret == -1) {
			if (errno == EOPNOTSUPP)
				RTE_LOG(ERR, EAL, "64 bit counters not supported\n");

			ret = -errno;
			goto out;
		}

		group->fds[event->index] = ret;
		num++;
	}

	return 0;
out:
	for (--num; num >= 0; num--) {
		close(group->fds[num]);
		group->fds[num] = -1;
	}


	return ret;
}

static int
mmap_events(int lcore_id)
{
	struct rte_pmu_event_group *group = &pmu->group[lcore_id];
	void *addr;
	int ret, i;

	for (i = 0; i < pmu->num_group_events; i++) {
		addr = mmap(0, rte_mem_page_size(), PROT_READ, MAP_SHARED, group->fds[i], 0);
		if (addr == MAP_FAILED) {
			ret = -errno;
			goto out;
		}

		group->mmap_pages[i] = addr;
	}

	return 0;
out:
	for (; i; i--) {
		munmap(group->mmap_pages[i - 1], rte_mem_page_size());
		group->mmap_pages[i - 1] = NULL;
	}

	return ret;
}

static void
cleanup_events(int lcore_id)
{
	struct rte_pmu_event_group *group = &pmu->group[lcore_id];
	int i;

	if (!group->fds)
		return;

	if (group->fds[0] != -1)
		ioctl(group->fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

	for (i = 0; i < pmu->num_group_events; i++) {
		if (group->mmap_pages[i]) {
			munmap(group->mmap_pages[i], rte_mem_page_size());
			group->mmap_pages[i] = NULL;
		}

		if (group->fds[i] != -1) {
			close(group->fds[i]);
			group->fds[i] = -1;
		}
	}

	rte_free(group->mmap_pages);
	rte_free(group->fds);

	group->mmap_pages = NULL;
	group->fds = NULL;
	group->enabled = false;
}

int __rte_noinline
rte_pmu_enable_group(int lcore_id)
{
	struct rte_pmu_event_group *group = &pmu->group[lcore_id];
	int ret;

	if (pmu->num_group_events == 0) {
		RTE_LOG(DEBUG, EAL, "no matching PMU events\n");

		return 0;
	}

	group->fds = rte_zmalloc(NULL, pmu->num_group_events, sizeof(*group->fds));
	if (!group->fds) {
		RTE_LOG(ERR, EAL, "failed to alloc descriptor memory\n");

		return -ENOMEM;
	}

	group->mmap_pages = rte_zmalloc(NULL, pmu->num_group_events, sizeof(*group->mmap_pages));
	if (!group->mmap_pages) {
		RTE_LOG(ERR, EAL, "failed to alloc userpage memory\n");

		ret = -ENOMEM;
		goto out;
	}

	ret = open_events(lcore_id);
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to open events on lcore-worker-%d\n", lcore_id);
		goto out;
	}

	ret = mmap_events(lcore_id);
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to map events on lcore-worker-%d\n", lcore_id);
		goto out;
	}

	if (ioctl(group->fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) == -1) {
		RTE_LOG(ERR, EAL, "failed to enable events on lcore-worker-%d\n", lcore_id);

		ret = -errno;
		goto out;
	}

	return 0;

out:
	cleanup_events(lcore_id);

	return ret;
}

static int
scan_pmus(void)
{
	char path[PATH_MAX];
	struct dirent *dent;
	const char *name;
	DIR *dirp;

	dirp = opendir(EVENT_SOURCE_DEVICES_PATH);
	if (!dirp)
		return -errno;

	while ((dent = readdir(dirp))) {
		name = dent->d_name;
		if (name[0] == '.')
			continue;

		/* sysfs entry should either contain cpus or be a cpu */
		if (!strcmp(name, "cpu"))
			break;

		snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/cpus", name);
		if (access(path, F_OK) == 0)
			break;
	}

	closedir(dirp);

	if (dent) {
		pmu->name = strdup(name);
		if (!pmu->name)
			return -ENOMEM;
	}

	return pmu->name ? 0 : -ENODEV;
}

int
rte_pmu_add_event(const char *name)
{
	struct rte_pmu_event *event;
	char path[PATH_MAX];

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/events/%s", pmu->name, name);
	if (access(path, R_OK))
		return -ENODEV;

	TAILQ_FOREACH(event, &pmu->event_list, next) {
		if (!strcmp(event->name, name))
			return event->index;
		continue;
	}

	event = rte_zmalloc(NULL, 1, sizeof(*event));
	if (!event)
		return -ENOMEM;

	event->name = strdup(name);
	if (!event->name) {
		rte_free(event);

		return -ENOMEM;
	}

	event->index = pmu->num_group_events++;
	TAILQ_INSERT_TAIL(&pmu->event_list, event, next);

	RTE_LOG(DEBUG, EAL, "%s even added at index %d\n", name, event->index);

	return event->index;
}

void
eal_pmu_init(void)
{
	int ret;

	pmu = rte_calloc(NULL, 1, sizeof(*pmu), RTE_CACHE_LINE_SIZE);
	if (!pmu) {
		RTE_LOG(ERR, EAL, "failed to alloc PMU\n");

		return;
	}

	TAILQ_INIT(&pmu->event_list);

	ret = scan_pmus();
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to find core pmu\n");
		goto out;
	}

	ret = pmu_arch_init();
	if (ret) {
		RTE_LOG(ERR, EAL, "failed to setup arch for PMU\n");
		goto out;
	}

	return;
out:
	free(pmu->name);
	rte_free(pmu);
}

void
eal_pmu_fini(void)
{
	struct rte_pmu_event *event, *tmp;
	int lcore_id;

	RTE_TAILQ_FOREACH_SAFE(event, &pmu->event_list, next, tmp) {
		TAILQ_REMOVE(&pmu->event_list, event, next);
		free(event->name);
		rte_free(event);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		cleanup_events(lcore_id);

	pmu_arch_fini();
	free(pmu->name);
	rte_free(pmu);
}
