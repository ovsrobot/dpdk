/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <regex.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/queue.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <rte_atomic.h>
#include <rte_per_lcore.h>
#include <rte_pmu.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include "pmu_private.h"

#define EVENT_SOURCE_DEVICES_PATH "/sys/bus/event_source/devices"

#ifndef GENMASK_ULL
#define GENMASK_ULL(h, l) ((~0ULL - (1ULL << (l)) + 1) & (~0ULL >> ((64 - 1 - (h)))))
#endif

#ifndef FIELD_PREP
#define FIELD_PREP(m, v) (((uint64_t)(v) << (__builtin_ffsll(m) - 1)) & (m))
#endif

RTE_DEFINE_PER_LCORE(struct rte_pmu_event_group, _event_group);
struct rte_pmu rte_pmu;

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
__rte_weak pmu_arch_fixup_config(uint64_t __rte_unused config[3])
{
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

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/format/%s", rte_pmu.name, name);
	fp = fopen(path, "r");
	if (fp == NULL)
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

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/events/%s", rte_pmu.name, name);
	fp = fopen(path, "r");
	if (fp == NULL)
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
do_perf_event_open(uint64_t config[3], int group_fd)
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

	return syscall(SYS_perf_event_open, &attr, 0, -1, group_fd, 0);
}

static int
open_events(struct rte_pmu_event_group *group)
{
	struct rte_pmu_event *event;
	uint64_t config[3];
	int num = 0, ret;

	/* group leader gets created first, with fd = -1 */
	group->fds[0] = -1;

	TAILQ_FOREACH(event, &rte_pmu.event_list, next) {
		ret = get_event_config(event->name, config);
		if (ret)
			continue;

		ret = do_perf_event_open(config, group->fds[0]);
		if (ret == -1) {
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
mmap_events(struct rte_pmu_event_group *group)
{
	long page_size = sysconf(_SC_PAGE_SIZE);
	unsigned int i;
	void *addr;
	int ret;

	for (i = 0; i < rte_pmu.num_group_events; i++) {
		addr = mmap(0, page_size, PROT_READ, MAP_SHARED, group->fds[i], 0);
		if (addr == MAP_FAILED) {
			ret = -errno;
			goto out;
		}

		group->mmap_pages[i] = addr;
	}

	return 0;
out:
	for (; i; i--) {
		munmap(group->mmap_pages[i - 1], page_size);
		group->mmap_pages[i - 1] = NULL;
	}

	return ret;
}

static void
cleanup_events(struct rte_pmu_event_group *group)
{
	unsigned int i;

	if (group->fds[0] != -1)
		ioctl(group->fds[0], PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

	for (i = 0; i < rte_pmu.num_group_events; i++) {
		if (group->mmap_pages[i]) {
			munmap(group->mmap_pages[i], sysconf(_SC_PAGE_SIZE));
			group->mmap_pages[i] = NULL;
		}

		if (group->fds[i] != -1) {
			close(group->fds[i]);
			group->fds[i] = -1;
		}
	}

	group->enabled = false;
}

int __rte_noinline
rte_pmu_enable_group(void)
{
	struct rte_pmu_event_group *group = &RTE_PER_LCORE(_event_group);
	int ret;

	if (rte_pmu.num_group_events == 0)
		return -ENODEV;

	ret = open_events(group);
	if (ret)
		goto out;

	ret = mmap_events(group);
	if (ret)
		goto out;

	if (ioctl(group->fds[0], PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) == -1) {
		ret = -errno;
		goto out;
	}

	if (ioctl(group->fds[0], PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) == -1) {
		ret = -errno;
		goto out;
	}

	rte_spinlock_lock(&rte_pmu.lock);
	TAILQ_INSERT_TAIL(&rte_pmu.event_group_list, group, next);
	rte_spinlock_unlock(&rte_pmu.lock);
	group->enabled = true;

	return 0;

out:
	cleanup_events(group);

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
	if (dirp == NULL)
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

	if (dent) {
		rte_pmu.name = strdup(name);
		if (rte_pmu.name == NULL) {
			closedir(dirp);

			return -ENOMEM;
		}
	}

	closedir(dirp);

	return rte_pmu.name ? 0 : -ENODEV;
}

static struct rte_pmu_event *
new_event(const char *name)
{
	struct rte_pmu_event *event;

	event = calloc(1, sizeof(*event));
	if (event == NULL)
		goto out;

	event->name = strdup(name);
	if (event->name == NULL) {
		free(event);
		event = NULL;
	}

out:
	return event;
}

static void
free_event(struct rte_pmu_event *event)
{
	free(event->name);
	free(event);
}

int
rte_pmu_add_event(const char *name)
{
	struct rte_pmu_event *event;
	char path[PATH_MAX];

	if (rte_pmu.name == NULL)
		return -ENODEV;

	if (rte_pmu.num_group_events + 1 >= MAX_NUM_GROUP_EVENTS)
		return -ENOSPC;

	snprintf(path, sizeof(path), EVENT_SOURCE_DEVICES_PATH "/%s/events/%s", rte_pmu.name, name);
	if (access(path, R_OK))
		return -ENODEV;

	TAILQ_FOREACH(event, &rte_pmu.event_list, next) {
		if (!strcmp(event->name, name))
			return event->index;
		continue;
	}

	event = new_event(name);
	if (event == NULL)
		return -ENOMEM;

	event->index = rte_pmu.num_group_events++;
	TAILQ_INSERT_TAIL(&rte_pmu.event_list, event, next);

	return event->index;
}

static int
add_events(const char *pattern)
{
	char *token, *copy;
	int ret = 0;

	copy = strdup(pattern);
	if (copy == NULL)
		return -ENOMEM;

	token = strtok(copy, ",");
	while (token) {
		ret = rte_pmu_add_event(token);
		if (ret < 0)
			break;

		token = strtok(NULL, ",");
	}

	free(copy);

	return ret >= 0 ? 0 : ret;
}

int
rte_pmu_add_events_by_pattern(const char *pattern)
{
	regmatch_t rmatch;
	char buf[BUFSIZ];
	unsigned int num;
	regex_t reg;
	int ret;

	/* events are matched against occurrences of e=ev1[,ev2,..] pattern */
	ret = regcomp(&reg, "e=([_[:alnum:]-],?)+", REG_EXTENDED);
	if (ret)
		return -EINVAL;

	for (;;) {
		if (regexec(&reg, pattern, 1, &rmatch, 0))
			break;

		num = rmatch.rm_eo - rmatch.rm_so;
		if (num > sizeof(buf))
			num = sizeof(buf);

		/* skip e= pattern prefix */
		memcpy(buf, pattern + rmatch.rm_so + 2, num - 2);
		buf[num - 2] = '\0';
		ret = add_events(buf);
		if (ret)
			break;

		pattern += rmatch.rm_eo;
	}

	regfree(&reg);

	return ret;
}

int
rte_pmu_init(void)
{
	int ret;

	/* Allow calling init from multiple contexts within a single thread. This simplifies
	 * resource management a bit e.g in case fast-path tracepoint has already been enabled
	 * via command line but application doesn't care enough and performs init/fini again.
	 */
	if (rte_pmu.initialized) {
		rte_pmu.initialized++;
		return 0;
	}

	ret = scan_pmus();
	if (ret)
		goto out;

	ret = pmu_arch_init();
	if (ret)
		goto out;

	TAILQ_INIT(&rte_pmu.event_list);
	TAILQ_INIT(&rte_pmu.event_group_list);
	rte_spinlock_init(&rte_pmu.lock);
	rte_pmu.initialized = 1;

	return 0;
out:
	free(rte_pmu.name);
	rte_pmu.name = NULL;

	return ret;
}

void
rte_pmu_fini(void)
{
	struct rte_pmu_event_group *group, *tmp_group;
	struct rte_pmu_event *event, *tmp_event;

	/* cleanup once init count drops to zero */
	if (!rte_pmu.initialized || --rte_pmu.initialized)
		return;

	RTE_TAILQ_FOREACH_SAFE(event, &rte_pmu.event_list, next, tmp_event) {
		TAILQ_REMOVE(&rte_pmu.event_list, event, next);
		free_event(event);
	}

	RTE_TAILQ_FOREACH_SAFE(group, &rte_pmu.event_group_list, next, tmp_group) {
		TAILQ_REMOVE(&rte_pmu.event_group_list, group, next);
		cleanup_events(group);
	}

	pmu_arch_fini();
	free(rte_pmu.name);
	rte_pmu.name = NULL;
	rte_pmu.num_group_events = 0;
}
