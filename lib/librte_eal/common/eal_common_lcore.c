/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>

#include "eal_internal_cfg.h"
#include "eal_private.h"
#include "eal_thread.h"

unsigned int rte_get_master_lcore(void)
{
	return rte_eal_get_configuration()->master_lcore;
}

unsigned int rte_lcore_count(void)
{
	return rte_eal_get_configuration()->lcore_count;
}

int rte_lcore_index(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0)
		lcore_id = (int)rte_lcore_id();

	return lcore_config[lcore_id].core_index;
}

int rte_lcore_to_cpu_id(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0)
		lcore_id = (int)rte_lcore_id();

	return lcore_config[lcore_id].core_id;
}

rte_cpuset_t rte_lcore_cpuset(unsigned int lcore_id)
{
	return lcore_config[lcore_id].cpuset;
}

enum rte_lcore_role_t
rte_eal_lcore_role(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return ROLE_OFF;
	return cfg->lcore_role[lcore_id];
}

int rte_lcore_is_enabled(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return 0;
	return cfg->lcore_role[lcore_id] == ROLE_RTE;
}

unsigned int rte_get_next_lcore(unsigned int i, int skip_master, int wrap)
{
	i++;
	if (wrap)
		i %= RTE_MAX_LCORE;

	while (i < RTE_MAX_LCORE) {
		if (!rte_lcore_is_enabled(i) ||
		    (skip_master && (i == rte_get_master_lcore()))) {
			i++;
			if (wrap)
				i %= RTE_MAX_LCORE;
			continue;
		}
		break;
	}
	return i;
}

unsigned int
rte_lcore_to_socket_id(unsigned int lcore_id)
{
	return lcore_config[lcore_id].socket_id;
}

static int
socket_id_cmp(const void *a, const void *b)
{
	const int *lcore_id_a = a;
	const int *lcore_id_b = b;

	if (*lcore_id_a < *lcore_id_b)
		return -1;
	if (*lcore_id_a > *lcore_id_b)
		return 1;
	return 0;
}

/*
 * Parse /sys/devices/system/cpu to get the number of physical and logical
 * processors on the machine. The function will fill the cpu_info
 * structure.
 */
int
rte_eal_cpu_init(void)
{
	/* pointer to global configuration */
	struct rte_config *config = rte_eal_get_configuration();
	unsigned lcore_id;
	unsigned count = 0;
	unsigned int socket_id, prev_socket_id;
	int lcore_to_socket_id[RTE_MAX_LCORE];

	/*
	 * Parse the maximum set of logical cores, detect the subset of running
	 * ones and enable them by default.
	 */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		lcore_config[lcore_id].core_index = count;

		/* init cpuset for per lcore config */
		CPU_ZERO(&lcore_config[lcore_id].cpuset);

		/* find socket first */
		socket_id = eal_cpu_socket_id(lcore_id);
		lcore_to_socket_id[lcore_id] = socket_id;

		if (eal_cpu_detected(lcore_id) == 0) {
			config->lcore_role[lcore_id] = ROLE_OFF;
			lcore_config[lcore_id].core_index = -1;
			continue;
		}

		/* By default, lcore 1:1 map to cpu id */
		CPU_SET(lcore_id, &lcore_config[lcore_id].cpuset);

		/* By default, each detected core is enabled */
		config->lcore_role[lcore_id] = ROLE_RTE;
		lcore_config[lcore_id].core_role = ROLE_RTE;
		lcore_config[lcore_id].core_id = eal_cpu_core_id(lcore_id);
		lcore_config[lcore_id].socket_id = socket_id;
		RTE_LOG(DEBUG, EAL, "Detected lcore %u as "
				"core %u on socket %u\n",
				lcore_id, lcore_config[lcore_id].core_id,
				lcore_config[lcore_id].socket_id);
		count++;
	}
	for (; lcore_id < CPU_SETSIZE; lcore_id++) {
		if (eal_cpu_detected(lcore_id) == 0)
			continue;
		RTE_LOG(DEBUG, EAL, "Skipped lcore %u as core %u on socket %u\n",
			lcore_id, eal_cpu_core_id(lcore_id),
			eal_cpu_socket_id(lcore_id));
	}

	/* Set the count of enabled logical cores of the EAL configuration */
	config->lcore_count = count;
	RTE_LOG(DEBUG, EAL,
		"Support maximum %u logical core(s) by configuration.\n",
		RTE_MAX_LCORE);
	RTE_LOG(INFO, EAL, "Detected %u lcore(s)\n", config->lcore_count);

	/* sort all socket id's in ascending order */
	qsort(lcore_to_socket_id, RTE_DIM(lcore_to_socket_id),
			sizeof(lcore_to_socket_id[0]), socket_id_cmp);

	prev_socket_id = -1;
	config->numa_node_count = 0;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		socket_id = lcore_to_socket_id[lcore_id];
		if (socket_id != prev_socket_id)
			config->numa_nodes[config->numa_node_count++] =
					socket_id;
		prev_socket_id = socket_id;
	}
	RTE_LOG(INFO, EAL, "Detected %u NUMA nodes\n", config->numa_node_count);

	return 0;
}

unsigned int
rte_socket_count(void)
{
	const struct rte_config *config = rte_eal_get_configuration();
	return config->numa_node_count;
}

int
rte_socket_id_by_idx(unsigned int idx)
{
	const struct rte_config *config = rte_eal_get_configuration();
	if (idx >= config->numa_node_count) {
		rte_errno = EINVAL;
		return -1;
	}
	return config->numa_nodes[idx];
}

struct lcore_notifier {
	TAILQ_ENTRY(lcore_notifier) next;
	rte_lcore_notifier_cb cb;
	void *arg;
};
static TAILQ_HEAD(lcore_notifiers_head, lcore_notifier) lcore_notifiers =
	TAILQ_HEAD_INITIALIZER(lcore_notifiers);
static rte_spinlock_t lcore_notifiers_lock = RTE_SPINLOCK_INITIALIZER;

void *
rte_lcore_notifier_register(rte_lcore_notifier_cb cb, void *arg)
{
	struct lcore_notifier *notifier;

	if (cb == NULL)
		return NULL;

	notifier = calloc(1, sizeof(*notifier));
	if (notifier == NULL)
		return NULL;

	notifier->cb = cb;
	notifier->arg = arg;
	rte_spinlock_lock(&lcore_notifiers_lock);
	TAILQ_INSERT_TAIL(&lcore_notifiers, notifier, next);
	rte_spinlock_unlock(&lcore_notifiers_lock);

	return notifier;
}

void
rte_lcore_notifier_unregister(void *handle)
{
	struct lcore_notifier *notifier = handle;

	rte_spinlock_lock(&lcore_notifiers_lock);
	TAILQ_REMOVE(&lcore_notifiers, notifier, next);
	rte_spinlock_unlock(&lcore_notifiers_lock);
	free(notifier);
}

rte_spinlock_t external_lcore_lock = RTE_SPINLOCK_INITIALIZER;

unsigned int
eal_lcore_external_reserve(void)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	unsigned int lcore_id;

	rte_spinlock_lock(&external_lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_eal_lcore_role(lcore_id) != ROLE_OFF)
			continue;
		cfg->lcore_role[lcore_id] = ROLE_EXTERNAL;
		cfg->lcore_count++;
		break;
	}
	rte_spinlock_unlock(&external_lcore_lock);

	return lcore_id;
}

void
eal_lcore_external_release(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	rte_spinlock_lock(&external_lcore_lock);
	if (rte_eal_lcore_role(lcore_id) == ROLE_EXTERNAL) {
		cfg->lcore_role[lcore_id] = ROLE_OFF;
		cfg->lcore_count--;
	}
	rte_spinlock_unlock(&external_lcore_lock);
}

void
rte_lcore_dump(FILE *f)
{
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];
	unsigned int lcore_id;
	const char *role;
	int ret;

	rte_spinlock_lock(&external_lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		switch (rte_eal_lcore_role(lcore_id)) {
		case ROLE_RTE:
			role = "RTE";
			break;
		case ROLE_SERVICE:
			role = "SERVICE";
			break;
		case ROLE_EXTERNAL:
			role = "EXTERNAL";
			break;
		default:
			continue;
		}

		ret = eal_thread_dump_affinity(&lcore_config[lcore_id].cpuset,
			cpuset, sizeof(cpuset));
		fprintf(f, "lcore %u, role %s, cpuset %s%s\n", lcore_id, role,
			cpuset, ret == 0 ? "" : "...");
	}
	rte_spinlock_unlock(&external_lcore_lock);
}

int
eal_lcore_external_notify_allocated(unsigned int lcore_id)
{
	struct lcore_notifier *notifier;
	int ret = 0;

	RTE_LOG(DEBUG, EAL, "New lcore %u.\n", lcore_id);
	rte_spinlock_lock(&lcore_notifiers_lock);
	TAILQ_FOREACH(notifier, &lcore_notifiers, next) {
		if (notifier->cb(lcore_id, RTE_LCORE_EVENT_NEW_EXTERNAL,
				notifier->arg) == 0)
			continue;

		/* Some notifier refused the new lcore, inform all notifiers
		 * that acked it.
		 */
		RTE_LOG(DEBUG, EAL, "A lcore notifier refused new lcore %u.\n",
			lcore_id);

		notifier = TAILQ_PREV(notifier, lcore_notifiers_head, next);
		while (notifier != NULL) {
			notifier->cb(lcore_id,
				RTE_LCORE_EVENT_RELEASE_EXTERNAL,
				notifier->arg);
			notifier = TAILQ_PREV(notifier, lcore_notifiers_head,
				next);
		}
		ret = -1;
		break;
	}
	rte_spinlock_unlock(&lcore_notifiers_lock);

	return ret;
}

void
eal_lcore_external_notify_removed(unsigned int lcore_id)
{
	struct lcore_notifier *notifier;

	RTE_LOG(DEBUG, EAL, "Released lcore %u.\n", lcore_id);
	rte_spinlock_lock(&lcore_notifiers_lock);
	TAILQ_FOREACH_REVERSE(notifier, &lcore_notifiers, lcore_notifiers_head,
			next) {
		notifier->cb(lcore_id, RTE_LCORE_EVENT_RELEASE_EXTERNAL,
			notifier->arg);
	}
	rte_spinlock_unlock(&lcore_notifiers_lock);
}
