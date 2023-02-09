/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#ifndef RTE_EXEC_ENV_WINDOWS
#include <rte_telemetry.h>
#endif

#include "eal_private.h"
#include "eal_thread.h"

unsigned int rte_get_main_lcore(void)
{
	return rte_eal_get_configuration()->main_lcore;
}

unsigned int rte_lcore_count(void)
{
	return rte_eal_get_configuration()->lcore_count;
}

int rte_lcore_index(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0) {
		if (rte_lcore_id() == LCORE_ID_ANY)
			return -1;

		lcore_id = (int)rte_lcore_id();
	}

	return lcore_config[lcore_id].core_index;
}

int rte_lcore_to_cpu_id(int lcore_id)
{
	if (unlikely(lcore_id >= RTE_MAX_LCORE))
		return -1;

	if (lcore_id < 0) {
		if (rte_lcore_id() == LCORE_ID_ANY)
			return -1;

		lcore_id = (int)rte_lcore_id();
	}

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

int
rte_lcore_has_role(unsigned int lcore_id, enum rte_lcore_role_t role)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	return cfg->lcore_role[lcore_id] == role;
}

int rte_lcore_is_enabled(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();

	if (lcore_id >= RTE_MAX_LCORE)
		return 0;
	return cfg->lcore_role[lcore_id] == ROLE_RTE;
}

unsigned int rte_get_next_lcore(unsigned int i, int skip_main, int wrap)
{
	i++;
	if (wrap)
		i %= RTE_MAX_LCORE;

	while (i < RTE_MAX_LCORE) {
		if (!rte_lcore_is_enabled(i) ||
		    (skip_main && (i == rte_get_main_lcore()))) {
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
			"Maximum logical cores by configuration: %u\n",
			RTE_MAX_LCORE);
	RTE_LOG(INFO, EAL, "Detected CPU lcores: %u\n", config->lcore_count);

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
	RTE_LOG(INFO, EAL, "Detected NUMA nodes: %u\n", config->numa_node_count);

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

static rte_rwlock_t lcore_lock = RTE_RWLOCK_INITIALIZER;
struct lcore_callback {
	TAILQ_ENTRY(lcore_callback) next;
	char *name;
	rte_lcore_init_cb init;
	rte_lcore_uninit_cb uninit;
	void *arg;
};
static TAILQ_HEAD(lcore_callbacks_head, lcore_callback) lcore_callbacks =
	TAILQ_HEAD_INITIALIZER(lcore_callbacks);

static int
callback_init(struct lcore_callback *callback, unsigned int lcore_id)
{
	if (callback->init == NULL)
		return 0;
	RTE_LOG(DEBUG, EAL, "Call init for lcore callback %s, lcore_id %u\n",
		callback->name, lcore_id);
	return callback->init(lcore_id, callback->arg);
}

static void
callback_uninit(struct lcore_callback *callback, unsigned int lcore_id)
{
	if (callback->uninit == NULL)
		return;
	RTE_LOG(DEBUG, EAL, "Call uninit for lcore callback %s, lcore_id %u\n",
		callback->name, lcore_id);
	callback->uninit(lcore_id, callback->arg);
}

static void
free_callback(struct lcore_callback *callback)
{
	free(callback->name);
	free(callback);
}

void *
rte_lcore_callback_register(const char *name, rte_lcore_init_cb init,
	rte_lcore_uninit_cb uninit, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;
	unsigned int lcore_id;

	if (name == NULL)
		return NULL;
	callback = calloc(1, sizeof(*callback));
	if (callback == NULL)
		return NULL;
	if (asprintf(&callback->name, "%s-%p", name, arg) == -1) {
		free(callback);
		return NULL;
	}
	callback->init = init;
	callback->uninit = uninit;
	callback->arg = arg;
	rte_rwlock_write_lock(&lcore_lock);
	if (callback->init == NULL)
		goto no_init;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		if (callback_init(callback, lcore_id) == 0)
			continue;
		/* Callback refused init for this lcore, uninitialize all
		 * previous lcore.
		 */
		while (lcore_id-- != 0) {
			if (cfg->lcore_role[lcore_id] == ROLE_OFF)
				continue;
			callback_uninit(callback, lcore_id);
		}
		free_callback(callback);
		callback = NULL;
		goto out;
	}
no_init:
	TAILQ_INSERT_TAIL(&lcore_callbacks, callback, next);
	RTE_LOG(DEBUG, EAL, "Registered new lcore callback %s (%sinit, %suninit).\n",
		callback->name, callback->init == NULL ? "NO " : "",
		callback->uninit == NULL ? "NO " : "");
out:
	rte_rwlock_write_unlock(&lcore_lock);
	return callback;
}

void
rte_lcore_callback_unregister(void *handle)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback = handle;
	unsigned int lcore_id;

	if (callback == NULL)
		return;
	rte_rwlock_write_lock(&lcore_lock);
	if (callback->uninit == NULL)
		goto no_uninit;
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		callback_uninit(callback, lcore_id);
	}
no_uninit:
	TAILQ_REMOVE(&lcore_callbacks, callback, next);
	rte_rwlock_write_unlock(&lcore_lock);
	RTE_LOG(DEBUG, EAL, "Unregistered lcore callback %s-%p.\n",
		callback->name, callback->arg);
	free_callback(callback);
}

unsigned int
eal_lcore_non_eal_allocate(void)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;
	struct lcore_callback *prev;
	unsigned int lcore_id;

	rte_rwlock_write_lock(&lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] != ROLE_OFF)
			continue;
		cfg->lcore_role[lcore_id] = ROLE_NON_EAL;
		cfg->lcore_count++;
		break;
	}
	if (lcore_id == RTE_MAX_LCORE) {
		RTE_LOG(DEBUG, EAL, "No lcore available.\n");
		goto out;
	}
	TAILQ_FOREACH(callback, &lcore_callbacks, next) {
		if (callback_init(callback, lcore_id) == 0)
			continue;
		/* Callback refused init for this lcore, call uninit for all
		 * previous callbacks.
		 */
		prev = TAILQ_PREV(callback, lcore_callbacks_head, next);
		while (prev != NULL) {
			callback_uninit(prev, lcore_id);
			prev = TAILQ_PREV(prev, lcore_callbacks_head, next);
		}
		RTE_LOG(DEBUG, EAL, "Initialization refused for lcore %u.\n",
			lcore_id);
		cfg->lcore_role[lcore_id] = ROLE_OFF;
		cfg->lcore_count--;
		lcore_id = RTE_MAX_LCORE;
		goto out;
	}
out:
	rte_rwlock_write_unlock(&lcore_lock);
	return lcore_id;
}

void
eal_lcore_non_eal_release(unsigned int lcore_id)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_callback *callback;

	rte_rwlock_write_lock(&lcore_lock);
	if (cfg->lcore_role[lcore_id] != ROLE_NON_EAL)
		goto out;
	TAILQ_FOREACH(callback, &lcore_callbacks, next)
		callback_uninit(callback, lcore_id);
	cfg->lcore_role[lcore_id] = ROLE_OFF;
	cfg->lcore_count--;
out:
	rte_rwlock_write_unlock(&lcore_lock);
}

int
rte_lcore_iterate(rte_lcore_iterate_cb cb, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	unsigned int lcore_id;
	int ret = 0;

	rte_rwlock_read_lock(&lcore_lock);
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (cfg->lcore_role[lcore_id] == ROLE_OFF)
			continue;
		ret = cb(lcore_id, arg);
		if (ret != 0)
			break;
	}
	rte_rwlock_read_unlock(&lcore_lock);
	return ret;
}

static const char *
lcore_role_str(enum rte_lcore_role_t role)
{
	switch (role) {
	case ROLE_RTE:
		return "RTE";
	case ROLE_SERVICE:
		return "SERVICE";
	case ROLE_NON_EAL:
		return "NON_EAL";
	default:
		return "UNKNOWN";
	}
}

static rte_lcore_usage_cb lcore_usage_cb;

void
rte_lcore_register_usage_cb(rte_lcore_usage_cb cb)
{
	lcore_usage_cb = cb;
}

static int
lcore_dump_cb(unsigned int lcore_id, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];
	struct rte_lcore_usage usage;
	rte_lcore_usage_cb usage_cb;
	char *usage_str = NULL;
	FILE *f = arg;
	int ret;

	/* The callback may not set all the fields in the structure, so clear it here. */
	memset(&usage, 0, sizeof(usage));
	/* Guard against concurrent modification of lcore_usage_cb. */
	usage_cb = lcore_usage_cb;
	if (usage_cb != NULL && usage_cb(lcore_id, &usage) == 0) {
		if (asprintf(&usage_str, ", busy cycles %"PRIu64"/%"PRIu64,
				usage.busy_cycles, usage.total_cycles) < 0) {
			return -ENOMEM;
		}
	}
	ret = eal_thread_dump_affinity(&lcore_config[lcore_id].cpuset, cpuset,
		sizeof(cpuset));
	fprintf(f, "lcore %u, socket %u, role %s, cpuset %s%s%s\n", lcore_id,
		rte_lcore_to_socket_id(lcore_id),
		lcore_role_str(cfg->lcore_role[lcore_id]),
		cpuset, ret == 0 ? "" : "...",
		usage_str != NULL ? usage_str : "");

	free(usage_str);

	return 0;
}

void
rte_lcore_dump(FILE *f)
{
	rte_lcore_iterate(lcore_dump_cb, f);
}

#ifndef RTE_EXEC_ENV_WINDOWS
static int
lcore_telemetry_id_cb(unsigned int lcore_id, void *arg)
{
	struct rte_tel_data *d = arg;
	return rte_tel_data_add_array_int(d, lcore_id);
}

static int
handle_lcore_list(const char *cmd __rte_unused,
	const char *params __rte_unused,
	struct rte_tel_data *d)
{
	int ret;

	ret = rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
	if (ret == 0)
		ret = rte_lcore_iterate(lcore_telemetry_id_cb, d);

	return ret;
}

struct lcore_telemetry_info {
	unsigned int lcore_id;
	struct rte_tel_data *d;
};

static int
lcore_telemetry_info_cb(unsigned int lcore_id, void *arg)
{
	struct rte_config *cfg = rte_eal_get_configuration();
	struct lcore_telemetry_info *info = arg;
	struct rte_lcore_usage usage;
	struct rte_tel_data *cpuset;
	rte_lcore_usage_cb usage_cb;
	unsigned int cpu;

	if (lcore_id != info->lcore_id)
		return 0;

	rte_tel_data_start_dict(info->d);
	rte_tel_data_add_dict_int(info->d, "lcore_id", lcore_id);
	rte_tel_data_add_dict_int(info->d, "socket", rte_lcore_to_socket_id(lcore_id));
	rte_tel_data_add_dict_string(info->d, "role", lcore_role_str(cfg->lcore_role[lcore_id]));
	cpuset = rte_tel_data_alloc();
	if (cpuset == NULL)
		return -ENOMEM;
	rte_tel_data_start_array(cpuset, RTE_TEL_INT_VAL);
	for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
		if (CPU_ISSET(cpu, &lcore_config[lcore_id].cpuset))
			rte_tel_data_add_array_int(cpuset, cpu);
	}
	rte_tel_data_add_dict_container(info->d, "cpuset", cpuset, 0);
	/* The callback may not set all the fields in the structure, so clear it here. */
	memset(&usage, 0, sizeof(usage));
	/* Guard against concurrent modification of lcore_usage_cb. */
	usage_cb = lcore_usage_cb;
	if (usage_cb != NULL && usage_cb(lcore_id, &usage) == 0) {
		rte_tel_data_add_dict_uint(info->d, "total_cycles", usage.total_cycles);
		rte_tel_data_add_dict_uint(info->d, "busy_cycles", usage.busy_cycles);
	}

	return 0;
}

static int
handle_lcore_info(const char *cmd __rte_unused, const char *params, struct rte_tel_data *d)
{
	struct lcore_telemetry_info info = { .d = d };
	unsigned long lcore_id;
	char *endptr;

	if (params == NULL)
		return -EINVAL;
	errno = 0;
	lcore_id = strtoul(params, &endptr, 10);
	if (errno)
		return -errno;
	if (*params == '\0' || *endptr != '\0' || lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;

	info.lcore_id = lcore_id;

	return rte_lcore_iterate(lcore_telemetry_info_cb, &info);
}

RTE_INIT(lcore_telemetry)
{
	rte_telemetry_register_cmd(
		"/eal/lcore/list", handle_lcore_list,
		"List of lcore ids. Takes no parameters");
	rte_telemetry_register_cmd(
		"/eal/lcore/info", handle_lcore_info,
		"Returns lcore info. Parameters: int lcore_id");
}
#endif /* !RTE_EXEC_ENV_WINDOWS */
