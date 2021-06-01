/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_cpuflags.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_power_intrinsics.h>

#include "rte_power_pmd_mgmt.h"

#define EMPTYPOLL_MAX  512

/* store some internal state */
static struct pmd_conf_data {
	/** what do we support? */
	struct rte_cpu_intrinsics intrinsics_support;
	/** pre-calculated tsc diff for 1us */
	uint64_t tsc_per_us;
	/** how many rte_pause can we fit in a microsecond? */
	uint64_t pause_per_us;
} global_data;

/**
 * Possible power management states of an ethdev port.
 */
enum pmd_mgmt_state {
	/** Device power management is disabled. */
	PMD_MGMT_DISABLED = 0,
	/** Device power management is enabled. */
	PMD_MGMT_ENABLED
};

struct queue {
	uint16_t portid;
	uint16_t qid;
};
struct pmd_core_cfg {
	struct queue queues[RTE_MAX_ETHPORTS];
	/**< Which port-queue pairs are associated with this lcore? */
	struct queue power_save_queue;
	/**< When polling multiple queues, all but this one will be ignored */
	bool power_save_queue_set;
	/**< When polling multiple queues, power save queue must be set */
	size_t n_queues;
	/**< How many queues are in the list? */
	volatile enum pmd_mgmt_state pwr_mgmt_state;
	/**< State of power management for this queue */
	enum rte_power_pmd_mgmt_type cb_mode;
	/**< Callback mode for this queue */
	const struct rte_eth_rxtx_callback *cur_cb;
	/**< Callback instance */
	uint64_t empty_poll_stats;
	/**< Number of empty polls */
} __rte_cache_aligned;
static struct pmd_core_cfg lcore_cfg[RTE_MAX_LCORE];

static inline bool
queue_equal(const struct queue *l, const struct queue *r)
{
	return l->portid == r->portid && l->qid == r->qid;
}

static inline void
queue_copy(struct queue *dst, const struct queue *src)
{
	dst->portid = src->portid;
	dst->qid = src->qid;
}

static inline bool
queue_is_power_save(const struct pmd_core_cfg *cfg, const struct queue *q) {
	const struct queue *pwrsave = &cfg->power_save_queue;

	/* if there's only single queue, no need to check anything */
	if (cfg->n_queues == 1)
		return true;
	return cfg->power_save_queue_set && queue_equal(q, pwrsave);
}

static int
queue_list_find(const struct pmd_core_cfg *cfg, const struct queue *q,
		size_t *idx) {
	size_t i;
	for (i = 0; i < cfg->n_queues; i++) {
		const struct queue *cur = &cfg->queues[i];
		if (queue_equal(cur, q)) {
			if (idx != NULL)
				*idx = i;
			return 0;
		}
	}
	return -1;
}

static int
queue_set_power_save(struct pmd_core_cfg *cfg, const struct queue *q) {
	if (queue_list_find(cfg, q, NULL) < 0)
		return -ENOENT;
	queue_copy(&cfg->power_save_queue, q);
	cfg->power_save_queue_set = true;
	return 0;
}

static int
queue_list_add(struct pmd_core_cfg *cfg, const struct queue *q)
{
	size_t idx = cfg->n_queues;
	if (idx >= RTE_DIM(cfg->queues))
		return -ENOSPC;
	/* is it already in the list? */
	if (queue_list_find(cfg, q, NULL) == 0)
		return -EEXIST;
	queue_copy(&cfg->queues[idx], q);
	cfg->n_queues++;

	return 0;
}

static int
queue_list_remove(struct pmd_core_cfg *cfg, const struct queue *q)
{
	struct queue *found, *pwrsave;
	size_t idx, last_idx = cfg->n_queues - 1;

	if (queue_list_find(cfg, q, &idx) != 0)
		return -ENOENT;

	/* erase the queue pair being deleted */
	found = &cfg->queues[idx];
	memset(found, 0, sizeof(*found));

	/* move the rest of the list */
	for (; idx < last_idx; idx++)
		queue_copy(&cfg->queues[idx], &cfg->queues[idx + 1]);
	cfg->n_queues--;

	/* if this was a power save queue, unset it */
	pwrsave = &cfg->power_save_queue;
	if (cfg->power_save_queue_set && queue_is_power_save(cfg, q)) {
		cfg->power_save_queue_set = false;
		memset(pwrsave, 0, sizeof(*pwrsave));
	}

	return 0;
}

static void
calc_tsc(void)
{
	const uint64_t hz = rte_get_timer_hz();
	const uint64_t tsc_per_us = hz / US_PER_S; /* 1us */

	global_data.tsc_per_us = tsc_per_us;

	/* only do this if we don't have tpause */
	if (!global_data.intrinsics_support.power_pause) {
		const uint64_t start = rte_rdtsc_precise();
		const uint32_t n_pauses = 10000;
		double us, us_per_pause;
		uint64_t end;
		unsigned int i;

		/* estimate number of rte_pause() calls per us*/
		for (i = 0; i < n_pauses; i++)
			rte_pause();

		end = rte_rdtsc_precise();
		us = (end - start) / (double)tsc_per_us;
		us_per_pause = us / n_pauses;

		global_data.pause_per_us = (uint64_t)(1.0 / us_per_pause);
	}
}

static uint16_t
clb_umwait(uint16_t port_id, uint16_t qidx, struct rte_mbuf **pkts __rte_unused,
		uint16_t nb_rx, uint16_t max_pkts __rte_unused,
		void *addr __rte_unused)
{
	const unsigned int lcore = rte_lcore_id();
	struct pmd_core_cfg *q_conf;

	q_conf = &lcore_cfg[lcore];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX)) {
			struct rte_power_monitor_cond pmc;
			uint16_t ret;

			/* use monitoring condition to sleep */
			ret = rte_eth_get_monitor_addr(port_id, qidx,
					&pmc);
			if (ret == 0)
				rte_power_monitor(&pmc, UINT64_MAX);
		}
	} else
		q_conf->empty_poll_stats = 0;

	return nb_rx;
}

static uint16_t
clb_pause(uint16_t port_id, uint16_t qidx, struct rte_mbuf **pkts __rte_unused,
		uint16_t nb_rx, uint16_t max_pkts __rte_unused,
		void *addr __rte_unused)
{
	const unsigned int lcore = rte_lcore_id();
	const struct queue q = {port_id, qidx};
	const bool empty = nb_rx == 0;
	struct pmd_core_cfg *q_conf;

	q_conf = &lcore_cfg[lcore];

	/* early exit */
	if (likely(!empty)) {
		q_conf->empty_poll_stats = 0;
	} else {
		/* do we care about this particular queue? */
		if (!queue_is_power_save(q_conf, &q))
			return nb_rx;

		/*
		 * we can increment unconditionally here because if there were
		 * non-empty polls in other queues assigned to this core, we
		 * dropped the counter to zero anyway.
		 */
		q_conf->empty_poll_stats++;
		/* sleep for 1 microsecond */
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX)) {
			/* use tpause if we have it */
			if (global_data.intrinsics_support.power_pause) {
				const uint64_t cur = rte_rdtsc();
				const uint64_t wait_tsc =
						cur + global_data.tsc_per_us;
				rte_power_pause(wait_tsc);
			} else {
				uint64_t i;
				for (i = 0; i < global_data.pause_per_us; i++)
					rte_pause();
			}
		}
	}

	return nb_rx;
}

static uint16_t
clb_scale_freq(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	const unsigned int lcore = rte_lcore_id();
	const struct queue q = {port_id, qidx};
	const bool empty = nb_rx == 0;
	struct pmd_core_cfg *q_conf;

	q_conf = &lcore_cfg[lcore];

	/* early exit */
	if (likely(!empty)) {
		q_conf->empty_poll_stats = 0;

		/* scale up freq immediately */
		rte_power_freq_max(rte_lcore_id());
	} else {
		/* do we care about this particular queue? */
		if (!queue_is_power_save(q_conf, &q))
			return nb_rx;

		/*
		 * we can increment unconditionally here because if there were
		 * non-empty polls in other queues assigned to this core, we
		 * dropped the counter to zero anyway.
		 */
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX))
			/* scale down freq */
			rte_power_freq_min(rte_lcore_id());
	}

	return nb_rx;
}

static int
check_scale(unsigned int lcore)
{
	enum power_management_env env;

	/* only PSTATE and ACPI modes are supported */
	if (!rte_power_check_env_supported(PM_ENV_ACPI_CPUFREQ) &&
	    !rte_power_check_env_supported(PM_ENV_PSTATE_CPUFREQ)) {
		RTE_LOG(DEBUG, POWER, "Neither ACPI nor PSTATE modes are supported\n");
		return -ENOTSUP;
	}
	/* ensure we could initialize the power library */
	if (rte_power_init(lcore))
		return -EINVAL;

	/* ensure we initialized the correct env */
	env = rte_power_get_env();
	if (env != PM_ENV_ACPI_CPUFREQ && env != PM_ENV_PSTATE_CPUFREQ) {
		RTE_LOG(DEBUG, POWER, "Neither ACPI nor PSTATE modes were initialized\n");
		return -ENOTSUP;
	}

	/* we're done */
	return 0;
}

static int
check_monitor(struct pmd_core_cfg *cfg, const struct queue *qdata)
{
	struct rte_power_monitor_cond dummy;

	/* check if rte_power_monitor is supported */
	if (!global_data.intrinsics_support.power_monitor) {
		RTE_LOG(DEBUG, POWER, "Monitoring intrinsics are not supported\n");
		return -ENOTSUP;
	}

	if (cfg->n_queues > 0) {
		RTE_LOG(DEBUG, POWER, "Monitoring multiple queues is not supported\n");
		return -ENOTSUP;
	}

	/* check if the device supports the necessary PMD API */
	if (rte_eth_get_monitor_addr(qdata->portid, qdata->qid,
			&dummy) == -ENOTSUP) {
		RTE_LOG(DEBUG, POWER, "The device does not support rte_eth_get_monitor_addr\n");
		return -ENOTSUP;
	}

	/* we're done */
	return 0;
}

int
rte_power_ethdev_pmgmt_queue_enable(unsigned int lcore_id, uint16_t port_id,
		uint16_t queue_id, enum rte_power_pmd_mgmt_type mode)
{
	const struct queue qdata = {port_id, queue_id};
	struct pmd_core_cfg *queue_cfg;
	struct rte_eth_dev_info info;
	rte_rx_callback_fn clb;
	int ret;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

	if (queue_id >= RTE_MAX_QUEUES_PER_PORT || lcore_id >= RTE_MAX_LCORE) {
		ret = -EINVAL;
		goto end;
	}

	if (rte_eth_dev_info_get(port_id, &info) < 0) {
		ret = -EINVAL;
		goto end;
	}

	/* check if queue id is valid */
	if (queue_id >= info.nb_rx_queues) {
		ret = -EINVAL;
		goto end;
	}

	queue_cfg = &lcore_cfg[lcore_id];

	/* if callback was already enabled, check current callback type */
	if (queue_cfg->pwr_mgmt_state != PMD_MGMT_DISABLED &&
			queue_cfg->cb_mode != mode) {
		ret = -EINVAL;
		goto end;
	}

	/* we need this in various places */
	rte_cpu_get_intrinsics_support(&global_data.intrinsics_support);

	switch (mode) {
	case RTE_POWER_MGMT_TYPE_MONITOR:
		/* check if we can add a new queue */
		ret = check_monitor(queue_cfg, &qdata);
		if (ret < 0)
			goto end;

		clb = clb_umwait;
		break;
	case RTE_POWER_MGMT_TYPE_SCALE:
		/* check if we can add a new queue */
		ret = check_scale(lcore_id);
		if (ret < 0)
			goto end;
		clb = clb_scale_freq;
		break;
	case RTE_POWER_MGMT_TYPE_PAUSE:
		/* figure out various time-to-tsc conversions */
		if (global_data.tsc_per_us == 0)
			calc_tsc();

		clb = clb_pause;
		break;
	default:
		RTE_LOG(DEBUG, POWER, "Invalid power management type\n");
		ret = -EINVAL;
		goto end;
	}
	/* add this queue to the list */
	ret = queue_list_add(queue_cfg, &qdata);
	if (ret < 0) {
		RTE_LOG(DEBUG, POWER, "Failed to add queue to list: %s\n",
				strerror(-ret));
		goto end;
	}

	/* initialize data before enabling the callback */
	if (queue_cfg->n_queues == 1) {
		queue_cfg->empty_poll_stats = 0;
		queue_cfg->cb_mode = mode;
		queue_cfg->pwr_mgmt_state = PMD_MGMT_ENABLED;
	}
	queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
			clb, NULL);

	ret = 0;
end:
	return ret;
}

int
rte_power_ethdev_pmgmt_queue_disable(unsigned int lcore_id,
		uint16_t port_id, uint16_t queue_id)
{
	const struct queue qdata = {port_id, queue_id};
	struct pmd_core_cfg *queue_cfg;
	int ret;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

	if (lcore_id >= RTE_MAX_LCORE || queue_id >= RTE_MAX_QUEUES_PER_PORT)
		return -EINVAL;

	/* no need to check queue id as wrong queue id would not be enabled */
	queue_cfg = &lcore_cfg[lcore_id];

	if (queue_cfg->pwr_mgmt_state != PMD_MGMT_ENABLED)
		return -EINVAL;

	/*
	 * There is no good/easy way to do this without race conditions, so we
	 * are just going to throw our hands in the air and hope that the user
	 * has read the documentation and has ensured that ports are stopped at
	 * the time we enter the API functions.
	 */
	ret = queue_list_remove(queue_cfg, &qdata);
	if (ret < 0)
		return -ret;

	/* if we've removed all queues from the lists, set state to disabled */
	if (queue_cfg->n_queues == 0)
		queue_cfg->pwr_mgmt_state = PMD_MGMT_DISABLED;

	switch (queue_cfg->cb_mode) {
	case RTE_POWER_MGMT_TYPE_MONITOR: /* fall-through */
	case RTE_POWER_MGMT_TYPE_PAUSE:
		rte_eth_remove_rx_callback(port_id, queue_id,
				queue_cfg->cur_cb);
		break;
	case RTE_POWER_MGMT_TYPE_SCALE:
		rte_power_freq_max(lcore_id);
		rte_eth_remove_rx_callback(port_id, queue_id,
				queue_cfg->cur_cb);
		rte_power_exit(lcore_id);
		break;
	}
	/*
	 * the API doc mandates that the user stops all processing on affected
	 * ports before calling any of these API's, so we can assume that the
	 * callbacks can be freed. we're intentionally casting away const-ness.
	 */
	rte_free((void *)queue_cfg->cur_cb);

	return 0;
}

int
rte_power_ethdev_pmgmt_queue_set_power_save(unsigned int lcore_id,
		uint16_t port_id, uint16_t queue_id)
{
	const struct queue qdata = {port_id, queue_id};
	struct pmd_core_cfg *queue_cfg;
	int ret;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);

	if (lcore_id >= RTE_MAX_LCORE || queue_id >= RTE_MAX_QUEUES_PER_PORT)
		return -EINVAL;

	/* no need to check queue id as wrong queue id would not be enabled */
	queue_cfg = &lcore_cfg[lcore_id];

	if (queue_cfg->pwr_mgmt_state != PMD_MGMT_ENABLED)
		return -EINVAL;

	ret = queue_set_power_save(queue_cfg, &qdata);
	if (ret < 0) {
		RTE_LOG(DEBUG, POWER, "Failed to set power save queue: %s\n",
			strerror(-ret));
		return -ret;
	}

	return 0;
}
