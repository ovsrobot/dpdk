/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_cpuflags.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_power_intrinsics.h>

#include "rte_power_pmd_mgmt.h"

#define EMPTYPOLL_MAX  512

/**
 * Possible power management states of an ethdev port.
 */
enum pmd_mgmt_state {
	/** Device power management is disabled. */
	PMD_MGMT_DISABLED = 0,
	/** Device power management is enabled. */
	PMD_MGMT_ENABLED,
};

struct pmd_queue_cfg {
	enum pmd_mgmt_state pwr_mgmt_state;
	/**< State of power management for this queue */
	enum rte_power_pmd_mgmt_type cb_mode;
	/**< Callback mode for this queue */
	const struct rte_eth_rxtx_callback *cur_cb;
	/**< Callback instance */
	rte_spinlock_t umwait_lock;
	/**< Per-queue status lock - used only for UMWAIT mode */
	volatile void *wait_addr;
	/**< UMWAIT wakeup address */
	uint64_t empty_poll_stats;
	/**< Number of empty polls */
} __rte_cache_aligned;

static struct pmd_queue_cfg port_cfg[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];

/* trigger a write to the cache line we're waiting on */
static inline void
umwait_wakeup(volatile void *addr)
{
	uint64_t val;

	val = __atomic_load_n((volatile uint64_t *)addr, __ATOMIC_RELAXED);
	__atomic_compare_exchange_n((volatile uint64_t *)addr, &val, val, 0,
			__ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

static inline void
umwait_sleep(struct pmd_queue_cfg *q_conf, uint16_t port_id, uint16_t qidx)
{
	volatile void *target_addr;
	uint64_t expected, mask;
	uint8_t data_sz;
	uint16_t ret;

	/*
	 * get wake up address fot this RX queue, as well as expected value,
	 * comparison mask, and data size.
	 */
	ret = rte_eth_get_wake_addr(port_id, qidx, &target_addr,
			&expected, &mask, &data_sz);

	/* this should always succeed as all checks have been done already */
	if (unlikely(ret != 0))
		return;

	/*
	 * take out a spinlock to prevent control plane from concurrently
	 * modifying the wakeup data.
	 */
	rte_spinlock_lock(&q_conf->umwait_lock);

	/* have we been disabled by control plane? */
	if (q_conf->pwr_mgmt_state == PMD_MGMT_ENABLED) {
		/* we're good to go */

		/*
		 * store the wakeup address so that control plane can trigger a
		 * write to this address and wake us up.
		 */
		q_conf->wait_addr = target_addr;
		/* -1ULL is maximum value for TSC */
		rte_power_monitor_sync(target_addr, expected, mask, -1ULL,
				data_sz, &q_conf->umwait_lock);
		/* erase the address */
		q_conf->wait_addr = NULL;
	}
	rte_spinlock_unlock(&q_conf->umwait_lock);
}

static uint16_t
clb_umwait(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *addr __rte_unused)
{

	struct pmd_queue_cfg *q_conf;

	q_conf = &port_cfg[port_id][qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX))
			umwait_sleep(q_conf, port_id, qidx);
	} else
		q_conf->empty_poll_stats = 0;

	return nb_rx;
}

static uint16_t
clb_pause(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *addr __rte_unused)
{
	struct pmd_queue_cfg *q_conf;

	q_conf = &port_cfg[port_id][qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		/* sleep for 1 microsecond */
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX))
			rte_delay_us(1);
	} else
		q_conf->empty_poll_stats = 0;

	return nb_rx;
}

static uint16_t
clb_scale_freq(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	struct pmd_queue_cfg *q_conf;

	q_conf = &port_cfg[port_id][qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX))
			/* scale down freq */
			rte_power_freq_min(rte_lcore_id());
	} else {
		q_conf->empty_poll_stats = 0;
		/* scale up freq */
		rte_power_freq_max(rte_lcore_id());
	}

	return nb_rx;
}

int
rte_power_pmd_mgmt_queue_enable(unsigned int lcore_id,
		uint16_t port_id, uint16_t queue_id,
		enum rte_power_pmd_mgmt_type mode)
{
	struct rte_eth_dev *dev;
	struct pmd_queue_cfg *queue_cfg;
	int ret;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);
	dev = &rte_eth_devices[port_id];

	/* check if queue id is valid */
	if (queue_id >= dev->data->nb_rx_queues ||
			queue_id >= RTE_MAX_QUEUES_PER_PORT) {
		return -EINVAL;
	}

	queue_cfg = &port_cfg[port_id][queue_id];

	if (queue_cfg->pwr_mgmt_state == PMD_MGMT_ENABLED) {
		ret = -EINVAL;
		goto end;
	}

	switch (mode) {
	case RTE_POWER_MGMT_TYPE_WAIT:
	{
		/* check if rte_power_monitor is supported */
		uint64_t dummy_expected, dummy_mask;
		struct rte_cpu_intrinsics i;
		volatile void *dummy_addr;
		uint8_t dummy_sz;

		rte_cpu_get_intrinsics_support(&i);

		if (!i.power_monitor) {
			RTE_LOG(DEBUG, POWER, "Monitoring intrinsics are not supported\n");
			ret = -ENOTSUP;
			goto end;
		}

		/* check if the device supports the necessary PMD API */
		if (rte_eth_get_wake_addr(port_id, queue_id,
				&dummy_addr, &dummy_expected,
				&dummy_mask, &dummy_sz) == -ENOTSUP) {
			RTE_LOG(DEBUG, POWER, "The device does not support rte_eth_rxq_ring_addr_get\n");
			ret = -ENOTSUP;
			goto end;
		}
		/* initialize UMWAIT spinlock */
		rte_spinlock_init(&queue_cfg->umwait_lock);

		/* initialize data before enabling the callback */
		queue_cfg->empty_poll_stats = 0;
		queue_cfg->cb_mode = mode;
		queue_cfg->pwr_mgmt_state = PMD_MGMT_ENABLED;

		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
				clb_umwait, NULL);
		break;
	}
	case RTE_POWER_MGMT_TYPE_SCALE:
	{
		enum power_management_env env;
		/* only PSTATE and ACPI modes are supported */
		if (!rte_power_check_env_supported(PM_ENV_ACPI_CPUFREQ) &&
				!rte_power_check_env_supported(
					PM_ENV_PSTATE_CPUFREQ)) {
			RTE_LOG(DEBUG, POWER, "Neither ACPI nor PSTATE modes are supported\n");
			ret = -ENOTSUP;
			goto end;
		}
		/* ensure we could initialize the power library */
		if (rte_power_init(lcore_id)) {
			ret = -EINVAL;
			goto end;
		}
		/* ensure we initialized the correct env */
		env = rte_power_get_env();
		if (env != PM_ENV_ACPI_CPUFREQ &&
				env != PM_ENV_PSTATE_CPUFREQ) {
			RTE_LOG(DEBUG, POWER, "Neither ACPI nor PSTATE modes were initialized\n");
			ret = -ENOTSUP;
			goto end;
		}
		/* initialize data before enabling the callback */
		queue_cfg->empty_poll_stats = 0;
		queue_cfg->cb_mode = mode;
		queue_cfg->pwr_mgmt_state = PMD_MGMT_ENABLED;

		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id,
				queue_id, clb_scale_freq, NULL);
		break;
	}
	case RTE_POWER_MGMT_TYPE_PAUSE:
		/* initialize data before enabling the callback */
		queue_cfg->empty_poll_stats = 0;
		queue_cfg->cb_mode = mode;
		queue_cfg->pwr_mgmt_state = PMD_MGMT_ENABLED;

		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
				clb_pause, NULL);
		break;
	}
	ret = 0;

end:
	return ret;
}

int
rte_power_pmd_mgmt_queue_disable(unsigned int lcore_id,
		uint16_t port_id, uint16_t queue_id)
{
	struct pmd_queue_cfg *queue_cfg;
	int ret;

	queue_cfg = &port_cfg[port_id][queue_id];

	if (queue_cfg->pwr_mgmt_state == PMD_MGMT_DISABLED) {
		ret = -EINVAL;
		goto end;
	}

	switch (queue_cfg->cb_mode) {
	case RTE_POWER_MGMT_TYPE_WAIT:
		rte_spinlock_lock(&queue_cfg->umwait_lock);

		/* wake up the core from UMWAIT sleep, if any */
		if (queue_cfg->wait_addr != NULL)
			umwait_wakeup(queue_cfg->wait_addr);
		/*
		 * we need to disable early as there might be callback currently
		 * spinning on a lock.
		 */
		queue_cfg->pwr_mgmt_state = PMD_MGMT_DISABLED;

		rte_spinlock_unlock(&queue_cfg->umwait_lock);
		/* fall-through */
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
	 * we don't free the RX callback here because it is unsafe to do so
	 * unless we know for a fact that all data plane threads have stopped.
	 */
	queue_cfg->cur_cb = NULL;
	queue_cfg->pwr_mgmt_state = PMD_MGMT_DISABLED;
	ret = 0;
end:
	return ret;
}
