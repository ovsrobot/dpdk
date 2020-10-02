/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>
#include <rte_power_intrinsics.h>

#include "rte_power_pmd_mgmt.h"
#include "pmd_mgmt.h"


#define EMPTYPOLL_MAX  512
#define PAUSE_NUM  64

static struct pmd_port_cfg port_cfg[RTE_MAX_ETHPORTS];

static uint16_t
rte_power_mgmt_umwait(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{

	struct pmd_queue_cfg *q_conf;
	q_conf = &port_cfg[port_id].queue_cfg[qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX)) {
			volatile void *target_addr;
			uint64_t expected, mask;
			uint16_t ret;

			/*
			 * get address of next descriptor in the RX
			 * ring for this queue, as well as expected
			 * value and a mask.
			 */
			ret = rte_eth_get_wake_addr(port_id, qidx,
						    &target_addr, &expected,
						    &mask);
			if (ret == 0)
				/* -1ULL is maximum value for TSC */
				rte_power_monitor(target_addr,
						  expected, mask,
						  0, -1ULL);
		}
	} else
		q_conf->empty_poll_stats = 0;

	return nb_rx;
}

static uint16_t
rte_power_mgmt_pause(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	struct pmd_queue_cfg *q_conf;
	int i;
	q_conf = &port_cfg[port_id].queue_cfg[qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX)) {
			for (i = 0; i < PAUSE_NUM; i++)
				rte_pause();
		}
	} else
		q_conf->empty_poll_stats = 0;

	return nb_rx;
}

static uint16_t
rte_power_mgmt_scalefreq(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	struct pmd_queue_cfg *q_conf;
	q_conf = &port_cfg[port_id].queue_cfg[qidx];

	if (unlikely(nb_rx == 0)) {
		q_conf->empty_poll_stats++;
		if (unlikely(q_conf->empty_poll_stats > EMPTYPOLL_MAX)) {
			/*scale down freq */
			rte_power_freq_min(rte_lcore_id());

		}
	} else {
		q_conf->empty_poll_stats = 0;
		/* scal up freq */
		rte_power_freq_max(rte_lcore_id());
	}

	return nb_rx;
}

int
rte_power_pmd_mgmt_queue_enable(unsigned int lcore_id,
				uint16_t port_id,
				uint16_t queue_id,
				enum rte_power_pmd_mgmt_type mode)
{
	struct rte_eth_dev *dev;
	struct pmd_queue_cfg *queue_cfg;
	int ret = 0;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);
	dev = &rte_eth_devices[port_id];

	if (port_cfg[port_id].queue_cfg == NULL) {
		port_cfg[port_id].ref_cnt = 0;
		/* allocate memory for empty poll stats */
		port_cfg[port_id].queue_cfg  = rte_malloc_socket(NULL,
					sizeof(struct pmd_queue_cfg)
					* RTE_MAX_QUEUES_PER_PORT,
					0, dev->data->numa_node);
		if (port_cfg[port_id].queue_cfg == NULL)
			return -ENOMEM;
	}

	queue_cfg = &port_cfg[port_id].queue_cfg[queue_id];

	if (queue_cfg->pwr_mgmt_state == PMD_MGMT_ENABLED) {
		ret = -EINVAL;
		goto failure_handler;
	}

	switch (mode) {
	case RTE_POWER_MGMT_TYPE_WAIT:
		if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_WAITPKG)) {
			ret = -ENOTSUP;
			goto failure_handler;
		}
		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
						rte_power_mgmt_umwait, NULL);
		break;
	case RTE_POWER_MGMT_TYPE_SCALE:
		/* init scale freq */
		if (rte_power_init(lcore_id)) {
			ret = -EINVAL;
			goto failure_handler;
		}
		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
					rte_power_mgmt_scalefreq, NULL);
		break;
	case RTE_POWER_MGMT_TYPE_PAUSE:
		queue_cfg->cur_cb = rte_eth_add_rx_callback(port_id, queue_id,
						rte_power_mgmt_pause, NULL);
		break;
	}
	queue_cfg->cb_mode = mode;
	port_cfg[port_id].ref_cnt++;
	queue_cfg->pwr_mgmt_state = PMD_MGMT_ENABLED;
	return ret;

failure_handler:
	if (port_cfg[port_id].ref_cnt == 0) {
		rte_free(port_cfg[port_id].queue_cfg);
		port_cfg[port_id].queue_cfg = NULL;
	}
	return ret;
}

int
rte_power_pmd_mgmt_queue_disable(unsigned int lcore_id,
				uint16_t port_id,
				uint16_t queue_id)
{
	struct pmd_queue_cfg *queue_cfg;

	if (port_cfg[port_id].ref_cnt <= 0)
		return -EINVAL;

	queue_cfg = &port_cfg[port_id].queue_cfg[queue_id];

	if (queue_cfg->pwr_mgmt_state == PMD_MGMT_DISABLED)
		return -EINVAL;

	switch (queue_cfg->cb_mode) {
	case RTE_POWER_MGMT_TYPE_WAIT:
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
	/* it's not recommend to free callback instance here.
	 * it cause memory leak which is a known issue.
	 */
	queue_cfg->cur_cb = NULL;
	queue_cfg->pwr_mgmt_state = PMD_MGMT_DISABLED;
	port_cfg[port_id].ref_cnt--;

	if (port_cfg[port_id].ref_cnt == 0) {
		rte_free(port_cfg[port_id].queue_cfg);
		port_cfg[port_id].queue_cfg = NULL;
	}
	return 0;
}
