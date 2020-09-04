/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2020 Intel Corporation
 */

#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_ethdev.h>

#include "rte_power.h"



static uint16_t
rte_power_mgmt_umwait(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{

	struct rte_eth_dev *dev = &rte_eth_devices[port_id];

	if (unlikely(nb_rx == 0)) {
		dev->empty_poll_stats[qidx].num++;
		if (unlikely(dev->empty_poll_stats[qidx].num >
			     ETH_EMPTYPOLL_MAX)) {
			volatile void *target_addr;
			uint64_t expected, mask;
			uint16_t ret;

			/*
			 * get address of next descriptor in the RX
			 * ring for this queue, as well as expected
			 * value and a mask.
			 */
			ret = (*dev->dev_ops->next_rx_desc)
				(dev->data->rx_queues[qidx],
				 &target_addr, &expected, &mask);
			if (ret == 0)
				/* -1ULL is maximum value for TSC */
				rte_power_monitor(target_addr,
						  expected, mask,
						  0, -1ULL);
		}
	} else
		dev->empty_poll_stats[qidx].num = 0;

	return nb_rx;
}

static uint16_t
rte_power_mgmt_pause(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];

	int i;

	if (unlikely(nb_rx == 0)) {

		dev->empty_poll_stats[qidx].num++;

		if (unlikely(dev->empty_poll_stats[qidx].num >
			     ETH_EMPTYPOLL_MAX)) {

			for (i = 0; i < RTE_ETH_PAUSE_NUM; i++)
				rte_pause();

		}
	} else
		dev->empty_poll_stats[qidx].num = 0;

	return nb_rx;
}

static uint16_t
rte_power_mgmt_scalefreq(uint16_t port_id, uint16_t qidx,
		struct rte_mbuf **pkts __rte_unused, uint16_t nb_rx,
		uint16_t max_pkts __rte_unused, void *_  __rte_unused)
{
	struct rte_eth_dev *dev = &rte_eth_devices[port_id];

	if (unlikely(nb_rx == 0)) {
		dev->empty_poll_stats[qidx].num++;
		if (unlikely(dev->empty_poll_stats[qidx].num >
			     ETH_EMPTYPOLL_MAX)) {

			/*scale down freq */
			rte_power_freq_min(rte_lcore_id());

		}
	} else {
		dev->empty_poll_stats[qidx].num = 0;
		/* scal up freq */
		rte_power_freq_max(rte_lcore_id());
	}

	return nb_rx;
}

int
rte_power_pmd_mgmt_enable(unsigned int lcore_id,
			uint16_t port_id,
			enum rte_eth_dev_power_mgmt_cb_mode mode)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);
	dev = &rte_eth_devices[port_id];

	if (dev->pwr_mgmt_state == RTE_ETH_DEV_POWER_MGMT_ENABLED)
		return -EINVAL;
	/* allocate memory for empty poll stats */
	dev->empty_poll_stats = rte_malloc_socket(NULL,
						  sizeof(struct rte_eth_ep_stat)
						  * RTE_MAX_QUEUES_PER_PORT,
						  0, dev->data->numa_node);
	if (dev->empty_poll_stats == NULL)
		return -ENOMEM;

	switch (mode) {
	case RTE_ETH_DEV_POWER_MGMT_CB_WAIT:
		if (!rte_cpu_get_flag_enabled(RTE_CPUFLAG_WAITPKG))
			return -ENOTSUP;
		dev->cur_pwr_cb = rte_eth_add_rx_callback(port_id, 0,
						rte_power_mgmt_umwait, NULL);
		break;
	case RTE_ETH_DEV_POWER_MGMT_CB_SCALE:
		/* init scale freq */
		if (rte_power_init(lcore_id))
			return -EINVAL;
		dev->cur_pwr_cb = rte_eth_add_rx_callback(port_id, 0,
					rte_power_mgmt_scalefreq, NULL);
		break;
	case RTE_ETH_DEV_POWER_MGMT_CB_PAUSE:
		dev->cur_pwr_cb = rte_eth_add_rx_callback(port_id, 0,
						rte_power_mgmt_pause, NULL);
		break;
	}

	dev->cb_mode = mode;
	dev->pwr_mgmt_state = RTE_ETH_DEV_POWER_MGMT_ENABLED;
	return 0;
}

int
rte_power_pmd_mgmt_disable(unsigned int lcore_id,
				uint16_t port_id)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -EINVAL);
	dev = &rte_eth_devices[port_id];

	/*add flag check */

	if (dev->pwr_mgmt_state == RTE_ETH_DEV_POWER_MGMT_DISABLED)
		return -EINVAL;

	/* rte_free ignores NULL so safe to call without checks */
	rte_free(dev->empty_poll_stats);

	switch (dev->cb_mode) {
	case RTE_ETH_DEV_POWER_MGMT_CB_WAIT:
	case RTE_ETH_DEV_POWER_MGMT_CB_PAUSE:
		rte_eth_remove_rx_callback(port_id, 0,
					   dev->cur_pwr_cb);
		break;
	case RTE_ETH_DEV_POWER_MGMT_CB_SCALE:
		rte_power_freq_max(lcore_id);
		rte_eth_remove_rx_callback(port_id, 0,
					   dev->cur_pwr_cb);
		if (rte_power_exit(lcore_id))
			return -EINVAL;
		break;
	}

	dev->pwr_mgmt_state = RTE_ETH_DEV_POWER_MGMT_DISABLED;
	dev->cur_pwr_cb = NULL;
	dev->cb_mode = 0;

	return 0;
}
