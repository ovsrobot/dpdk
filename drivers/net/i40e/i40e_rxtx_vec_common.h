/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _I40E_RXTX_VEC_COMMON_H_
#define _I40E_RXTX_VEC_COMMON_H_
#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>

#include <ieth_rxtx_vec_common.h>
#include "i40e_ethdev.h"
#include "i40e_rxtx.h"

#ifndef __INTEL_COMPILER
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif

static inline int
i40e_tx_desc_done(struct ieth_tx_queue *txq, uint16_t idx)
{
	return (txq->i40e_tx_ring[idx].cmd_type_offset_bsz &
			rte_cpu_to_le_64(I40E_TXD_QW1_DTYPE_MASK)) ==
				rte_cpu_to_le_64(I40E_TX_DESC_DTYPE_DESC_DONE);
}

static __rte_always_inline int
i40e_tx_free_bufs(struct ieth_tx_queue *txq)
{
	return ieth_tx_free_bufs(txq, i40e_tx_desc_done);
}

static inline void
_i40e_rx_queue_release_mbufs_vec(struct i40e_rx_queue *rxq)
{
	const unsigned mask = rxq->nb_rx_desc - 1;
	unsigned i;

	if (rxq->sw_ring == NULL || rxq->rxrearm_nb >= rxq->nb_rx_desc)
		return;

	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
		     i != rxq->rxrearm_start;
		     i = (i + 1) & mask) {
			if (rxq->sw_ring[i].mbuf != NULL)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}

	rxq->rxrearm_nb = rxq->nb_rx_desc;

	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->nb_rx_desc);
}

static inline int
i40e_rxq_vec_setup_default(struct i40e_rx_queue *rxq)
{
	uintptr_t p;
	struct rte_mbuf mb_def = { .buf_addr = 0 }; /* zeroed mbuf */

	mb_def.nb_segs = 1;
	mb_def.data_off = RTE_PKTMBUF_HEADROOM;
	mb_def.port = rxq->port_id;
	rte_mbuf_refcnt_set(&mb_def, 1);

	/* prevent compiler reordering: rearm_data covers previous fields */
	rte_compiler_barrier();
	p = (uintptr_t)&mb_def.rearm_data;
	rxq->mbuf_initializer = *(uint64_t *)p;
	rxq->rx_using_sse = 1;
	return 0;
}

static inline int
i40e_rx_vec_dev_conf_condition_check_default(struct rte_eth_dev *dev)
{
#ifndef RTE_LIBRTE_IEEE1588
	struct i40e_adapter *ad =
		I40E_DEV_PRIVATE_TO_ADAPTER(dev->data->dev_private);
	struct rte_eth_rxmode *rxmode = &dev->data->dev_conf.rxmode;
	struct i40e_rx_queue *rxq;
	uint16_t desc, i;
	bool first_queue;

	/* no QinQ support */
	if (rxmode->offloads & RTE_ETH_RX_OFFLOAD_VLAN_EXTEND)
		return -1;

	/**
	 * Vector mode is allowed only when number of Rx queue
	 * descriptor is power of 2.
	 */
	if (!dev->data->dev_started) {
		first_queue = true;
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			if (!rxq)
				continue;
			desc = rxq->nb_rx_desc;
			if (first_queue)
				ad->rx_vec_allowed =
					rte_is_power_of_2(desc);
			else
				ad->rx_vec_allowed =
					ad->rx_vec_allowed ?
					rte_is_power_of_2(desc) :
					ad->rx_vec_allowed;
			first_queue = false;
		}
	} else {
		/* Only check the first queue's descriptor number */
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			if (!rxq)
				continue;
			desc = rxq->nb_rx_desc;
			ad->rx_vec_allowed = rte_is_power_of_2(desc);
			break;
		}
	}

	return 0;
#else
	RTE_SET_USED(dev);
	return -1;
#endif
}

#endif
