/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _I40E_RXTX_VEC_COMMON_H_
#define _I40E_RXTX_VEC_COMMON_H_
#include <stdint.h>
#include <ethdev_driver.h>
#include <rte_malloc.h>

#include "../common/rx.h"
#include "i40e_ethdev.h"
#include "i40e_rxtx.h"

static inline int
i40e_tx_desc_done(struct ci_tx_queue *txq, uint16_t idx)
{
	return (txq->ci_tx_ring[idx].cmd_type_offset_bsz &
			rte_cpu_to_le_64(CI_TXD_QW1_DTYPE_M)) ==
				rte_cpu_to_le_64(CI_TX_DESC_DTYPE_DESC_DONE);
}

static inline void
_i40e_rx_queue_release_mbufs_vec(struct ci_rx_queue *rxq)
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

#ifdef RTE_LIBRTE_IEEE1588
/* The hardware latches Rx timestamps into one of four registers and only
 * reports the register index in the descriptor, so there is nothing to
 * extract in SIMD and this is done one descriptor at a time.
 */
static inline void
i40e_rx_vec_desc_to_timesync(volatile union ci_rx_desc *rxdp,
		struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	for (uint16_t i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *mb = rx_pkts[i];
		const uint64_t qword1 =
			rte_le_to_cpu_64(rxdp[i].wb.qword1.status_error_len);

		mb->ol_flags |= i40e_get_iee15888_flags(mb, qword1);
	}
}
#endif

static inline int
i40e_rx_vec_dev_conf_condition_check_default(struct rte_eth_dev *dev)
{
	/**
	 * Vector mode is allowed only when number of Rx queue
	 * descriptor is power of 2.
	 */
	for (uint16_t i = 0; i < dev->data->nb_rx_queues; i++) {
		struct ci_rx_queue *rxq = dev->data->rx_queues[i];
		if (!rxq)
			continue;
		if (!ci_rxq_vec_capable(rxq->nb_rx_desc, rxq->rx_free_thresh))
			return -1;
	}

	return 0;
}

#endif
