/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef _ICE_RXTX_VEC_COMMON_H_
#define _ICE_RXTX_VEC_COMMON_H_

#include <rte_cycles.h>
#include <rte_mbuf_dyn.h>

#include "../common/rx.h"
#include "ice_rxtx.h"

#ifndef RTE_NET_INTEL_USE_16BYTE_DESC
/*
 * Extend the 32b Rx timestamps stashed in the mbuf dynfield by the vector
 * loop to 64b, set the timestamp flag and mark PTP packets. Only EOP
 * descriptors carry the timestamp; it is stored on the packet's first segment.
 */
static inline void
ice_rx_vec_ts_finalize(struct ci_rx_queue *rxq, struct rte_mbuf **rx_pkts,
		       uint16_t nb_bufs, const uint8_t *split_flags)
{
	struct ice_vsi *vsi = rxq->ice_vsi;
	struct ice_adapter *ad = vsi->adapter;
	struct ice_hw *hw = ICE_VSI_TO_HW(vsi);
	const uint64_t ms_hz = rte_get_timer_hz() / 1000;
	bool is_tsinit = rte_get_timer_cycles() / ms_hz - rxq->hw_time_update > 4;
	/* first segment of a packet that started in a previous burst */
	struct rte_mbuf *head = split_flags != NULL ? rxq->pkt_first_seg : NULL;
	uint16_t k;

	for (k = 0; k < nb_bufs; k++) {
		struct rte_mbuf *mb = rx_pkts[k];
		uint32_t ts_high;
		uint64_t ts_ns;

		if (head == NULL)
			head = mb;
		if (split_flags != NULL && split_flags[k] != 0)
			continue;

		ts_high = *RTE_MBUF_DYNFIELD(mb, rxq->ts_offset, uint32_t *);
		if (unlikely(is_tsinit)) {
			ts_ns = ice_tstamp_convert_32b_64b(hw, ad, 1, ts_high);
			rxq->hw_time_low = (uint32_t)ts_ns;
			rxq->hw_time_high = (uint32_t)(ts_ns >> 32);
			is_tsinit = false;
		} else {
			if (ts_high < rxq->hw_time_low)
				rxq->hw_time_high += 1;
			ts_ns = (uint64_t)rxq->hw_time_high << 32 | ts_high;
			rxq->hw_time_low = ts_high;
		}
		*RTE_MBUF_DYNFIELD(head, rxq->ts_offset, rte_mbuf_timestamp_t *) = ts_ns;
		/* reassembly copies ol_flags from the EOP segment to the head */
		mb->ol_flags |= rxq->ts_flag;

		if (ad->ptp_ena && (mb->packet_type & RTE_PTYPE_L2_MASK) ==
				RTE_PTYPE_L2_ETHER_TIMESYNC) {
			rxq->time_high = ts_high;
			head->timesync = rxq->queue_id;
			mb->timesync = rxq->queue_id;
			mb->ol_flags |= RTE_MBUF_F_RX_IEEE1588_PTP;
		}
		head = NULL;
	}
	rxq->hw_time_update = rte_get_timer_cycles() / ms_hz;
}
#endif

static inline int
ice_tx_desc_done(struct ci_tx_queue *txq, uint16_t idx)
{
	return (txq->ci_tx_ring[idx].cmd_type_offset_bsz &
			rte_cpu_to_le_64(CI_TXD_QW1_DTYPE_M)) ==
				rte_cpu_to_le_64(CI_TX_DESC_DTYPE_DESC_DONE);
}

static inline void
_ice_rx_queue_release_mbufs_vec(struct ci_rx_queue *rxq)
{
	const unsigned int mask = rxq->nb_rx_desc - 1;
	unsigned int i;

	if (unlikely(!rxq->sw_ring)) {
		PMD_DRV_LOG(DEBUG, "sw_ring is NULL");
		return;
	}

	if (rxq->rxrearm_nb >= rxq->nb_rx_desc)
		return;

	/* free all mbufs that are valid in the ring */
	if (rxq->rxrearm_nb == 0) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	} else {
		for (i = rxq->rx_tail;
		     i != rxq->rxrearm_start;
		     i = (i + 1) & mask) {
			if (rxq->sw_ring[i].mbuf)
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
		}
	}

	rxq->rxrearm_nb = rxq->nb_rx_desc;

	/* set all entries to NULL */
	memset(rxq->sw_ring, 0, sizeof(rxq->sw_ring[0]) * rxq->nb_rx_desc);
}

static inline int
ice_rx_vec_queue_default(struct ci_rx_queue *rxq)
{
	if (!rxq)
		return -1;

	if (!ci_rxq_vec_capable(rxq->nb_rx_desc, rxq->rx_free_thresh))
		return -1;

	if (rxq->proto_xtr != PROTO_XTR_NONE)
		return -1;

	return 0;
}

static inline int
ice_tx_vec_queue_default(struct ci_tx_queue *txq)
{
	if (!txq)
		return -1;

	if (!ci_txq_vec_capable(txq->tx_rs_thresh))
		return -1;

	return 0;
}

static inline int
ice_rx_vec_dev_check_default(struct rte_eth_dev *dev)
{
	int i;
	struct ci_rx_queue *rxq;
	int ret = 0;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		ret = (ice_rx_vec_queue_default(rxq));
		if (ret < 0)
			break;
	}

	return ret;
}

static inline int
ice_tx_vec_dev_check_default(struct rte_eth_dev *dev)
{
	int i;
	struct ci_tx_queue *txq;
	int ret = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		ret = ice_tx_vec_queue_default(txq);
		if (ret < 0)
			return -1;
	}

	return ret;
}

#endif
