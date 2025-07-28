/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_ethdev.h>

#include "sxe_logs.h"
#include "sxevf.h"
#include "sxevf_tx.h"
#include "sxevf_queue.h"
#include "sxe_tx_common.h"

void sxevf_tx_configure(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	sxevf_tx_queue_s *txq;
	u16 i;
	u32 len;

	for (i = 0; i < eth_dev->data->nb_tx_queues; i++) {
		txq = eth_dev->data->tx_queues[i];
		len = txq->ring_depth * sizeof(sxevf_tx_data_desc_u);
		sxevf_tx_desc_configure(hw, len, txq->base_addr, txq->reg_idx);

		sxevf_tx_queue_thresh_set(hw, txq->reg_idx,
			txq->pthresh, txq->hthresh, txq->wthresh);
	}

	LOG_DEBUG_BDF("tx queue num:%u tx configure done.",
			eth_dev->data->nb_tx_queues);
}

s32 sxevf_tx_descriptor_status(void *tx_queue, u16 offset)
{
	return __sxe_tx_descriptor_status(tx_queue, offset);
}

u16 sxevf_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num)
{
	return __sxe_pkts_xmit_with_offload(tx_queue, tx_pkts, pkts_num);
}

#endif
