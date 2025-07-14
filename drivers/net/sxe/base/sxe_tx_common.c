/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_net.h>

#include "sxe_hw.h"
#include "sxe_logs.h"
#include "sxe_queue_common.h"
#include "sxe_tx_common.h"

int __sxe_tx_descriptor_status(void *tx_queue, u16 offset)
{
	int ret = RTE_ETH_TX_DESC_FULL;
	u32 desc_idx;
	struct sxe_tx_queue *txq = tx_queue;
	volatile u32 *status;

	if (unlikely(offset >= txq->ring_depth)) {
		ret = -EINVAL;
		goto l_end;
	}

	desc_idx = txq->next_to_use + offset;

	desc_idx = ((desc_idx + txq->rs_thresh - 1) / txq->rs_thresh) * txq->rs_thresh;
	if (desc_idx >= txq->ring_depth) {
		desc_idx -= txq->ring_depth;
		if (desc_idx >= txq->ring_depth)
			desc_idx -= txq->ring_depth;
	}

	status = &txq->desc_ring[desc_idx].wb.status;
	if (*status & rte_cpu_to_le_32(SXE_TX_DESC_STAT_DD))
		ret = RTE_ETH_TX_DESC_DONE;

l_end:
	return ret;
}
