/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Arm Limited.
 */

#include <stdint.h>
#include <ethdev_driver.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_rxtx.h"

#include "ixgbe_rxtx_vec_common.h"

#include "../common/recycle_mbufs.h"

void
ixgbe_recycle_rx_descriptors_refill_vec(void *rx_queue, uint16_t nb_mbufs)
{
	ci_rx_recycle_mbufs(rx_queue, nb_mbufs);
}

uint16_t
ixgbe_recycle_tx_mbufs_reuse_vec(void *tx_queue,
		struct rte_eth_recycle_rxq_info *recycle_rxq_info)
{
	return ci_tx_recycle_mbufs(tx_queue, ixgbe_tx_desc_done, recycle_rxq_info);
}
