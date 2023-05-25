/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Arm Limited.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_ether.h>
#include <rte_ethdev.h>

#include "testpmd.h"

/*
 * Forwarding of packets in I/O mode.
 * Enable mbufs recycle mode to recycle txq used mbufs
 * for rxq mbuf ring. This can bypass mempool path and
 * save CPU cycles.
 */
static bool
pkt_burst_recycle_mbufs(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;

	/* Recycle used mbufs from the txq, and move these mbufs into
	 * the rxq mbuf ring.
	 */
	rte_eth_recycle_mbufs(fs->rx_port, fs->rx_queue,
			fs->tx_port, fs->tx_queue, &(fs->recycle_rxq_info));

	/*
	 * Receive a burst of packets and forward them.
	 */
	nb_rx = common_fwd_stream_receive(fs, pkts_burst, nb_pkt_per_burst);
	if (unlikely(nb_rx == 0))
		return false;

	common_fwd_stream_transmit(fs, pkts_burst, nb_rx);

	return true;
}

static void
recycle_mbufs_stream_init(struct fwd_stream *fs)
{
	/* Retrieve information about given ports's Rx queue
	 * for recycling mbufs.
	 */
	rte_eth_recycle_rx_queue_info_get(fs->rx_port, fs->rx_queue,
			&(fs->recycle_rxq_info));

	common_fwd_stream_init(fs);
}

struct fwd_engine recycle_mbufs_engine = {
	.fwd_mode_name  = "recycle_mbufs",
	.stream_init    = recycle_mbufs_stream_init,
	.packet_fwd     = pkt_burst_recycle_mbufs,
};
