/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_ETH_RING_H_
#define _RTE_ETH_RING_H_

#include <rte_compat.h>
#include <rte_ring.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Create a new ethdev port from a set of rings
 *
 * @param name
 *    name to be given to the new ethdev port
 * @param rx_queues
 *    pointer to array of rte_rings to be used as RX queues
 * @param nb_rx_queues
 *    number of elements in the rx_queues array
 * @param tx_queues
 *    pointer to array of rte_rings to be used as TX queues
 * @param nb_tx_queues
 *    number of elements in the tx_queues array
 * @param numa_node
 *    the numa node on which the memory for this port is to be allocated
 * @return
 *    the port number of the newly created the ethdev or -1 on error.
 */
int rte_eth_from_rings(const char *name,
		struct rte_ring * const rx_queues[],
		const unsigned nb_rx_queues,
		struct rte_ring *const tx_queues[],
		const unsigned nb_tx_queues,
		const unsigned numa_node);

/**
 * Create a new ethdev port from a ring
 *
 * This function is a shortcut call for rte_eth_from_rings for the
 * case where one wants to take a single rte_ring and use it as though
 * it were an ethdev
 *
 * @param ring
 *    the ring to be used as an ethdev
 * @return
 *    the port number of the newly created ethdev, or -1 on error
 */
int rte_eth_from_ring(struct rte_ring *r);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Attach two ring-backed ethdev ports as peers.
 *
 * After this call the link state of each port reflects whether its
 * peer is started, similar to how carrier is handled on Linux veth
 * devices.  Stopping, closing, or setting link-down on one side will
 * cause the other side to report link-down as well.
 *
 * Only ring-backed ports (created by rte_eth_from_rings or the
 * net_ring vdev driver) can be paired.  A port that already has a
 * peer must be un-paired first (by closing or removing it).
 *
 * @param port_id_a
 *    port id of the first ring-backed ethdev
 * @param port_id_b
 *    port id of the second ring-backed ethdev
 * @return
 *    0 on success, -1 on error (rte_errno is set).
 */
__rte_experimental
int rte_eth_ring_attach_peer(uint16_t port_id_a, uint16_t port_id_b);

#ifdef __cplusplus
}
#endif

#endif
