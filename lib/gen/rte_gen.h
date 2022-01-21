/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#ifndef _RTE_GEN_H_
#define _RTE_GEN_H_

/**
 * @file
 * RTE gen
 *
 * A library for the generation of packets, to allow easy generation
 * of various flows of packets.
 */

#include <stdint.h>
#include <rte_compat.h>

#ifdef __cplusplus
extern "C" {
#endif


/** Structure that represents a logical traffic generator. */
struct rte_gen;

/* Forward declarations for DPDK componeents. */
struct rte_mbuf;
struct rte_mempool;

/* Allocate and initialize a traffic generator instance. */
__rte_experimental
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool);

/* Free a traffic generator instance. */
__rte_experimental
void
rte_gen_destroy(struct rte_gen *gen);

/**
 * Call to receive a burst of generated packets
 *
 * @param gen
 *   Gen instance to be used.
 * @param rx_pkts
 *   mbuf where packets will be generated.
 * @param nb_pkts
 *   number of packets to be generated
 *
 * @retval nb_pkts
 *   On success the number of rx'ed packets will be returned
 * @retval 0
 *   Failure.
 */
__rte_experimental
uint16_t
rte_gen_rx_burst(struct rte_gen *gen,
		 struct rte_mbuf **rx_pkts,
		 const uint16_t nb_pkts);

/** Call to transmit a burst of traffic back to the generator.
 * This allows the generator to calculate stats/properties of the stream.
 *
 * If the pkt_latencies parameter is not NULL, it is expected to be a pointer
 * to an array of uint64_t values that has nb_pkts in length. Each individual
 * packet latency will be stored to the array.
 *
 * @param gen
 *   Gen instance to be used.
 * @param tx_pkts
 *   mbuf to be used to tx packets
 * @param pkt_latencies
 *   Array to store latencies of sent packets
 * @param nb_pkts
 *   The number of packets to be tx'ed
 *
 * @retval nb_pkts
 *   On success the number of packets tx'ed is returned
 */
__rte_experimental
uint16_t
rte_gen_tx_burst(struct rte_gen *gen,
		 struct rte_mbuf **tx_pkts,
		 uint64_t *pkt_latencies,
		 const uint16_t nb_pkts);


#ifdef __cplusplus
}
#endif

#endif /* _RTE_GEN_H_ */
