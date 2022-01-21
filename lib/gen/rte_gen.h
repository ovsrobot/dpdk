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
struct rte_mempool;

/* Allocate and initialize a traffic generator instance. */
__rte_experimental
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool);

/* Free a traffic generator instance. */
__rte_experimental
void
rte_gen_destroy(struct rte_gen *gen);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_GEN_H_ */
