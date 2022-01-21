/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include "rte_gen.h"

#include <rte_mbuf.h>
#include <rte_malloc.h>

#define GEN_MAX_BURST 32

/** Structure that represents a traffic generator. */
struct rte_gen {
	/* Mempool that buffers are retrieved from. */
	struct rte_mempool *mp;
};

/* Allocate and initialize a traffic generator instance. */
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool)
{
	struct rte_gen *gen = rte_zmalloc(NULL, sizeof(*gen), 0);
	if (gen == NULL)
		return NULL;

	gen->mp = mempool;

	return gen;
}

/* Free a traffic generator instance. */
void
rte_gen_destroy(struct rte_gen *gen)
{
	rte_free(gen);
}

uint16_t
rte_gen_rx_burst(struct rte_gen *gen,
		 struct rte_mbuf **rx_pkts,
		 const uint16_t nb_pkts)
{
	/* Get a bulk of nb_pkts from the mempool. */
	int err = rte_mempool_get_bulk(gen->mp, (void **)rx_pkts, nb_pkts);
	if (err)
		return 0;

	const uint32_t pkt_len = 64;

	uint32_t i;
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *m = rx_pkts[i];
		uint8_t *pkt_data = rte_pktmbuf_mtod(m, uint8_t *);

		memset(pkt_data, 0, pkt_len);

		m->pkt_len  = pkt_len;
		m->data_len = pkt_len;
	}

	return nb_pkts;
}

uint16_t
rte_gen_tx_burst(struct rte_gen *gen,
		 struct rte_mbuf **tx_pkts,
		 uint64_t *pkt_latencies,
		 const uint16_t nb_pkts)
{
	RTE_SET_USED(gen);
	RTE_SET_USED(pkt_latencies);

	rte_pktmbuf_free_bulk(tx_pkts, nb_pkts);

	return nb_pkts;
}
