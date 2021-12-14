/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include "rte_gen.h"

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hexdump.h>
#include <rte_log.h>

RTE_LOG_REGISTER(gen_logtype, lib.gen, NOTICE);

#define TGEN_LOG(level, fmt, args...)				\
	rte_log(RTE_LOG_ ## level, gen_logtype, "%s(): " fmt,	\
		__func__, ## args)

#define GEN_MAX_BURST 32
#define GEN_INIT_PKT_SIZE 64

/** Structure that represents a traffic generator. */
struct rte_gen {
	/* Mempool that buffers are retrieved from. */
	struct rte_mempool *mp;

	/* Packet template to send. */
	struct rte_mbuf *base_pkt;
};

/* Allocate and initialize a traffic generator instance. */
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool)
{
	struct rte_gen *gen = rte_zmalloc(NULL, sizeof(*gen), 0);
	if (gen == NULL)
		return NULL;

	gen->mp = mempool;

	uint8_t data[GEN_INIT_PKT_SIZE];
	memset(data, 0, GEN_INIT_PKT_SIZE);
	int32_t err = rte_gen_packet_set_raw(gen, data, GEN_INIT_PKT_SIZE);
	if (err) {
		TGEN_LOG(ERR, "Failed to set initial packet\n");
		rte_free(gen);
		return NULL;
	}

	return gen;
}

/* Free a traffic generator instance. */
void
rte_gen_destroy(struct rte_gen *gen)
{
	rte_pktmbuf_free(gen->base_pkt);
	rte_free(gen);
}

int32_t
rte_gen_packet_set_raw(struct rte_gen *gen,
		       const uint8_t *raw_data,
		       uint32_t raw_data_size)
{

	struct rte_mbuf *new_pkt = rte_pktmbuf_alloc(gen->mp);
	if (!new_pkt) {
		TGEN_LOG(ERR, "Failed to retireve mbuf for parser\n");
		return -ENOMEM;
	}

	uint8_t *base_data = rte_pktmbuf_mtod(new_pkt, uint8_t *);
	new_pkt->pkt_len = raw_data_size;
	new_pkt->data_len = raw_data_size;
	rte_memcpy(base_data, raw_data, raw_data_size);

	/* If old packet exists, free it. */
	struct rte_mbuf *old_pkt = gen->base_pkt;
	gen->base_pkt = new_pkt;

	if (old_pkt)
		rte_pktmbuf_free(old_pkt);

	return 0;
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

	if (!gen->base_pkt)
		return 0;

	const uint32_t base_size = gen->base_pkt->pkt_len;
	const uint8_t *base_data = rte_pktmbuf_mtod(gen->base_pkt, uint8_t *);

	uint32_t i;
	for (i = 0; i < nb_pkts; i++) {
		struct rte_mbuf *m = rx_pkts[i];
		uint8_t *pkt_data = rte_pktmbuf_mtod(m, uint8_t *);

		rte_memcpy(pkt_data, base_data, base_size);
		m->pkt_len = base_size;
		m->data_len = base_size;
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
