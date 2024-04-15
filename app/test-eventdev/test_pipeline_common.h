/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2017 Cavium, Inc.
 */

#ifndef _TEST_PIPELINE_COMMON_
#define _TEST_PIPELINE_COMMON_

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_eventdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_prefetch.h>
#include <rte_service.h>
#include <rte_service_component.h>
#include <rte_spinlock.h>
#include <rte_udp.h>

#include "evt_common.h"
#include "evt_options.h"
#include "evt_test.h"

struct test_pipeline;

struct __rte_cache_aligned worker_data {
	uint64_t processed_pkts;
	uint8_t dev_id;
	uint8_t port_id;
	struct test_pipeline *t;
};

struct __rte_cache_aligned test_pipeline {
	/* Don't change the offset of "done". Signal handler use this memory
	 * to terminate all lcores work.
	 */
	int done;
	uint8_t nb_workers;
	uint8_t internal_port;
	uint8_t tx_evqueue_id[RTE_MAX_ETHPORTS];
	enum evt_test_result result;
	uint32_t nb_flows;
	uint64_t outstand_pkts;
	struct rte_mempool *pool[RTE_MAX_ETHPORTS];
	struct worker_data worker[EVT_MAX_PORTS];
	struct evt_options *opt;
	alignas(RTE_CACHE_LINE_SIZE) uint8_t sched_type_list[EVT_MAX_STAGES];
};

#define BURST_SIZE 16

#define PIPELINE_WORKER_SINGLE_STAGE_INIT \
	struct worker_data *w  = arg;     \
	struct test_pipeline *t = w->t;   \
	const uint8_t dev = w->dev_id;    \
	const uint8_t port = w->port_id;  \
	alignas(RTE_CACHE_LINE_SIZE) struct rte_event ev

#define PIPELINE_WORKER_SINGLE_STAGE_BURST_INIT \
	int i;                                  \
	struct worker_data *w  = arg;           \
	struct test_pipeline *t = w->t;         \
	const uint8_t dev = w->dev_id;          \
	const uint8_t port = w->port_id;        \
	alignas(RTE_CACHE_LINE_SIZE) struct rte_event ev[BURST_SIZE + 1]

#define PIPELINE_WORKER_MULTI_STAGE_INIT                         \
	struct worker_data *w  = arg;                            \
	struct test_pipeline *t = w->t;                          \
	uint8_t cq_id;                                           \
	const uint8_t dev = w->dev_id;                           \
	const uint8_t port = w->port_id;                         \
	const uint8_t last_queue = t->opt->nb_stages - 1;        \
	uint8_t *const sched_type_list = &t->sched_type_list[0]; \
	const uint8_t nb_stages = t->opt->nb_stages + 1;	 \
	alignas(RTE_CACHE_LINE_SIZE) struct rte_event ev

#define PIPELINE_WORKER_MULTI_STAGE_BURST_INIT                   \
	int i;                                                   \
	struct worker_data *w  = arg;                            \
	struct test_pipeline *t = w->t;                          \
	uint8_t cq_id;                                           \
	const uint8_t dev = w->dev_id;                           \
	const uint8_t port = w->port_id;                         \
	const uint8_t last_queue = t->opt->nb_stages - 1;        \
	uint8_t *const sched_type_list = &t->sched_type_list[0]; \
	const uint8_t nb_stages = t->opt->nb_stages + 1;	 \
	alignas(RTE_CACHE_LINE_SIZE) struct rte_event ev[BURST_SIZE + 1]

static __rte_always_inline void
pipeline_fwd_event(struct rte_event *ev, uint8_t sched)
{
	ev->event_type = RTE_EVENT_TYPE_CPU;
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->sched_type = sched;
}

static __rte_always_inline void
pipeline_fwd_event_vector(struct rte_event *ev, uint8_t sched)
{
	ev->event_type = RTE_EVENT_TYPE_CPU_VECTOR;
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->sched_type = sched;
}

static __rte_always_inline uint8_t
pipeline_event_tx(const uint8_t dev, const uint8_t port,
		  struct rte_event *const ev, struct test_pipeline *t)
{
	uint8_t enq;

	rte_event_eth_tx_adapter_txq_set(ev->mbuf, 0);
	do {
		enq = rte_event_eth_tx_adapter_enqueue(dev, port, ev, 1, 0);
	} while (!enq && !t->done);

	return enq;
}

static __rte_always_inline uint8_t
pipeline_event_tx_vector(const uint8_t dev, const uint8_t port,
			 struct rte_event *const ev, struct test_pipeline *t)
{
	uint8_t enq;

	ev->vec->queue = 0;
	do {
		enq = rte_event_eth_tx_adapter_enqueue(dev, port, ev, 1, 0);
	} while (!enq && !t->done);

	return enq;
}

static __rte_always_inline uint16_t
pipeline_event_tx_burst(const uint8_t dev, const uint8_t port,
			struct rte_event *ev, const uint16_t nb_rx,
			struct test_pipeline *t)
{
	uint16_t enq;

	enq = rte_event_eth_tx_adapter_enqueue(dev, port, ev, nb_rx, 0);
	while (enq < nb_rx && !t->done) {
		enq += rte_event_eth_tx_adapter_enqueue(dev, port,
				ev + enq, nb_rx - enq, 0);
	}

	return enq;
}

static __rte_always_inline uint8_t
pipeline_event_enqueue(const uint8_t dev, const uint8_t port,
		       struct rte_event *ev, struct test_pipeline *t)
{
	uint8_t enq;

	do {
		enq = rte_event_enqueue_burst(dev, port, ev, 1);
	} while (!enq && !t->done);

	return enq;
}

static __rte_always_inline uint16_t
pipeline_event_enqueue_burst(const uint8_t dev, const uint8_t port,
			     struct rte_event *ev, const uint16_t nb_rx,
			     struct test_pipeline *t)
{
	uint16_t enq;

	enq = rte_event_enqueue_burst(dev, port, ev, nb_rx);
	while (enq < nb_rx && !t->done) {
		enq += rte_event_enqueue_burst(dev, port,
						ev + enq, nb_rx - enq);
	}

	return enq;
}


static inline int
pipeline_nb_event_ports(struct evt_options *opt)
{
	return evt_nr_active_lcores(opt->wlcores);
}

int pipeline_test_result(struct evt_test *test, struct evt_options *opt);
int pipeline_opt_check(struct evt_options *opt, uint64_t nb_queues);
int pipeline_test_setup(struct evt_test *test, struct evt_options *opt);
int pipeline_ethdev_setup(struct evt_test *test, struct evt_options *opt);
int pipeline_event_rx_adapter_setup(struct evt_options *opt, uint8_t stride,
		struct rte_event_port_conf prod_conf);
int pipeline_event_tx_adapter_setup(struct evt_options *opt,
		struct rte_event_port_conf prod_conf);
int pipeline_mempool_setup(struct evt_test *test, struct evt_options *opt);
int pipeline_event_port_setup(struct evt_test *test, struct evt_options *opt,
		uint8_t *queue_arr, uint8_t nb_queues,
		const struct rte_event_port_conf p_conf);
int pipeline_launch_lcores(struct evt_test *test, struct evt_options *opt,
		int (*worker)(void *));
void pipeline_opt_dump(struct evt_options *opt, uint8_t nb_queues);
void pipeline_test_destroy(struct evt_test *test, struct evt_options *opt);
void pipeline_eventdev_destroy(struct evt_test *test, struct evt_options *opt);
void pipeline_ethdev_destroy(struct evt_test *test, struct evt_options *opt);
void pipeline_ethdev_rx_stop(struct evt_test *test, struct evt_options *opt);
void pipeline_mempool_destroy(struct evt_test *test, struct evt_options *opt);
void pipeline_worker_cleanup(uint8_t dev, uint8_t port, struct rte_event ev[],
			     uint16_t enq, uint16_t deq);

#endif /* _TEST_PIPELINE_COMMON_ */
