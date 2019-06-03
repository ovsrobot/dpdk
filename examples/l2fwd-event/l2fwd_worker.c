/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright (C) 2019 Marvell International Ltd.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "l2fwd_common.h"
#include "l2fwd_worker.h"

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   port_statistics[portid].tx,
			   port_statistics[portid].rx,
			   port_statistics[portid].dropped);

		total_packets_dropped += port_statistics[portid].dropped;
		total_packets_tx += port_statistics[portid].tx;
		total_packets_rx += port_statistics[portid].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

static inline void
l2fwd_drain_buffers(struct lcore_queue_conf *qconf)
{
	unsigned int i, sent;
	unsigned int portid;
	struct rte_eth_dev_tx_buffer *buffer;

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
		buffer = tx_buffer[portid];

		sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
		if (sent)
			port_statistics[portid].tx += sent;
	}
}

static inline void
l2fwd_periodic_drain_stats_monitor(struct lcore_queue_conf *qconf,
		struct tsc_tracker *t, int is_master_core)
{
	uint64_t diff_tsc, cur_tsc;

	cur_tsc = rte_rdtsc();

	/*
	 * TX burst queue drain
	 */
	diff_tsc = cur_tsc - t->prev_tsc;
	if (unlikely(diff_tsc > t->drain_tsc)) {

		/* Drain buffers */
		l2fwd_drain_buffers(qconf);

		/* if timer is enabled */
		if (timer_period > 0) {

			/* advance the timer */
			t->timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(t->timer_tsc >= timer_period)) {

				/* do this only on master core */
				if (is_master_core) {
					print_stats();
					/* reset the timer */
					t->timer_tsc = 0;
				}
			}
		}

		t->prev_tsc = cur_tsc;
	}
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned int dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned int portid)
{
	unsigned int dst_port;
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	buffer = tx_buffer[dst_port];
	sent = rte_eth_tx_buffer(dst_port, 0, buffer, m);
	if (sent)
		port_statistics[dst_port].tx += sent;
}

/* main processing loop */
static void
l2fwd_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned int lcore_id;
	unsigned int i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	int is_master_core;
	struct tsc_tracker tsc = {0};

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	/* Set drain tsc */
	tsc.drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	/* Set the flag if master core */
	is_master_core = (lcore_id == rte_get_master_lcore()) ? 1 : 0;

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid);
			}
		}
	}
}

int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}
