/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_bus_vdev.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eventdev.h>

#include "slb_evdev.h"

#define NUM_PORTS 4
#define NUM_QUEUES 4
#define PORT_PROD 0
#define PORT_W1   1
#define PORT_W2   2
#define PORT_CONS 3

#define Q_PARALLEL 0
#define Q_ATOMIC   1
#define Q_ORDERED  2
#define Q_SINGLE   3

#define NUM_FLOWS 4
#define EVENTS_PER_FLOW 16
#define TOTAL_ATOMIC_EVENTS (NUM_FLOWS * EVENTS_PER_FLOW)

static int g_dev_id = -1;

static int
init_selftest_device(void)
{
	struct rte_event_dev_config dev_conf = {
		.dequeue_timeout_ns = 0,
		.nb_event_queues = NUM_QUEUES,
		.nb_event_ports = NUM_PORTS,
		.nb_events_limit = 4096,
		.nb_event_queue_flows = 1024,
		.nb_event_port_dequeue_depth = 64,
		.nb_event_port_enqueue_depth = 64,
	};
	struct rte_event_queue_conf q_conf;
	struct rte_event_port_conf p_conf = {
		.dequeue_depth = 64,
		.enqueue_depth = 64,
		.new_event_threshold = 2048,
		.event_port_cfg = 0
	};
	struct rte_event_dev_info info;
	uint8_t ldb_queues[] = { Q_PARALLEL, Q_ATOMIC, Q_ORDERED };
	uint8_t single_q = Q_SINGLE;
	int ret;
	int p;

	g_dev_id = rte_event_dev_get_dev_id(SLB_PMD_NAME);
	if (g_dev_id < 0) {
		ret = rte_vdev_init("event_slb_selftest", NULL);
		if (ret < 0) {
			SLB_LOG_LINE(ERR, "Failed to init vdev event_slb_selftest");
			return -1;
		}
		g_dev_id = rte_event_dev_get_dev_id("event_slb_selftest");
		if (g_dev_id < 0) {
			SLB_LOG_LINE(ERR, "Cannot find initialized vdev");
			return -1;
		}
	}

	ret = rte_event_dev_info_get(g_dev_id, &info);
	if (ret < 0) {
		SLB_LOG_LINE(ERR, "Failed to get dev info");
		return -1;
	}

	ret = rte_event_dev_configure(g_dev_id, &dev_conf);
	if (ret < 0) {
		SLB_LOG_LINE(ERR, "Failed to configure device, ret=%d", ret);
		return -1;
	}

	/* Setup Queues */
	memset(&q_conf, 0, sizeof(q_conf));
	q_conf.nb_atomic_flows = 1024;
	q_conf.nb_atomic_order_sequences = 1024;
	q_conf.priority = RTE_EVENT_DEV_PRIORITY_NORMAL;

	/* Q0: Parallel */
	q_conf.schedule_type = RTE_SCHED_TYPE_PARALLEL;
	q_conf.event_queue_cfg = 0;
	ret = rte_event_queue_setup(g_dev_id, Q_PARALLEL, &q_conf);
	if (ret < 0)
		return -1;

	/* Q1: Atomic */
	q_conf.schedule_type = RTE_SCHED_TYPE_ATOMIC;
	q_conf.event_queue_cfg = 0;
	ret = rte_event_queue_setup(g_dev_id, Q_ATOMIC, &q_conf);
	if (ret < 0)
		return -1;

	/* Q2: Ordered */
	q_conf.schedule_type = RTE_SCHED_TYPE_ORDERED;
	q_conf.event_queue_cfg = 0;
	ret = rte_event_queue_setup(g_dev_id, Q_ORDERED, &q_conf);
	if (ret < 0)
		return -1;

	/* Q3: Single-link */
	q_conf.schedule_type = RTE_SCHED_TYPE_PARALLEL;
	q_conf.event_queue_cfg = RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	ret = rte_event_queue_setup(g_dev_id, Q_SINGLE, &q_conf);
	if (ret < 0)
		return -1;

	/* Setup Ports */
	for (p = 0; p < NUM_PORTS; p++) {
		if (p == PORT_CONS)
			p_conf.event_port_cfg = RTE_EVENT_PORT_CFG_SINGLE_LINK;
		else
			p_conf.event_port_cfg = 0;

		ret = rte_event_port_setup(g_dev_id, p, &p_conf);
		if (ret < 0)
			return -1;
	}

	/* Link Queues */
	ret = rte_event_port_link(g_dev_id, PORT_W1, ldb_queues, NULL, 3);
	if (ret != 3)
		return -1;

	ret = rte_event_port_link(g_dev_id, PORT_W2, ldb_queues, NULL, 3);
	if (ret != 3)
		return -1;

	ret = rte_event_port_link(g_dev_id, PORT_CONS, &single_q, NULL, 1);
	if (ret != 1)
		return -1;

	ret = rte_event_dev_start(g_dev_id);
	if (ret < 0)
		return -1;

	return 0;
}

static void
cleanup_selftest_device(void)
{
	if (g_dev_id >= 0) {
		rte_event_dev_stop(g_dev_id);
		rte_event_dev_close(g_dev_id);
		g_dev_id = -1;
	}
}

static int
test_parallel_queue(void)
{
	struct rte_event rx_ev[32];
	struct rte_event ev[32];
	uint16_t enqd, deqd = 0;
	uint16_t n = 0;
	int tries = 0;
	int i;

	memset(ev, 0, sizeof(ev));

	for (i = 0; i < 32; i++) {
		ev[i].op = RTE_EVENT_OP_NEW;
		ev[i].sched_type = RTE_SCHED_TYPE_PARALLEL;
		ev[i].queue_id = Q_PARALLEL;
		ev[i].u64 = 1000 + i;
	}

	enqd = rte_event_enqueue_burst(g_dev_id, PORT_PROD, ev, 32);
	if (enqd != 32) {
		SLB_LOG_LINE(ERR, "Parallel enqueue failed, expected 32, got %u", enqd);
		return -1;
	}

	while (deqd < 32 && tries++ < 1000) {
		n = rte_event_dequeue_burst(g_dev_id, PORT_W1, rx_ev + deqd,
					    32 - deqd, 0);
		deqd += n;
		if (deqd < 32) {
			n = rte_event_dequeue_burst(g_dev_id, PORT_W2,
						    rx_ev + deqd, 32 - deqd, 0);
			deqd += n;
		}
	}

	if (deqd != 32) {
		SLB_LOG_LINE(ERR, "Parallel dequeue failed, expected 32, got %u", deqd);
		return -1;
	}

	/* Release events */
	for (i = 0; i < 32; i++)
		rx_ev[i].op = RTE_EVENT_OP_RELEASE;
	rte_event_enqueue_burst(g_dev_id, PORT_W1, rx_ev, 32);

	return 0;
}

static int
test_atomic_queue(void)
{
	struct rte_event rx_ev[64];
	struct rte_event ev[64];
	int expected_seq[NUM_FLOWS];
	uint16_t enqd = 0;
	uint16_t deqd = 0;
	int tries = 0;
	int idx = 0;
	int e, f;
	uint16_t i, n;

	memset(ev, 0, sizeof(ev));

	for (e = 0; e < EVENTS_PER_FLOW; e++) {
		for (f = 0; f < NUM_FLOWS; f++) {
			ev[idx].op = RTE_EVENT_OP_NEW;
			ev[idx].sched_type = RTE_SCHED_TYPE_ATOMIC;
			ev[idx].queue_id = Q_ATOMIC;
			ev[idx].flow_id = f;
			ev[idx].u64 = e; /* sequence number */
			idx++;
		}
	}

	while (enqd < TOTAL_ATOMIC_EVENTS) {
		n = rte_event_enqueue_burst(g_dev_id, PORT_PROD, ev + enqd,
					    TOTAL_ATOMIC_EVENTS - enqd);
		if (n == 0)
			break;
		enqd += n;
	}
	if (enqd != TOTAL_ATOMIC_EVENTS) {
		SLB_LOG_LINE(ERR, "Atomic enqueue failed, expected %d, got %u",
			     TOTAL_ATOMIC_EVENTS, enqd);
		return -1;
	}

	for (f = 0; f < NUM_FLOWS; f++)
		expected_seq[f] = 0;

	while (deqd < TOTAL_ATOMIC_EVENTS && tries++ < 2000) {
		n = rte_event_dequeue_burst(g_dev_id, PORT_W1, rx_ev, 16, 0);
		for (i = 0; i < n; i++) {
			int fid = rx_ev[i].flow_id;

			if (rx_ev[i].u64 != (uint64_t)expected_seq[fid]) {
				SLB_LOG_LINE(ERR,
					     "Flow %d out of order! Expected %d got %" PRIu64,
					     fid, expected_seq[fid], rx_ev[i].u64);
				return -1;
			}
			expected_seq[fid]++;
			rx_ev[i].op = RTE_EVENT_OP_RELEASE;
		}
		if (n > 0)
			rte_event_enqueue_burst(g_dev_id, PORT_W1, rx_ev, n);
		deqd += n;

		n = rte_event_dequeue_burst(g_dev_id, PORT_W2, rx_ev, 16, 0);
		for (i = 0; i < n; i++) {
			int fid = rx_ev[i].flow_id;

			if (rx_ev[i].u64 != (uint64_t)expected_seq[fid]) {
				SLB_LOG_LINE(ERR,
					     "Flow %d out of order! Expected %d got %" PRIu64,
					     fid, expected_seq[fid], rx_ev[i].u64);
				return -1;
			}
			expected_seq[fid]++;
			rx_ev[i].op = RTE_EVENT_OP_RELEASE;
		}
		if (n > 0)
			rte_event_enqueue_burst(g_dev_id, PORT_W2, rx_ev, n);
		deqd += n;
	}

	if (deqd != TOTAL_ATOMIC_EVENTS) {
		SLB_LOG_LINE(ERR, "Atomic dequeue failed, expected %d got %u",
			     TOTAL_ATOMIC_EVENTS, deqd);
		return -1;
	}

	return 0;
}

static int
test_ordered_forward(void)
{
	const int num_events = 32;
	struct rte_event rx[16];
	struct rte_event ev[32];
	uint16_t enqd;
	uint16_t fwd = 0;
	uint16_t cons_rx = 0;
	int tries = 0;
	int i;
	uint16_t n;

	memset(ev, 0, sizeof(ev));

	for (i = 0; i < num_events; i++) {
		ev[i].op = RTE_EVENT_OP_NEW;
		ev[i].sched_type = RTE_SCHED_TYPE_ORDERED;
		ev[i].queue_id = Q_ORDERED;
		ev[i].u64 = i;
	}

	enqd = rte_event_enqueue_burst(g_dev_id, PORT_PROD, ev, num_events);
	if (enqd != num_events)
		return -1;

	/* Workers dequeue and forward to Q_SINGLE */
	while (fwd < num_events && tries++ < 2000) {
		n = rte_event_dequeue_burst(g_dev_id, PORT_W1, rx, 16, 0);
		for (i = 0; i < n; i++) {
			rx[i].op = RTE_EVENT_OP_FORWARD;
			rx[i].queue_id = Q_SINGLE;
			rx[i].sched_type = RTE_SCHED_TYPE_PARALLEL;
		}
		if (n > 0)
			rte_event_enqueue_burst(g_dev_id, PORT_W1, rx, n);
		fwd += n;

		n = rte_event_dequeue_burst(g_dev_id, PORT_W2, rx, 16, 0);
		for (i = 0; i < n; i++) {
			rx[i].op = RTE_EVENT_OP_FORWARD;
			rx[i].queue_id = Q_SINGLE;
			rx[i].sched_type = RTE_SCHED_TYPE_PARALLEL;
		}
		if (n > 0)
			rte_event_enqueue_burst(g_dev_id, PORT_W2, rx, n);
		fwd += n;
	}

	if (fwd != num_events) {
		SLB_LOG_LINE(ERR, "Ordered workers failed to forward all events (%u/%d)",
			     fwd, num_events);
		return -1;
	}

	/* Consumer on PORT_CONS must receive all events in exact sequence 0..num_events-1 */
	tries = 0;
	while (cons_rx < num_events && tries++ < 2000) {
		n = rte_event_dequeue_burst(g_dev_id, PORT_CONS, rx, 16, 0);
		for (i = 0; i < n; i++) {
			if (rx[i].u64 != cons_rx) {
				SLB_LOG_LINE(ERR,
					     "Ordered seq violation! Expected %u got %" PRIu64,
					     cons_rx, rx[i].u64);
				return -1;
			}
			if (rx[i].sched_type != RTE_SCHED_TYPE_ATOMIC) {
				SLB_LOG_LINE(ERR,
					     "Single-link dequeue sched_type expected %u, got %u",
					     RTE_SCHED_TYPE_ATOMIC, rx[i].sched_type);
				return -1;
			}
			cons_rx++;
			rx[i].op = RTE_EVENT_OP_RELEASE;
		}
		if (n > 0)
			rte_event_enqueue_burst(g_dev_id, PORT_CONS, rx, n);
	}

	if (cons_rx != num_events) {
		SLB_LOG_LINE(ERR, "Consumer received %u/%d ordered events",
			     cons_rx, num_events);
		return -1;
	}

	return 0;
}

static int
test_single_link(void)
{
	struct rte_event rx[16];
	struct rte_event ev[16];
	uint16_t enqd;
	uint16_t deqd = 0;
	int tries = 0;
	int i;
	uint16_t n;

	memset(ev, 0, sizeof(ev));

	for (i = 0; i < 16; i++) {
		ev[i].op = RTE_EVENT_OP_NEW;
		ev[i].sched_type = RTE_SCHED_TYPE_PARALLEL;
		ev[i].queue_id = Q_SINGLE;
		ev[i].u64 = 5000 + i;
	}

	enqd = rte_event_enqueue_burst(g_dev_id, PORT_PROD, ev, 16);
	if (enqd != 16)
		return -1;

	while (deqd < 16 && tries++ < 1000) {
		n = rte_event_dequeue_burst(g_dev_id, PORT_CONS,
					    rx + deqd, 16 - deqd, 0);
		deqd += n;
	}

	if (deqd != 16) {
		SLB_LOG_LINE(ERR, "Single-link dequeue failed (%u/16)", deqd);
		return -1;
	}

	for (i = 0; i < 16; i++) {
		if (rx[i].u64 != (uint64_t)(5000 + i))
			return -1;
		if (rx[i].sched_type != RTE_SCHED_TYPE_ATOMIC) {
			SLB_LOG_LINE(ERR,
				     "Single-link dequeue sched_type expected %u, got %u",
				     RTE_SCHED_TYPE_ATOMIC, rx[i].sched_type);
			return -1;
		}
		rx[i].op = RTE_EVENT_OP_RELEASE;
	}
	rte_event_enqueue_burst(g_dev_id, PORT_CONS, rx, 16);

	return 0;
}

static int
test_stop_flush(void)
{
	struct rte_event rx[16];
	struct rte_event ev[16];
	uint16_t enqd;
	uint16_t deqd;
	int ret;
	int i;

	memset(ev, 0, sizeof(ev));

	for (i = 0; i < 16; i++) {
		ev[i].op = RTE_EVENT_OP_NEW;
		ev[i].sched_type = RTE_SCHED_TYPE_PARALLEL;
		ev[i].queue_id = Q_PARALLEL;
		ev[i].u64 = 9000 + i;
	}

	enqd = rte_event_enqueue_burst(g_dev_id, PORT_PROD, ev, 16);
	if (enqd != 16)
		return -1;

	/* Stop device flushes all queued events */
	rte_event_dev_stop(g_dev_id);

	/* Restart device */
	ret = rte_event_dev_start(g_dev_id);
	if (ret < 0)
		return -1;

	/* Verify no leftover events */
	deqd = rte_event_dequeue_burst(g_dev_id, PORT_W1, rx, 16, 0);
	if (deqd != 0) {
		SLB_LOG_LINE(ERR, "Stop flush failed, received %u events after restart",
			     deqd);
		return -1;
	}

	return 0;
}

int
test_slb_eventdev(void)
{
	SLB_LOG_LINE(INFO, "=== Running SLB Eventdev Selftest ===");

	if (init_selftest_device() < 0) {
		SLB_LOG_LINE(ERR, "Initialization failed");
		cleanup_selftest_device();
		return -1;
	}

	SLB_LOG_LINE(INFO, "  [1/5] Testing Parallel Queue...");
	if (test_parallel_queue() < 0) {
		SLB_LOG_LINE(ERR, "  FAILED: Parallel Queue test failed");
		cleanup_selftest_device();
		return -1;
	}
	SLB_LOG_LINE(INFO, "  [1/5] Parallel Queue: PASS");

	SLB_LOG_LINE(INFO, "  [2/5] Testing Atomic Queue...");
	if (test_atomic_queue() < 0) {
		SLB_LOG_LINE(ERR, "  FAILED: Atomic Queue test failed");
		cleanup_selftest_device();
		return -1;
	}
	SLB_LOG_LINE(INFO, "  [2/5] Atomic Queue: PASS");

	SLB_LOG_LINE(INFO, "  [3/5] Testing Ordered Queue...");
	if (test_ordered_forward() < 0) {
		SLB_LOG_LINE(ERR, "  FAILED: Ordered Queue test failed");
		cleanup_selftest_device();
		return -1;
	}
	SLB_LOG_LINE(INFO, "  [3/5] Ordered Queue: PASS");

	SLB_LOG_LINE(INFO, "  [4/5] Testing Single-Link Queue...");
	if (test_single_link() < 0) {
		SLB_LOG_LINE(ERR, "  FAILED: Single-Link Queue test failed");
		cleanup_selftest_device();
		return -1;
	}
	SLB_LOG_LINE(INFO, "  [4/5] Single-Link Queue: PASS");

	SLB_LOG_LINE(INFO, "  [5/5] Testing Device Stop & Flush...");
	if (test_stop_flush() < 0) {
		SLB_LOG_LINE(ERR, "  FAILED: Stop Flush test failed");
		cleanup_selftest_device();
		return -1;
	}
	SLB_LOG_LINE(INFO, "  [5/5] Device Stop & Flush: PASS");

	cleanup_selftest_device();
	SLB_LOG_LINE(INFO, "=== SLB Eventdev Selftest PASSED ===");
	return 0;
}
