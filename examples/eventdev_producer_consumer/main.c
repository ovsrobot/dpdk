/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <getopt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_launch.h>
#include <rte_malloc.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>

#define BATCH_SIZE 32

static unsigned int num_workers = 4;
static bool g_is_mbuf;
static uint64_t num_packets = (1L << 25); /* do ~32M packets */
static int sched_type = RTE_SCHED_TYPE_ATOMIC;

struct prod_data {
	uint8_t event_dev_id;
	uint8_t event_port_id;
	int32_t qid;
};

struct cons_data {
	uint8_t event_dev_id;
	uint8_t event_port_id;
};

struct worker_data {
	uint8_t event_dev_id;
	int event_port_id;
	int32_t qid;
};

static volatile int done;
static int quiet;

#define PORT_0 0
#define QUEUE_0 0
static struct rte_mempool *mp;

static int
worker(void *arg)
{
	struct rte_event rcv_events[BATCH_SIZE];

	struct worker_data *data = (struct worker_data *)arg;
	uint8_t event_dev_id = data->event_dev_id;
	uint8_t event_port_id = data->event_port_id;
	int32_t qid = data->qid;
	uint64_t sent = 0, received = 0;
	uint16_t n;

	if (!quiet)
		printf("Worker core %d started, portId=%d, sending to qid=%d\n",
		       rte_lcore_id(), event_port_id, qid);

	while (!done) {
		uint16_t k;
		int npkts_to_send, npkts_sent = 0;
		struct rte_event *ev;
		uint64_t delay_start;

		/* Cannot wait for IRQ here due to the way that
		 * we check for when we are done.
		 */
		n = rte_event_dequeue_burst(event_dev_id,
					    event_port_id,
					    rcv_events,
					    RTE_DIM(rcv_events),
					    0);

		if (n == 0) {
			rte_pause();
			continue;
		} else if (!quiet)
			printf("Worker received %d events(%"PRIu64" total)\n",
			       n, received);

		delay_start = rte_rdtsc();
		while (delay_start > rte_rdtsc())
			;

		received += n;

		ev = &rcv_events[0];
		for (k = 0; k < n; k++) {
			ev->queue_id = qid;
			ev->op = RTE_EVENT_OP_FORWARD;
			ev++;
		}

		ev = &rcv_events[0];
		npkts_to_send = n, npkts_sent = 0;

		while (npkts_sent < npkts_to_send)  {
			int iter_sent = 0;
			iter_sent = rte_event_enqueue_burst(event_dev_id,
							    event_port_id,
							    &ev[npkts_sent],
							    n - npkts_sent);
			npkts_sent += iter_sent;
		}
	} /* while (!done) */

	if (!quiet)
		printf("%s %d thread done. RX= %"PRIu64" TX= %"PRIu64"\n",
			__func__, rte_lcore_id(), received, sent);

	return 0;
}

static int
consumer(void *arg)
{
	struct rte_event events[BATCH_SIZE];
	struct cons_data *data = (struct cons_data *)arg;
	uint8_t event_dev_id = data->event_dev_id;
	uint8_t event_port_id = data->event_port_id;
	int64_t npackets = num_packets;
	uint64_t start_time = 0;
	uint64_t freq_khz = rte_get_timer_hz() / 1000;
	uint16_t n;
	uint64_t deq_start, deq_end;

	deq_start = rte_rdtsc();
	while (npackets > 0) {
		uint16_t i;
		n = rte_event_dequeue_burst(event_dev_id,
					    event_port_id,
					    events,
					    RTE_DIM(events),
					    0);

		if (g_is_mbuf) {
			for (i = 0; i < n; i++) {
				/* Could pack these up and do a bulk free */
				if (!quiet)
					printf("%s: mbuf[%d].seqno = %"
						PRIu64"\n", __func__, i,
						events[i].mbuf->tx_offload);
				if (events[i].mbuf->tx_offload < 100000000000)
					rte_pktmbuf_free(events[i].mbuf);
				rte_cldemote(events[i].mbuf);
			}
		} /* if (g_is_mbuf) */
		npackets -= n;
	} /* while */

	deq_end = rte_rdtsc();
	printf("Consumer done in %"PRIu64" cycles (%f cycles/evt)"
	       " (%f pkts/sec)\n", deq_end-deq_start,
	       (float)(deq_end - deq_start)/(float)num_packets,
	       (float) (num_packets * rte_get_timer_hz()) /
	       (float) (deq_end - deq_start));
	printf("deq_end = %"PRIu64", deq_start = %"PRIu64"\n",
	       deq_end, deq_start);

	printf("Consumer done! RX=%"PRIu64", time %"PRIu64"ms\n",
	       num_packets,
	       (rte_get_timer_cycles() - start_time) / freq_khz);
	done = 1;
	return 0;
}


static int
producer(void *arg)
{
	struct prod_data *data = (struct prod_data *)arg;
	int64_t npackets = num_packets;
	uint64_t mbuf_seqno = 0;
	uint8_t event_dev_id;
	uint8_t event_port_id;
	int fid_counter = 0;
	int err;
	int64_t retry_count = 0;
	int32_t qid = data->qid;
	uint64_t enq_start, enq_end;
	int k = 0;
	struct rte_mbuf *m;
	struct rte_event producer_events[BATCH_SIZE];
	struct rte_event *ev = &producer_events[0];
	int l = 0;
	struct rte_mbuf *mbufs[BATCH_SIZE];

	event_dev_id = data->event_dev_id;
	event_port_id = data->event_port_id;

	for (k = 0; k < BATCH_SIZE; k++) {
		if (!g_is_mbuf)
			m = NULL;
		ev->queue_id = qid;
		ev->priority = 0;
		ev->mbuf = m;
		ev->sched_type = sched_type;
		ev->op = RTE_EVENT_OP_NEW;
		ev++;
	}

	enq_start = rte_rdtsc();
	do {
		int64_t npkt_start;
		ev = &producer_events[0];
		retry_count = 0;

		if (g_is_mbuf) {
			err = rte_pktmbuf_alloc_bulk(mp,
						     &mbufs[0],
						     BATCH_SIZE);
			if (err) {
				printf("mbuf alloc failed after sending %"
				       PRIu64" with err=%d\n",
				       num_packets - npackets, err);
				return -1;
			}

			for (l = 0; l < BATCH_SIZE; l++) {
				m = mbufs[l];
				/* Using tx_offload field of rte_mbuf to store
				 * seq nums as .udata64 has been removed
				 */
				m->tx_offload = mbuf_seqno++;
				producer_events[l].mbuf = m;
				producer_events[l].flow_id = fid_counter++;
				if (!quiet)
					printf("%s: mbuf[%d].seqno = %"PRIu64"\n",
						__func__, l,
						producer_events[l].mbuf->tx_offload);
			} /* for l = 0 - BATCH_SIZE */
		} /* if g_is_mbuf */
		else {
			for (l = 0; l < BATCH_SIZE; l++)
				producer_events[l].flow_id = fid_counter++;
		}
		npkt_start = npackets;
		while (npackets > npkt_start - BATCH_SIZE) {
			int64_t num_sent = npkt_start - npackets;
			npackets -= rte_event_enqueue_burst(event_dev_id,
							    event_port_id,
							    &ev[num_sent],
							    BATCH_SIZE -
							    num_sent);
		}
	} while ((npackets > 0) && retry_count++ < 100000000000);

	enq_end = rte_rdtsc();

	if (npackets > 0)
		rte_panic("%s thread failed to enqueue events\n", __func__);

	if (num_packets > 0 && npackets > 0)
		printf("npackets not sent: %"PRIu64"\n", npackets);

	printf("Producer done. %"PRIu64" packets sent in %"PRIu64" cycles"
	       "(%f cycles/evt) (%f pkts/sec)\n",
	       num_packets, enq_end - enq_start,
	       (float)(enq_end - enq_start)/(float)num_packets,
	       (float) (num_packets * rte_get_timer_hz()) /
	       (float) (enq_end - enq_start));
	printf("enq_enq = %"PRIu64", enq_start = %"PRIu64"\n",
	       enq_end, enq_start);
	return 0;
}

static struct option long_options[] = {
	{"workers", required_argument, 0, 'w'},
	{"packets", required_argument, 0, 'n'},
	{"ordered", no_argument, 0, 'o'},
	{"parallel", no_argument, 0, 'u'},
	{"quiet", no_argument, 0, 'q'},
	{"useMbufs", no_argument, 0, 'm'},
	{0, 0, 0, 0}
};

static void
usage(void)
{
	const char *usage_str =
		"  Usage: eventdev_producer_consumer [options]\n"
		"  Options:\n"
		"  -w, --workers=N       Use N workers (default 4)\n"
		"  -n, --packets=N       Send N packets (default ~32M),"
					 " 0 implies no limit\n"
		"  -o, --ordered         Use ordered scheduling\n"
		"  -u, --parallel        Use parallel scheduling\n"
		"  -q, --quiet           Minimize printed output\n"
		"  -m, --use-mbufs       Use mbufs for enqueue\n"
		"\n";

	fprintf(stderr, "%s", usage_str);
	exit(1);
}

static void
parse_app_args(int argc, char **argv)
{
	/* Parse cli options*/
	int option_index;
	int c;
	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "w:n:ouqm", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'w':
			num_workers = (unsigned int)atoi(optarg);
			break;
		case 'n':
			num_packets = (unsigned long)atol(optarg);
			break;
		case 'o':
			if (sched_type == RTE_SCHED_TYPE_PARALLEL)
				rte_panic("Cannot specify both -o and -u\n");
			sched_type = RTE_SCHED_TYPE_ORDERED;
			break;
		case 'u':
			if (sched_type == RTE_SCHED_TYPE_ORDERED)
				rte_panic("Cannot specify both -o and -u\n");
			sched_type = RTE_SCHED_TYPE_PARALLEL;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'm':
			g_is_mbuf = true;
			break;
		default:
			usage();
		}
	}
}

static uint8_t
setup_event_dev(struct prod_data *prod_data,
		struct cons_data *cons_data,
		struct worker_data *worker_data,
		int id)
{
	struct rte_event_dev_info dev_info;
	struct rte_event_dev_config config = {0};
	struct rte_event_queue_conf queue_config = {0};
	struct rte_event_port_conf port_config = {0};
	uint8_t queue_id;
	uint8_t priority;
	int prod_port = 0;
	int cons_port = 1;
	int worker_port_base = 2;
	int prod_qid = 0;
	int cons_qid = 1;
	int worker_qid = 2;
	unsigned int i;
	int ret;

	/* Better yet, always use event dev 0 so the app can use either. You can
	 * check that there's at least 1 eventdev with rte_event_dev_count().
	 */

	if (id < 0)
		rte_panic("%s: invalid ev_dev ID %d\n", __func__, id);
	else
		printf("%s: ev_dev ID %d\n", __func__, id);

	rte_event_dev_info_get(id, &dev_info);

	if (num_workers)
		config.nb_event_queues = 3;
	else
		config.nb_event_queues = 2;

	config.nb_single_link_event_port_queues = 2;
	config.nb_event_ports = num_workers +
		config.nb_single_link_event_port_queues;
	config.nb_events_limit = dev_info.max_num_events;
	config.nb_event_queue_flows = dev_info.max_event_queue_flows;
	config.nb_event_port_dequeue_depth =
					dev_info.max_event_port_dequeue_depth;
	config.nb_event_port_enqueue_depth =
					dev_info.max_event_port_enqueue_depth;
	config.dequeue_timeout_ns = 0;
	config.event_dev_cfg = RTE_EVENT_DEV_CFG_PER_DEQUEUE_TIMEOUT;

	ret = rte_event_dev_configure(id, &config);
	if (ret)
		rte_panic("Failed to configure the event dev\n");
	else
		printf("eventdev configured!\n");

	/* Create queues */
	queue_config.event_queue_cfg = 0;
	queue_config.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;
	queue_config.nb_atomic_order_sequences =
		(sched_type == RTE_SCHED_TYPE_ORDERED) ? 1024 : 0;
	queue_config.nb_atomic_flows = dev_info.max_event_queue_flows;
	queue_config.schedule_type = sched_type;

	if (num_workers) {
		ret = rte_event_queue_setup(id, worker_qid, &queue_config);
		if (ret < 0)
			rte_panic("Failed to create the scheduled QID\n");
		else
			printf("rte_event_queue_setup success for worker_qid\n");
	}

	queue_config.event_queue_cfg = RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	queue_config.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;

	cons_qid = 1;
	ret = rte_event_queue_setup(id, cons_qid, &queue_config);
	if (ret < 0)
		rte_panic("Failed to create the cons directed QID\n");
	else
		printf("rte_event_queue_setup success for cons_qid\n");

	queue_config.event_queue_cfg = RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	queue_config.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;

	prod_qid = 0;
	ret = rte_event_queue_setup(id, prod_qid, &queue_config);
	if (ret < 0)
		rte_panic("Failed to create the prod directed QID\n");
	else
		printf("rte_event_queue_setup success for prod_qid\n");

	/* Create two directed ports */

	port_config.dequeue_depth = dev_info.max_event_port_dequeue_depth;
	port_config.enqueue_depth = dev_info.max_event_port_enqueue_depth;

	/* Set producer new event threshold to 3/4 max */
	port_config.new_event_threshold = 3 * (dev_info.max_num_events >> 2);
	port_config.event_port_cfg = RTE_EVENT_PORT_CFG_SINGLE_LINK;
	ret = rte_event_port_setup(id, prod_port, &port_config);
	if (ret < 0)
		rte_panic("Failed to create the producer port\n");
	else
		printf("rte_event_port_setup for prod_port ok\n");

	/* Set consumer and worker new event threshold to max */
	port_config.new_event_threshold = dev_info.max_num_events;
	ret = rte_event_port_setup(id, cons_port, &port_config);
	if (ret < 0)
		rte_panic("Failed to create the consumer port\n");
	else
		printf("rte_event_port_setup for cons_port ok\n");

	port_config.event_port_cfg = 0;

	/* Create load-balanced worker ports */
	for (i = 0; i < num_workers; i++) {
		worker_data[i].event_port_id = i + worker_port_base;
		ret = rte_event_port_setup(id, worker_data[i].event_port_id,
					   &port_config);
		if (ret < 0)
			rte_panic("Failed to create worker port #%d\n", i);
		else
			printf("rte_event_port_setup for worker port %d ok\n",
			       i);
	}

	printf("link worker queues\n");
	/* Map ports/qids */
	for (i = 0; i < num_workers; i++) {
		queue_id = worker_qid;
		priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;

		ret = rte_event_port_link(id, worker_data[i].event_port_id,
					  &queue_id, &priority, 1);
		if (ret != 1)
			rte_panic("Failed to map worker%d port to worker_qid\n",
				  i);
	}

	printf("link consumer queue\n");
	/* Link consumer port to its QID */
	queue_id = cons_qid;
	priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;

	ret = rte_event_port_link(id, cons_port, &queue_id, &priority, 1);
	if (ret != 1)
		rte_panic("Failed to map consumer port to cons_qid\n");

	printf("link producer queue\n");
	/* Link producer port to its QID */
	queue_id = prod_qid;
	priority = RTE_EVENT_DEV_PRIORITY_HIGHEST;

	ret = rte_event_port_link(id, prod_port, &queue_id, &priority, 1);
	if (ret != 1)
		rte_panic("Failed to map producer port to prod_qid\n");

	/* Dispatch to workers */
	if (num_workers) {
		*prod_data = (struct prod_data){.event_dev_id = id,
						.event_port_id = prod_port,
						.qid = worker_qid};
		*cons_data = (struct cons_data){.event_dev_id = id,
						.event_port_id = cons_port};
		for (i = 0; i < num_workers; i++) {
			struct worker_data *w = &worker_data[i];
			w->event_dev_id = id;
			w->qid = cons_qid;
		}
	} else {
		*prod_data = (struct prod_data){.event_dev_id = id,
						.event_port_id = prod_port,
						.qid = cons_qid};
		*cons_data = (struct cons_data){.event_dev_id = id,
						.event_port_id = cons_port};
	}

	ret = rte_event_dev_start(id);
	if (ret)
		rte_panic("Failed to start the event dev\n");
	if (g_is_mbuf) {
		mp = rte_pktmbuf_pool_create("packet_pool",
				/* mbufs */ dev_info.max_num_events,
				/* cache_size */ 512,
				/* priv_size*/ 0,
				/* data_room_size */ 2048,
				rte_socket_id());

		if (mp == NULL) {
			printf("mbuf pool create failed\n");
			return -1;
		}
	}
	return (uint8_t) id;
}

int
main(int argc, char **argv)
{
	struct prod_data prod_data = {0};
	struct cons_data cons_data = {0};
	uint64_t start, end;
	struct worker_data *worker_data = NULL;
	unsigned int nworkers = 0;
	int lcore_id;
	int err;
	int has_prod = 0;
	int has_cons = 0;
	int evdev_id = 0; /* TODO - allow app to override */

	done = 0;
	quiet = 0;
	mp = NULL;
	g_is_mbuf = false;

	err = rte_eal_init(argc, argv);
	if (err < 0)
		rte_panic("Invalid EAL arguments\n");

	argc -= err;
	argv += err;

	/* Parse cli options*/
	parse_app_args(argc, argv);

	if (!quiet) {
		printf("  Config:\n");
		printf("\tworkers: %d\n", num_workers);
		printf("\tpackets: %"PRIu64"\n", num_packets);
		if (sched_type == RTE_SCHED_TYPE_ORDERED)
			printf("\tworker_qid type: ordered\n");
		if (sched_type == RTE_SCHED_TYPE_ATOMIC)
			printf("\tworker_qid type: atomic\n");
		printf("\n");
	}

	const unsigned int cores_needed = num_workers +
			/*main*/ 1 +
			/*producer*/ 1 +
			/*consumer*/ 1;

	if (!quiet) {
		printf("Number of cores available: %d\n", rte_lcore_count());
		printf("Number of cores to be used: %d\n", cores_needed);
	}

	if (rte_lcore_count() < cores_needed)
		rte_panic("Too few cores\n");

	const uint8_t ndevs = rte_event_dev_count();
	if (ndevs == 0)
		rte_panic(
			"No event devs found. Do you need"
			" to pass in a --vdev flag?\n");
	if (ndevs > 1)
		fprintf(stderr,
			"Warning: More than one event dev, but using idx 0");

	if (num_workers) {
		worker_data = rte_calloc(0, num_workers,
					 sizeof(worker_data[0]), 0);
		if (worker_data == NULL)
			rte_panic("rte_calloc failed\n");
	}

	uint8_t id = setup_event_dev(&prod_data, &cons_data, worker_data,
				    evdev_id);

	printf("setup_event_dev returned eventdev_id = %d\n", id);

	start = rte_rdtsc();

	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (has_prod && has_cons && nworkers == num_workers)
			break;

		if (!has_prod) {
			err = rte_eal_remote_launch(producer, &prod_data,
						    lcore_id);
			if (err)
				rte_panic("Failed to launch producer\n");
			printf("Launched producer\n");
			has_prod = 1;
			continue;
		}

		if (!has_cons) {
			err = rte_eal_remote_launch(consumer, &cons_data,
						    lcore_id);
			if (err)
				rte_panic("Failed to launch consumer\n");
			printf("Launched consumer\n");
			has_cons = 1;
			continue;
		}

		if (nworkers < num_workers) {
			err = rte_eal_remote_launch(worker,
						    &worker_data[nworkers],
						    lcore_id);
			if (err)
				rte_panic("Failed to launch worker%d\n",
					  nworkers);
			nworkers++;
			printf("Launched worker %d\n", nworkers);
			continue;
		}
	}

	rte_eal_mp_wait_lcore();
	end = rte_rdtsc();
	printf("[%s()] DLB scheduled %"PRIu64" packets in %"PRIu64" cycles\n",
	       __func__, num_packets, end - start);
	printf("[%s()] \t %f packets/sec\n",
	       __func__, (float) (num_packets * rte_get_timer_hz()) /
	       (float) (end - start));

	printf("Test Complete\n");

	/* Cleanup done automatically by kernel on app exit */

	return 0;
}
