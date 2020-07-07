/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 *
 * authors:
 *   Felix Moessbauer <felix.moessbauer@siemens.com>
 *   Henning Schild <henning.schild@siemens.com>
 *
 * launch (non-rt kernel): l2reflect --lcores 0@0,1@6 -n 1
 * launch (rt kernel): l2reflect --lcores 0@0,1@6 -n 1 -- -P 50 -r -l
 *
 * The l2reflect application implements a ping-pong benchmark to
 * measure the latency between two instances. For communication,
 * we use raw ethernet and send one packet at a time. The timing data
 * is collected locally and min/max/avg values are displayed in a TUI.
 * Finally, a histogram of the latencies is printed which can be
 * further processed with the jitterdebugger visualization scripts.
 * To debug latency spikes, a max threshold can be defined.
 * If it is hit, a trace point is created on both instances.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/signal.h>
#include <assert.h>
#include <unistd.h>
#include <sys/io.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdatomic.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>

#include "l2reflect.h"
#include "stats.h"

#define RTE_LOGTYPE_L2REFLECT RTE_LOGTYPE_USER1

#define NSEC_PER_SEC 1000000000

#define MBUF_SIZE (2048 + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)
#define NB_MBUF 2047

#define MAX_PKT_BURST 32
/* warmup a few round before starting the measurement */
#define WARMUP_ROUNDS 42

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

static struct timespec last_sent, last_recv;
static int quiet, disable_int, priority, policy, l2reflect_mlock,
	l2reflect_interrupt, trace_fd;

static atomic_int sleep_start;

static uint64_t rounds;
static int quiet, disable_int, priority, policy, l2reflect_mlock,
	l2reflect_interrupt, trace_fd;

/* Configurable number of RX/TX ring descriptors */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

static uint32_t l2reflect_q;
static uint64_t l2reflect_break_usec = UINT64_MAX;
static uint64_t l2reflect_break_usec;

static struct rte_ether_addr ether_bcast_addr = {
	.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

struct rte_mempool *l2reflect_pktmbuf_pool;

static void
l2reflect_usage(const char *prgname)
{
	printf("%s [EAL options] -- [-p PORT] -P [PRIO] [-b USEC] [-r] [-f] [-l]"
	       "[-s] [-q] [-d] [-S] [-i MSEC]\n"
	       "  -p PORT: port to configure\n"
	       "  -P PRIO: scheduling priority to use\n"
	       "  -b USEC: break when latency > USEC\n"
	       "  -r: scheduling policy SCHED_RR\n"
	       "  -f: scheduling policy SCHED_FIFO\n"
	       "  -l: lock memory (mlockall)\n"
	       "  -s: send one packet on startup\n"
	       "  -q: quiet, do not print stats\n"
	       "  -d: die die die cli\n"
	       "  -H USEC: create histogram of latencies with USEC time slices\n"
	       "  -F FILE: write histogram to file\n"
	       "  -S: start processing threads in sleep, wake with SIGUSR2\n"
	       "  -i MSEC: use interrupts instead of polling (cont. on interrupt or after MSEC)\n",
	       prgname);
}

/* Parse the argument given in the command line of the application */
static int
l2reflect_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];
	static struct option lgopts[] = { { NULL, 0, 0, 0 } };

	argvopt = argv;
	policy = SCHED_OTHER;
	hist_filename = NULL;
	l2reflect_output_hist = 0;

	while ((opt = getopt_long(argc, argvopt, "p:P:b:H:F:i:sqdrflS", lgopts,
				  &option_index)) != EOF) {
		switch (opt) {
		/* port */
		case 'p':
			l2reflect_port_number =
				(uint16_t)strtoul(optarg, NULL, 10);
			break;
		case 'P':
			priority = strtoul(optarg, NULL, 10);
			if (priority > 0) {
				if (policy == SCHED_OTHER)
					policy = SCHED_RR;
				l2reflect_mlock = 1;
			}
			break;
		case 'b':
			l2reflect_break_usec = strtoul(optarg, NULL, 10);
			break;
		case 'S':
			sleep_start = 1;
			break;
		case 'q':
			quiet = 1;
			break;
		case 'd':
			disable_int = 1;
			break;
		case 'r':
			policy = SCHED_RR;
			break;
		case 'f':
			policy = SCHED_FIFO;
			break;
		case 'l':
			l2reflect_mlock = 1;
			break;
		case 'H':
			l2reflect_hist = 1;
			hist_bucket_usec = strtoul(optarg, NULL, 10);
#ifndef RTE_HAS_CJSON
			printf("not compiled with cjson support\n");
			return -1;
#endif
			break;
		case 'F':
			hist_filename = strndup(optarg, 128);
			break;
		case 'i':
			l2reflect_interrupt = 1;
			l2reflect_sleep_msec = strtoul(optarg, NULL, 10);
			break;
		default:
			l2reflect_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;

	if (hist_filename && !l2reflect_hist) {
		printf("-F switch requires -H switch as well\n");
		return -1;
	}

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

__rte_format_printf(1, 0)
static void
trace_write(const char *fmt, ...)
{
	va_list ap;
	char buf[256];
	int n, err;

	if (trace_fd == 0)
		trace_fd = open("/sys/kernel/debug/tracing/trace_marker",
				O_WRONLY);
	if (trace_fd < 0)
		return;

	va_start(ap, fmt);
	n = vsnprintf(buf, 256, fmt, ap);
	va_end(ap);

	err = write(trace_fd, buf, n);
	assert(err >= 1);
}

/* Send a burst of one packet */
static int
l2reflect_send_packet(struct rte_mbuf **m, uint16_t port)
{
	unsigned int ret;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;
	uint16_t type;

	eth = rte_pktmbuf_mtod(*m, struct rte_ether_hdr *);
	pkt = (struct my_magic_packet *)eth;
	type = pkt->type;

	ret = rte_eth_tx_burst(port, l2reflect_q, m, 1);
	if (unlikely(ret < 1)) {
		rte_pktmbuf_free(*m);
	} else {
		if (type == TRACE_TYPE_DATA) {
			clock_gettime(CLOCK_MONOTONIC, &last_sent);
			l2reflect_state = S_RUNNING;
		}
	}
	return 0;
}

static void
l2reflect_simple_forward(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	pkt = (struct my_magic_packet *)eth;

	/* dst addr */
	rte_ether_addr_copy(&eth->s_addr, &eth->d_addr);
	/* src addr */
	rte_ether_addr_copy(&l2reflect_port_eth_addr, &eth->s_addr);

	if ((eth->ether_type == rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT)) &&
	    (pkt->magic == MAGIC_TRACE_PAYLOAD)) {
		/* and the native one */
		trace_write("sending traced packet\n");
	}

	l2reflect_send_packet(&m, l2reflect_port_number);
}

static struct rte_mbuf *
l2reflect_new_pkt(unsigned int type)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;

	m = rte_pktmbuf_alloc(l2reflect_pktmbuf_pool);
	if (m == NULL)
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc failed\n");

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (l2reflect_state != S_ELECT_LEADER)
		rte_ether_addr_copy(&l2reflect_remote_eth_addr, &eth->d_addr);
	else
		rte_ether_addr_copy(&ether_bcast_addr, &eth->d_addr);

	/* src addr */
	rte_ether_addr_copy(&l2reflect_port_eth_addr, &eth->s_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT);

	m->data_len = 64;
	m->nb_segs = 1;
	m->pkt_len = 64;
	m->l2_len = sizeof(struct rte_ether_hdr);

	pkt = (struct my_magic_packet *)eth;
	pkt->type = type;
	pkt->breakval = l2reflect_break_usec;

	return m;
}

static void
l2reflect_send_reset(void)
{
	struct rte_mbuf *m;
	m = l2reflect_new_pkt(TRACE_TYPE_RSET);
	l2reflect_send_packet(&m, l2reflect_port_number);
}

static void
l2reflect_send_quit(void)
{
	struct rte_mbuf *m;
	m = l2reflect_new_pkt(TRACE_TYPE_QUIT);
	l2reflect_send_packet(&m, l2reflect_port_number);
}

static void
l2reflect_new_ball(void)
{
	struct rte_mbuf *pnewball;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;

	printf("Should create a packet to play with ...\n");
	pnewball = l2reflect_new_pkt(TRACE_TYPE_DATA);

	eth = rte_pktmbuf_mtod(pnewball, struct rte_ether_hdr *);

	printf("from MAC address: %02X:%02X:%02X:%02X:%02X:%02X to"
			" %02X:%02X:%02X:%02X:%02X:%02X\n\n",
			eth->s_addr.addr_bytes[0], eth->s_addr.addr_bytes[1],
			eth->s_addr.addr_bytes[2], eth->s_addr.addr_bytes[3],
			eth->s_addr.addr_bytes[4], eth->s_addr.addr_bytes[5],
			eth->d_addr.addr_bytes[0], eth->d_addr.addr_bytes[1],
			eth->d_addr.addr_bytes[2], eth->d_addr.addr_bytes[3],
			eth->d_addr.addr_bytes[4], eth->d_addr.addr_bytes[5]);

	pkt = (struct my_magic_packet *)eth;

	/* we are tracing lets tell the others */
	if (l2reflect_break_usec)
		pkt->magic = MAGIC_TRACE_PAYLOAD;

	l2reflect_send_packet(&pnewball, l2reflect_port_number);
}

static inline int64_t
calcdiff_ns(struct timespec t1, struct timespec t2)
{
	int64_t diff;
	diff = NSEC_PER_SEC * (int64_t)((int)t1.tv_sec - (int)t2.tv_sec);
	diff += ((int)t1.tv_nsec - (int)t2.tv_nsec);
	return diff;
}

static inline unsigned int
l2reflect_rx_filter(
	struct rte_mbuf **bufs,
	unsigned int nb_rx,
	unsigned int data_only)
{
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;
	unsigned int i, ret;

	ret = 0;
	for (i = 0; i < nb_rx; i++) {
		eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);
		if (l2reflect_state != S_ELECT_LEADER &&
		    !ether_addr_cmp(&eth->s_addr, &l2reflect_remote_eth_addr))
			goto drop;

		if (eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT))
			goto drop;

		pkt = (struct my_magic_packet *)eth;
		if (data_only && (pkt->type != TRACE_TYPE_DATA &&
				  pkt->type != TRACE_TYPE_RSET &&
				  pkt->type != TRACE_TYPE_QUIT))
			goto drop;

		bufs[ret++] = bufs[i];
		continue;
drop:
		rte_pktmbuf_free(bufs[i]);
	}

	return ret;
}

static int
elect_leader(uint16_t portid)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;
	uint64_t my_mac, other_mac, breakval;
	unsigned int i, nb_rx;
	int i_win;
	int searching = 1;

	other_mac = 0ULL;
	my_mac = 0ULL;
	breakval = 0;

	while (l2reflect_state == S_ELECT_LEADER) {
		nb_rx = rte_eth_rx_burst(portid, l2reflect_q, pkts_burst,
					 MAX_PKT_BURST);
		nb_rx = l2reflect_rx_filter(pkts_burst, nb_rx, 0);
		for (i = 0; i < nb_rx && searching; i++) {
			eth = rte_pktmbuf_mtod(pkts_burst[i],
					       struct rte_ether_hdr *);
			pkt = (struct my_magic_packet *)eth;
			if (pkt->type == TRACE_TYPE_HELO ||
			    pkt->type == TRACE_TYPE_EHLO) {
				l2reflect_state = S_RUNNING;
				rte_ether_addr_copy(&eth->s_addr,
						    &l2reflect_remote_eth_addr);
				rte_ether_addr_copy(
					&eth->s_addr,
					(struct rte_ether_addr *)&other_mac);
				rte_ether_addr_copy(
					&l2reflect_port_eth_addr,
					(struct rte_ether_addr *)&my_mac);
				breakval = pkt->breakval;
				/* break, but cleanup */
				searching = 0;
			}
			if (pkt->type == TRACE_TYPE_HELO) {
				m = l2reflect_new_pkt(TRACE_TYPE_EHLO);
				RTE_LOG(INFO, L2REFLECT, "found one EHLO\n");
				l2reflect_send_packet(&m,
						      l2reflect_port_number);
			}
			rte_pktmbuf_free(pkts_burst[i]);
		}
		m = l2reflect_new_pkt(TRACE_TYPE_HELO);
		RTE_LOG(INFO, L2REFLECT, "looking for player HELO\n");
		l2reflect_send_packet(&m, l2reflect_port_number);
		usleep(500000);
	}
	/* leave election logic */
	if (l2reflect_state != S_RUNNING)
		return 0;

	if (my_mac == other_mac)
		rte_exit(EXIT_FAILURE, "talking to myself ... confused\n");

	/* the one with the bigger MAC is the leader */
	i_win = (my_mac > other_mac);

	RTE_LOG(INFO, L2REFLECT, "i am the \"%s\"\n", i_win ? "rick" : "morty");

	/* looser takes tracing break value from winner */
	if (!i_win)
		l2reflect_break_usec = breakval;

	return i_win;
}

/*
 * add the measured time diff to the statistics.
 * return false if threshold is hit
 */
static inline bool
add_to_record(const uint64_t diff)
{
	record.rounds++;
	/* do not count the first rounds, diff would be too high */
	if (record.rounds > WARMUP_ROUNDS) {
		if (l2reflect_hist) {
			const uint64_t bucket =
				MIN(diff / (hist_bucket_usec * 1000),
				    HIST_CAP_BUCKET);
			record.hist[bucket]++;
		}

		record.avg_round += (double)diff;
		if (diff < record.min_round)
			record.min_round = diff;
		if (diff > record.max_round) {
			record.max_round = diff;
			if (l2reflect_break_usec &&
				(record.max_round >
					l2reflect_break_usec *
						1000))
				return false;
		}
	}
	return true;
}

/*
 * process a single packet.
 * return false if latency threshold is hit
 */
static inline bool
process_packet(
	struct my_magic_packet *pkt,
	uint64_t *diff)
{
	if (pkt->type == TRACE_TYPE_DATA) {
		clock_gettime(CLOCK_MONOTONIC, &last_recv);
		*diff = calcdiff_ns(last_recv, last_sent);
		if (!add_to_record(*diff))
			return false;
	}
	if (pkt->magic == MAGIC_TRACE_PAYLOAD) {
		/* and the native one */
		trace_write("received traced packet\n");
	}
	return true;
}

/* main processing loop */
static void
l2reflect_main_loop(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned int lcore_id;
	unsigned int j, nb_rx, nb_evt;
	uint16_t portid;
	uint64_t diff = 0;
	int sender;
	struct my_magic_packet *pkt;
	struct rte_ether_hdr *eth;
	struct rte_epoll_event event;

	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, L2REFLECT, "entering main loop on lcore %u\n", lcore_id);

	portid = l2reflect_port_number;
	RTE_LOG(INFO, L2REFLECT, " -- lcoreid=%u portid=%u\n", lcore_id,
		portid);

restart:
	init_record();
	l2reflect_state = S_ELECT_LEADER;
	sender = elect_leader(portid);

	/* we are the sender so we bring one ball into the game */
	if (sender)
		l2reflect_new_ball();

	while (l2reflect_state == S_RUNNING) {
		if (l2reflect_interrupt) {
			rte_eth_dev_rx_intr_enable(portid, l2reflect_q);
			/* wait for interrupt or timeout */
			nb_evt = rte_epoll_wait(RTE_EPOLL_PER_THREAD, &event, 1,
						l2reflect_sleep_msec);
			rte_eth_dev_rx_intr_disable(portid, l2reflect_q);
			if (nb_evt == 0 && rounds > WARMUP_ROUNDS)
				++record.timeouts;
		}

		nb_rx = rte_eth_rx_burst(portid, l2reflect_q, pkts_burst,
					 MAX_PKT_BURST);

		/* TODO use drivers/hw to filter mac */
		nb_rx = l2reflect_rx_filter(pkts_burst, nb_rx, 1);

		/* remote is telling us to reset or stop */
		if (nb_rx) {
			eth = rte_pktmbuf_mtod(pkts_burst[0],
					       struct rte_ether_hdr *);
			pkt = (struct my_magic_packet *)eth;
			if (eth->ether_type ==
				rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT)) {
				if (pkt->type == TRACE_TYPE_RSET) {
					rte_pktmbuf_free(pkts_burst[0]);
					goto restart;
				}
				if (pkt->type == TRACE_TYPE_QUIT) {
					l2reflect_state = S_REMOTE_TERM;
					break;
				}
			}
		}

		if (l2reflect_state == S_RUNNING && nb_rx) {
			eth = rte_pktmbuf_mtod(pkts_burst[0],
					struct rte_ether_hdr *);
			pkt = (struct my_magic_packet *)eth;
			if (eth->ether_type ==
				rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT)) {
				if (!process_packet(pkt, &diff))
					break;
			}
		}
		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			rte_prefetch0(rte_pktmbuf_mtod(m, void *));
			l2reflect_simple_forward(m);
		}
	}
	const int state_cpy = l2reflect_state;
	switch (state_cpy) {
	case S_RESET_TRX:
		l2reflect_send_reset();
		l2reflect_state = S_ELECT_LEADER;
	case S_ELECT_LEADER:
		goto restart;
	}

	if (state_cpy == S_LOCAL_TERM) {
		l2reflect_send_quit();
		if (record.max_round > l2reflect_break_usec) {
			printf("hit latency threshold (%" PRIu64
			       ".%03u > %" PRIu64 ")\n",
			       diff / 1000, (unsigned int)(diff % 1000),
			       l2reflect_break_usec);
		}
	} else if (state_cpy == S_REMOTE_TERM) {
		printf("received message that remote hit threshold (or is cancelled)\n");
	}
}

static int
l2reflect_launch_one_lcore(__rte_unused void *dummy)
{
	struct sched_param param;
	int err;

	if (sleep_start) {
		printf("Sleeping and waiting for SIGCONT\n");
		while (sleep_start)
			usleep(10000);

		printf("Got SIGCONT, continuing");
	}
	if (l2reflect_mlock) {
		err = mlockall(MCL_CURRENT | MCL_FUTURE);
		if (err)
			rte_exit(EXIT_FAILURE, "mlockall failed: %s\n",
				 strerror(errno));
	}
	if (priority > 0 || policy != SCHED_OTHER) {
		memset(&param, 0, sizeof(param));
		param.sched_priority = priority;
		err = sched_setscheduler(0, policy, &param);
		if (err)
			rte_exit(EXIT_FAILURE,
				 "sched_setscheduler failed: %s\n",
				 strerror(errno));
	}
	if (l2reflect_interrupt) {
		err = rte_eth_dev_rx_intr_ctl_q(l2reflect_port_number,
						l2reflect_q,
						RTE_EPOLL_PER_THREAD,
						RTE_INTR_EVENT_ADD, NULL);
		if (err)
			rte_exit(EXIT_FAILURE,
				 "could not register I/O interrupt\n");
	}
	l2reflect_main_loop();
	return 0;
}

static void
sig_handler(int signum)
{
	switch (signum) {
	case SIGUSR1:
		if (l2reflect_state == S_RUNNING)
			l2reflect_state = S_RESET_TRX;
		break;
	case SIGUSR2:
		l2reflect_output_hist = 1;
		break;
	case SIGCONT:
		sleep_start = 0;
		break;
	case SIGHUP:
	case SIGINT:
		l2reflect_state = S_LOCAL_TERM;
		break;
	}
}

int
main(int argc, char **argv)
{
	struct rte_eth_dev_info dev_info;
	int ret;
	uint32_t i;
	uint16_t nb_ports;
	unsigned int lcore_id;
	struct sigaction action;
	bzero(&action, sizeof(action));
	char mempool_name[128];

	action.sa_handler = sig_handler;
	if (sigaction(SIGHUP, &action, NULL) < 0 ||
	    sigaction(SIGUSR1, &action, NULL) < 0 ||
	    sigaction(SIGUSR2, &action, NULL) < 0 ||
	    sigaction(SIGCONT, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0) {
		rte_exit(EXIT_FAILURE, "Could not register signal handler\n");
	}

	lcore_id = rte_lcore_id();
	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL arguments\n");
	argc -= ret;
	argv += ret;

	/* parse application arguments (after the EAL ones) */
	ret = l2reflect_parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L2REFLECT arguments\n");

	snprintf(mempool_name, sizeof(mempool_name), "mbuf_pool_%d", getpid());
	printf("About to create mempool \"%s\"\n", mempool_name);
	/* create the mbuf pool */
	l2reflect_pktmbuf_pool =
		rte_mempool_create(mempool_name, NB_MBUF, MBUF_SIZE,
			MAX_PKT_BURST, sizeof(struct rte_pktmbuf_pool_private),
			rte_pktmbuf_pool_init, NULL,
			rte_pktmbuf_init, NULL, rte_socket_id(), 0);

	if (l2reflect_pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE,
			 "Cannot init/find mbuf pool name %s\nError: %d %s\n",
			 mempool_name, rte_errno, rte_strerror(rte_errno));

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports - bye\n");
	if (l2reflect_port_number + 1 > nb_ports)
		rte_exit(EXIT_FAILURE, "Chosen port %d does not exist - bye\n",
			 l2reflect_port_number);
	printf("We have %d ports and will use port %d\n", nb_ports,
	       l2reflect_port_number);

	rte_eth_dev_info_get(l2reflect_port_number, &dev_info);
	printf("Initializing port %u... ", l2reflect_port_number);
	fflush(stdout);

	if (l2reflect_interrupt)
		port_conf.intr_conf.rxq = 1;
	ret = rte_eth_dev_configure(l2reflect_port_number, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%s, port=%u\n",
			 strerror(-ret), l2reflect_port_number);

	rte_eth_macaddr_get(l2reflect_port_number, &l2reflect_port_eth_addr);

	/* init RX queues */
	fflush(stdout);
	for (i = 0; i <= l2reflect_q; i++) {
		ret = rte_eth_rx_queue_setup(
			l2reflect_port_number, i, nb_rxd,
			rte_eth_dev_socket_id(l2reflect_port_number), NULL,
			l2reflect_pktmbuf_pool);
		if (ret < 0)
			rte_exit(
				EXIT_FAILURE,
				"rte_eth_rx_queue_setup:err=%s, port=%u q=%u\n",
				strerror(-ret), l2reflect_port_number, i);
	}

	/* init one TX queue on each port */
	fflush(stdout);
	ret = rte_eth_tx_queue_setup(
		l2reflect_port_number, 0, nb_txd,
		rte_eth_dev_socket_id(l2reflect_port_number), NULL);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_tx_queue_setup:err=%s, port=%u\n",
			 strerror(-ret), (unsigned int)l2reflect_port_number);

	/* Start device */
	ret = rte_eth_dev_start(l2reflect_port_number);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%s, port=%u\n",
			 strerror(-ret), (unsigned int)l2reflect_port_number);

	rte_eth_promiscuous_enable(l2reflect_port_number);

	printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
	       (unsigned int)l2reflect_port_number,
	       l2reflect_port_eth_addr.addr_bytes[0],
	       l2reflect_port_eth_addr.addr_bytes[1],
	       l2reflect_port_eth_addr.addr_bytes[2],
	       l2reflect_port_eth_addr.addr_bytes[3],
	       l2reflect_port_eth_addr.addr_bytes[4],
	       l2reflect_port_eth_addr.addr_bytes[5]);

	/*
	 * in quiet mode the master executes the main packet loop
	 * otherwise the one slave does it and the master prints stats
	 */
	if (quiet) {
		assert(rte_lcore_count() == 1);
		if (disable_int) {
			iopl(3);
			asm("cli");
		}
		l2reflect_launch_one_lcore(NULL);
	} else {
		assert(rte_lcore_count() == 2);
		/* the slave reflects the packets */
		RTE_LCORE_FOREACH_SLAVE(lcore_id)
		{
			rte_eal_remote_launch(l2reflect_launch_one_lcore, NULL,
					      lcore_id);
		}

		/* the master prints the stats */
		init_record();
		l2reflect_stats_loop();
		rte_eal_mp_wait_lcore();
	}
	rte_eal_cleanup();

	if (l2reflect_hist)
		output_histogram_snapshot();

	cleanup_record();

	if (trace_fd)
		close(trace_fd);

	return 0;
}
