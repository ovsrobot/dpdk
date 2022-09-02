/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 *
 * The l2reflect application implements a ping-pong benchmark to
 * measure the latency between two instances. For communication,
 * we use raw ethernet and send one packet at a time. The timing data
 * is collected locally and min/max/avg values are displayed in a TUI.
 * Finally, a histogram of the latencies is printed which can be
 * further processed with the jitterdebugger visualization scripts.
 * To debug latency spikes, a max threshold can be defined.
 * If it is hit, a trace point is created on both instances.
 *
 * Examples:
 *   launch (non-rt kernel): l2reflect --lcores 0@0,1@6 -n 1
 *   launch (rt kernel): l2reflect --lcores 0@0,1@6 -n 1 -- -P 50 -r -l
 *
 * For histogram data, launch with -H <usec> -F <output file>, e.g.
 * -H 10 -F histogram.json for a histogram with 10 usec buckets which
 * is written to a histogram.json file. This file can then be visualized
 * using the jitterdebugger plotting scripts:
 *   jitterplot hist histogram.json
 *
 * While the application is running, it can be controlled by sending
 * signals to one of the processes:
 * - SIGUSR1: reset the min/max/avg on both instances
 * - SIGUSR2: output / write the current histogram
 * - SIGHUP/SIGINT: gracefully terminate both instances
 *
 * Note on wiring:
 * The l2reflect application sends the packets via a physical ethernet
 * interface. When running both instances on a single system, at least
 * two dedicated physical ports and a (physical) loopback between them
 * is required.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>
#include <getopt.h>
#include <sys/signal.h>
#include <assert.h>
#include <unistd.h>
#ifdef HAS_SYS_IO
#include <sys/io.h>
#endif
#include <sched.h>
#include <sys/mman.h>
#include <stdatomic.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_eal_trace.h>
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
#include "payload.h"
#include "utils.h"
#include "colors.h"
#include "stats.h"

#define NSEC_PER_SEC 1000000000

#define NB_MBUF 2047

#define MAX_PKT_BURST 32
/* warmup a few round before starting the measurement */
#define WARMUP_ROUNDS 42

/* break after one second */
#define DEFAULT_BREAKVAL_USEC 1000000ull
/* break if no rx for more than this rounds */
#define RX_TIMEOUT_MASK ~0xFFFFFull

/* delay between two election packets */
#define DELAY_ELECTION_MS 500

int l2reflect_hist;
unsigned int l2reflect_hist_buckets = HIST_NUM_BUCKETS_DEFAULT;
atomic_int l2reflect_output_hist;
int l2reflect_fake_mac;
int l2reflect_interrupt;
uint64_t l2reflect_sleep_msec;
uint64_t l2reflect_pkt_bytes = 64;
uint16_t l2reflect_port_number;
atomic_int l2reflect_state;
struct rte_ether_addr l2reflect_port_eth_addr;
struct rte_ether_addr l2reflect_remote_eth_addr;

static struct timespec last_sent, last_recv;
static int quiet, disable_int, priority, policy, l2reflect_mlock;

static atomic_int sleep_start;
static uint64_t rounds;

/* Configurable number of RX/TX ring descriptors */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 128
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

static uint32_t l2reflect_q;
static uint64_t l2reflect_break_usec = DEFAULT_BREAKVAL_USEC;

static struct rte_ether_addr ether_bcast_addr = {
	.addr_bytes = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }
};

struct rte_mempool *l2reflect_pktmbuf_pool;

static void
l2reflect_usage(const char *prgname)
{
	printf("%s [EAL options] -- [-p PORT] -P [PRIO] [-b USEC] [-n SIZE] [-r] [-f] [-l]"
	       "[-q] [-d] [-H USEC] [-B NUM] [-F FILE] [-S] [-i MSEC] [-m] [-c] [-h]\n"
	       "  -p PORT: port to configure\n"
	       "  -P PRIO: scheduling priority to use\n"
	       "  -b USEC: break when latency > USEC\n"
	       "  -n SIZE: size of packet in bytes [%i,%i]\n"
	       "           (when using jumbo frames, sender and receiver values have to match)\n"
	       "  -r: scheduling policy SCHED_RR\n"
	       "  -f: scheduling policy SCHED_FIFO\n"
	       "  -l: lock memory (mlockall)\n"
	       "  -q: quiet, do not print stats\n"
#ifdef HAS_SYS_IO
	       "  -d: ignore maskable interrupts\n"
#endif
	       "  -H USEC: create histogram of latencies with USEC time slices\n"
	       "  -B NUM: number of histogram buckets\n"
	       "  -F FILE: write histogram to file\n"
	       "  -S: start processing threads in sleep, wake with SIGCONT\n"
	       "  -i MSEC: use interrupts instead of polling (cont. on interrupt or after MSEC)\n"
	       "  -m: fake the source mac addr by adding 1 to the last tuple\n"
	       "  -c: disable colored output\n"
	       "  -h: display help message\n",
	       prgname, RTE_ETHER_MIN_LEN, MAX_JUMBO_PKT_LEN);
}

static int
check_opts_for_help(int argc, char **argv, void(*display_help)(const char *))
{
	if (argc > 2 && !strncmp(argv[1], "--", 3)) {
		if (!strncmp(argv[2], "-h", 3) || !strncmp(argv[2], "--help", 7)) {
			display_help(argv[0]);
			return 1;
		}
	}
	return 0;
}

/* Parse the argument given in the command line of the application */
static int
l2reflect_parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	int opt_colors = 1;
	char *prgname = argv[0];
	static struct option lgopts[] = { { NULL, 0, 0, 0 } };

	argvopt = argv;
	policy = SCHED_OTHER;
	hist_filename = NULL;
	l2reflect_output_hist = 0;

	while ((opt = getopt_long(argc, argvopt, "p:P:b:H:B:F:i:n:qdrflScm", lgopts,
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
#ifndef RTE_HAS_JANSSON
			printf("not compiled with cjson support\n");
			return -1;
#endif
			break;
		case 'B':
			l2reflect_hist_buckets = strtoul(optarg, NULL, 10);
			break;
		case 'F':
			hist_filename = strndup(optarg, 128);
			break;
		case 'i':
			l2reflect_interrupt = 1;
			l2reflect_sleep_msec = strtoul(optarg, NULL, 10);
			break;
		case 'n':
			l2reflect_pkt_bytes = strtoull(optarg, NULL, 10);
			if (l2reflect_pkt_bytes < RTE_ETHER_MIN_LEN ||
			   l2reflect_pkt_bytes > MAX_JUMBO_PKT_LEN) {
				printf("packet size %" PRIu64 " not valid\n", l2reflect_pkt_bytes);
				return -1;
			}
			if (l2reflect_pkt_bytes > RTE_MBUF_DEFAULT_DATAROOM) {
				printf("NOT IMPLEMENTED. Packet size %" PRIu64 " requires segmented buffers.\n",
					l2reflect_pkt_bytes);
				return -1;
			}
			break;
		case 'c':
			opt_colors = 0;
			break;
		case 'm':
			l2reflect_fake_mac = 1;
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

	/* output is redirected, disable coloring */
	if (!isatty(fileno(stdout)))
		opt_colors = 0;

	enable_colors(opt_colors);

	ret = optind - 1;
	optind = 0; /* reset getopt lib */
	return ret;
}

/* Send a burst of one packet */
static inline int
l2reflect_send_packet(struct rte_mbuf **m, uint16_t port)
{
	unsigned int ret;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;
	uint16_t type;

	eth = rte_pktmbuf_mtod(*m, struct rte_ether_hdr *);
	pkt = (struct my_magic_packet *)eth;
	type = pkt->type;

	if (likely(type == TRACE_TYPE_DATA))
		clock_gettime(CLOCK_MONOTONIC, &last_sent);
	ret = rte_eth_tx_burst(port, l2reflect_q, m, 1);
	if (unlikely(ret < 1))
		rte_pktmbuf_free(*m);
	return 0;
}

static inline void
l2reflect_simple_forward(struct rte_mbuf *m)
{
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
	pkt = (struct my_magic_packet *)eth;

	/* dst addr */
	rte_ether_addr_copy(&eth->src_addr, &eth->dst_addr);
	/* src addr */
	rte_ether_addr_copy(&l2reflect_port_eth_addr, &eth->src_addr);

	if (unlikely(pkt->magic == MAGIC_TRACE_PAYLOAD))
		rte_eal_trace_generic_str("sending traced packet");

	l2reflect_send_packet(&m, l2reflect_port_number);
}

static struct rte_mbuf *
l2reflect_new_pkt(unsigned int type)
{
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct my_magic_packet *pkt;
	uint64_t frame_bytes = RTE_ETHER_MIN_LEN;

	m = rte_pktmbuf_alloc(l2reflect_pktmbuf_pool);
	if (m == NULL)
		rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc failed\n");

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	if (type == TRACE_TYPE_DATA)
		frame_bytes = l2reflect_pkt_bytes;

	/* zero out packet to make dumps better readable */
	memset(eth, 0, frame_bytes - RTE_ETHER_CRC_LEN);

	if (type == TRACE_TYPE_HELO)
		rte_ether_addr_copy(&ether_bcast_addr, &eth->dst_addr);
	else
		rte_ether_addr_copy(&l2reflect_remote_eth_addr, &eth->dst_addr);

	/* src addr */
	rte_ether_addr_copy(&l2reflect_port_eth_addr, &eth->src_addr);
	eth->ether_type = rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT);

	m->data_len = frame_bytes - RTE_ETHER_CRC_LEN;
	m->pkt_len = frame_bytes - RTE_ETHER_CRC_LEN;

	pkt = (struct my_magic_packet *)eth;
	pkt->type = type;
	pkt->breakval = l2reflect_break_usec;
	pkt->req_pkt_bytes = l2reflect_pkt_bytes;

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
	char mac_src_str[RTE_ETHER_ADDR_FMT_SIZE];
	char mac_dst_str[RTE_ETHER_ADDR_FMT_SIZE];

	RTE_LOG(INFO, L2REFLECT, "Should create a packet to play with ...\n");
	pnewball = l2reflect_new_pkt(TRACE_TYPE_DATA);

	eth = rte_pktmbuf_mtod(pnewball, struct rte_ether_hdr *);

	rte_ether_format_addr(mac_src_str, sizeof(mac_src_str), &l2reflect_port_eth_addr);
	rte_ether_format_addr(mac_dst_str, sizeof(mac_dst_str), &l2reflect_remote_eth_addr);
	RTE_LOG(INFO, L2REFLECT, "from MAC address: %s to %s\n\n", mac_src_str, mac_dst_str);

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

/* filter the received packets for actual l2reflect messages */
static inline unsigned int
l2reflect_rx_filter(
	struct rte_mbuf *buf)
{
	struct rte_ether_hdr *eth;
	eth = rte_pktmbuf_mtod(buf, struct rte_ether_hdr *);

	if (unlikely(buf->nb_segs > 1))
		RTE_LOG(WARNING, L2REFLECT, "Segmented packet: data-len: %i, pkt-len: %i, #seg: %i\n",
			buf->data_len, buf->pkt_len, buf->nb_segs);

	/* check for the l2reflect ether type */
	if (unlikely(eth->ether_type != rte_cpu_to_be_16(ETHER_TYPE_L2REFLECT)))
		return 0;

	/*
	 * if the packet is not from our partner
	 * (and we already have a partner), drop it
	 */
	if (unlikely(l2reflect_state != S_ELECT_LEADER &&
		!rte_is_same_ether_addr(&eth->src_addr, &l2reflect_remote_eth_addr)))
		return 0;

	/* filter bounce-back packets */
	if (unlikely(rte_is_same_ether_addr(&eth->src_addr, &l2reflect_port_eth_addr)))
		return 0;

	return 1;
}

/*
 * automatically elect the leader of the benchmark by
 * sending out HELO packets and waiting for responses.
 * On response, the mac addresses are compared and the
 * numerically larger one becomes the leader.
 */
static int
elect_leader(uint16_t portid)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	struct rte_ether_hdr *eth;
	struct rte_ether_addr *src_addr;
	struct rte_eth_dev_info dev_info;
	struct my_magic_packet *pkt;
	unsigned int i, nb_rx;
	int ehlo_send = 0;
	int i_win;

	while (l2reflect_state == S_ELECT_LEADER) {
		/* send a packet to make sure the MAC addr of this interface is publicly known */
		m = l2reflect_new_pkt(TRACE_TYPE_HELO);
		RTE_LOG(INFO, L2REFLECT, "looking for player HELO\n");
		l2reflect_send_packet(&m, l2reflect_port_number);
		rte_delay_ms(DELAY_ELECTION_MS);

		/* receive election packets */
		nb_rx = rte_eth_rx_burst(portid, l2reflect_q, pkts_burst,
					 MAX_PKT_BURST);

		/* note: do not short-circuit as otherwise the mbufs are not freed */
		for (i = 0; i < nb_rx; i++) {
			m = pkts_burst[i];
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			src_addr = &eth->src_addr;
			pkt = (struct my_magic_packet *)eth;

			if (!l2reflect_rx_filter(m)) {
				rte_pktmbuf_free(m);
				continue;
			}

			if (pkt->type == TRACE_TYPE_EHLO && l2reflect_state == S_ELECT_LEADER) {
				/* check if both modes are equal */
				if (((l2reflect_pkt_bytes <= RTE_ETHER_MTU)
				   != (pkt->req_pkt_bytes <= RTE_ETHER_MTU))) {
					l2reflect_state = S_LOCAL_TERM;
					m = l2reflect_new_pkt(TRACE_TYPE_QUIT);
					l2reflect_send_packet(&m, l2reflect_port_number);
					rte_exit(EXIT_FAILURE,
						"remote and local jumbo config does not match "
						"(%" PRIu64 " vs %" PRIu64 ")\n",
						l2reflect_pkt_bytes, pkt->req_pkt_bytes);
				}
				if (l2reflect_pkt_bytes != pkt->req_pkt_bytes) {
					l2reflect_pkt_bytes = MAX(l2reflect_pkt_bytes,
								  pkt->req_pkt_bytes);
					rte_eth_dev_info_get(l2reflect_port_number, &dev_info);
					const uint32_t overhead_len = eth_dev_get_overhead_len(
									dev_info.max_rx_pktlen,
									dev_info.max_mtu);
					const uint16_t mtu = MAX(l2reflect_pkt_bytes - overhead_len,
								 dev_info.min_mtu);
					RTE_LOG(INFO, L2REFLECT,
						"update frame sizes: frame: %" PRIu64 ", MTU %d\n",
						l2reflect_pkt_bytes, mtu);
					const int ret = rte_eth_dev_set_mtu(
								l2reflect_port_number,
								mtu);
					if (ret < 0)
						rte_exit(EXIT_FAILURE, "failed to update MTU: %s\n",
								 strerror(-ret));
				}

				if (ehlo_send) {
					l2reflect_state = S_RUNNING;
					RTE_LOG(INFO, L2REFLECT, "Enter running state\n");
				}
			}
			/* we got a HELO packet, respond with EHLO */
			if (pkt->type == TRACE_TYPE_HELO) {
				char mac_str_other[RTE_ETHER_ADDR_FMT_SIZE];
				rte_ether_addr_copy(src_addr, &l2reflect_remote_eth_addr);
				m = l2reflect_new_pkt(TRACE_TYPE_EHLO);
				rte_ether_format_addr(
				  mac_str_other, sizeof(mac_str_other), &l2reflect_remote_eth_addr);
				RTE_LOG(INFO, L2REFLECT, "found one HELO from %s\n", mac_str_other);
				l2reflect_send_packet(&m, l2reflect_port_number);
				ehlo_send = 1;
			}
			rte_pktmbuf_free(m);
		}
	}

	if (rte_is_same_ether_addr(&l2reflect_port_eth_addr, &l2reflect_remote_eth_addr))
		rte_exit(EXIT_FAILURE, "talking to myself ... confused\n");

	/* the one with the bigger MAC is the leader */
	i_win = ((*((uint64_t *)&l2reflect_port_eth_addr)   & MAC_ADDR_CMP) >
			 (*((uint64_t *)&l2reflect_remote_eth_addr) & MAC_ADDR_CMP));

	RTE_LOG(INFO, L2REFLECT, "i am the \"%s\"\n", i_win ? "rick" : "morty");

	return i_win;
}

/*
 * add the measured time diff to the statistics.
 * return false if threshold is hit
 */
static inline int
add_to_record(const uint64_t diff)
{
	record.rounds++;
	/* do not count the first rounds, diff would be too high */
	if (record.rounds < WARMUP_ROUNDS)
		return 1;

	if (l2reflect_hist) {
		const uint64_t bucket =
			MIN(diff / (hist_bucket_usec * 1000), l2reflect_hist_buckets-1);
		record.hist[bucket]++;
	}

	record.avg_round_ns += (double)diff;
	if (diff < record.min_round_ns)
		record.min_round_ns = diff;
	if (diff > record.max_round_ns) {
		record.max_round_ns = diff;
		if (l2reflect_break_usec &&
		   (record.max_round_ns > (l2reflect_break_usec * 1000)))
			return 0;
	}
	return 1;
}

/*
 * process a single packet.
 * return false if latency threshold is hit
 */
static inline int
process_packet(
	struct my_magic_packet *pkt,
	struct timespec *rx_time,
	uint64_t *diff)
{
	if (pkt->type == TRACE_TYPE_DATA) {
		rte_memcpy(&last_recv, rx_time, sizeof(*rx_time));
		*diff = calcdiff_ns(last_recv, last_sent);
		if (!unlikely(add_to_record(*diff))) {
			/* TODO: improve tracing */
			rte_eal_trace_generic_u64(record.max_round_ns / 1000);
			return 0;
		}
	}
	if (pkt->magic == MAGIC_TRACE_PAYLOAD)
		rte_eal_trace_generic_str("received traced packet");

	return 1;
}

/*
 * free all packet buffers in the range [begin, end[.
 */
static void
free_pktbufs(
		struct rte_mbuf **bufs,
		int begin,
		int end)
{
	int i = begin;
	for (; i < end; i++)
		rte_pktmbuf_free(bufs[0]);
}

/*
 * return 1 in case the ball was lost (cheap check)
 */
static inline void
check_ball_lost(const uint64_t dp_idle) {
	/* only check if we are in running state and have a breakval */
	if (unlikely(dp_idle & RX_TIMEOUT_MASK) &&
	   l2reflect_state == S_RUNNING &&
	   l2reflect_break_usec &&
	   record.rounds > WARMUP_ROUNDS) {
		RTE_LOG(INFO, L2REFLECT, "lost ball after %" PRIu64 " rounds\n", record.rounds);
		l2reflect_state = S_LOCAL_TERM;
	}
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
	/* number of consequent idle passes */
	uint64_t dp_idle = 0;
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
	assert_link_status(portid);

restart:
	init_record();
	rte_eth_stats_reset(portid);
	l2reflect_state = S_ELECT_LEADER;
	sender = elect_leader(portid);

	if (l2reflect_break_usec)
		rte_eal_trace_generic_str("hit breakval");

	/* the leader election implements a latch (half-barrier).
	 * To ensure that the other party is in running state, we
	 * have to wait at least a full election period
	 */
	rte_delay_ms(DELAY_ELECTION_MS * 2);

	/* we are the sender so we bring one ball into the game */
	if (sender)
		l2reflect_new_ball();

	/* reset the record */
	init_record();
	while (l2reflect_state == S_RUNNING) {
		struct timespec rx_time;

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

		if (nb_rx) {
			clock_gettime(CLOCK_MONOTONIC, &rx_time);
			dp_idle = 0;
		} else
			++dp_idle;

		for (j = 0; j < nb_rx; j++) {
			m = pkts_burst[j];
			eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
			pkt = (struct my_magic_packet *)eth;

			rte_prefetch0(eth);

			if (unlikely(!l2reflect_rx_filter(m))) {
				rte_pktmbuf_free(m);
				continue;
			}

			/* remote is telling us to reset or stop */
			if (unlikely(pkt->type == TRACE_TYPE_RSET)) {
				free_pktbufs(pkts_burst, j, nb_rx);
				goto restart;
			}
			if (unlikely(pkt->type == TRACE_TYPE_QUIT)) {
				l2reflect_state = S_REMOTE_TERM;
				free_pktbufs(pkts_burst, j, nb_rx);
				break;
			}

			if (likely(l2reflect_state == S_RUNNING)) {
				if (unlikely(!process_packet(pkt, &rx_time, &diff))) {
					l2reflect_state = S_LOCAL_TERM;
					free_pktbufs(pkts_burst, j, nb_rx);
					break;
				}
				l2reflect_simple_forward(m);
			}
		}
		check_ball_lost(dp_idle);
	}

	const int state_cpy = l2reflect_state;
	switch (state_cpy) {
	case S_RESET_TRX:
		l2reflect_send_reset();
		l2reflect_state = S_ELECT_LEADER;
		/* fallthrough */
	case S_ELECT_LEADER:
		goto restart;
	}

	if (state_cpy == S_LOCAL_TERM) {
		rte_eal_trace_generic_str("local termination");
		l2reflect_send_quit();
	} else if (state_cpy == S_REMOTE_TERM) {
		RTE_LOG(INFO, L2REFLECT, "received message that remote hit threshold (or is cancelled)\n");
	}
}

static int
l2reflect_launch_one_lcore(__rte_unused void *dummy)
{
	struct sched_param param;
	int err;

	if (sleep_start) {
		RTE_LOG(INFO, L2REFLECT, "Sleeping and waiting for SIGCONT\n");
		while (sleep_start) {
			rte_delay_ms(10);
			if (l2reflect_state == S_LOCAL_TERM)
				rte_exit(EXIT_SUCCESS, "Quit\n");
		}
		RTE_LOG(INFO, L2REFLECT, "Got SIGCONT, continuing");
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
	struct rte_eth_txconf txconf;
	int ret;
	uint32_t i;
	uint16_t nb_ports;
	unsigned int lcore_id;
	struct sigaction action;
	bzero(&action, sizeof(action));
	char mempool_name[128];
	char mac_str[RTE_ETHER_ADDR_FMT_SIZE];

	action.sa_handler = sig_handler;
	if (sigaction(SIGHUP, &action, NULL) < 0 ||
	    sigaction(SIGUSR1, &action, NULL) < 0 ||
	    sigaction(SIGUSR2, &action, NULL) < 0 ||
	    sigaction(SIGCONT, &action, NULL) < 0 ||
	    sigaction(SIGINT, &action, NULL) < 0) {
		rte_exit(EXIT_FAILURE, "Could not register signal handler\n");
	}

	lcore_id = rte_lcore_id();

	if (check_opts_for_help(argc, argv, l2reflect_usage))
		return 0;

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
	RTE_LOG(DEBUG, L2REFLECT, "About to create mempool \"%s\"\n", mempool_name);
	/* create the mbuf pool */
	l2reflect_pktmbuf_pool =
		rte_pktmbuf_pool_create(mempool_name, NB_MBUF,
			MAX_PKT_BURST, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

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
	RTE_LOG(INFO, L2REFLECT, "We have %d ports and will use port %d\n", nb_ports,
	       l2reflect_port_number);

	rte_eth_dev_info_get(l2reflect_port_number, &dev_info);
	RTE_LOG(INFO, L2REFLECT, "Initializing port %u ...\n", l2reflect_port_number);
	fflush(stdout);

	if (l2reflect_interrupt)
		port_conf.intr_conf.rxq = 1;

	ret = config_port_max_pkt_len(&port_conf, &dev_info);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Invalid max packet length: %u (port %u)\n",
			l2reflect_port_number, l2reflect_port_number);

	ret = rte_eth_dev_configure(l2reflect_port_number, 1, 1, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Cannot configure device: err=%s, port=%u\n",
			strerror(-ret), l2reflect_port_number);

	ret = rte_eth_dev_adjust_nb_rx_tx_desc(l2reflect_port_number, &nb_rxd, &nb_txd);
	if (ret != 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot adjust # of Rx/Tx descriptors to HW limits: err=%s, port=%u\n",
			 strerror(-ret), l2reflect_port_number);

	/* init RX queues */
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
	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	ret = rte_eth_tx_queue_setup(
		l2reflect_port_number, 0, nb_txd,
		rte_eth_dev_socket_id(l2reflect_port_number), &txconf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_tx_queue_setup:err=%s, port=%u\n",
			 strerror(-ret), (unsigned int)l2reflect_port_number);

	/* Start device */
	ret = rte_eth_dev_start(l2reflect_port_number);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%s, port=%u\n",
			 strerror(-ret), (unsigned int)l2reflect_port_number);

	rte_eth_macaddr_get(l2reflect_port_number, &l2reflect_port_eth_addr);

	/*
	 * When running on a Tap device, we might want to use a foreign
	 * mac address to make sure that the application and the Tap device
	 * do not share the same MAC addr. By that, we enforce that the
	 * bridge learns this address and correctly forwards unicast packets.
	 */
	if (l2reflect_fake_mac)
		l2reflect_port_eth_addr.addr_bytes[5] += 1;

	rte_ether_format_addr(mac_str, sizeof(mac_str),
			      &l2reflect_port_eth_addr);
	RTE_LOG(INFO, L2REFLECT, "Port %u, MAC address: %s\n\n",
	       (unsigned int)l2reflect_port_number, mac_str);

	/*
	 * in quiet mode the primary executes the main packet loop
	 * otherwise the one worker does it and the primary prints stats
	 */
	if (quiet) {
		assert(rte_lcore_count() == 1);
#ifdef HAS_SYS_IO
		if (disable_int) {
			iopl(3);
			asm("cli");
		}
#endif
		RTE_LOG(INFO, L2REFLECT, "PID %i, Parent %i\n", getpid(), getppid());
		l2reflect_launch_one_lcore(NULL);
	} else {
		assert(rte_lcore_count() == 2);
		/* the worker reflects the packets */
		RTE_LCORE_FOREACH_WORKER(lcore_id)
		{
			rte_eal_remote_launch(l2reflect_launch_one_lcore, NULL,
					      lcore_id);
		}

		/* the primary prints the stats */
		init_record();
		l2reflect_stats_loop();
		rte_eal_mp_wait_lcore();
	}
	rte_eal_cleanup();

	if (l2reflect_hist)
		output_histogram_snapshot();

	cleanup_record();

	return 0;
}
