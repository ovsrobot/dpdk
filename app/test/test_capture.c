/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Functional test for the capture library.
 *
 * The capture library has no public C API: it is driven entirely through the
 * telemetry socket. The output is a path ('out=') that the primary opens
 * itself and writes pcapng into; the caller never receives packet data over
 * the control socket. This test therefore behaves like an external capture
 * tool. It:
 *
 *   1. builds a virtual ethdev backed by net_null. Rx synthesizes packets and
 *      Tx is a sink that frees whatever it is handed, which is all this test
 *      needs and avoids the per-queue ring bookkeeping of net_ring. The port
 *      is given NB_QUEUES queues so per-queue selection can be exercised;
 *   2. creates a FIFO and opens its read end (so the primary's non-blocking
 *      O_WRONLY open finds a reader);
 *   3. connects to this process's own telemetry socket;
 *   4. runs three phases:
 *        - lifecycle: start an all-queue capture, check a pcapng stream
 *          appears, the capture is listed, stats account for traffic injected
 *          on every queue in both directions, and it tears down when the
 *          reader disconnects;
 *        - parameters: an out-of-range queue index is rejected, not started;
 *        - selection: a queue=CAPTURE_QUEUE capture installs callbacks on that
 *          queue only, so traffic on any other queue is not captured while
 *          traffic on that one is, in both directions. The selected queue is
 *          neither the first nor the last of NB_QUEUES, so an off-by-one in
 *          either install loop is caught. Both directions are steerable here:
 *          the test names the queue in rte_eth_rx_burst()/rte_eth_tx_burst()
 *          and net_null sources or sinks on whichever queue it is handed.
 *
 * The test is skipped (not failed) if telemetry is not enabled or the net_null
 * driver is not available.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include <rte_bus_vdev.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include "test.h"

#define TELEMETRY_VERSION	"v2"
#define CAPTURE_START		"/ethdev/capture/start"
#define CAPTURE_LIST		"/ethdev/capture/list"
#define CAPTURE_STATS		"/ethdev/capture/stats"

#define NULL_VDEV_NAME		"net_null_capture"
#define NB_QUEUES		4
#define CAPTURE_QUEUE		2	/* not first or last of NB_QUEUES */
#define RING_SIZE		256
#define NB_MBUFS		1024
#define MBUF_CACHE		32
#define NB_PKTS			32
#define PKT_LEN			64
#define REPLY_LEN		16384

/* pcapng Section Header Block type, byte-order independent on disk. */
static const uint8_t pcapng_shb_magic[4] = { 0x0a, 0x0d, 0x0d, 0x0a };

static struct rte_mempool *test_mp;
static uint16_t test_port = RTE_MAX_ETHPORTS;
static char fifo_path[PATH_MAX];

/* --- telemetry client helpers ------------------------------------------ */

/* Connect to this process's telemetry socket; -1 (and skip) if unavailable. */
static int
tel_connect(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	char buf[REPLY_LEN];
	int s;

	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/dpdk_telemetry.%s",
		 rte_eal_get_runtime_dir(), TELEMETRY_VERSION);

	s = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (s < 0)
		return -1;

	if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(s);
		return -1;
	}

	/* Server greets with an info message; consume it. */
	if (recv(s, buf, sizeof(buf), 0) <= 0) {
		close(s);
		return -1;
	}
	return s;
}

/* Send a command and read the reply. */
static int
tel_cmd(int s, const char *cmd, char *reply, size_t reply_sz)
{
	ssize_t n;

	if (send(s, cmd, strlen(cmd), 0) < 0)
		return -1;
	n = recv(s, reply, reply_sz - 1, 0);
	if (n < 0)
		return -1;
	reply[n] = '\0';
	return 0;
}

/* Minimal JSON scanning: find "key" and read the unsigned number after it. */
static int
json_uint(const char *s, const char *key, uint64_t *out)
{
	const char *p = strstr(s, key);

	if (p == NULL)
		return -1;
	for (p += strlen(key); *p != '\0' && !isdigit((unsigned char)*p); p++)
		;
	if (*p == '\0')
		return -1;
	*out = strtoull(p, NULL, 10);
	return 0;
}

/* Read the first element of the array in a list reply; -1 if empty/absent. */
static int
json_first_array_uint(const char *s, uint64_t *out)
{
	const char *p = strchr(s, '[');

	if (p == NULL)
		return -1;
	for (p++; *p == ' '; p++)
		;
	if (*p == ']' || !isdigit((unsigned char)*p))
		return -1;
	*out = strtoull(p, NULL, 10);
	return 0;
}

/* Query the accepted counter for a capture id via telemetry. */
static int
capture_accepted(int sock, uint64_t id, uint64_t *accepted)
{
	char cmd[64], reply[REPLY_LEN];

	snprintf(cmd, sizeof(cmd), "%s,%" PRIu64, CAPTURE_STATS, id);
	if (tel_cmd(sock, cmd, reply, sizeof(reply)) < 0)
		return -1;
	return json_uint(reply, "\"accepted\"", accepted);
}

/*
 * Poll the capture list until it is empty (the capture has torn down).
 * Returns 0 once empty, -1 on timeout (~2s) or telemetry failure.
 */
static int
wait_list_empty(int sock)
{
	char reply[REPLY_LEN];
	uint64_t id;

	for (int i = 0; i < 200; i++) {
		if (tel_cmd(sock, CAPTURE_LIST, reply, sizeof(reply)) < 0)
			return -1;
		if (json_first_array_uint(reply, &id) < 0)
			return 0;
		rte_delay_ms(10);
	}
	return -1;
}

/* --- packet injection --------------------------------------------------- */

/*
 * Pull count packets from a queue. net_null synthesizes them and pulling runs
 * the capture Rx callback on each; the mbufs are ours to free.
 */
static int
inject_rx(uint16_t queue, unsigned int count)
{
	struct rte_mbuf *bufs[NB_PKTS];
	uint16_t got;

	if (count > NB_PKTS)
		count = NB_PKTS;

	got = rte_eth_rx_burst(test_port, queue, bufs, count);
	rte_pktmbuf_free_bulk(bufs, got);
	return got == count ? 0 : -1;	/* net_null fills the whole request */
}

/*
 * Transmit count packets on a queue. The capture Tx callback runs first (it
 * only copies) and net_null then frees the originals, so nothing is reclaimed
 * here.
 */
static int
inject_tx(uint16_t queue, unsigned int count)
{
	struct rte_mbuf *bufs[NB_PKTS];

	if (count > NB_PKTS)
		count = NB_PKTS;

	for (unsigned int i = 0; i < count; i++) {
		struct rte_mbuf *m = rte_pktmbuf_alloc(test_mp);

		if (m == NULL) {
			rte_pktmbuf_free_bulk(bufs, i);
			return -1;
		}
		m->pkt_len = m->data_len = PKT_LEN;
		memset(rte_pktmbuf_mtod(m, void *), 0, PKT_LEN);
		bufs[i] = m;
	}

	/* net_null accepts the whole burst. */
	return rte_eth_tx_burst(test_port, queue, bufs, count) == count ? 0 : -1;
}

/*
 * Inject on every queue except skip; pass NB_QUEUES to cover them all.
 */
static int
inject_rx_except(uint16_t skip, unsigned int count)
{
	for (uint16_t q = 0; q < NB_QUEUES; q++) {
		if (q != skip && inject_rx(q, count) < 0)
			return -1;
	}
	return 0;
}

static int
inject_tx_except(uint16_t skip, unsigned int count)
{
	for (uint16_t q = 0; q < NB_QUEUES; q++) {
		if (q != skip && inject_tx(q, count) < 0)
			return -1;
	}
	return 0;
}

/* --- fixture ------------------------------------------------------------ */

static int
build_port(void)
{
	struct rte_eth_conf conf = { 0 };

	test_mp = rte_pktmbuf_pool_create("capture_test_mp", NB_MBUFS, MBUF_CACHE,
					  0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (test_mp == NULL)
		return -1;

	if (rte_vdev_init(NULL_VDEV_NAME, NULL) < 0)
		return -1;
	if (rte_eth_dev_get_port_by_name(NULL_VDEV_NAME, &test_port) != 0)
		return -1;

	if (rte_eth_dev_configure(test_port, NB_QUEUES, NB_QUEUES, &conf) < 0)
		return -1;
	for (uint16_t q = 0; q < NB_QUEUES; q++) {
		if (rte_eth_rx_queue_setup(test_port, q, RING_SIZE, rte_socket_id(),
					   NULL, test_mp) < 0)
			return -1;
		if (rte_eth_tx_queue_setup(test_port, q, RING_SIZE, rte_socket_id(),
					   NULL) < 0)
			return -1;
	}

	return rte_eth_dev_start(test_port);
}

static void
teardown_port(void)
{
	if (test_port != RTE_MAX_ETHPORTS) {
		rte_eth_dev_stop(test_port);
		/*
		 * Uninit drives the driver's remove, which closes and releases
		 * the ethdev port and removes the vdev in one path. No separate
		 * rte_eth_dev_close() is needed and null's close is idempotent,
		 * so this is safe even if a tree's close already released it.
		 */
		rte_vdev_uninit(NULL_VDEV_NAME);
		test_port = RTE_MAX_ETHPORTS;
	}
	rte_mempool_free(test_mp);
	test_mp = NULL;
}

/* Create the capture FIFO in the runtime dir; -1 on failure. */
static int
make_fifo(void)
{
	snprintf(fifo_path, sizeof(fifo_path), "%s/capture_test.%d",
		 rte_eal_get_runtime_dir(), (int)getpid());
	unlink(fifo_path);			/* clear any stale node */
	if (mkfifo(fifo_path, 0600) < 0)
		return -1;
	return 0;
}

/* --- the test ----------------------------------------------------------- */

static int
test_capture(void)
{
	char cmd[PATH_MAX + 64], reply[REPLY_LEN], pcapng[REPLY_LEN];
	int sock = -1, rd = -1;
	int ret = TEST_FAILED;
	uint64_t id, accepted;
	struct timeval tv;
	fd_set rfds;
	ssize_t n;

	fifo_path[0] = '\0';

	/*
	 * The library writes to the FIFO; a closed reader must give the writer
	 * EPIPE, not a fatal SIGPIPE. The library masks SIGPIPE on its drain
	 * thread, but ignore it here too so the test process is safe regardless.
	 */
	signal(SIGPIPE, SIG_IGN);

	sock = tel_connect();
	if (sock < 0) {
		printf("telemetry socket not available, skipping\n");
		return TEST_SKIPPED;
	}

	if (build_port() < 0) {
		printf("could not build net_null test port, skipping\n");
		ret = TEST_SKIPPED;
		goto out;
	}

	if (make_fifo() < 0)
		goto out;

	/*
	 * Phase 1: all-queue lifecycle.
	 *
	 * Open the read end before starting: the primary opens the FIFO
	 * O_WRONLY|O_NONBLOCK and would get ENXIO with no reader present.
	 * O_RDONLY|O_NONBLOCK returns immediately even with no writer yet.
	 */
	rd = open(fifo_path, O_RDONLY | O_NONBLOCK);
	if (rd < 0)
		goto out;

	snprintf(cmd, sizeof(cmd), "%s,%u,out=%s", CAPTURE_START, test_port, fifo_path);
	TEST_ASSERT_SUCCESS(tel_cmd(sock, cmd, reply, sizeof(reply)),
			    "capture start command failed");
	TEST_ASSERT(strstr(reply, "error") == NULL,
		    "capture start returned an error: %s", reply);

	/*
	 * Inject traffic on every queue: with no queue= the callbacks must be
	 * installed on all of them. Rx callbacks run synchronously inside
	 * rx_burst, so the accepted counter is up to date as soon as this
	 * returns.
	 */
	TEST_ASSERT_SUCCESS(inject_rx_except(NB_QUEUES, NB_PKTS),
			    "rx injection failed");

	/* A pcapng stream (at least the section header) must appear. */
	FD_ZERO(&rfds);
	FD_SET(rd, &rfds);
	tv = (struct timeval){ .tv_sec = 2 };
	TEST_ASSERT(select(rd + 1, &rfds, NULL, NULL, &tv) > 0,
		    "no pcapng output within timeout");
	n = read(rd, pcapng, sizeof(pcapng));
	TEST_ASSERT(n >= 4, "short pcapng read (%zd)", n);
	TEST_ASSERT(memcmp(pcapng, pcapng_shb_magic, sizeof(pcapng_shb_magic)) == 0,
		    "output does not start with a pcapng section header block");

	/* The capture must show up in the list. */
	TEST_ASSERT_SUCCESS(tel_cmd(sock, CAPTURE_LIST, reply, sizeof(reply)),
			    "capture list command failed");
	TEST_ASSERT_SUCCESS(json_first_array_uint(reply, &id),
			    "no capture id in list reply: %s", reply);

	/* Stats must report exactly the packets we injected, on every queue. */
	TEST_ASSERT_SUCCESS(capture_accepted(sock, id, &accepted),
			    "capture stats query failed");
	TEST_ASSERT_EQUAL(accepted, (uint64_t)(NB_QUEUES * NB_PKTS),
			  "accepted %" PRIu64 " != %d", accepted, NB_QUEUES * NB_PKTS);

	/* Same for the Tx side of every queue. */
	TEST_ASSERT_SUCCESS(inject_tx_except(NB_QUEUES, NB_PKTS),
			    "tx injection failed");
	TEST_ASSERT_SUCCESS(capture_accepted(sock, id, &accepted),
			    "capture stats query failed");
	TEST_ASSERT_EQUAL(accepted, (uint64_t)(2 * NB_QUEUES * NB_PKTS),
			  "accepted %" PRIu64 " != %d", accepted, 2 * NB_QUEUES * NB_PKTS);

	/*
	 * Close the reader: the capture should detect the hangup and tear down.
	 * The drain thread's idle poll notices POLLERR on the write end on its
	 * own; the extra injection just shortens the wait if it was mid-drain.
	 */
	close(rd);
	rd = -1;
	inject_rx(0, NB_PKTS);	/* any queue; all are captured here */
	TEST_ASSERT_SUCCESS(wait_list_empty(sock),
			    "capture did not tear down after reader closed");

	/*
	 * Phase 2: parameter validation. An out-of-range queue index must be
	 * rejected. The range check runs before the output is opened, so no
	 * reader is needed and no capture should be left behind.
	 */
	snprintf(cmd, sizeof(cmd), "%s,%u,out=%s,queue=%u",
		 CAPTURE_START, test_port, fifo_path, NB_QUEUES);
	TEST_ASSERT_SUCCESS(tel_cmd(sock, cmd, reply, sizeof(reply)),
			    "capture start command failed");
	TEST_ASSERT(strstr(reply, "error") != NULL,
		    "out-of-range queue=%u was not rejected: %s", NB_QUEUES, reply);
	TEST_ASSERT_SUCCESS(wait_list_empty(sock),
			    "rejected start left a capture behind");

	/*
	 * Phase 3: single-queue selection. With queue=CAPTURE_QUEUE the
	 * callbacks are installed on that queue only: traffic on any other
	 * queue must not be captured, traffic on that one must be, in both
	 * directions. The counters are bumped synchronously inside
	 * rx_burst/tx_burst, so every check here is race-free.
	 */
	rd = open(fifo_path, O_RDONLY | O_NONBLOCK);
	TEST_ASSERT(rd >= 0, "reopen fifo failed: %s", strerror(errno));

	snprintf(cmd, sizeof(cmd), "%s,%u,out=%s,queue=%u",
		 CAPTURE_START, test_port, fifo_path, CAPTURE_QUEUE);
	TEST_ASSERT_SUCCESS(tel_cmd(sock, cmd, reply, sizeof(reply)),
			    "queue=%u capture start failed", CAPTURE_QUEUE);
	TEST_ASSERT(strstr(reply, "error") == NULL,
		    "queue=%u capture start returned an error: %s",
		    CAPTURE_QUEUE, reply);
	TEST_ASSERT_SUCCESS(json_uint(reply, "\"id\"", &id),
			    "no id in start reply: %s", reply);

	/* Unselected queues: callbacks never installed, nothing captured. */
	TEST_ASSERT_SUCCESS(inject_rx_except(CAPTURE_QUEUE, NB_PKTS),
			    "rx inject on unselected queues failed");
	TEST_ASSERT_SUCCESS(inject_tx_except(CAPTURE_QUEUE, NB_PKTS),
			    "tx inject on unselected queues failed");
	TEST_ASSERT_SUCCESS(capture_accepted(sock, id, &accepted),
			    "capture stats query failed");
	TEST_ASSERT_EQUAL(accepted, (uint64_t)0,
			  "other queues captured under queue=%u (accepted %" PRIu64 ")",
			  CAPTURE_QUEUE, accepted);

	/* Selected queue: captured, on Rx and on Tx. */
	TEST_ASSERT_SUCCESS(inject_rx(CAPTURE_QUEUE, NB_PKTS),
			    "rx inject on queue %u failed", CAPTURE_QUEUE);
	TEST_ASSERT_SUCCESS(capture_accepted(sock, id, &accepted),
			    "capture stats query failed");
	TEST_ASSERT_EQUAL(accepted, (uint64_t)NB_PKTS,
			  "rx queue %u not captured (accepted %" PRIu64 ")",
			  CAPTURE_QUEUE, accepted);

	TEST_ASSERT_SUCCESS(inject_tx(CAPTURE_QUEUE, NB_PKTS),
			    "tx inject on queue %u failed", CAPTURE_QUEUE);
	TEST_ASSERT_SUCCESS(capture_accepted(sock, id, &accepted),
			    "capture stats query failed");
	TEST_ASSERT_EQUAL(accepted, (uint64_t)(2 * NB_PKTS),
			  "tx queue %u not captured (accepted %" PRIu64 ")",
			  CAPTURE_QUEUE, accepted);

	close(rd);
	rd = -1;
	TEST_ASSERT_SUCCESS(wait_list_empty(sock),
			    "queue=%u capture did not tear down", CAPTURE_QUEUE);

	ret = TEST_SUCCESS;
out:
	if (rd >= 0)
		close(rd);
	if (fifo_path[0] != '\0')
		unlink(fifo_path);
	if (sock >= 0)
		close(sock);
	teardown_port();
	return ret;
}

REGISTER_FAST_TEST(capture_autotest, NOHUGE_OK, ASAN_OK, test_capture);
