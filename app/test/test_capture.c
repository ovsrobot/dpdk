/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Functional test for the capture library.
 *
 * The capture library has no public C API: it is driven entirely through the
 * telemetry socket, and the pcapng output is delivered over a file descriptor
 * passed to the primary process with SCM_RIGHTS. This test therefore behaves
 * like an external capture tool. It:
 *
 *   1. builds a virtual ethdev backed by rings (net_ring), like test_pdump.c;
 *   2. connects to this process's own telemetry socket;
 *   3. starts a capture, passing the write end of a pipe as the output fd;
 *   4. injects packets through the port and checks that
 *        - a pcapng stream appears on the pipe,
 *        - /ethdev/capture/list reports the capture,
 *        - /ethdev/capture/stats reports the expected accepted count;
 *   5. closes the read end and checks the capture tears itself down and
 *      disappears from /ethdev/capture/list.
 *
 * The test is skipped (not failed) if telemetry is not enabled or the ring
 * driver is not available.
 */

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_eth_ring.h>
#include <rte_mbuf.h>
#include <rte_ring.h>

#include "test.h"

#define TELEMETRY_VERSION	"v2"
#define CAPTURE_START		"/ethdev/capture/start"
#define CAPTURE_LIST		"/ethdev/capture/list"
#define CAPTURE_STATS		"/ethdev/capture/stats"

#define RING_SIZE		256
#define NB_MBUFS		1024
#define MBUF_CACHE		32
#define NB_PKTS			32
#define PKT_LEN			64
#define REPLY_LEN		16384

/* pcapng Section Header Block type, byte-order independent on disk. */
static const uint8_t pcapng_shb_magic[4] = { 0x0a, 0x0d, 0x0d, 0x0a };

static struct rte_mempool *test_mp;
static struct rte_ring *rx_ring, *tx_ring;
static uint16_t test_port = RTE_MAX_ETHPORTS;

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

/* Send a command (no fd) and read the reply. */
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

/* Send a command passing one fd as SCM_RIGHTS, discard the reply. */
static int
tel_cmd_fd(int s, const char *cmd, int fd)
{
	char cbuf[CMSG_SPACE(sizeof(int))] = { 0 };
	char reply[REPLY_LEN];
	struct iovec iov = { .iov_base = (void *)(uintptr_t)cmd, .iov_len = strlen(cmd) };
	struct msghdr msg = {
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = cbuf,
		.msg_controllen = sizeof(cbuf),
	};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(cmsg), &fd, sizeof(int));

	if (sendmsg(s, &msg, 0) < 0)
		return -1;
	if (recv(s, reply, sizeof(reply), 0) < 0)
		return -1;
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

/* --- packet injection --------------------------------------------------- */

/* Push NB_PKTS minimal packets through the port's Rx path. */
static int
inject_rx(unsigned int count)
{
	struct rte_mbuf *bufs[NB_PKTS];
	uint16_t got;

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

	if (rte_ring_enqueue_bulk(rx_ring, (void **)bufs, count, NULL) != count) {
		rte_pktmbuf_free_bulk(bufs, count);
		return -1;
	}

	/* Pulling from the port runs the capture Rx callback on each packet. */
	got = rte_eth_rx_burst(test_port, 0, bufs, count);
	rte_pktmbuf_free_bulk(bufs, got);
	return 0;
}

/* --- fixture ------------------------------------------------------------ */

static int
build_port(void)
{
	struct rte_eth_conf conf = { 0 };
	int ret;

	test_mp = rte_pktmbuf_pool_create("capture_test_mp", NB_MBUFS, MBUF_CACHE,
					  0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	if (test_mp == NULL)
		return -1;

	rx_ring = rte_ring_create("capture_test_rx", RING_SIZE, rte_socket_id(),
				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	tx_ring = rte_ring_create("capture_test_tx", RING_SIZE, rte_socket_id(),
				  RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (rx_ring == NULL || tx_ring == NULL)
		return -1;

	ret = rte_eth_from_rings("net_capture_test", &rx_ring, 1, &tx_ring, 1, rte_socket_id());
	if (ret < 0)
		return -1;
	test_port = ret;

	if (rte_eth_dev_configure(test_port, 1, 1, &conf) < 0)
		return -1;
	if (rte_eth_rx_queue_setup(test_port, 0, RING_SIZE, rte_socket_id(), NULL, test_mp) < 0)
		return -1;
	if (rte_eth_tx_queue_setup(test_port, 0, RING_SIZE, rte_socket_id(), NULL) < 0)
		return -1;
	if (rte_eth_dev_start(test_port) < 0)
		return -1;

	return 0;
}

static void
teardown_port(void)
{
	if (test_port != RTE_MAX_ETHPORTS) {
		rte_eth_dev_stop(test_port);
		rte_eth_dev_close(test_port);
		test_port = RTE_MAX_ETHPORTS;
	}
	rte_ring_free(rx_ring);
	rte_ring_free(tx_ring);
	rte_mempool_free(test_mp);
	rx_ring = tx_ring = NULL;
	test_mp = NULL;
}

/* --- the test ----------------------------------------------------------- */

static int
test_capture(void)
{
	char cmd[128], reply[REPLY_LEN], pcapng[REPLY_LEN];
	int sock = -1, pipefd[2] = { -1, -1 };
	int ret = TEST_FAILED;
	uint64_t id, accepted;
	struct timeval tv;
	fd_set rfds;
	ssize_t n;

	/* The drain thread writes to the pipe; a closed reader must give EPIPE,
	 * not a fatal SIGPIPE. (The library itself should arguably ignore
	 * SIGPIPE too; see review notes.)
	 */
	signal(SIGPIPE, SIG_IGN);

	sock = tel_connect();
	if (sock < 0) {
		printf("telemetry socket not available, skipping\n");
		return TEST_SKIPPED;
	}

	if (build_port() < 0) {
		printf("could not build ring-backed test port, skipping\n");
		ret = TEST_SKIPPED;
		goto out;
	}

	if (pipe(pipefd) < 0)
		goto out;

	/* Start the capture, handing it the write end of the pipe. */
	snprintf(cmd, sizeof(cmd), "%s,%u", CAPTURE_START, test_port);
	TEST_ASSERT_SUCCESS(tel_cmd_fd(sock, cmd, pipefd[1]),
			    "capture start command failed");

	/* The library now holds its own dup of the write end; drop ours so the
	 * capture sees a hangup once we close the read end below.
	 */
	close(pipefd[1]);
	pipefd[1] = -1;

	/* Inject traffic. Rx callbacks run synchronously inside rx_burst, so the
	 * accepted counter is up to date as soon as this returns.
	 */
	TEST_ASSERT_SUCCESS(inject_rx(NB_PKTS), "packet injection failed");

	/* A pcapng stream (at least the section header) must appear. */
	FD_ZERO(&rfds);
	FD_SET(pipefd[0], &rfds);
	tv = (struct timeval){ .tv_sec = 2 };
	TEST_ASSERT(select(pipefd[0] + 1, &rfds, NULL, NULL, &tv) > 0,
		    "no pcapng output within timeout");
	n = read(pipefd[0], pcapng, sizeof(pcapng));
	TEST_ASSERT(n >= 4, "short pcapng read (%zd)", n);
	TEST_ASSERT(memcmp(pcapng, pcapng_shb_magic, sizeof(pcapng_shb_magic)) == 0,
		    "output does not start with a pcapng section header block");

	/* The capture must show up in the list. */
	TEST_ASSERT_SUCCESS(tel_cmd(sock, CAPTURE_LIST, reply, sizeof(reply)),
			    "capture list command failed");
	TEST_ASSERT_SUCCESS(json_first_array_uint(reply, &id),
			    "no capture id in list reply: %s", reply);

	/* Stats must report exactly the packets we injected. */
	snprintf(cmd, sizeof(cmd), "%s,%" PRIu64, CAPTURE_STATS, id);
	TEST_ASSERT_SUCCESS(tel_cmd(sock, cmd, reply, sizeof(reply)),
			    "capture stats command failed");
	TEST_ASSERT_SUCCESS(json_uint(reply, "\"accepted\"", &accepted),
			    "no accepted counter in stats reply: %s", reply);
	TEST_ASSERT_EQUAL(accepted, (uint64_t)NB_PKTS,
			  "accepted %" PRIu64 " != %d", accepted, NB_PKTS);

	/* Close the reader: the capture should tear itself down. The drain
	 * thread only notices on its next write, so nudge it with more traffic.
	 */
	close(pipefd[0]);
	pipefd[0] = -1;
	inject_rx(NB_PKTS);

	for (int i = 0; i < 200; i++) {	/* up to ~2s */
		TEST_ASSERT_SUCCESS(tel_cmd(sock, CAPTURE_LIST, reply, sizeof(reply)),
				    "capture list command failed");
		if (json_first_array_uint(reply, &id) < 0) {
			ret = TEST_SUCCESS;
			goto out;
		}
		rte_delay_ms(10);
	}
	printf("capture did not tear down after reader closed: %s\n", reply);

out:
	if (pipefd[0] >= 0)
		close(pipefd[0]);
	if (pipefd[1] >= 0)
		close(pipefd[1]);
	if (sock >= 0)
		close(sock);
	teardown_port();
	return ret;
}

REGISTER_TEST_COMMAND(capture_autotest, test_capture);
