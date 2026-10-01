/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Starting and stopping a capture, and streaming the captured packets
 * to the client over the data connection.
 */

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pcapng.h>
#include <rte_pdump.h>
#include <rte_ring.h>
#include <rte_stdatomic.h>
#include <rte_time.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

#define BURST_SIZE                    32
#define MBUF_CACHE_SIZE               32
#define SLEEP_THRESHOLD		      100
#define SLEEP_US		      100
#define DATA_ACCEPT_TIMEOUT_MS        10000

/* Reference point for converting a captured TSC to a time of day.
 * The TSC is the same counter in the primary that did the capture.
 */
static uint64_t tsc_base;
static uint64_t ns_base;

void
timestamp_init(void)
{
	struct timespec ts;
	uint64_t cycles;

	cycles = rte_get_tsc_cycles();
	clock_gettime(CLOCK_REALTIME, &ts);
	ns_base = rte_timespec_to_ns(&ts);
	tsc_base = (cycles + rte_get_tsc_cycles()) / 2;
}

/* Convert a captured TSC to nanoseconds since the Unix epoch.  Whole
 * seconds come out first so scaling the remainder cannot overflow, and
 * a packet copied before startup is behind the reference point.
 */
static uint64_t
timestamp_to_ns(uint64_t cycles)
{
	const uint64_t hz = rte_get_tsc_hz();
	uint64_t delta, secs, rem;
	bool before;

	before = cycles < tsc_base;
	delta = before ? tsc_base - cycles : cycles - tsc_base;

	secs = delta / hz;
	rem = delta % hz;
	delta = secs * NSEC_PER_SEC + (rem * NSEC_PER_SEC) / hz;

	return before ? ns_base - delta : ns_base + delta;
}


/* Open an ephemeral TCP listening socket; return fd, set *port_out. */
static int
open_data_listener(uint16_t *port_out)
{
	struct sockaddr_storage addr = listen_addr;
	socklen_t alen;
	int fd;

	set_sockaddr_port(&addr, 0);

	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		RPCAPD_LOG(ERR, "data socket: %s", strerror(errno));
		return -1;
	}

	alen = listen_addrlen;
	if (bind(fd, (struct sockaddr *)&addr, alen) < 0 ||
	    listen(fd, 1) < 0 ||
	    getsockname(fd, (struct sockaddr *)&addr, &alen) < 0) {
		RPCAPD_LOG(ERR, "data port bind/listen: %s", strerror(errno));
		close(fd);
		return -1;
	}
	*port_out = get_sockaddr_port(&addr);
	return fd;
}

static struct rte_ring *
create_capture_ring(uint16_t port)
{
	char name[RTE_RING_NAMESIZE];

	snprintf(name, sizeof(name), "rpcapd_r_%u_%d", port, getpid());
	return rte_ring_create(name, ring_size, rte_socket_id(), 0);
}

static struct rte_mempool *
create_capture_mempool(uint16_t port, uint32_t snaplen)
{
	char name[RTE_MEMPOOL_NAMESIZE];
	/* Leaves room for the pcapng block header, the options and the
	 * trailer, as well as the packet itself.
	 */
	uint32_t mbuf_size = rte_pcapng_mbuf_size(snaplen);

	snprintf(name, sizeof(name), "rpcapd_p_%u_%d", port, getpid());
	return rte_pktmbuf_pool_create(name, ring_size * 2, MBUF_CACHE_SIZE, 0,
				       mbuf_size, rte_socket_id());
}


/* Tear down anything that handle_startcap brought up.
 * Safe to call after partial setup as well as after a successful capture.
 */
void
stop_capture(struct session *s)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int n;

	if (s->capture_on) {
		rte_pdump_disable(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags);
		RPCAPD_LOG(NOTICE, "capture stopped on %s (%u packets)",
			s->name, s->npkt);
	}
	s->capture_on = false;

	if (s->promisc_set) {
		rte_eth_promiscuous_disable(s->port);
		s->promisc_set = false;
	}

	if (s->ring != NULL) {
		while ((n = rte_ring_sc_dequeue_burst(s->ring, (void **)pkts,
						      BURST_SIZE, NULL)) > 0)
			rte_pktmbuf_free_bulk(pkts, n);
		rte_ring_free(s->ring);
		s->ring = NULL;
	}
	if (s->mp != NULL) {
		rte_mempool_free(s->mp);
		s->mp = NULL;
	}

	/* Only safe once pdump is disabled */
	rte_free(s->prm);
	s->prm = NULL;
	if (s->data.fd >= 0) {
		tls_close(&s->data);
		close(s->data.fd);
		s->data.fd = -1;
	}
}

/*
 * STARTCAP_REQ: open the data connection and arm the pdump callback.
 * We use passive mode with the server-allocated data port:
 *   - the server picks an ephemeral port and listens on it
 *   - the server returns that port in startcapreply.portdata
 *   - the client connects back to that port for the packet stream
 */
int
handle_startcap(const struct conn *c, uint32_t plen, struct session *s)
{
	struct rpcap_startcapreq req;
	uint16_t data_port;
	uint16_t flags;
	struct rte_bpf_prm *recorded;
	int data_listen;
	int data_fd;
	int ret;

	/* Keep a filter set before the capture started, drop one from a
	 * capture being restarted: this request brings its own.
	 */
	recorded = s->capture_on ? NULL : s->prm;
	if (recorded != NULL)
		s->prm = NULL;
	stop_capture(s);
	s->prm = recorded;

	if (!s->opened) {
		rpcap_discard(c, plen);
		return rpcap_send_error(c, 0, "no interface open");
	}

	if (plen < sizeof(req)) {
		rpcap_discard(c, plen);
		return rpcap_send_error(c, 0, "short startcap request");
	}
	if (recv_full(c, &req, sizeof(req)) < 0)
		return -1;

	flags = rte_be_to_cpu_16(req.flags);
	if (flags & RPCAP_STARTCAPREQ_FLAG_DGRAM) {
		rpcap_discard(c, plen - sizeof(req));
		return rpcap_send_error(c, 0, "UDP data transfer not supported");
	}

	ret = read_filter(c, plen - sizeof(req), s);
	if (ret != 0)
		return ret < 0 ? -1 : 0;	/* error already reported to client */

	/* Direction flags map onto pdump's RX/TX selection; neither (or both)
	 * means capture in both directions.
	 */
	s->pdump_flags = RTE_PDUMP_FLAG_RXTX;
	if ((flags & (RPCAP_STARTCAPREQ_FLAG_INBOUND |
		      RPCAP_STARTCAPREQ_FLAG_OUTBOUND)) ==
	    RPCAP_STARTCAPREQ_FLAG_INBOUND)
		s->pdump_flags = RTE_PDUMP_FLAG_RX;
	else if ((flags & (RPCAP_STARTCAPREQ_FLAG_INBOUND |
			   RPCAP_STARTCAPREQ_FLAG_OUTBOUND)) ==
		 RPCAP_STARTCAPREQ_FLAG_OUTBOUND)
		s->pdump_flags = RTE_PDUMP_FLAG_TX;

	s->snaplen = rte_be_to_cpu_32(req.snaplen);
	if (s->snaplen == 0 || s->snaplen > DEFAULT_SNAPLEN)
		s->snaplen = DEFAULT_SNAPLEN;

	s->ring = create_capture_ring(s->port);
	s->mp = create_capture_mempool(s->port, s->snaplen);
	if (s->ring == NULL || s->mp == NULL) {
		RPCAPD_LOG(ERR, "ring/mempool alloc failed: %s",
			rte_strerror(rte_errno));
		stop_capture(s);
		return rpcap_send_error(c, 0, "DPDK alloc failed");
	}

	data_listen = open_data_listener(&data_port);
	if (data_listen < 0) {
		stop_capture(s);
		return rpcap_send_error(c, 0, "data port setup failed");
	}

	/* Leave the port alone if it is already promiscuous: it belongs to
	 * the primary process, and stop_capture() must not turn off
	 * something this daemon did not turn on.
	 */
	if ((flags & RPCAP_STARTCAPREQ_FLAG_PROMISC) &&
	    rte_eth_promiscuous_get(s->port) != 1) {
		if (rte_eth_promiscuous_enable(s->port) == 0)
			s->promisc_set = true;
		else
			RPCAPD_LOG(NOTICE, "cannot enable promiscuous mode on %s",
				s->name);
	}

	/* Setup packet capture callbacks. */
	if (rte_pdump_enable_bpf(s->port, RTE_PDUMP_ALL_QUEUES,
				 s->pdump_flags | RTE_PDUMP_FLAG_PCAPNG,
				 s->snaplen, s->ring, s->mp, s->prm) < 0) {
		RPCAPD_LOG(ERR, "rte_pdump_enable_bpf port %u failed: %s",
			s->port, rte_strerror(rte_errno));
		close(data_listen);
		stop_capture(s);
		return rpcap_send_error(c, 0, "cannot enable capture");
	}
	s->capture_on = true;
	s->npkt = 0;

	struct rpcap_startcapreply reply = {
		.bufsize = rte_cpu_to_be_32(s->snaplen * BURST_SIZE),
		.portdata = rte_cpu_to_be_16(data_port),
	};
	if (rpcap_send_msg(c, RPCAP_MSG_STARTCAP_REPLY, 0, &reply, sizeof(reply)) < 0) {
		close(data_listen);
		stop_capture(s);
		return -1;
	}

	RPCAPD_LOG(DEBUG, "awaiting connection");

	data_fd = accept_from(data_listen, &s->peer, DATA_ACCEPT_TIMEOUT_MS);
	close(data_listen);
	if (data_fd < 0) {
		stop_capture(s);
		return -1;
	}

	/* Bound how long a send can block. */
	if (send_timeout > 0) {
		struct timeval tv = {
			.tv_sec = send_timeout,
		};

		if (setsockopt(data_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
			RPCAPD_LOG(NOTICE, "cannot set data send timeout: %s",
				   strerror(errno));
	}

	s->data.fd = data_fd;

	/* The client starts its handshake as soon as it has connected,
	 * so promote before anything is sent.
	 */
	if (use_tls && tls_accept(&s->data) < 0) {
		stop_capture(s);
		return -1;
	}

	RPCAPD_LOG(NOTICE,
		   "capture started on %s (snaplen %u, data port %u)",
		   s->name, s->snaplen, data_port);
	return 0;
}

/*
 * Frame each packet from the ring into an RPCAP_MSG_PACKET message and
 * send it on the data connection.  MSG_MORE corks the socket until the
 * ring drains, so a backlog coalesces into full segments.  pdump wraps
 * packets in a pcapng enhanced packet block, which carries the capture
 * time and the pre-truncation length.
 */
static ssize_t
process_ring(struct session *s, unsigned int *avail)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int i, n;
	ssize_t written = 0;

	n = rte_ring_sc_dequeue_burst(s->ring, (void **)pkts, BURST_SIZE, avail);
	if (n == 0)
		return 0;

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		uint8_t buf[MAX_CAPTURE_LEN];
		struct rte_pcapng_pkt pkt;
		uint32_t caplen, wirelen;
		const void *data;

		if (unlikely(rte_pcapng_pkt_info(m, &pkt) != 0)) {
			RPCAPD_LOG(ERR, "malformed capture mbuf on %s", s->name);
			goto error;
		}

		caplen = pkt.captured_len;
		if (unlikely(caplen > sizeof(buf)))
			caplen = sizeof(buf);

		/* clients reject a packet whose len is below its caplen */
		wirelen = RTE_MAX(pkt.original_len, caplen);
		data = rte_pktmbuf_read(m, pkt.data_offset, caplen, buf);
		if (unlikely(data == NULL)) {
			RPCAPD_LOG(ERR, "short capture mbuf on %s", s->name);
			goto error;
		}

		s->npkt++;

		struct rpcap_header hdr = {
			.ver = RPCAP_VERSION,
			.type = RPCAP_MSG_PACKET,
			.plen = rte_cpu_to_be_32(sizeof(struct rpcap_pkthdr) + caplen),
		};

		/* rpcap protocol has timestamp in microseconds. */
		uint64_t us = timestamp_to_ns(pkt.cycles) / 1000;
		struct rpcap_pkthdr pkthdr = {
			.timestamp_sec = rte_cpu_to_be_32(us / US_PER_S),
			.timestamp_usec = rte_cpu_to_be_32(us % US_PER_S),
			.caplen = rte_cpu_to_be_32(caplen),
			.len = rte_cpu_to_be_32(wirelen),
			.npkt = rte_cpu_to_be_32(s->npkt),
		};

		struct iovec iov[3] = {
			{
				.iov_base = &hdr,
				.iov_len = sizeof(hdr),
			},
			{
				.iov_base = &pkthdr,
				.iov_len = sizeof(pkthdr),
			},
			{
				.iov_base = (void *)(uintptr_t)data,
				.iov_len = caplen,
			},
		};

		/* more to come in this burst, or still queued in the ring */
		bool more = (i + 1 < n) || (*avail > 0);

		if (send_iov_full(&s->data, iov, 3, more ? MSG_MORE : 0) < 0) {
			if (errno == EPIPE || errno == ECONNRESET)
				RPCAPD_LOG(DEBUG, "data connection closed by client");
			else if (errno == EAGAIN || errno == EWOULDBLOCK)
				RPCAPD_LOG(NOTICE,
					   "client stopped reading data connection, closing");
			else
				RPCAPD_LOG(NOTICE, "send on data connection failed: %s",
					   strerror(errno));
			goto error;
		}
		rte_pktmbuf_free(m);
		written += sizeof(hdr) + sizeof(pkthdr) + caplen;
	}

	return written;

error:
	rte_pktmbuf_free_bulk(pkts + i, n - i);
	return -1;
}

/* Poll the control socket while idle.
 * Returns 0 to keep capturing, 1 if a control message (typically
 * ENDCAP) is pending, or -1 if the client has gone away.
 */
static int
check_socket_status(const struct conn *ctrl)
{
	struct pollfd pfd = { .fd = ctrl->fd, .events = POLLIN };

	/* A request may already be decrypted and waiting out of sight
	 * of poll(), sharing a TLS record with an earlier one.
	 */
	if (tls_pending(ctrl))
		return 1;

	if (poll(&pfd, 1, 0) < 0) {
		if (errno == EINTR)
			return 0;
		RPCAPD_LOG(ERR, "poll failed: %s", strerror(errno));
		return -1;
	}
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		RPCAPD_LOG(DEBUG, "client closed control connection");
		return -1;
	}
	if (pfd.revents & POLLIN)
		return 1;
	return 0;
}

/*
 * Drain the ring until a control message arrives, the data connection
 * breaks, or a quit signal is delivered.  Returns 0 if the session
 * should continue, -1 if the client is gone.
 *
 * The control socket is polled every iteration, not only when the ring
 * is empty: a client waiting for a reply stops draining the data
 * socket, and both ends wedge once the buffers fill.
 */
int
capture_loop(const struct conn *ctrl, struct session *s)
{
	unsigned int empty_count = 0;

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		ssize_t written;
		unsigned int avail = 0;

		switch (check_socket_status(ctrl)) {
		case 1:
			/* control message pending, let caller service it */
			return 0;
		case 0:
			break;
		default:
			/* client is gone */
			return -1;
		}

		written = process_ring(s, &avail);
		if (written < 0) {
			/* process_ring has already logged the reason */
			return -1;
		}

		if (written > 0) {
			/* are there more packets? */
			empty_count = (avail == 0);
			continue;
		}

		if (empty_count < SLEEP_THRESHOLD) {
			/* spin a few times before checking */
			++empty_count;
			rte_pause();
			continue;
		}

		/* ring has been empty for a while: stop spinning */
		rte_delay_us_sleep(SLEEP_US);
	}
	return 0;
}

int
handle_endcap(const struct conn *c, uint32_t plen, struct session *s)
{
	if (rpcap_discard(c, plen) < 0)
		return -1;
	stop_capture(s);
	return rpcap_send_msg(c, RPCAP_MSG_ENDCAP_REPLY, 0, NULL, 0);
}

int
handle_stats(const struct conn *c, uint32_t plen, const struct session *s)
{
	struct rte_eth_stats es = { 0 };

	if (rpcap_discard(c, plen) < 0)
		return -1;

	if (s->capture_on)
		rte_eth_stats_get(s->port, &es);

	struct rpcap_stats reply = {
		.ifrecv   = rte_cpu_to_be_32((uint32_t)es.ipackets),
		.ifdrop   = rte_cpu_to_be_32((uint32_t)es.ierrors),
		.krnldrop = 0,
		.svrcapt  = rte_cpu_to_be_32(s->npkt),
	};
	return rpcap_send_msg(c, RPCAP_MSG_STATS_REPLY, 0, &reply, sizeof(reply));
}
