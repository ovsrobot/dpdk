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
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pdump.h>
#include <rte_ring.h>
#include <rte_stdatomic.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

#define BURST_SIZE                    32
#define POLL_INTERVAL_MS              500

/* Two rpcap headers plus the segments of one captured packet. */
#define PKT_MAX_IOV                   34

/* A capture is sent from the mbuf segments, so a packet at the snaplen
 * has to fit in the iovecs left after the two headers.
 */
static_assert(MAX_SNAPLEN <= (PKT_MAX_IOV - 2) * RTE_MBUF_DEFAULT_DATAROOM,
	      "snaplen needs more iovecs than PKT_MAX_IOV");
#define SLEEP_THRESHOLD		      100
#define SLEEP_US		      100
#define DATA_ACCEPT_TIMEOUT_MS        10000

/*
 * Open an ephemeral TCP listening socket for the data connection;
 * return fd, set *port_out.
 *
 * The local address of the control connection is used, not the bind
 * address: the daemon may be listening on several addresses, and the
 * data connection has to be reachable the way the client reached the
 * control connection.
 */
static int
open_data_listener(const struct conn *ctrl, uint16_t *port_out)
{
	struct sockaddr_storage addr;
	socklen_t alen = sizeof(addr);
	int fd;

	if (getsockname(ctrl->fd, (struct sockaddr *)&addr, &alen) < 0) {
		RPCAPD_LOG(ERR, "getsockname: %s", strerror(errno));
		return -1;
	}
	set_sockaddr_port(&addr, 0);

	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	if (fd < 0) {
		RPCAPD_LOG(ERR, "data socket: %s", strerror(errno));
		return -1;
	}

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
create_capture_mempool(uint16_t port)
{
	char name[RTE_MEMPOOL_NAMESIZE];

	snprintf(name, sizeof(name), "rpcapd_p_%u_%d", port, getpid());

	/*
	 * No per-lcore cache: the primary allocates from this pool in the
	 * pdump callback and this process frees, and both would index
	 * local_cache[] by an lcore id that the two processes can share.
	 * Multi-process ops are named explicitly for the same reason.
	 */
	return rte_pktmbuf_pool_create_by_ops(name, ring_size * 2, 0, 0,
					      RTE_MBUF_DEFAULT_BUF_SIZE,
					      rte_socket_id(), "ring_mp_mc");
}


/* Tear down anything that handle_startcap brought up.
 * Safe to call after partial setup as well as after a successful capture.
 */
void
stop_capture(struct session *s)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int n;

	/* First: nothing below may run while the data thread is still
	 * dequeuing from the ring or writing to the data socket.
	 */
	stop_data_thread(s);

	/*
	 * If the primary is gone the shared memory state cannot be trusted:
	 * pdump IPC has no one to answer it, the port belongs to a dead
	 * process, and the ring, mempool and heap locks may have been held
	 * when it died.  Drop the references and leave the memory alone.
	 */
	if (!rte_eal_primary_proc_alive(NULL)) {
		s->capture_on = false;
		s->promisc_set = false;
		s->ring = NULL;
		s->mp = NULL;
		s->prm = NULL;
		if (s->data.fd >= 0) {
			close(s->data.fd);
			s->data.fd = -1;
		}
		return;
	}

	if (s->capture_on) {
		rte_pdump_disable(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags);
		RPCAPD_LOG(NOTICE, "capture stopped on %s (%u packets)",
			s->name,
			rte_atomic_load_explicit(&s->npkt, rte_memory_order_relaxed));
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
	if (s->snaplen == 0)
		s->snaplen = DEFAULT_SNAPLEN;
	else if (s->snaplen > MAX_SNAPLEN)
		s->snaplen = MAX_SNAPLEN;

	s->ring = create_capture_ring(s->port);
	s->mp = create_capture_mempool(s->port);
	if (s->ring == NULL || s->mp == NULL) {
		RPCAPD_LOG(ERR, "ring/mempool alloc failed: %s",
			rte_strerror(rte_errno));
		stop_capture(s);
		return rpcap_send_error(c, 0, "DPDK alloc failed");
	}

	data_listen = open_data_listener(c, &data_port);
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

	/*
	 * Setup packet capture callbacks.  The copy into the ring is of the
	 * whole packet: the snapshot is applied when it leaves the ring, so
	 * that the length before truncation is still known and can be
	 * reported to the client as the wire length.  A zero snaplen is how
	 * pdump is asked not to truncate.
	 */
	if (rte_pdump_enable_bpf(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags,
				 0, s->ring, s->mp, s->prm) < 0) {
		RPCAPD_LOG(ERR, "rte_pdump_enable_bpf port %u failed: %s",
			s->port, rte_strerror(rte_errno));
		close(data_listen);
		stop_capture(s);
		return rpcap_send_error(c, 0, "cannot enable capture");
	}
	s->capture_on = true;
	rte_atomic_store_explicit(&s->npkt, 0, rte_memory_order_relaxed);

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

	s->data.fd = data_fd;

	/* Bound how long a send can block. */
	if (send_timeout > 0) {
		struct timeval tv = {
			.tv_sec = send_timeout,
		};

		if (setsockopt(data_fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
			RPCAPD_LOG(NOTICE, "cannot set data send timeout: %s",
				   strerror(errno));
	}

	if (start_data_thread(s) < 0) {
		stop_capture(s);
		return rpcap_send_error(c, 0, "cannot start capture thread");
	}

	RPCAPD_LOG(NOTICE,
		   "capture started on %s (snaplen %u, data port %u)",
		   s->name, s->snaplen, data_port);
	return 0;
}

/*
 * Point iovecs at len bytes of an mbuf chain, starting at off.  The
 * capture is sent straight from the mbufs: a copy into one flat buffer
 * would cost a memcpy per packet on the datapath for no benefit, since
 * sendmsg() takes a scatter list.
 *
 * Returns the number of iovecs used, or -1 if the chain needs more than
 * the caller allows.
 */
static int
mbuf_to_iov(const struct rte_mbuf *m, uint32_t off, uint32_t len,
	    struct iovec *iov, int maxiov)
{
	int n = 0;

	while (m != NULL && len > 0) {
		uint32_t seg = rte_pktmbuf_data_len(m);

		if (off >= seg) {
			/* Not reached the data yet. */
			off -= seg;
			m = m->next;
			continue;
		}

		if (n == maxiov)
			return -1;

		seg -= off;
		if (seg > len)
			seg = len;

		iov[n].iov_base = rte_pktmbuf_mtod_offset(m, void *, off);
		iov[n].iov_len = seg;
		n++;

		len -= seg;
		off = 0;
		m = m->next;
	}

	return (len == 0) ? n : -1;
}

/*
 * Frame each packet from the ring into an RPCAP_MSG_PACKET message and
 * send it on the data connection.  MSG_MORE corks the socket until the
 * ring drains, so a backlog coalesces into full segments.
 *
 * pdump copies the whole packet, so both the snapshot and the timestamp
 * are applied here: the wire length is still the full length, and the
 * time of day is taken once per burst rather than per packet.
 */
static ssize_t
process_ring(struct session *s, unsigned int *avail)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	struct timespec now;
	unsigned int i, n;
	ssize_t written = 0;

	n = rte_ring_sc_dequeue_burst(s->ring, (void **)pkts, BURST_SIZE, avail);
	if (n == 0)
		return 0;

	clock_gettime(CLOCK_REALTIME, &now);

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		struct iovec iov[PKT_MAX_IOV];
		uint32_t caplen, wirelen, npkt;
		int niov;

		wirelen = rte_pktmbuf_pkt_len(m);
		caplen = RTE_MIN(wirelen, s->snaplen);

		/* Only this thread writes npkt, so a load and store is
		 * enough; the STATS reader just needs a torn-free value.
		 */
		npkt = rte_atomic_load_explicit(&s->npkt,
						rte_memory_order_relaxed) + 1;
		rte_atomic_store_explicit(&s->npkt, npkt,
					  rte_memory_order_relaxed);

		struct rpcap_header hdr = {
			.ver = RPCAP_VERSION,
			.type = RPCAP_MSG_PACKET,
			.plen = rte_cpu_to_be_32(sizeof(struct rpcap_pkthdr) + caplen),
		};

		/* rpcap protocol has timestamp in microseconds. */
		struct rpcap_pkthdr pkthdr = {
			.timestamp_sec = rte_cpu_to_be_32(now.tv_sec),
			.timestamp_usec = rte_cpu_to_be_32(now.tv_nsec / 1000),
			.caplen = rte_cpu_to_be_32(caplen),
			.len = rte_cpu_to_be_32(wirelen),
			.npkt = rte_cpu_to_be_32(npkt),
		};

		iov[0].iov_base = &hdr;
		iov[0].iov_len = sizeof(hdr);
		iov[1].iov_base = &pkthdr;
		iov[1].iov_len = sizeof(pkthdr);

		niov = mbuf_to_iov(m, 0, caplen, iov + 2, PKT_MAX_IOV - 2);
		if (unlikely(niov < 0)) {
			RPCAPD_LOG(ERR, "short capture mbuf on %s", s->name);
			goto error;
		}
		niov += 2;

		/* more to come in this burst, or still queued in the ring */
		bool more = (i + 1 < n) || (*avail > 0);

		if (send_iov_full(&s->data, iov, niov, more ? MSG_MORE : 0) < 0) {
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

/*
 * Data thread: drain the ring and stream packets until asked to stop.
 *
 * This runs separately from the control connection because the ring has
 * no file descriptor to poll.  A single thread would have to choose
 * between blocking on the control socket (and not draining the ring) or
 * spinning on the ring (and answering requests late); worse, a blocking
 * send to a slow client would stall control requests entirely, which is
 * what a client does when it asks for statistics and waits for a reply
 * without reading packets.
 */
static uint32_t
data_thread_main(void *arg)
{
	struct session *s = arg;
	unsigned int empty_count = 0;

	while (!rte_atomic_load_explicit(&s->data_stop, rte_memory_order_relaxed) &&
	       !rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		unsigned int avail = 0;
		ssize_t written;

		written = process_ring(s, &avail);
		if (written < 0) {
			/* process_ring has logged the reason */
			break;
		}

		if (written > 0) {
			/* are there more packets? */
			empty_count = (avail == 0);
			continue;
		}

		if (empty_count < SLEEP_THRESHOLD) {
			/* spin a few times before sleeping */
			++empty_count;
			rte_pause();
			continue;
		}

		/* ring has been empty for a while: stop spinning */
		rte_delay_us_sleep(SLEEP_US);
	}

	/* Wake the control thread: it polls this alongside the control
	 * socket, so a client that closes only the data connection is
	 * noticed without waiting for it to send a request.
	 */
	if (eventfd_write(s->data_done_fd, 1) < 0)
		RPCAPD_LOG(DEBUG, "cannot signal data thread exit: %s",
			   strerror(errno));
	return 0;
}

int
start_data_thread(struct session *s)
{
	int rc;

	rte_atomic_store_explicit(&s->data_stop, false, rte_memory_order_relaxed);

	s->data_done_fd = eventfd(0, EFD_CLOEXEC);
	if (s->data_done_fd < 0) {
		RPCAPD_LOG(ERR, "eventfd: %s", strerror(errno));
		return -1;
	}

	rc = rte_thread_create_control(&s->data_thread, "rpcapd-data",
				       data_thread_main, s);
	if (rc != 0) {
		RPCAPD_LOG(ERR, "cannot create data thread: %s", rte_strerror(-rc));
		close(s->data_done_fd);
		s->data_done_fd = -1;
		return -1;
	}
	s->data_running = true;
	return 0;
}

/*
 * Wait until the control connection has a request or the data thread has
 * exited, whichever comes first.  The thread signals an eventfd on its
 * way out, which makes its exit just another pollable event: a client
 * that closes only the data connection is noticed straight away instead
 * of when it next sends a request.
 *
 * Returns 1 if a request is waiting, 0 if the data thread is done, or -1.
 */
int
wait_ctrl_or_data_exit(const struct conn *ctrl, const struct session *s)
{
	struct pollfd pfd[2] = {
		{ .fd = ctrl->fd,         .events = POLLIN },
		{ .fd = s->data_done_fd,  .events = POLLIN },
	};
	int nfds = (s->data_running && s->data_done_fd >= 0) ? 2 : 1;

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		int rc = poll(pfd, nfds, POLL_INTERVAL_MS);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			RPCAPD_LOG(ERR, "poll failed: %s", strerror(errno));
			return -1;
		}
		if (pfd[0].revents != 0)
			return 1;
		if (nfds > 1 && pfd[1].revents != 0)
			return 0;
	}
	return -1;
}

void
stop_data_thread(struct session *s)
{
	if (!s->data_running)
		return;

	rte_atomic_store_explicit(&s->data_stop, true, rte_memory_order_relaxed);
	rte_thread_join(s->data_thread, NULL);
	s->data_running = false;

	close(s->data_done_fd);
	s->data_done_fd = -1;
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
	struct rte_pdump_stats ps = { 0 };
	uint64_t ifrecv = 0, dropped = 0;

	if (rpcap_discard(c, plen) < 0)
		return -1;

	/* Report what the capture saw, not the port's lifetime counters:
	 * port stats include traffic from before the capture started and
	 * say nothing about packets pdump had to drop.  Same accounting as
	 * dpdk-dumpcap.  The client maps krnldrop to the "dropped by
	 * kernel" count and ifdrop to interface drops, which pdump does
	 * not distinguish, so the drops are reported as the former.
	 */
	if (s->capture_on && rte_pdump_stats(s->port, &ps) == 0) {
		ifrecv = ps.accepted + ps.filtered;
		dropped = ps.nombuf + ps.ringfull;
	}

	struct rpcap_stats reply = {
		.ifrecv   = rte_cpu_to_be_32((uint32_t)ifrecv),
		.ifdrop   = 0,
		.krnldrop = rte_cpu_to_be_32((uint32_t)dropped),
		.svrcapt  = rte_cpu_to_be_32(
			rte_atomic_load_explicit(&s->npkt, rte_memory_order_relaxed)),
	};
	return rpcap_send_msg(c, RPCAP_MSG_STATS_REPLY, 0, &reply, sizeof(reply));
}
