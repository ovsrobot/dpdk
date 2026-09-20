/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Demonstration server for the rpcap protocol for DPDK.
 * This allows a libpcap client (e.g. Wireshark or tcpdump)
 * to use "rpcap://host[:port]/portname" as capture device.
 *
 * Based on the DPDK dumpcap application and on rpcapd from libpcap:
 *   https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
 *
 * Only the bits of the RPCAP protocol that are needed for an
 * unauthenticated, passive-mode capture session are implemented.
 * Configuration files, active mode, sampling and concurrent clients
 * are intentionally omitted to keep the example small.
 *
 * A capture filter may be sent with the start-capture request:
 * the client compiles it, so it arrives as cBPF which is converted to
 * DPDK BPF and handed to pdump.  Filters cannot be changed once the
 * capture is running; see the UPDATEFILTER handling.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include <rte_alarm.h>
#include <rte_bpf.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pdump.h>
#include <rte_stdatomic.h>
#include <rte_ring.h>
#include <rte_version.h>

#include "rpcap-protocol.h"

#define BURST_SIZE                    32
#define MBUF_CACHE_SIZE               32
#define DEFAULT_RING_SIZE             2048
#define MAX_RING_SIZE                 (1U << 20)
#define DEFAULT_SNAPLEN               RTE_MBUF_DEFAULT_DATAROOM
#define PRIMARY_MONITOR_INTERVAL_US   (500 * 1000)
#define SLEEP_THRESHOLD		      100
#define SLEEP_US		      100

#define DATA_ACCEPT_TIMEOUT_MS        10000
#define POLL_INTERVAL_MS              500

#define MAX_FILTER_INSNS              4096

#define RTE_LOGTYPE_RPCAPD RTE_LOGTYPE_USER1
#define RPCAPD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RPCAPD, "%s(): ", __func__, __VA_ARGS__)

/* Per-client capture session state. */
struct session {
	int      data_fd;
	uint16_t port;				/* DPDK ethdev port being captured */
	char     name[RTE_ETH_NAME_MAX_LEN];
	uint32_t snaplen;
	uint32_t npkt;				/* packet sequence for rpcap_pkthdr */
	uint32_t pdump_flags;			/* RTE_PDUMP_FLAG_* in use */
	bool     opened;			/* OPEN_REQ has selected a port */
	bool     capture_on;
	bool     promisc_set;			/* we enabled promiscuous mode */
	struct rte_ring    *ring;
	struct rte_mempool *mp;
	struct rte_bpf_prm *prm;		/* capture filter, NULL if none */
};

/* Command-line options */
static uint16_t listen_port = RPCAP_DEFAULT_NETPORT;
static uint32_t ring_size = DEFAULT_RING_SIZE;
static const char *lcore_arg;
static const char *file_prefix;
static const char *bind_arg;		/* -b argument, resolved after option parsing */
static const char *debug_file;		/* --debug-file argument */
static bool ipv4_only;			/* -4: restrict to IPv4 */
static unsigned int debug_log;		/* -D count: raise RPCAPD log verbosity */

static struct sockaddr_storage listen_addr;
static socklen_t               listen_addrlen;

static void stop_capture(struct session *s);

static void
set_sockaddr_port(struct sockaddr_storage *ss, uint16_t port)
{
	if (ss->ss_family == AF_INET6)
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
	else
		((struct sockaddr_in *)ss)->sin_port = htons(port);
}

static uint16_t
get_sockaddr_port(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET6)
		return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
	return ntohs(((const struct sockaddr_in *)ss)->sin_port);
}

static bool
is_loopback(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const void *)ss;

		return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
	}
	if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const void *)ss;

		return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
	}
	return false;
}

static void
parse_bind_addr(const char *str, int family)
{
	struct addrinfo hints = {
		.ai_family   = family,
		.ai_socktype = SOCK_STREAM,
		.ai_flags    = AI_NUMERICHOST | AI_PASSIVE,
	};
	struct addrinfo *res;
	int rc;

	rc = getaddrinfo(str, NULL, &hints, &res);
	if (rc != 0)
		rte_exit(EXIT_FAILURE, "Invalid bind address '%s': %s\n",
			 str, gai_strerror(rc));
	memcpy(&listen_addr, res->ai_addr, res->ai_addrlen);
	listen_addrlen = res->ai_addrlen;
	freeaddrinfo(res);
}

static RTE_ATOMIC(bool) quit_signal;

static void
signal_handler(int sig __rte_unused)
{
	rte_atomic_store_explicit(&quit_signal, true, rte_memory_order_relaxed);
}

/*
 * Wait for fd to become readable, in POLL_INTERVAL_MS slices so that a
 * quit signal (from SIGINT/SIGTERM or from the primary process dying)
 * is noticed while blocked.  timeout_ms < 0 waits indefinitely.
 *
 * Returns 1 when readable, 0 on timeout, -1 on error or quit.
 */
static int
wait_readable(int fd, int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		int wait_ms = POLL_INTERVAL_MS;
		int rc;

		if (timeout_ms >= 0) {
			if (timeout_ms == 0)
				return 0;
			if (timeout_ms < wait_ms)
				wait_ms = timeout_ms;
			timeout_ms -= wait_ms;
		}

		rc = poll(&pfd, 1, wait_ms);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			RPCAPD_LOG(ERR, "poll failed: %s", strerror(errno));
			return -1;
		}
		if (rc > 0)
			return 1;
	}
	return -1;
}

/* accept() with a timeout, so a stalled client cannot wedge the daemon. */
static int
accept_timeout(int listen_fd, int timeout_ms)
{
	int fd;

	switch (wait_readable(listen_fd, timeout_ms)) {
	case 1:
		break;
	case 0:
		RPCAPD_LOG(ERR, "timed out waiting for data connection");
		return -1;
	default:
		return -1;
	}

	fd = accept(listen_fd, NULL, NULL);
	if (fd < 0)
		RPCAPD_LOG(ERR, "accept: %s", strerror(errno));
	return fd;
}

/* Read exactly len bytes; return 0 on success, -1 on error or EOF. */
static int
recv_full(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n;

		/* Wait with a timeout rather than blocking in recv(), so a
		 * quit signal or a dead primary is acted on promptly.
		 */
		if (wait_readable(fd, -1) != 1)
			return -1;

		n = recv(fd, p, len, 0);
		if (n < 0 && errno == EINTR)
			continue;

		if (n <= 0)
			return -1;

		p += n;
		len -= n;
	}
	return 0;
}

/*
 * Send all of iov, resending the remainder if sendmsg() reports a short
 * count (possible when the connection breaks or a signal arrives after
 * some bytes were copied).  Consumes iov, so pass a scratch copy.
 */
static int
send_iov_full(int fd, struct iovec *iov, int iovcnt, int flags)
{
	struct msghdr msg = {
		.msg_iov    = iov,
		.msg_iovlen = iovcnt,
	};

	while (msg.msg_iovlen > 0) {
		ssize_t n = sendmsg(fd, &msg, flags | MSG_NOSIGNAL);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			return -1;

		/* Drop whole iovecs that were fully sent, then trim the
		 * partially sent one.
		 */
		while (msg.msg_iovlen > 0 && (size_t)n >= msg.msg_iov->iov_len) {
			n -= msg.msg_iov->iov_len;
			msg.msg_iov++;
			msg.msg_iovlen--;
		}
		if (n > 0) {
			msg.msg_iov->iov_base = (char *)msg.msg_iov->iov_base + n;
			msg.msg_iov->iov_len -= n;
		}
	}
	return 0;
}

static int
rpcap_send_msg(int fd, uint8_t type, uint16_t value, const void *payload, uint32_t plen)
{
	struct rpcap_header hdr = {
		.ver = RPCAP_VERSION,
		.type = type,
		.value = htons(value),
		.plen = htonl(plen),
	};
	struct iovec iov[2] = {
		{ .iov_base = &hdr,                        .iov_len = sizeof(hdr) },
		{ .iov_base = (void *)(uintptr_t)payload,  .iov_len = plen },
	};

	return send_iov_full(fd, iov, plen > 0 ? 2 : 1, 0);
}

static int
rpcap_send_error(int fd, uint16_t errcode, const char *msg)
{
	RPCAPD_LOG(WARNING, "sending error to client: %s", msg);
	return rpcap_send_msg(fd, RPCAP_MSG_ERROR, errcode, msg, strlen(msg));
}

static int
rpcap_recv_header(int fd, struct rpcap_header *hdr)
{
	if (recv_full(fd, hdr, sizeof(*hdr)) < 0)
		return -1;
	hdr->value = ntohs(hdr->value);
	hdr->plen = ntohl(hdr->plen);
	return 0;
}

/* Throw away plen bytes of payload we don't care about. */
static int
rpcap_discard(int fd, uint32_t plen)
{
	uint8_t buf[256];

	while (plen > 0) {
		size_t chunk = plen > sizeof(buf) ? sizeof(buf) : plen;

		if (recv_full(fd, buf, chunk) < 0)
			return -1;
		plen -= chunk;
	}
	return 0;
}

/* Build and send the list of available DPDK ports. */
static int
handle_findallif(int fd)
{
	uint8_t *buf = NULL;
	size_t buflen = 0;
	uint16_t nif = 0;
	uint16_t p;
	int rc;

	RTE_ETH_FOREACH_DEV(p) {
		static const char desc[] = "DPDK port";
		char name[RTE_ETH_NAME_MAX_LEN];
		size_t namelen, desclen, entry;
		uint8_t *nb;

		if (rte_eth_dev_get_name_by_port(p, name) < 0) {
			RPCAPD_LOG(DEBUG, "can not find name for port %u", p);
			continue;
		}

		RPCAPD_LOG(DEBUG, "findallif: port %u -> '%s'", p, name);
		namelen = strlen(name);
		desclen = strlen(desc);
		entry = sizeof(struct rpcap_findalldevs_if) + namelen + desclen;

		nb = realloc(buf, buflen + entry);
		if (nb == NULL) {
			RPCAPD_LOG(ERR, "out of memory in findallif");
			free(buf);
			return rpcap_send_error(fd, 0, "out of memory");
		}
		buf = nb;

		struct rpcap_findalldevs_if iface = {
			.namelen = htons(namelen),
			.desclen = htons(desclen),
			.flags = htonl(PCAP_IF_UP | PCAP_IF_RUNNING),
		};
		memcpy(buf + buflen, &iface, sizeof(iface));
		memcpy(buf + buflen + sizeof(iface), name, namelen);
		memcpy(buf + buflen + sizeof(iface) + namelen, desc, desclen);
		buflen += entry;
		nif++;
	}

	RPCAPD_LOG(DEBUG, "findallif: %u interface(s)", nif);
	rc = rpcap_send_msg(fd, RPCAP_MSG_FINDALLIF_REPLY, nif, buf, buflen);
	free(buf);
	return rc;
}

/* OPEN_REQ: payload is the interface name (no NUL). */
static int
handle_open(int fd, uint32_t plen, struct session *s)
{
	struct rpcap_openreply reply = {
		.linktype = htonl(DLT_EN10MB),
	};
	uint16_t port;

	/* Unconditionally, not just when capture_on: a failed UPDATEFILTER
	 * leaves the ring, mempool and data connection live with the capture
	 * already disabled, and those must not survive into a new session.
	 */
	stop_capture(s);

	if (plen >= sizeof(s->name)) {
		rpcap_discard(fd, plen);
		return rpcap_send_error(fd, 0, "interface name too long");
	}
	if (recv_full(fd, s->name, plen) < 0)
		return -1;
	s->name[plen] = '\0';

	if (rte_eth_dev_get_port_by_name(s->name, &port) < 0) {
		RPCAPD_LOG(WARNING, "open: no such port '%s'", s->name);
		/* s->name has already been overwritten; make sure a later
		 * STARTCAP cannot capture the previously opened port.
		 */
		s->opened = false;
		return rpcap_send_error(fd, 0, "unknown interface");
	}
	s->port = port;
	s->opened = true;

	RPCAPD_LOG(DEBUG, "open: '%s' -> dpdk port %u", s->name, port);
	return rpcap_send_msg(fd, RPCAP_MSG_OPEN_REPLY, 0, &reply, sizeof(reply));
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
	uint32_t mbuf_size = RTE_PKTMBUF_HEADROOM + snaplen;

	snprintf(name, sizeof(name), "rpcapd_p_%u_%d", port, getpid());
	return rte_pktmbuf_pool_create(name, ring_size * 2, MBUF_CACHE_SIZE, 0,
				       mbuf_size, rte_socket_id());
}

/*
 * Read the optional capture filter that follows a start-capture request,
 * and convert it for pdump. Client passes cBPF.
 */
static int
read_filter(int fd, uint32_t plen, struct session *s)
{
	struct rpcap_filterbpf_insn winsn;
	struct rpcap_filter filter;
	struct bpf_program bf;
	struct bpf_insn *insns;
	uint32_t i, nitems;

	if (plen == 0)
		return 0;		/* no filter: capture everything */

	if (plen < sizeof(filter)) {
		if (rpcap_discard(fd, plen) < 0)
			return -1;
		return rpcap_send_error(fd, 0, "short filter header") < 0 ? -1 : 1;
	}

	if (recv_full(fd, &filter, sizeof(filter)) < 0)
		return -1;
	plen -= sizeof(filter);

	if (ntohs(filter.filtertype) != RPCAP_UPDATEFILTER_BPF) {
		if (rpcap_discard(fd, plen) < 0)
			return -1;
		return rpcap_send_error(fd, 0, "unsupported filter type") < 0 ? -1 : 1;
	}

	/* nitems is client-supplied; bound it before trusting the length. */
	nitems = ntohl(filter.nitems);
	if (nitems == 0)
		return rpcap_discard(fd, plen) < 0 ? -1 : 0;

	if (nitems > MAX_FILTER_INSNS || plen < nitems * sizeof(winsn)) {
		if (rpcap_discard(fd, plen) < 0)
			return -1;
		return rpcap_send_error(fd, 0, "bad filter length") < 0 ? -1 : 1;
	}

	insns = calloc(nitems, sizeof(*insns));
	if (insns == NULL) {
		if (rpcap_discard(fd, plen) < 0)
			return -1;
		return rpcap_send_error(fd, 0, "out of memory") < 0 ? -1 : 1;
	}

	for (i = 0; i < nitems; i++) {
		if (recv_full(fd, &winsn, sizeof(winsn)) < 0) {
			free(insns);
			return -1;
		}
		insns[i].code = ntohs(winsn.code);
		insns[i].jt   = winsn.jt;
		insns[i].jf   = winsn.jf;
		insns[i].k    = ntohl(winsn.k);
	}
	plen -= nitems * sizeof(winsn);

	/* Anything after the instructions is padding we do not need. */
	if (rpcap_discard(fd, plen) < 0) {
		free(insns);
		return -1;
	}

	bf.bf_len = nitems;
	bf.bf_insns = insns;

	/* Reject a malformed program here */
	if (!bpf_validate(bf.bf_insns, bf.bf_len)) {
		free(insns);
		return rpcap_send_error(fd, 0, "invalid filter program") < 0 ? -1 : 1;
	}

	/* A filter recorded by an earlier UPDATEFILTER may still be here;
	 * it is about to be replaced, so do not leak it.
	 */
	rte_free(s->prm);
	s->prm = rte_bpf_convert(&bf);
	free(insns);
	if (s->prm == NULL) {
		RPCAPD_LOG(ERR, "rte_bpf_convert failed: %s",
			rte_strerror(rte_errno));
		return rpcap_send_error(fd, 0, "cannot convert filter") < 0 ? -1 : 1;
	}

	RPCAPD_LOG(DEBUG, "capture filter: %u instructions", nitems);
	return 0;
}

/* Tear down anything that handle_startcap brought up.  Safe to call
 * after partial setup as well as after a successful capture.
 */
static void
stop_capture(struct session *s)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int n;

	if (s->capture_on) {
		rte_pdump_disable(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags);
		RPCAPD_LOG(INFO, "capture stopped on %s (%u packets)",
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
	if (s->data_fd >= 0) {
		close(s->data_fd);
		s->data_fd = -1;
	}
}

/*
 * STARTCAP_REQ: open the data connection and arm the pdump callback.
 * We use passive mode with the server-allocated data port:
 *   - the server picks an ephemeral port and listens on it
 *   - the server returns that port in startcapreply.portdata
 *   - the client connects back to that port for the packet stream
 */
static int
handle_startcap(int fd, uint32_t plen, struct session *s)
{
	struct rpcap_startcapreq req;
	uint16_t data_port;
	uint16_t flags;
	struct rte_bpf_prm *recorded;
	int data_listen;
	int data_fd;
	int ret;

	recorded = s->prm;
	s->prm = NULL;
	stop_capture(s);
	s->prm = recorded;

	if (!s->opened) {
		rpcap_discard(fd, plen);
		return rpcap_send_error(fd, 0, "no interface open");
	}

	if (plen < sizeof(req)) {
		rpcap_discard(fd, plen);
		return rpcap_send_error(fd, 0, "short startcap request");
	}
	if (recv_full(fd, &req, sizeof(req)) < 0)
		return -1;

	flags = ntohs(req.flags);
	if (flags & RPCAP_STARTCAPREQ_FLAG_DGRAM) {
		rpcap_discard(fd, plen - sizeof(req));
		return rpcap_send_error(fd, 0, "UDP data transfer not supported");
	}

	ret = read_filter(fd, plen - sizeof(req), s);
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

	s->snaplen = ntohl(req.snaplen);
	if (s->snaplen == 0 || s->snaplen > DEFAULT_SNAPLEN)
		s->snaplen = DEFAULT_SNAPLEN;

	s->ring = create_capture_ring(s->port);
	s->mp = create_capture_mempool(s->port, s->snaplen);
	if (s->ring == NULL || s->mp == NULL) {
		RPCAPD_LOG(ERR, "ring/mempool alloc failed: %s",
			rte_strerror(rte_errno));
		stop_capture(s);
		return rpcap_send_error(fd, 0, "DPDK alloc failed");
	}

	data_listen = open_data_listener(&data_port);
	if (data_listen < 0) {
		stop_capture(s);
		return rpcap_send_error(fd, 0, "data port setup failed");
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

	/* Arm pdump before replying. */
	if (rte_pdump_enable_bpf(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags,
				 s->snaplen, s->ring, s->mp, s->prm) < 0) {
		RPCAPD_LOG(ERR, "rte_pdump_enable_bpf port %u failed: %s",
			s->port, rte_strerror(rte_errno));
		close(data_listen);
		stop_capture(s);
		return rpcap_send_error(fd, 0, "cannot enable capture");
	}
	s->capture_on = true;
	s->npkt = 0;

	struct rpcap_startcapreply reply = {
		.bufsize = htonl(s->snaplen * BURST_SIZE),
		.portdata = htons(data_port),
	};
	if (rpcap_send_msg(fd, RPCAP_MSG_STARTCAP_REPLY, 0, &reply, sizeof(reply)) < 0) {
		close(data_listen);
		stop_capture(s);
		return -1;
	}

	RPCAPD_LOG(DEBUG, "awaiting connection");

	data_fd = accept_timeout(data_listen, DATA_ACCEPT_TIMEOUT_MS);
	close(data_listen);
	if (data_fd < 0) {
		stop_capture(s);
		return -1;
	}

	s->data_fd = data_fd;

	RPCAPD_LOG(INFO,
		"capture started on %s (snaplen %u, data port %u)",
		s->name, s->snaplen, data_port);
	return 0;
}

/*
 * UPDATEFILTER_REQ: replace the capture filter.
 *
 * pdump takes its filter when the callback is armed and offers no way
 * to replace it, so this disables and re-enables the callback with the
 * new program.  Packets already in the ring are kept; only the brief
 * gap between disable and enable is lost.  Refusing the request is not
 * an option: libpcap sends UPDATEFILTER right after STARTCAP when the
 * client was opened with PCAP_OPENFLAG_NOCAPTURE_RPCAP and aborts the
 * capture if it fails, and Wireshark sets that flag by default.
 *
 * Before the capture starts this just records the filter for the
 * eventual STARTCAP.
 */
static int
handle_updatefilter(int fd, uint32_t plen, struct session *s)
{
	struct rte_bpf_prm *old = s->prm;
	int ret;

	s->prm = NULL;
	ret = read_filter(fd, plen, s);
	if (ret != 0) {
		/* Malformed request: keep running with the old filter. */
		rte_free(s->prm);
		s->prm = old;
		return ret < 0 ? -1 : 0;	/* error already reported */
	}

	if (!s->capture_on) {
		rte_free(old);
		return rpcap_send_msg(fd, RPCAP_MSG_UPDATEFILTER_REPLY, 0, NULL, 0);
	}

	rte_pdump_disable(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags);
	s->capture_on = false;

	if (rte_pdump_enable_bpf(s->port, RTE_PDUMP_ALL_QUEUES, s->pdump_flags,
				 s->snaplen, s->ring, s->mp, s->prm) < 0) {
		RPCAPD_LOG(ERR, "rte_pdump_enable_bpf port %u failed: %s",
			s->port, rte_strerror(rte_errno));
		rte_free(old);
		/* The capture cannot be resumed, so do not leave the ring,
		 * mempool and data connection behind: the client has been
		 * told the capture is over, and a session that is neither
		 * capturing nor torn down has no way back.
		 */
		stop_capture(s);
		return rpcap_send_error(fd, 0, "cannot apply filter");
	}
	s->capture_on = true;

	/* Safe now that the old program is no longer referenced. */
	rte_free(old);

	RPCAPD_LOG(DEBUG, "capture filter updated on %s", s->name);
	return rpcap_send_msg(fd, RPCAP_MSG_UPDATEFILTER_REPLY, 0, NULL, 0);
}

/*
 * Pull a burst from the ring, frame each packet into an RPCAP_MSG_PACKET
 * message, and send it on the data connection.  MSG_MORE corks the
 * socket until the ring drains, so a backlog coalesces into full
 * segments instead of flushing every BURST_SIZE packets.
 */
static ssize_t
process_ring(struct session *s, unsigned int *avail)
{
	struct rte_mbuf *pkts[BURST_SIZE];
	unsigned int i, n;
	ssize_t written = 0;
	struct timeval tv;

	n = rte_ring_sc_dequeue_burst(s->ring, (void **)pkts, BURST_SIZE, avail);
	if (n == 0)
		return 0;

	/* One timestamp for the whole burst */
	gettimeofday(&tv, NULL);

	for (i = 0; i < n; i++) {
		struct rte_mbuf *m = pkts[i];
		/* Sized from the same bound that clamps caplen below, so the
		 * two cannot drift apart.
		 */
		uint8_t buf[DEFAULT_SNAPLEN];
		uint32_t pktlen = rte_pktmbuf_pkt_len(m);
		uint32_t caplen = pktlen < s->snaplen ? pktlen : s->snaplen;
		const void *data;

		s->npkt++;

		struct rpcap_header hdr = {
			.ver = RPCAP_VERSION,
			.type = RPCAP_MSG_PACKET,
			.plen = htonl(sizeof(struct rpcap_pkthdr) + caplen),
		};

		/*
		 * pdump copies at most the snaplen into the capture mempool
		 * and rte_pktmbuf_copy() counts only what it copied, so
		 * pktlen is already clamped: a truncated packet is reported
		 * with len == caplen.  The original wire length does not
		 * reach this process.  See the Limitations section of
		 * doc/guides/sample_app_ug/rpcapd.rst.
		 */
		struct rpcap_pkthdr pkthdr = {
			.timestamp_sec = htonl((uint32_t)tv.tv_sec),
			.timestamp_usec = htonl((uint32_t)tv.tv_usec),
			.caplen = htonl(caplen),
			.len = htonl(pktlen),
			.npkt = htonl(s->npkt),
		};

		data = rte_pktmbuf_read(m, 0, caplen, buf);

		struct iovec iov[3] = {
			{ .iov_base = &hdr,                       .iov_len = sizeof(hdr) },
			{ .iov_base = &pkthdr,                    .iov_len = sizeof(pkthdr) },
			{ .iov_base = (void *)(uintptr_t)data,    .iov_len = caplen },
		};

		/* more to come in this burst, or still queued in the ring */
		bool more = (i + 1 < n) || (*avail > 0);

		if (send_iov_full(s->data_fd, iov, 3, more ? MSG_MORE : 0) < 0) {
			if (errno == EPIPE || errno == ECONNRESET)
				RPCAPD_LOG(DEBUG, "data connection closed by client");
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
check_socket_status(int ctrl_fd)
{
	struct pollfd pfd = { .fd = ctrl_fd, .events = POLLIN };

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
 * Stay in the capture loop until either:
 *   - a control message arrives (typically ENDCAP),
 *   - the data connection breaks, or
 *   - a quit signal is delivered.
 *
 * Returns 0 if the session should continue (the caller reads the
 * pending control message), -1 if the client is gone.
 *
 * The control socket is polled once per iteration, not just when the
 * ring runs dry.  A client that sends a request mid-capture blocks
 * waiting for the reply without draining the data socket, so under
 * sustained traffic a poll that only happens while idle never runs and
 * both ends wedge once the socket buffers fill.
 */
static int
capture_loop(int ctrl_fd, struct session *s)
{
	unsigned int empty_count = 0;

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		ssize_t written;
		unsigned int avail = 0;

		switch (check_socket_status(ctrl_fd)) {
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

static int
handle_endcap(int fd, uint32_t plen, struct session *s)
{
	if (rpcap_discard(fd, plen) < 0)
		return -1;
	stop_capture(s);
	return rpcap_send_msg(fd, RPCAP_MSG_ENDCAP_REPLY, 0, NULL, 0);
}

static int
handle_stats(int fd, uint32_t plen, const struct session *s)
{
	struct rte_eth_stats es = { 0 };

	if (rpcap_discard(fd, plen) < 0)
		return -1;

	if (s->capture_on)
		rte_eth_stats_get(s->port, &es);

	struct rpcap_stats reply = {
		.ifrecv   = htonl((uint32_t)es.ipackets),
		.ifdrop   = htonl((uint32_t)es.ierrors),
		.krnldrop = 0,
		.svrcapt  = htonl(s->npkt),
	};
	return rpcap_send_msg(fd, RPCAP_MSG_STATS_REPLY, 0, &reply, sizeof(reply));
}

/* Service a single client until it disconnects. */
static void
handle_client(int ctrl_fd)
{
	struct sockaddr_storage peer;
	socklen_t plen = sizeof(peer);
	char host[NI_MAXHOST] = "?";
	struct session s = { .data_fd = -1 };

	if (getpeername(ctrl_fd, (struct sockaddr *)&peer, &plen) == 0)
		getnameinfo((struct sockaddr *)&peer, plen,
			    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	RPCAPD_LOG(INFO, "client %s connected", host);

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		struct rpcap_header hdr;

		/* Drain the ring whenever a capture is running */
		if (s.capture_on && capture_loop(ctrl_fd, &s) < 0)
			goto done;

		if (rpcap_recv_header(ctrl_fd, &hdr) < 0)
			break;

		/* Only version 0 is spoken here */
		if (hdr.ver != RPCAP_VERSION) {
			RPCAPD_LOG(WARNING, "unsupported protocol version %u",
				hdr.ver);
			if (rpcap_discard(ctrl_fd, hdr.plen) < 0 ||
			    rpcap_send_error(ctrl_fd, PCAP_ERR_WRONGVER,
					     "unsupported protocol version") < 0)
				goto done;
			continue;
		}

		switch (hdr.type) {
		case RPCAP_MSG_AUTH_REQ:
			/* No auth: discard credentials, ack with empty reply.
			 * libpcap treats a zero-length AUTH_REPLY as "version
			 * 0 only, same byte order".
			 */
			if (rpcap_discard(ctrl_fd, hdr.plen) < 0 ||
			    rpcap_send_msg(ctrl_fd, RPCAP_MSG_AUTH_REPLY, 0, NULL, 0) < 0)
				goto done;
			break;
		case RPCAP_MSG_FINDALLIF_REQ:
			if (rpcap_discard(ctrl_fd, hdr.plen) < 0 || handle_findallif(ctrl_fd) < 0)
				goto done;
			break;
		case RPCAP_MSG_OPEN_REQ:
			if (handle_open(ctrl_fd, hdr.plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_STARTCAP_REQ:
			if (handle_startcap(ctrl_fd, hdr.plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_UPDATEFILTER_REQ:
			if (handle_updatefilter(ctrl_fd, hdr.plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_ENDCAP_REQ:
			if (handle_endcap(ctrl_fd, hdr.plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_STATS_REQ:
			if (handle_stats(ctrl_fd, hdr.plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_CLOSE:
			rpcap_discard(ctrl_fd, hdr.plen);
			goto done;
		default:
			RPCAPD_LOG(WARNING, "unsupported request type 0x%02x", hdr.type);
			if (rpcap_discard(ctrl_fd, hdr.plen) < 0 ||
			    rpcap_send_error(ctrl_fd, 0, "unsupported request") < 0)
				goto done;
			break;
		}
	}
done:
	stop_capture(&s);
	close(ctrl_fd);
	RPCAPD_LOG(INFO, "client %s disconnected", host);
}

static int
open_listen_socket(uint16_t port)
{
	struct sockaddr_storage addr = listen_addr;
	char host[NI_MAXHOST];
	int fd, one = 1;

	set_sockaddr_port(&addr, port);

	fd = socket(addr.ss_family, SOCK_STREAM, 0);
	if (fd < 0)
		rte_exit(EXIT_FAILURE, "socket: %s\n", strerror(errno));
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	if (bind(fd, (struct sockaddr *)&addr, listen_addrlen) < 0)
		rte_exit(EXIT_FAILURE, "bind(%u): %s\n", port, strerror(errno));

	int err = getnameinfo((struct sockaddr *)&listen_addr, listen_addrlen,
			      host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	if (err != 0)
		rte_exit(EXIT_FAILURE, "Listen address lookup failed: %s\n",
			 gai_strerror(err));

	RPCAPD_LOG(NOTICE, "listening on %s port %u", host, listen_port);

	if (!is_loopback(&listen_addr))
		RPCAPD_LOG(WARNING,
			"non-loopback address %s; "
			"rpcap is unauthenticated and unencrypted, captured traffic is exposed to the network",
			host);

	if (listen(fd, 1) < 0)
		rte_exit(EXIT_FAILURE, "listen: %s\n", strerror(errno));

	return fd;
}

static void
usage(FILE *f, const char *progname)
{
	fprintf(f, "Usage: %s [options]\n", progname);
	fprintf(f,
		"  -p, --port <port>     listen port (default %u)\n"
		"  -b, --bind <addr>     bind address (default 127.0.0.1)\n"
		"  -4                    use only IPv4 (reject IPv6 bind addresses)\n"
		"  -N <ring size>        ring size in packets (default %u)\n"
		"  -D, --debug           increase log verbosity (-D info, -DD debug)\n"
		"      --debug-file <f>  redirect log output to file <f> (append mode)\n"
		"      --version         print version and exit\n"
		"  -h, --help            print this help and exit\n"
		"      --lcore=<core>    CPU core to run on (default: any)\n"
		"      --file-prefix=<p> prefix to use for multi-process\n"
		"\n"
		"WARNING: rpcap is unauthenticated and unencrypted.  Binding to\n"
		"any non-loopback address exposes captured traffic to the\n"
		"network.  Sample application; not for production use.\n",
		RPCAP_DEFAULT_NETPORT, DEFAULT_RING_SIZE);
}

static void
print_version(void)
{
	printf("rpcapd, a remote packet capture daemon (DPDK pdump backend)\n"
	       "Built against %s\n", rte_version());
}

static void
parse_opts(int argc, char **argv)
{
	enum {
		OPT_LONG_ONLY = 0x100,
		OPT_DEBUG_FILE,
		OPT_VERSION,
	};
	static const struct option long_options[] = {
		{ "port",        required_argument, NULL, 'p' },
		{ "bind",        required_argument, NULL, 'b' },
		{ "debug",       no_argument,       NULL, 'D' },
		{ "help",        no_argument,       NULL, 'h' },
		{ "version",     no_argument,       NULL, OPT_VERSION },
		{ "debug-file",  required_argument, NULL, OPT_DEBUG_FILE },
		{ "file-prefix", required_argument, NULL, 0 },
		{ "lcore",       required_argument, NULL, 0 },
		{ NULL, 0, NULL, 0 },
	};
	int option_index, c;

	while ((c = getopt_long(argc, argv, "hD4p:b:N:",
				long_options, &option_index)) != -1) {
		switch (c) {
		case 'p': {
			unsigned long u = strtoul(optarg, NULL, 0);

			if (u == 0 || u > UINT16_MAX)
				rte_exit(EXIT_FAILURE, "Invalid port: %s\n", optarg);
			listen_port = (uint16_t)u;
			break;
		}
		case 'b':
			bind_arg = optarg;
			break;
		case '4':
			ipv4_only = true;
			break;
		case 'N': {
			unsigned long u = strtoul(optarg, NULL, 0);

			/* Check the full value before narrowing it: an upper
			 * bound is needed anyway because rte_align32pow2()
			 * wraps to zero above 2^31, and that failure would
			 * otherwise only surface in rte_ring_create() on the
			 * first capture.
			 */
			if (u < 64 || u > MAX_RING_SIZE)
				rte_exit(EXIT_FAILURE,
					 "Ring size must be between 64 and %u\n",
					 MAX_RING_SIZE);
			ring_size = (uint32_t)u;
			/* rte_ring_create() requires a power of two. */
			if (!rte_is_power_of_2(ring_size)) {
				ring_size = rte_align32pow2(ring_size);
				RPCAPD_LOG(NOTICE, "ring size rounded up to %u",
					ring_size);
			}
			break;
		}
		case 'D':
			debug_log++;
			break;
		case 'h':
			usage(stdout, argv[0]);
			exit(0);
		case OPT_VERSION:
			print_version();
			exit(0);
		case OPT_DEBUG_FILE:
			debug_file = optarg;
			break;
		case 0: {
			const char *longopt = long_options[option_index].name;

			if (!strcmp(longopt, "lcore")) {
				lcore_arg = optarg;
				break;
			} else if (!strcmp(longopt, "file-prefix")) {
				file_prefix = optarg;
				break;
			}
		}
			/* fallthrough */
		default:
			usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	/* Resolve the bind address now that -4 has been seen. */
	parse_bind_addr(bind_arg ? bind_arg : "127.0.0.1",
			ipv4_only ? AF_INET : AF_UNSPEC);
}

/*
 * Periodic check that the DPDK primary process is still alive.
 * If it dies our shared-memory state (rings, mempools, pdump) becomes
 * unsafe to touch, so we set quit_signal and let the main loop tear
 * down cleanly on its next iteration.  The callback runs on the EAL
 * interrupt thread; quit_signal is atomic so the read in the main
 * loop is well-defined.
 */
static void
monitor_primary(void *arg __rte_unused)
{
	if (rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed))
		return;

	if (rte_eal_primary_proc_alive(NULL)) {
		rte_eal_alarm_set(PRIMARY_MONITOR_INTERVAL_US, monitor_primary, NULL);
		return;
	}

	RPCAPD_LOG(NOTICE, "primary process exited, shutting down");
	rte_atomic_store_explicit(&quit_signal, true, rte_memory_order_relaxed);
}

static void
enable_primary_monitor(void)
{
	if (rte_eal_alarm_set(PRIMARY_MONITOR_INTERVAL_US, monitor_primary, NULL) < 0)
		RPCAPD_LOG(WARNING, "failed to install primary process monitor");
}

static void
disable_primary_monitor(void)
{
	rte_eal_alarm_cancel(monitor_primary, NULL);
}

/*
 * Bring up EAL as a secondary process so that pdump can attach to a
 * running primary DPDK application.  Mirrors dumpcap's approach: the
 * RPCAP user sees a small set of options (port, ring size) rather
 * than the full DPDK EAL command line.
 */
static int
dpdk_init(void)
{
	static const char * const args[] = {
		"rpcapd",
		"--proc-type", "secondary",
		"--log-level", "info",        /* EAL stays quiet */
	};
	int eal_argc = RTE_DIM(args);
	rte_cpuset_t cpuset = { };
	char **eal_argv;
	unsigned int i;

	if (file_prefix != NULL)
		eal_argc += 2;

	if (lcore_arg != NULL)
		eal_argc += 2;

	eal_argv = calloc(eal_argc + 1, sizeof(char *));
	if (eal_argv == NULL)
		return -1;

	for (i = 0; i < RTE_DIM(args); i++) {
		eal_argv[i] = strdup(args[i]);
		if (eal_argv[i] == NULL)
			return -1;
	}

	if (file_prefix != NULL && *file_prefix != '\0') {
		eal_argv[i++] = strdup("--file-prefix");
		eal_argv[i++] = strdup(file_prefix);
		if (eal_argv[i - 1] == NULL || eal_argv[i - 2] == NULL)
			return -1;
	}

	if (lcore_arg != NULL) {
		eal_argv[i++] = strdup("--lcores");
		eal_argv[i++] = strdup(lcore_arg);
		if (eal_argv[i - 1] == NULL || eal_argv[i - 2] == NULL)
			return -1;
	}
	eal_argc = i;

	/*
	 * Need to get the original cpuset, before EAL init changes
	 * the affinity of this thread (main lcore).
	 */
	if (lcore_arg == NULL &&
	    rte_thread_get_affinity_by_id(rte_thread_self(), &cpuset) != 0)
		rte_panic("rte_thread_getaffinity failed\n");

	if (rte_eal_init(eal_argc, eal_argv) < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed: is the primary process running?\n");

	/*
	 * If no lcore argument was specified,
	 * then run this program as a normal process
	 * which can be scheduled on any non-isolated CPU.
	 */
	if (lcore_arg == NULL &&
	    rte_thread_set_affinity_by_id(rte_thread_self(), &cpuset) != 0)
		RPCAPD_LOG(INFO, "Can not restore original CPU affinity");

	if (rte_pdump_init() < 0)
		rte_exit(EXIT_FAILURE, "rte_pdump_init failed\n");

	return 0;
}

int
main(int argc, char **argv)
{
	struct sigaction action = {
		.sa_handler = signal_handler,
	};
	int srv_fd;

	parse_opts(argc, argv);

	/*
	 * Redirect log output before EAL init so EAL's own messages are
	 * captured too.  The FILE handle is intentionally never closed:
	 * the kernel reclaims it at process exit.
	 */
	if (debug_file != NULL) {
		FILE *fp = fopen(debug_file, "a");

		if (fp == NULL)
			rte_exit(EXIT_FAILURE, "Cannot open debug file '%s': %s\n",
				 debug_file, strerror(errno));
		setvbuf(fp, NULL, _IOLBF, 0);
		rte_openlog_stream(fp);
	}

	if (dpdk_init() < 0)
		rte_exit(EXIT_FAILURE, "EAL init failure\n");

	/* Default to NOTICE: only things the operator needs to see.
	 * Each -D steps down one level, to INFO then DEBUG.
	 */
	rte_log_set_level(RTE_LOGTYPE_RPCAPD,
			  debug_log >= 2 ? RTE_LOG_DEBUG :
			  debug_log == 1 ? RTE_LOG_INFO : RTE_LOG_NOTICE);

	if (rte_eth_dev_count_avail() == 0)
		rte_exit(EXIT_FAILURE, "No Ethernet ports found\n");

	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);

	/* If peer closes, this detected in next recv() */
	signal(SIGPIPE, SIG_IGN);

	srv_fd = open_listen_socket(listen_port);

	enable_primary_monitor();

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		int cfd = accept_timeout(srv_fd, -1);

		if (cfd < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		handle_client(cfd);
	}

	disable_primary_monitor();
	RPCAPD_LOG(NOTICE, "shutting down");
	close(srv_fd);
	rte_pdump_uninit();
	return rte_eal_cleanup() ? EXIT_FAILURE : 0;
}
