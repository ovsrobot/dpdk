/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Socket helpers and rpcap message framing, used by both the control
 * connection and the data connection.
 */

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_stdatomic.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

#define POLL_INTERVAL_MS              500

/* Monotonic milliseconds, for timing out across repeated waits. */
static int64_t
get_monotonic_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void
set_sockaddr_port(struct sockaddr_storage *ss, uint16_t port)
{
	if (ss->ss_family == AF_INET6)
		((struct sockaddr_in6 *)ss)->sin6_port = htons(port);
	else
		((struct sockaddr_in *)ss)->sin_port = htons(port);
}

uint16_t
get_sockaddr_port(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET6)
		return ntohs(((const struct sockaddr_in6 *)ss)->sin6_port);
	return ntohs(((const struct sockaddr_in *)ss)->sin_port);
}


/* Wait for a connection to become readable with timeout */
int
wait_readable(const struct conn *c, int timeout_ms)
{
	struct pollfd pfd = { .fd = c->fd, .events = POLLIN };

	/* Decrypted bytes buffered in the SSL object are invisible to poll() */
	if (tls_pending(c))
		return 1;

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
int
accept_timeout(int listen_fd, int timeout_ms)
{
	struct conn listener = { .fd = listen_fd };
	int fd;

	switch (wait_readable(&listener, timeout_ms)) {
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

/* Compare the host part of two addresses, ignoring the port: the data
 * connection comes from an ephemeral port, not the control one.
 */
static bool
same_host(const struct sockaddr_storage *a, const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *sa = (const void *)a;
		const struct sockaddr_in *sb = (const void *)b;

		return sa->sin_addr.s_addr == sb->sin_addr.s_addr;
	}
	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sa = (const void *)a;
		const struct sockaddr_in6 *sb = (const void *)b;

		return IN6_ARE_ADDR_EQUAL(&sa->sin6_addr, &sb->sin6_addr);
	}
	return false;
}

/*
 * Accept a data connection only from the control connection's peer;
 * the port is handed to the client in the clear, so any local user
 * could otherwise race for the stream.  A mismatch is rejected and the
 * wait continues.
 */
int
accept_from(int listen_fd, const struct sockaddr_storage *want, int timeout_ms)
{
	struct conn listener = { .fd = listen_fd };
	int remaining = timeout_ms;

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		struct sockaddr_storage peer;
		socklen_t peerlen = sizeof(peer);
		char host[NI_MAXHOST] = "?";
		int64_t start, waited;
		int fd;

		start = get_monotonic_ms();
		switch (wait_readable(&listener, remaining)) {
		case 1:
			break;
		case 0:
			RPCAPD_LOG(ERR, "timed out waiting for data connection");
			return -1;
		default:
			return -1;
		}

		fd = accept(listen_fd, (struct sockaddr *)&peer, &peerlen);
		if (fd < 0) {
			if (errno == EINTR || errno == ECONNABORTED)
				goto next;
			RPCAPD_LOG(ERR, "accept: %s", strerror(errno));
			return -1;
		}

		if (same_host(&peer, want))
			return fd;

		getnameinfo((struct sockaddr *)&peer, peerlen,
			    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
		RPCAPD_LOG(WARNING,
			   "rejected data connection from %s: does not match control peer",
			   host);
		close(fd);
next:
		if (remaining >= 0) {
			waited = get_monotonic_ms() - start;
			remaining -= (waited > 0) ? (int)waited : 0;
			if (remaining <= 0) {
				RPCAPD_LOG(ERR,
					   "timed out waiting for data connection");
				return -1;
			}
		}
	}
	return -1;
}

/* Read exactly len bytes; return 0 on success, -1 on error or EOF. */
int
recv_full(const struct conn *c, void *buf, size_t len)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n;

		/* Timed wait, so a quit signal or a dead primary is acted
		 * on promptly.
		 */
		if (wait_readable(c, -1) != 1)
			return -1;

		if (c->ssl != NULL)
			n = tls_recv(c->ssl, p, len);
		else
			n = recv(c->fd, p, len, 0);

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
 * No scatter/gather write in TLS, and SSL_write() gives each call its
 * own record, so gather into one buffer rather than paying record
 * overhead per piece.
 */
static int
send_iov_tls(struct ssl_st *ssl, const struct iovec *iov, int iovcnt)
{
	uint8_t buf[sizeof(struct rpcap_header) + sizeof(struct rpcap_pkthdr) +
		    MAX_CAPTURE_LEN];
	const uint8_t *p = buf;
	size_t len = 0;
	int i;

	for (i = 0; i < iovcnt; i++) {
		if (len + iov[i].iov_len > sizeof(buf)) {
			/* Cannot happen: buf is sized for both headers plus
			 * MAX_CAPTURE_LEN.
			 */
			RPCAPD_LOG(ERR, "message too large for TLS buffer");
			errno = EMSGSIZE;
			return -1;
		}
		memcpy(buf + len, iov[i].iov_base, iov[i].iov_len);
		len += iov[i].iov_len;
	}

	while (len > 0) {
		int n = tls_send(ssl, p, len);

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
int
send_iov_full(const struct conn *c, struct iovec *iov, int iovcnt, int flags)
{
	struct msghdr msg = {
		.msg_iov    = iov,
		.msg_iovlen = iovcnt,
	};

	if (c->ssl != NULL)
		return send_iov_tls(c->ssl, iov, iovcnt);

	while (msg.msg_iovlen > 0) {
		ssize_t n = sendmsg(c->fd, &msg, flags | MSG_NOSIGNAL);

		if (n < 0) {
			/*
			 * Send blocks rather than polling first; the data
			 * socket has a send timeout so a client that stops
			 * reading fails with EAGAIN.
			 */
			if (errno == EINTR &&
			    !rte_atomic_load_explicit(&quit_signal,
						      rte_memory_order_relaxed))
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

int
rpcap_send_msg(const struct conn *c, uint8_t type, uint16_t value,
	       const void *payload, uint32_t plen)
{
	struct rpcap_header hdr = {
		.ver = RPCAP_VERSION,
		.type = type,
		.value = rte_cpu_to_be_16(value),
		.plen = rte_cpu_to_be_32(plen),
	};
	struct iovec iov[2] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		},
		{
			.iov_base = (void *)(uintptr_t)payload,
			.iov_len = plen,
		},
	};

	return send_iov_full(c, iov, plen > 0 ? 2 : 1, 0);
}

int
rpcap_send_error(const struct conn *c, uint16_t errcode, const char *msg)
{
	RPCAPD_LOG(WARNING, "sending error to client: %s", msg);
	return rpcap_send_msg(c, RPCAP_MSG_ERROR, errcode, msg, strlen(msg));
}

/* Throw away plen bytes of payload we don't care about. */
int
rpcap_discard(const struct conn *c, uint32_t plen)
{
	uint8_t buf[256];

	while (plen > 0) {
		size_t chunk = plen > sizeof(buf) ? sizeof(buf) : plen;

		if (recv_full(c, buf, chunk) < 0)
			return -1;
		plen -= chunk;
	}
	return 0;
}
