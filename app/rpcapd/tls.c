/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * TLS transport for the rpcaps:// scheme.  Both the control and the
 * data connection are promoted.  Built as stubs when DPDK was
 * configured without OpenSSL.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "rpcapd.h"

/* How long a peer may take to complete a handshake. */
#define TLS_HANDSHAKE_TIMEOUT_SEC	10

#ifdef RTE_HAS_OPENSSL

#include <openssl/err.h>
#include <openssl/ssl.h>

static SSL_CTX *tls_ctx;

static const char *
tls_strerror(void)
{
	unsigned long e = ERR_get_error();

	return (e != 0) ? ERR_reason_error_string(e) : "unknown error";
}

/*
 * Build the server context at startup, so a bad certificate fails here
 * rather than on the first client's handshake.
 */
int
tls_init(const char *certfile, const char *keyfile)
{
	tls_ctx = SSL_CTX_new(TLS_server_method());
	if (tls_ctx == NULL) {
		RPCAPD_LOG(ERR, "cannot create TLS context: %s", tls_strerror());
		return -1;
	}

	if (SSL_CTX_set_min_proto_version(tls_ctx, TLS1_2_VERSION) != 1) {
		RPCAPD_LOG(ERR, "cannot set minimum TLS version: %s", tls_strerror());
		return -1;
	}

	/* Hides a renegotiation from SSL_read()/SSL_write(). */
	SSL_CTX_set_mode(tls_ctx, SSL_MODE_AUTO_RETRY);

	if (SSL_CTX_use_certificate_chain_file(tls_ctx, certfile) != 1) {
		RPCAPD_LOG(ERR, "cannot read certificate file '%s': %s",
			   certfile, tls_strerror());
		return -1;
	}

	if (SSL_CTX_use_PrivateKey_file(tls_ctx, keyfile, SSL_FILETYPE_PEM) != 1) {
		RPCAPD_LOG(ERR, "cannot read private key file '%s': %s",
			   keyfile, tls_strerror());
		return -1;
	}

	if (SSL_CTX_check_private_key(tls_ctx) != 1) {
		RPCAPD_LOG(ERR, "private key '%s' does not match certificate '%s'",
			   keyfile, certfile);
		return -1;
	}

	return 0;
}

/*
 * SSL_accept() on a blocking socket waits indefinitely, and only one
 * client is served at a time, so bound the handshake with socket
 * timeouts.
 */
static int
set_handshake_timeout(int fd, time_t seconds)
{
	struct timeval tv = { .tv_sec = seconds };

	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
		RPCAPD_LOG(NOTICE, "cannot set TLS handshake timeout: %s",
			   strerror(errno));
		return -1;
	}
	return 0;
}

int
tls_accept(struct conn *c)
{
	SSL *ssl = SSL_new(tls_ctx);
	bool timed = set_handshake_timeout(c->fd, TLS_HANDSHAKE_TIMEOUT_SEC) == 0;

	if (ssl == NULL) {
		RPCAPD_LOG(ERR, "SSL_new: %s", tls_strerror());
		return -1;
	}

	if (SSL_set_fd(ssl, c->fd) != 1) {
		RPCAPD_LOG(ERR, "SSL_set_fd: %s", tls_strerror());
		SSL_free(ssl);
		return -1;
	}

	if (SSL_accept(ssl) != 1) {
		/* A timeout surfaces as a syscall error on the read. */
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			RPCAPD_LOG(ERR, "TLS handshake timed out after %u seconds",
				   TLS_HANDSHAKE_TIMEOUT_SEC);
		else
			RPCAPD_LOG(ERR, "TLS handshake failed: %s", tls_strerror());
		SSL_free(ssl);
		return -1;
	}

	/* Back to blocking for the session. */
	if (timed)
		set_handshake_timeout(c->fd, 0);

	RPCAPD_LOG(DEBUG, "TLS established: %s %s",
		   SSL_get_version(ssl), SSL_get_cipher(ssl));
	c->ssl = ssl;
	return 0;
}

/* Send the close_notify alert so the client does not report a truncated
 * stream.  The caller still owns the socket.
 */
void
tls_close(struct conn *c)
{
	if (c->ssl == NULL)
		return;

	SSL_shutdown(c->ssl);
	SSL_free(c->ssl);
	c->ssl = NULL;
}

/*
 * Map an SSL error onto the send()/recv() contract the callers expect:
 * byte count on success, -1 with errno set on failure.
 */
static int
tls_error(SSL *ssl, int ret, const char *what)
{
	int err = SSL_get_error(ssl, ret);

	switch (err) {
	case SSL_ERROR_ZERO_RETURN:
		/* Clean shutdown by the peer: an orderly EOF. */
		return 0;
	case SSL_ERROR_SYSCALL:
		/* errno is already set, unless the peer just vanished. */
		if (errno == 0)
			errno = ECONNRESET;
		return -1;
	case SSL_ERROR_WANT_READ:
	case SSL_ERROR_WANT_WRITE:
		errno = EAGAIN;
		return -1;
	default:
		RPCAPD_LOG(DEBUG, "%s: %s", what, tls_strerror());
		errno = EPROTO;
		return -1;
	}
}

int
tls_send(struct ssl_st *ssl, const void *buf, size_t len)
{
	int ret = SSL_write(ssl, buf, len);

	if (ret > 0)
		return ret;
	return tls_error(ssl, ret, "SSL_write");
}

int
tls_recv(struct ssl_st *ssl, void *buf, size_t len)
{
	int ret = SSL_read(ssl, buf, len);

	if (ret > 0)
		return ret;
	return tls_error(ssl, ret, "SSL_read");
}

/*
 * One TLS record can hold several rpcap messages, and once read off the
 * socket the rest sit in the SSL object where poll() cannot see them.
 * Every wait must check this first.
 */
bool
tls_pending(const struct conn *c)
{
	return c->ssl != NULL && SSL_pending(c->ssl) > 0;
}

#else /* !RTE_HAS_OPENSSL */

int
tls_init(const char *certfile __rte_unused, const char *keyfile __rte_unused)
{
	RPCAPD_LOG(ERR, "built without OpenSSL, TLS is not available");
	return -1;
}

int
tls_accept(struct conn *c __rte_unused)
{
	return -1;
}

void
tls_close(struct conn *c __rte_unused)
{
}

int
tls_send(struct ssl_st *ssl __rte_unused, const void *buf __rte_unused,
	 size_t len __rte_unused)
{
	errno = ENOTSUP;
	return -1;
}

int
tls_recv(struct ssl_st *ssl __rte_unused, void *buf __rte_unused,
	 size_t len __rte_unused)
{
	errno = ENOTSUP;
	return -1;
}

bool
tls_pending(const struct conn *c __rte_unused)
{
	return false;
}

#endif /* RTE_HAS_OPENSSL */

/*
 * Turn away a handshake from a daemon without -S.  Written straight to
 * the socket since there is no SSL context to generate it with.
 */
void
tls_reject_handshake(int fd)
{
	static const uint8_t alert[] = {
		21,	/* content type: alert */
		3, 3,	/* legacy record version: TLS 1.2 */
		0, 2,	/* payload length */
		2,	/* level: fatal */
		40,	/* description: handshake_failure */
	};

	RPCAPD_LOG(WARNING, "rejecting TLS handshake: server is not using TLS");
	if (write(fd, alert, sizeof(alert)) != (ssize_t)sizeof(alert))
		RPCAPD_LOG(DEBUG, "could not send TLS alert: %s", strerror(errno));
}
