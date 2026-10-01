/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Control requests handled before a capture starts: authentication,
 * the interface list, and selecting an interface.
 */

#include <crypt.h>
#include <errno.h>
#include <pwd.h>
#include <shadow.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

/* Slow down a client working through a password list. */
#define AUTH_FAIL_DELAY_SEC	1

/* Bound what a client can make us allocate for credentials. */
#define MAX_CREDENTIAL_LEN	256

/* Build and send the list of available DPDK ports. */
int
handle_findallif(const struct conn *c)
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
			return rpcap_send_error(c, 0, "out of memory");
		}
		buf = nb;

		struct rpcap_findalldevs_if iface = {
			.namelen = rte_cpu_to_be_16(namelen),
			.desclen = rte_cpu_to_be_16(desclen),
			.flags = rte_cpu_to_be_32(PCAP_IF_UP | PCAP_IF_RUNNING),
		};
		memcpy(buf + buflen, &iface, sizeof(iface));
		memcpy(buf + buflen + sizeof(iface), name, namelen);
		memcpy(buf + buflen + sizeof(iface) + namelen, desc, desclen);
		buflen += entry;
		nif++;
	}

	RPCAPD_LOG(DEBUG, "findallif: %u interface(s)", nif);
	rc = rpcap_send_msg(c, RPCAP_MSG_FINDALLIF_REPLY, nif, buf, buflen);
	free(buf);
	return rc;
}

/*
 * Check credentials against the system password database, as libpcap's
 * rpcapd does.  Privileges are not dropped afterwards, since that would
 * break the capture, so this authenticates without authorising.
 * Returns 0 if the credentials are good.
 */
static int
check_password(const char *user, const char *password)
{
	const struct passwd *pw;
	const struct spwd *sp;
	const char *hash;
	char *result;

	pw = getpwnam(user);
	if (pw == NULL) {
		RPCAPD_LOG(NOTICE, "authentication failed: no such user");
		return -1;
	}

	/* The password database only holds a placeholder when the real
	 * hash lives in the shadow file.
	 */
	sp = getspnam(user);
	hash = (sp != NULL) ? sp->sp_pwdp : pw->pw_passwd;

	/* Not a hash: the account is locked ('!' or '*') or has no
	 * password.  Either way there is nothing to check against.
	 */
	if (hash == NULL || *hash != '$') {
		RPCAPD_LOG(NOTICE,
			   "authentication failed: account has no usable password "
			   "(is /etc/shadow readable?)");
		return -1;
	}

	errno = 0;
	result = crypt(password, hash);
	if (result == NULL) {
		RPCAPD_LOG(ERR, "crypt failed: %s",
			   errno != 0 ? strerror(errno) : "unknown error");
		return -1;
	}

	if (strcmp(result, hash) != 0) {
		RPCAPD_LOG(NOTICE, "authentication failed: wrong password");
		return -1;
	}

	return 0;
}

/*
 * Wipe a credential before freeing it.  explicit_bzero() because the
 * compiler may drop a memset() before free() as a dead store.
 */
static void
free_credential(char *cred)
{
	if (cred != NULL) {
		explicit_bzero(cred, strlen(cred));
		free(cred);
	}
}

/* Read a length-prefixed credential out of the AUTH_REQ payload. */
static int
recv_credential(const struct conn *c, uint32_t len, uint32_t *plen, char **out)
{
	char *buf;

	if (len > *plen || len > MAX_CREDENTIAL_LEN)
		return -1;

	buf = malloc(len + 1);
	if (buf == NULL)
		return -1;

	if (recv_full(c, buf, len) < 0) {
		explicit_bzero(buf, len);
		free(buf);
		return -1;
	}
	buf[len] = '\0';
	*plen -= len;
	*out = buf;
	return 0;
}

/*
 * AUTH_REQ: null authentication is accepted from a loopback peer only;
 * a remote client needs a username and password, unless -n was given.
 */
int
handle_auth(const struct conn *c, uint32_t plen, struct session *s)
{
	char *user = NULL, *password = NULL;
	struct rpcap_auth auth;
	uint16_t type;
	int rc;

	s->authenticated = false;

	if (plen < sizeof(auth)) {
		rpcap_discard(c, plen);
		return rpcap_send_error(c, PCAP_ERR_AUTH, "short authentication request");
	}

	if (recv_full(c, &auth, sizeof(auth)) < 0)
		return -1;
	plen -= sizeof(auth);

	type = rte_be_to_cpu_16(auth.type);
	switch (type) {
	case RPCAP_RMTAUTH_NULL:
		if (rpcap_discard(c, plen) < 0)
			return -1;

		if (!is_loopback(&s->peer) && !null_auth_ok) {
			RPCAPD_LOG(NOTICE,
				   "rejecting null authentication from remote client");
			return rpcap_send_error(c, PCAP_ERR_AUTH_FAILED,
						"this server requires a username and "
						"password for remote clients");
		}
		break;

	case RPCAP_RMTAUTH_PWD:
		if (recv_credential(c, rte_be_to_cpu_16(auth.slen1), &plen, &user) < 0 ||
		    recv_credential(c, rte_be_to_cpu_16(auth.slen2), &plen, &password) < 0) {
			free_credential(user);
			return -1;
		}

		if (rpcap_discard(c, plen) < 0) {
			free_credential(user);
			free_credential(password);
			return -1;
		}

		/* Refuse before checking, so a rejected password has not
		 * already crossed the network in the clear.
		 */
		if (c->ssl == NULL && !is_loopback(&s->peer)) {
			free_credential(user);
			free_credential(password);
			RPCAPD_LOG(NOTICE,
				   "refusing password authentication on an unencrypted connection");
			return rpcap_send_error(c, PCAP_ERR_AUTH_FAILED,
						"this server will not accept a password "
						"over an unencrypted connection; "
						"use rpcaps://");
		}

		rc = check_password(user, password);
		free_credential(user);
		free_credential(password);

		if (rc != 0) {
			/* Delay a guess, and do not say which of the two
			 * was wrong.
			 */
			sleep(AUTH_FAIL_DELAY_SEC);
			return rpcap_send_error(c, PCAP_ERR_AUTH_FAILED,
						"authentication failed");
		}
		break;

	default:
		if (rpcap_discard(c, plen) < 0)
			return -1;
		RPCAPD_LOG(NOTICE, "rejecting authentication type %u", type);
		return rpcap_send_error(c, PCAP_ERR_AUTH_TYPE_NOTSUP,
					"authentication type not supported");
	}

	s->authenticated = true;
	return rpcap_send_msg(c, RPCAP_MSG_AUTH_REPLY, 0, NULL, 0);
}

/* OPEN_REQ: payload is the interface name (no NUL). */
int
handle_open(const struct conn *c, uint32_t plen, struct session *s)
{
	struct rpcap_openreply reply = {
		.linktype = rte_cpu_to_be_32(DLT_EN10MB),
	};
	uint16_t port;

	stop_capture(s);

	if (plen >= sizeof(s->name)) {
		rpcap_discard(c, plen);
		return rpcap_send_error(c, 0, "interface name too long");
	}
	if (recv_full(c, s->name, plen) < 0)
		return -1;
	s->name[plen] = '\0';

	if (rte_eth_dev_get_port_by_name(s->name, &port) < 0) {
		RPCAPD_LOG(WARNING, "open: no such port '%s'", s->name);
		/* s->name has already been overwritten; make sure a later
		 * STARTCAP cannot capture the previously opened port.
		 */
		s->opened = false;
		return rpcap_send_error(c, 0, "unknown interface");
	}
	s->port = port;
	s->opened = true;

	RPCAPD_LOG(DEBUG, "open: '%s' -> dpdk port %u", s->name, port);
	return rpcap_send_msg(c, RPCAP_MSG_OPEN_REPLY, 0, &reply, sizeof(reply));
}
