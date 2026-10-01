/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Control requests handled before a capture starts: authentication,
 * the interface list, and selecting an interface.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_ethdev.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

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
 * AUTH_REQ: check the authentication type only.
 *
 * There is no credential store, so a username and password cannot be
 * verified; refuse them rather than reply that they were accepted.
 */
int
handle_auth(const struct conn *c, uint32_t plen)
{
	struct rpcap_auth auth;
	uint16_t type;

	if (plen < sizeof(auth)) {
		rpcap_discard(c, plen);
		return rpcap_send_error(c, 0, "short authentication request");
	}

	if (recv_full(c, &auth, sizeof(auth)) < 0)
		return -1;

	/* Discard any username and password that followed. */
	if (rpcap_discard(c, plen - sizeof(auth)) < 0)
		return -1;

	type = rte_be_to_cpu_16(auth.type);
	if (type != RPCAP_RMTAUTH_NULL) {
		RPCAPD_LOG(NOTICE, "rejecting authentication type %u", type);
		return rpcap_send_error(c, PCAP_ERR_AUTH_TYPE_NOTSUP,
					"this server cannot check credentials; "
					"connect without a username or password");
	}

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
