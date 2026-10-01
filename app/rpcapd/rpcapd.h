/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * State and helpers shared between the parts of the rpcap daemon.
 */

#ifndef _RPCAPD_H_
#define _RPCAPD_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_stdatomic.h>

struct rte_bpf_prm;
struct rte_mempool;
struct rte_ring;

#define RTE_LOGTYPE_RPCAPD RTE_LOGTYPE_USER1
#define RPCAPD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RPCAPD, "%s(): ", __func__, __VA_ARGS__)

/* Largest snaplen a client can be given. */
#define DEFAULT_SNAPLEN		RTE_MBUF_DEFAULT_DATAROOM

/*
 * rte_pcapng_copy() truncates to the snaplen and then re-inserts any
 * VLAN or QinQ tag the NIC stripped, so a capture can exceed the
 * snaplen by up to two tags.
 */
#define MAX_CAPTURE_LEN		(DEFAULT_SNAPLEN + 2 * sizeof(struct rte_vlan_hdr))

/* A connection to the client. */
struct conn {
	int fd;
};

/* Per-client capture session state. */
struct session {
	struct conn data;			/* data connection */
	struct sockaddr_storage peer;		/* control connection peer */
	uint16_t port;				/* DPDK ethdev port being captured */
	char     name[RTE_ETH_NAME_MAX_LEN];
	uint32_t snaplen;
	uint32_t npkt;				/* packet sequence for rpcap_pkthdr */
	uint32_t pdump_flags;			/* direction bits handed to pdump */
	bool     opened;			/* OPEN_REQ has selected a port */
	bool     capture_on;
	bool     promisc_set;			/* we enabled promiscuous mode */
	struct rte_ring    *ring;
	struct rte_mempool *mp;
	struct rte_bpf_prm *prm;		/* capture filter, NULL if none */
};

/* Set once by the signal handler to unwind the main and capture loops. */
extern RTE_ATOMIC(bool) quit_signal;

/* Command-line settings needed outside of main.c */
extern uint32_t ring_size;
extern uint32_t send_timeout;		/* seconds; 0 means no limit */

/* Address the control socket is bound to; the data socket uses the same
 * address with an ephemeral port.
 */
extern struct sockaddr_storage listen_addr;
extern socklen_t               listen_addrlen;

/* sock.c: transport and message framing */
int wait_readable(const struct conn *c, int timeout_ms);
int accept_timeout(int listen_fd, int timeout_ms);
int accept_from(int listen_fd, const struct sockaddr_storage *want,
		int timeout_ms);
int recv_full(const struct conn *c, void *buf, size_t len);
int send_iov_full(const struct conn *c, struct iovec *iov, int iovcnt, int flags);
int rpcap_send_msg(const struct conn *c, uint8_t type, uint16_t value,
		   const void *payload, uint32_t plen);
int rpcap_send_error(const struct conn *c, uint16_t errcode, const char *msg);
int rpcap_discard(const struct conn *c, uint32_t plen);
void set_sockaddr_port(struct sockaddr_storage *ss, uint16_t port);
uint16_t get_sockaddr_port(const struct sockaddr_storage *ss);

/* session.c: control requests handled before a capture starts */
int handle_auth(const struct conn *c, uint32_t plen);
int handle_findallif(const struct conn *c);
int handle_open(const struct conn *c, uint32_t plen, struct session *s);

/* filter.c */
int read_filter(const struct conn *c, uint32_t plen, struct session *s);
int handle_updatefilter(const struct conn *c, uint32_t plen, struct session *s);

/* capture.c */
void timestamp_init(void);
int handle_startcap(const struct conn *c, uint32_t plen, struct session *s);
int handle_endcap(const struct conn *c, uint32_t plen, struct session *s);
int handle_stats(const struct conn *c, uint32_t plen, const struct session *s);
void stop_capture(struct session *s);
int capture_loop(const struct conn *ctrl, struct session *s);

#endif /* _RPCAPD_H_ */
