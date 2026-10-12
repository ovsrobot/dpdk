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
#include <rte_thread.h>

struct rte_bpf_prm;
struct rte_mempool;
struct rte_ring;

#define RTE_LOGTYPE_RPCAPD RTE_LOGTYPE_USER1
#define RPCAPD_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, RPCAPD, "%s(): ", __func__, __VA_ARGS__)

/*
 * Largest snaplen a client can be given, the classic pcap maximum.
 * A client asking for more, as tcpdump does by default, gets this.
 * Nothing can be captured above it anyway: an mbuf packet length is
 * 32 bits but a port cannot deliver a frame this large to begin with.
 * What the value does bound is how many mbuf segments one capture can
 * span, which has to stay within the iovec budget of a single send.
 */
#define MAX_SNAPLEN		UINT16_MAX

/* Used when a client asks for no limit. */
#define DEFAULT_SNAPLEN		MAX_SNAPLEN

/* A connection to the client. */
struct conn {
	int fd;
};

/*
 * Per-client capture session state.
 *
 * While a capture runs the data connection belongs to a separate thread.
 * The ring has no file descriptor, so one thread cannot wait for both
 * packets and control requests without starving one of them.  Fields
 * shared with that thread are marked; the rest are set before it starts
 * and read-only while it runs.
 */
struct session {
	struct conn data;			/* data connection (data thread) */
	struct sockaddr_storage peer;		/* control connection peer */
	uint16_t port;				/* DPDK ethdev port being captured */
	char     name[RTE_ETH_NAME_MAX_LEN];
	uint32_t snaplen;
	RTE_ATOMIC(uint32_t) npkt;		/* shared: rpcap_pkthdr sequence */
	uint32_t pdump_flags;			/* direction bits handed to pdump */
	bool     opened;			/* OPEN_REQ has selected a port */
	bool     capture_on;
	bool     promisc_set;			/* we enabled promiscuous mode */
	struct rte_ring    *ring;
	struct rte_mempool *mp;
	struct rte_bpf_prm *prm;		/* capture filter, NULL if none */

	rte_thread_t     data_thread;		/* valid while data_running */
	bool             data_running;
	int              data_done_fd;		/* eventfd: data thread exited */
	RTE_ATOMIC(bool) data_stop;		/* shared: asks it to finish */
};

/* Set once by the signal handler to unwind the main and capture loops. */
extern RTE_ATOMIC(bool) quit_signal;

/* Command-line settings needed outside of main.c */
extern uint32_t ring_size;
extern uint32_t send_timeout;		/* seconds; 0 means no limit */

/* Largest number of addresses the listener will bind. */
#define MAX_LISTEN_SOCKETS	8

/* sock.c: transport and message framing */
int wait_readable(const struct conn *c, int timeout_ms);
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
int handle_startcap(const struct conn *c, uint32_t plen, struct session *s);
int handle_endcap(const struct conn *c, uint32_t plen, struct session *s);
int handle_stats(const struct conn *c, uint32_t plen, const struct session *s);
void stop_capture(struct session *s);
int start_data_thread(struct session *s);
void stop_data_thread(struct session *s);
int wait_ctrl_or_data_exit(const struct conn *ctrl, const struct session *s);

#endif /* _RPCAPD_H_ */
