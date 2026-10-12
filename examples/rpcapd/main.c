/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 *
 * Server for the rpcap protocol, which lets a libpcap client such as
 * Wireshark or tcpdump use "rpcap://host[:port]/portname" as a capture
 * device.
 *
 * Based on the DPDK dumpcap application and on rpcapd from libpcap:
 *   https://github.com/the-tcpdump-group/libpcap/tree/master/rpcapd
 *
 * Only the bits of the RPCAP protocol that are needed for an
 * unauthenticated, passive-mode capture session are implemented.
 * Configuration files, active mode, sampling and concurrent clients
 * are intentionally omitted.
 *
 * Options, startup and the control connection dispatcher live here; the
 * request handlers are in session.c, capture.c and filter.c.
 */

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
#include <sys/types.h>
#include <unistd.h>

#include <rte_alarm.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_pdump.h>
#include <rte_stdatomic.h>
#include <rte_version.h>

#include "rpcap-protocol.h"
#include "rpcapd.h"

#define DEFAULT_RING_SIZE             2048
#define MAX_RING_SIZE                 (1U << 20)
#define PRIMARY_MONITOR_INTERVAL_US   (500 * 1000)
#define DATA_SEND_TIMEOUT_SEC         10
#define POLL_INTERVAL_MS              500

/* Command-line options */
static uint16_t listen_port = RPCAP_DEFAULT_NETPORT;
uint32_t ring_size = DEFAULT_RING_SIZE;
static const char *lcore_arg;
static const char *file_prefix;
static const char *debug_file;		/* --debug-file argument */
static unsigned int debug_log;		/* -D count: raise RPCAPD log verbosity */
uint32_t send_timeout = DATA_SEND_TIMEOUT_SEC;	/* 0 means no limit */

RTE_ATOMIC(bool) quit_signal;

/* strtoul() that rejects an empty string and trailing garbage. */
static unsigned long
parse_number(const char *arg, const char *what)
{
	char *end;
	unsigned long val;

	errno = 0;
	val = strtoul(arg, &end, 0);
	if (errno != 0 || end == arg || *end != '\0')
		rte_exit(EXIT_FAILURE, "Invalid %s: %s\n", what, arg);

	return val;
}

/*
 * Open a listening socket for every loopback address.  "localhost"
 * normally gives both 127.0.0.1 and ::1 and a client may use either, so
 * bind them all rather than picking one.  Returns the number of sockets.
 *
 * Only loopback is bound: the protocol has no authentication or
 * encryption, so anything reachable from another host would expose all
 * captured traffic.
 */
static unsigned int
open_listen_sockets(uint16_t port, int *fds)
{
	static const char bind_addr[] = "localhost";
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_flags    = AI_PASSIVE,
	};
	struct sockaddr_storage bound[MAX_LISTEN_SOCKETS];
	struct addrinfo *res, *ai;
	unsigned int n = 0;
	int rc;

	rc = getaddrinfo(bind_addr, NULL, &hints, &res);
	if (rc != 0)
		rte_exit(EXIT_FAILURE, "Cannot resolve '%s': %s\n",
			 bind_addr, gai_strerror(rc));

	for (ai = res; ai != NULL && n < MAX_LISTEN_SOCKETS; ai = ai->ai_next) {
		struct sockaddr_storage addr;
		char host[NI_MAXHOST];
		unsigned int j;
		int fd, one = 1;

		/* Zeroed first: only ai_addrlen bytes are copied in and the
		 * duplicate check below compares the whole structure.
		 */
		memset(&addr, 0, sizeof(addr));
		memcpy(&addr, ai->ai_addr, ai->ai_addrlen);
		set_sockaddr_port(&addr, port);

		/* The resolver can return the same address twice, for
		 * instance from both /etc/hosts and DNS; binding it again
		 * would fail with EADDRINUSE.
		 */
		for (j = 0; j < n; j++)
			if (memcmp(&bound[j], &addr, sizeof(addr)) == 0)
				break;
		if (j < n)
			continue;
		bound[n] = addr;

		if (getnameinfo((struct sockaddr *)&addr, ai->ai_addrlen,
				host, sizeof(host), NULL, 0, NI_NUMERICHOST) != 0)
			snprintf(host, sizeof(host), "?");

		fd = socket(ai->ai_family, SOCK_STREAM, 0);
		if (fd < 0) {
			/* A kernel booted with ipv6.disable=1 has no AF_INET6
			 * at all; 127.0.0.1 is still usable.
			 */
			if (errno == EAFNOSUPPORT) {
				RPCAPD_LOG(NOTICE, "skipping %s: %s",
					   host, strerror(errno));
				continue;
			}
			rte_exit(EXIT_FAILURE, "socket: %s\n", strerror(errno));
		}

		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

		/* Do not let the v6 socket also answer for v4, which would
		 * make it overlap with the 127.0.0.1 socket on the same port.
		 */
		if (ai->ai_family == AF_INET6)
			setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));

		if (bind(fd, (struct sockaddr *)&addr, ai->ai_addrlen) < 0) {
			/* The address resolved but is not configured, as
			 * happens for ::1 with disable_ipv6 set on lo.
			 */
			if (errno == EADDRNOTAVAIL) {
				RPCAPD_LOG(NOTICE, "skipping %s: %s",
					   host, strerror(errno));
				close(fd);
				continue;
			}
			rte_exit(EXIT_FAILURE, "bind(%s port %u): %s\n",
				 host, port, strerror(errno));
		}

		if (listen(fd, 1) < 0)
			rte_exit(EXIT_FAILURE, "listen: %s\n", strerror(errno));

		RPCAPD_LOG(NOTICE, "listening on %s port %u", host, port);

		fds[n++] = fd;
	}

	if (ai != NULL)
		RPCAPD_LOG(WARNING, "'%s' has more than %u addresses, ignoring the rest",
			bind_addr, MAX_LISTEN_SOCKETS);

	freeaddrinfo(res);

	if (n == 0)
		rte_exit(EXIT_FAILURE, "No address to listen on\n");

	return n;
}

static void
signal_handler(int sig __rte_unused)
{
	rte_atomic_store_explicit(&quit_signal, true, rte_memory_order_relaxed);
}

/*
 * Wait for a connection on any listening socket and accept it.
 *
 * accept(2) reports an error pending on the new connection as if the
 * accept() itself had failed; those are specific to that connection, so
 * keep waiting instead of returning a failure the caller would have to
 * classify.
 */
static int
accept_any(const int *fds, unsigned int nfds)
{
	struct pollfd pfd[MAX_LISTEN_SOCKETS];
	unsigned int i;

	for (i = 0; i < nfds; i++) {
		pfd[i].fd = fds[i];
		pfd[i].events = POLLIN;
	}

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		int rc = poll(pfd, nfds, POLL_INTERVAL_MS);

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			RPCAPD_LOG(ERR, "poll failed: %s", strerror(errno));
			return -1;
		}

		for (i = 0; i < nfds; i++) {
			int fd;

			if ((pfd[i].revents & POLLIN) == 0)
				continue;

			fd = accept(fds[i], NULL, NULL);
			if (fd >= 0)
				return fd;

			switch (errno) {
			case EINTR:
			case EAGAIN:
			case ECONNABORTED:
			case EHOSTUNREACH:
			case ENETDOWN:
			case ENETUNREACH:
			case ENOPROTOOPT:
			case EPROTO:
				RPCAPD_LOG(DEBUG, "accept: %s", strerror(errno));
				break;
			default:
				RPCAPD_LOG(ERR, "accept: %s", strerror(errno));
				return -1;
			}
		}
	}
	return -1;
}

/* Service a single client until it disconnects. */
static void
handle_client(int ctrl_fd)
{
	struct sockaddr_storage peer;
	socklen_t peerlen = sizeof(peer);
	char host[NI_MAXHOST] = "?";
	struct conn ctrl = { .fd = ctrl_fd };
	struct session s = { .data.fd = -1 };

	/* Remembered so the data connection can be matched against it. */
	if (getpeername(ctrl_fd, (struct sockaddr *)&peer, &peerlen) != 0) {
		RPCAPD_LOG(ERR, "getpeername: %s", strerror(errno));
		close(ctrl_fd);
		return;
	}
	s.peer = peer;
	getnameinfo((struct sockaddr *)&peer, peerlen,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	RPCAPD_LOG(NOTICE, "client %s connected", host);

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		struct rpcap_header hdr;
		uint32_t plen;

		/* While capturing, the data thread's exit is an event too:
		 * the client may have dropped only the data connection.
		 */
		if (s.capture_on && wait_ctrl_or_data_exit(&ctrl, &s) == 0) {
			RPCAPD_LOG(NOTICE, "data connection finished, ending session");
			goto done;
		}

		if (recv_full(&ctrl, &hdr, sizeof(hdr)) < 0)
			break;

		plen = rte_be_to_cpu_32(hdr.plen);

		/* Only version 0 is spoken here */
		if (hdr.ver != RPCAP_VERSION) {
			RPCAPD_LOG(WARNING, "unsupported protocol version %u",
				hdr.ver);
			if (rpcap_discard(&ctrl, plen) < 0 ||
			    rpcap_send_error(&ctrl, PCAP_ERR_WRONGVER,
					     "unsupported protocol version") < 0)
				goto done;
			continue;
		}

		switch (hdr.type) {
		case RPCAP_MSG_AUTH_REQ:
			/* libpcap treats a zero-length AUTH_REPLY as "version
			 * 0 only, same byte order".
			 */
			if (handle_auth(&ctrl, plen) < 0)
				goto done;
			break;
		case RPCAP_MSG_FINDALLIF_REQ:
			if (rpcap_discard(&ctrl, plen) < 0 || handle_findallif(&ctrl) < 0)
				goto done;
			break;
		case RPCAP_MSG_OPEN_REQ:
			if (handle_open(&ctrl, plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_STARTCAP_REQ:
			if (handle_startcap(&ctrl, plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_UPDATEFILTER_REQ:
			if (handle_updatefilter(&ctrl, plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_ENDCAP_REQ:
			if (handle_endcap(&ctrl, plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_STATS_REQ:
			if (handle_stats(&ctrl, plen, &s) < 0)
				goto done;
			break;
		case RPCAP_MSG_CLOSE:
			rpcap_discard(&ctrl, plen);
			goto done;
		default:
			RPCAPD_LOG(WARNING, "unsupported request type 0x%02x", hdr.type);
			if (rpcap_discard(&ctrl, plen) < 0 ||
			    rpcap_send_error(&ctrl, PCAP_ERR_WRONGMSG,
					     "unsupported request") < 0)
				goto done;
			break;
		}
	}
done:
	stop_capture(&s);
	close(ctrl_fd);
	RPCAPD_LOG(NOTICE, "client %s disconnected", host);
}


static void
usage(FILE *f, const char *progname)
{
	fprintf(f, "Usage: %s [options]\n", progname);
	fprintf(f,
		"  -p, --port <port>     listen port (default %u)\n"
		"  -N <ring size>        ring size in packets (default %u)\n"
		"  -D, --debug           increase log verbosity (-D info, -DD debug)\n"
		"      --debug-file <f>  redirect log output to file <f> (append mode)\n"
		"      --send-timeout <s> seconds a data send may block before the\n"
		"                        client is treated as dead (default %u, 0 waits\n"
		"                        forever)\n"
		"      --version         print version and exit\n"
		"  -h, --help            print this help and exit\n"
		"      --lcore=<core>    CPU core to run on (default: any)\n"
		"      --file-prefix=<p> prefix to use for multi-process\n"
		"\n"
		"The listener is bound to the loopback addresses only: rpcap is\n"
		"unauthenticated and unencrypted.\n",
		RPCAP_DEFAULT_NETPORT, DEFAULT_RING_SIZE,
		DATA_SEND_TIMEOUT_SEC);
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
		OPT_SEND_TIMEOUT,
	};
	static const struct option long_options[] = {
		{ "port",         required_argument, NULL, 'p' },
		{ "debug",        no_argument,       NULL, 'D' },
		{ "help",         no_argument,       NULL, 'h' },
		{ "version",      no_argument,       NULL, OPT_VERSION },
		{ "debug-file",   required_argument, NULL, OPT_DEBUG_FILE },
		{ "send-timeout", required_argument, NULL, OPT_SEND_TIMEOUT },
		{ "file-prefix",  required_argument, NULL, 0 },
		{ "lcore",        required_argument, NULL, 0 },
		{ NULL, 0, NULL, 0 },
	};
	int option_index, c;

	while ((c = getopt_long(argc, argv, "hDp:N:",
				long_options, &option_index)) != -1) {
		switch (c) {
		case 'p': {
			unsigned long u = parse_number(optarg, "port");

			if (u == 0 || u > UINT16_MAX)
				rte_exit(EXIT_FAILURE, "Invalid port: %s\n", optarg);
			listen_port = (uint16_t)u;
			break;
		}
		case 'N': {
			unsigned long u = parse_number(optarg, "ring size");

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
		case OPT_SEND_TIMEOUT: {
			unsigned long u = parse_number(optarg, "send timeout");

			/* Zero means wait forever, which is what the socket
			 * does without SO_SNDTIMEO.
			 */
			if (u > INT32_MAX)
				rte_exit(EXIT_FAILURE,
					 "Invalid send timeout: %s\n", optarg);
			send_timeout = (uint32_t)u;
			break;
		}
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
 * running primary DPDK application. Hide most of the EAL
 * complexity and only show serious messages from EAL.
 */
static int
dpdk_init(void)
{
	static const char * const args[] = {
		"rpcapd",
		"--proc-type", "secondary",
		"--log-level", "lib.eal:warning",
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
	int srv_fds[MAX_LISTEN_SOCKETS];
	unsigned int nsrv, i;

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

	nsrv = open_listen_sockets(listen_port, srv_fds);

	enable_primary_monitor();

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		int cfd = accept_any(srv_fds, nsrv);

		/* Per-connection failures are retried inside; anything
		 * returned here is fatal or a quit signal.
		 */
		if (cfd < 0)
			break;

		handle_client(cfd);
	}

	disable_primary_monitor();
	RPCAPD_LOG(NOTICE, "shutting down");
	for (i = 0; i < nsrv; i++)
		close(srv_fds[i]);

	/* If the primary has exited, do not try to communicate with it. */
	if (!rte_eal_primary_proc_alive(NULL))
		return 0;

	rte_pdump_uninit();
	return rte_eal_cleanup() ? EXIT_FAILURE : 0;
}
