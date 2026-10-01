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
 * are intentionally omitted.
 *
 * Options, startup and the control connection dispatcher live here; the
 * request handlers are in session.c, capture.c and filter.c.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netdb.h>
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

/* Command-line options */
static uint16_t listen_port = RPCAP_DEFAULT_NETPORT;
uint32_t ring_size = DEFAULT_RING_SIZE;
static const char *lcore_arg;
static const char *file_prefix;
static const char *bind_addr;		/* -b argument; NULL means loopback */
static int bind_family = AF_UNSPEC;
static const char *debug_file;		/* --debug-file argument */
static unsigned int debug_log;		/* -D count: raise RPCAPD log verbosity */
uint32_t send_timeout = DATA_SEND_TIMEOUT_SEC;	/* 0 means no limit */

struct sockaddr_storage listen_addr;
socklen_t               listen_addrlen;

RTE_ATOMIC(bool) quit_signal;

static bool
is_loopback(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const void *)ss;

		return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
	}
	if (ss->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const void *)ss;

		/* A v4 client on a dual-stack socket arrives as
		 * ::ffff:127.0.0.1, which is loopback too.
		 */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
			return sin6->sin6_addr.s6_addr[12] == 127;

		return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
	}
	return false;
}

static void
parse_bind_addr(void)
{
	struct addrinfo hints = {
		.ai_family   = bind_family,
		.ai_socktype = SOCK_STREAM,
		.ai_flags    = AI_NUMERICHOST | AI_PASSIVE,
	};
	struct addrinfo *res;
	int rc;

	/* Loopback by default; the wildcard address is not a safe default. */
	if (bind_addr == NULL)
		bind_addr = (bind_family == AF_INET6) ? "::1" : "127.0.0.1";

	rc = getaddrinfo(bind_addr, NULL, &hints, &res);
	if (rc != 0)
		rte_exit(EXIT_FAILURE, "Invalid bind address '%s': %s\n",
			 bind_addr, gai_strerror(rc));
	memcpy(&listen_addr, res->ai_addr, res->ai_addrlen);
	listen_addrlen = res->ai_addrlen;
	freeaddrinfo(res);
}


static void
signal_handler(int sig __rte_unused)
{
	rte_atomic_store_explicit(&quit_signal, true, rte_memory_order_relaxed);
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

	/* Remembered so the data connection can be restricted to this peer. */
	if (getpeername(ctrl_fd, (struct sockaddr *)&peer, &peerlen) != 0) {
		RPCAPD_LOG(ERR, "getpeername: %s", strerror(errno));
		return;
	}
	s.peer = peer;
	getnameinfo((struct sockaddr *)&peer, peerlen,
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);
	RPCAPD_LOG(NOTICE, "client %s connected", host);

	while (!rte_atomic_load_explicit(&quit_signal, rte_memory_order_relaxed)) {
		struct rpcap_header hdr;
		uint32_t plen;

		/* Drain the ring whenever a capture is running */
		if (s.capture_on && capture_loop(&ctrl, &s) < 0)
			goto done;

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
			    rpcap_send_error(&ctrl, 0, "unsupported request") < 0)
				goto done;
			break;
		}
	}
done:
	stop_capture(&s);
	close(ctrl_fd);
	RPCAPD_LOG(NOTICE, "client %s disconnected", host);
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
		"  -b, --bind <addr>     bind address (default 127.0.0.1, ::1 with -6)\n"
		"  -4                    use only IPv4\n"
		"  -6                    use only IPv6\n"
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
		"WARNING: rpcap is unauthenticated and unencrypted.  Binding to\n"
		"any non-loopback address exposes captured traffic to the\n"
		"network.  Not for production use.\n",
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
		{ "bind",         required_argument, NULL, 'b' },
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

	while ((c = getopt_long(argc, argv, "hD46p:b:N:",
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
			bind_addr = optarg;
			break;
		case '4':
			bind_family = AF_INET;
			break;
		case '6':
			bind_family = AF_INET6;
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
		case OPT_SEND_TIMEOUT: {
			unsigned long u = strtoul(optarg, NULL, 0);

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

	/* Resolve the bind address now that -4/-6/-b have been seen. */
	parse_bind_addr();
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

	/* Needs the TSC frequency, so must follow rte_eal_init(). */
	timestamp_init();

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
