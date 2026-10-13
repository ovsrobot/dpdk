/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
 */

/*
 * Output side of capture: opening the pcapng stream, and the per-capture
 * thread that drains the ring into it.
 */

#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_mbuf.h>
#include <rte_pcapng.h>
#include <rte_pause.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>
#include <rte_thread.h>
#include <rte_version.h>

#include "private.h"

/*
 * Create the file handle for pcapng output
 * Note: can't really tell wireshark about errors since this in an
 * independent thread.
 */
static rte_pcapng_t *
capture_pcapng_open(const char *path, int *fd, uint16_t port_id, const char *filter)
{
	rte_pcapng_t *pcapng = NULL;
	char port_name[RTE_ETH_NAME_MAX_LEN];
	char appname[128];
	char ifname[IFNAMSIZ];
	char *ifdescr = NULL;
	struct utsname uts;
	char *osname = NULL;

	/* OS name is optional, just keep going if not found */
	if (uname(&uts) == 0 && asprintf(&osname, "%s %s", uts.sysname, uts.release) < 0)
		osname = NULL;

	/* add DPDK internal name */
	if (rte_eth_dev_get_name_by_port(port_id, port_name) != 0) {
		CAPTURE_LOG(NOTICE, "Could not find port name for %u", port_id);
		goto cleanup;
	}

	/* match name convention used by dpdk-wireshark-extcap */
	snprintf(ifname, sizeof(ifname), CAPTURE_EXTCAP_PREFIX ":%u", port_id);
	if (asprintf(&ifdescr, "DPDK %s", port_name) < 0)
		ifdescr = NULL;

	/* mirror what other applications do for name */
	snprintf(appname, sizeof(appname), CAPTURE_EXTCAP_PREFIX " (%s)", rte_version());

	/*
	 * Open the output in non-block mode in case it is a FIFO without a reader.
	 * Wireshark must open the read end before asking us to capture.
	 */
	*fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
	if (*fd < 0) {
		CAPTURE_LOG(ERR, "Could not open %s: %s", path, strerror(errno));
		goto cleanup;
	}

	/* recheck that it is ok to use */
	struct stat sb;
	if (fstat(*fd, &sb) < 0 || !is_fifo(&sb)) {
		CAPTURE_LOG(ERR, "Not safe to use %s", path);
		goto close_fd;
	}

	/* writes in the drain loop should block normally */
	int flags = fcntl(*fd, F_GETFL, 0);
	if (flags < 0 || fcntl(*fd, F_SETFL, flags & ~O_NONBLOCK) < 0) {
		CAPTURE_LOG(ERR, "fcntl %s: %s",  path,  strerror(errno));
		goto close_fd;
	}

	/* put pcapng header on and setup */
	pcapng = rte_pcapng_fdopen(*fd, osname, NULL, appname, NULL);
	if (pcapng == NULL) {
		CAPTURE_LOG(ERR, "Add section block failed");
		goto close_fd;
	}

	if (rte_pcapng_add_interface(pcapng, port_id, DLT_EN10MB, ifname, ifdescr, filter) < 0) {
		CAPTURE_LOG(ERR, "Add interface for port %u:%s failed", port_id, ifname);
		rte_pcapng_close(pcapng);  /* closes fd */
		pcapng = NULL;
	}
	goto cleanup;

close_fd:
	close(*fd);
cleanup:
	free(osname);
	free(ifdescr);
	return pcapng;
}



static void
capture_write_stats(rte_pcapng_t *pcapng, struct capture *cap)
{
	struct capture_total t;

	rte_spinlock_lock(&cap->cbs_lock);
	capture_sum_stats(cap, &t);
	rte_spinlock_unlock(&cap->cbs_lock);

	/* TODO: extend pcapng to have more stats */
	rte_pcapng_write_stats(pcapng, cap->port_id,
			       t.accepted + t.filtered + t.nombuf, /* ifrecv */
			       t.nombuf + t.ringfull, /* ifdrop */
			       NULL);
}

/* Check that output file is still ok to write (i.e FIFO not closed).
 * Used to detect when wireshark has exited, and idle.
 */
static int
check_fifo_status(int fd)
{
	struct pollfd pfd = { .fd = fd };

	if (poll(&pfd, 1, 0) < 0) {
		CAPTURE_LOG(ERR, "poll failed: %s", strerror(errno));
		return -1;
	}
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		CAPTURE_LOG(NOTICE, "fifo reader closed");
		return -1;
	}
	return 0;
}

static ssize_t
capture_process_ring(struct rte_ring *ring, rte_pcapng_t *pcapng,
		     unsigned int *available)
{
	struct rte_mbuf *pkts[CAPTURE_BURST_SIZE];
	unsigned int n;
	ssize_t written;

	n = rte_ring_sc_dequeue_burst(ring, (void **) pkts,
				      CAPTURE_BURST_SIZE, available);
	if (n == 0)
		return 0;

	written = rte_pcapng_write_packets(pcapng, pkts, n);
	rte_pktmbuf_free_bulk(pkts, n);

	return written;
}

static void
capture_flush_ring(struct rte_ring *ring)
{
	for (;;) {
		struct rte_mbuf *pkts[CAPTURE_BURST_SIZE];
		unsigned int n;

		n = rte_ring_sc_dequeue_burst(ring, (void **) pkts,
					      CAPTURE_BURST_SIZE, NULL);
		if (n == 0)
			break;

		rte_pktmbuf_free_bulk(pkts, n);
	}
}

/* The capture thread that moves packets from ring to the pcapng out */
uint32_t __rte_hot
capture_thread(void *arg)
{
	struct capture *cap = arg;
	unsigned int empty_count = 0;
	bool reader_gone = false;
	bool orphaned = false;
	int fd = -1;

	CAPTURE_LOG(INFO, "capture thread starting");

	char name[RTE_THREAD_NAME_SIZE];
	snprintf(name, sizeof(name), "cap-%u", cap->idx);
	rte_thread_set_prefixed_name(rte_thread_self(), name);

	/* This thread wants to detect when file gets closed (for FIFO) */
	sigset_t set;
	sigemptyset(&set);
	sigaddset(&set, SIGPIPE);
	pthread_sigmask(SIG_BLOCK, &set, NULL);

	rte_pcapng_t *pcapng = capture_pcapng_open(cap->output, &fd, cap->port_id,
						   __rte_capture_filter_string(cap->filter));
	if (pcapng == NULL) {
		/* secondaries attached before this thread started */
		if (capture_mp_broadcast(cap, CAPTURE_MP_STOP) < 0)
			orphaned = true;
		capture_remove_callbacks(cap);
		goto error;
	}

	while (rte_atomic_load_explicit(&cap->running, rte_memory_order_relaxed)) {
		ssize_t written;
		unsigned int avail;

		written = capture_process_ring(cap->ring, pcapng, &avail);
		if (written < 0) {
			if (errno == EPIPE)
				CAPTURE_LOG(DEBUG, "FIFO closed by reader");
			else
				CAPTURE_LOG(ERR, "write to file failed: %s", strerror(errno));

			reader_gone = true;
			break;
		}

		if (written > 0) {
			/* are there more packets? */
			empty_count = (avail == 0);
		} else if (empty_count < SLEEP_THRESHOLD) {
			/* spin a few times before checking */
			++empty_count;
			rte_pause();
		} else if (check_fifo_status(fd) == 0) {
			/* avoid consuming 100% CPU polling */
			rte_delay_us_sleep(SLEEP_US);
		} else {
			/* output FIFO has closed */
			reader_gone = true;
			break;
		}
	}

	/*
	 * Secondaries must stop first, they enqueue into the ring freed below.
	 * Their counters are in shared blocks, so still counted in the stats.
	 */
	CAPTURE_LOG(INFO, "capture thread stopping");
	if (capture_mp_broadcast(cap, CAPTURE_MP_STOP) < 0)
		orphaned = true;
	capture_remove_callbacks(cap);

	/* Process residual */
	if (reader_gone)
		capture_flush_ring(cap->ring);
	else {
		while (capture_process_ring(cap->ring, pcapng, NULL) > 0)
			continue;

		capture_write_stats(pcapng, cap);
	}

	rte_pcapng_close(pcapng);

error:
	capture_unlink(cap);
	if (orphaned) {
		/*
		 * A secondary did not confirm that it detached, so it may still
		 * be inside a burst holding this capture. Freeing the ring it
		 * writes into would corrupt that process, so leak instead.
		 */
		CAPTURE_LOG(ERR,
			    "capture %u: secondary still attached, leaking ring and pool",
			    cap->idx);
	} else {
		capture_free(cap);
	}

	return 0;
}
