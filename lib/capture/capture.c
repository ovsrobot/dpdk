/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Stephen Hemminger
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
#include <time.h>
#include <unistd.h>

#include <rte_branch_prediction.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_pcapng.h>
#include <rte_pause.h>
#include <rte_ring.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>
#include <rte_string_fns.h>
#include <rte_telemetry.h>
#include <rte_thread.h>
#include <rte_version.h>

#include "private.h"

#define CAPTURE_EXTCAP_PREFIX	"dpdk"
#define CAP_CMD_MAX		1024
#define DEFAULT_SNAPLEN		262144u	/* from tcpdump et.al. */
#define MBUF_POOL_CACHE_SIZE	32
#define CAPTURE_RING_SIZE	256
#define CAPTURE_POOL_SIZE	1024
#define SLEEP_THRESHOLD		100
#define SLEEP_US		100

RTE_LOG_REGISTER_DEFAULT(rte_capture_logtype, NOTICE);

/*
 * Active captures owned by this process. Control plane only, touched from the
 * telemetry handler and the drain threads but never the dataplane, so a plain
 * spinlock is enough.
 *
 * Only the creator has a capture on this list; the drain thread, output file
 * and ring lifetime all belong to it. A secondary reaches a capture through
 * the pointer in the IPC request, so no shared tailq is needed.
 */
static struct capture_list capture_list = TAILQ_HEAD_INITIALIZER(capture_list);
rte_spinlock_t capture_lock = RTE_SPINLOCK_INITIALIZER;


/* Parameter values: only used on stack inside parsing */
struct capture_config {
	uint16_t port_id;
	uint16_t queue;
	uint32_t snaplen;
	const char *filter_str;
	const char *output;
};

/* Helper that returns error to telemetry and logs it */
static void __rte_format_printf(2, 3)
capture_err(struct rte_tel_data *d, const char *format, ...)
{
	va_list ap;
	char msg[1024];

	va_start(ap, format);
	vsnprintf(msg, sizeof(msg), format, ap);
	va_end(ap);

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "error", msg);

	CAPTURE_LOG(NOTICE, "%s", msg);
}

static int
parse_uint32(const char *str, uint32_t *result, uint32_t limit)
{
	unsigned long val;
	char *endp;

	errno = 0;
	val = strtoul(str, &endp, 10);
	if (errno != 0 || *endp != '\0' || val >= limit)
		return -1;

	*result = val;
	return 0;
}

/*
 * Break the comma separated parameter string into tokens
 * and fill in the capture config structure.
 *
 * Does not use rte_kvargs because that would mangle [] etc in filter expression.
 */
static int
parse_params(char *str, struct capture_config *cfg, struct rte_tel_data *d)
{
	uint32_t snaplen = DEFAULT_SNAPLEN;
	char *args[8];
	int nargs;

	/* Need at least the port id */
	nargs = rte_strsplit(str, strlen(str), args, RTE_DIM(args), ',');
	if (nargs < 1) {
		capture_err(d, "missing parameters '%s'", str);
		return -1;
	}

	/* Parse port id (required) */
	uint32_t port_id;
	if (parse_uint32(args[0], &port_id, RTE_MAX_ETHPORTS) < 0) {
		capture_err(d, "invalid port_id='%s'", args[0]);
		return -1;
	}

	/* parse remainder as name=value parameters */
	for (int i = 1; i < nargs; i++) {
		char *key = args[i];

		/* split at the = */
		char *eq = strchr(args[i], '=');

		/* all current options require argument after = */
		if (eq == NULL || eq[1] == '\0') {
			capture_err(d,  "missing value for '%s'", key);
			return -1;
		}
		*eq = '\0';
		char *value = eq + 1;

		if (strcmp(key, "out") == 0) {
			cfg->output = value;
		} else if (strcmp(key, "filter") == 0) {
			cfg->filter_str = value;
		} else if (strcmp(key, "queue") == 0) {
			uint32_t q;

			if (parse_uint32(value, &q, RTE_MAX_QUEUES_PER_PORT) < 0) {
				capture_err(d, "invalid queue '%s'", value);
				return -1;
			}
			cfg->queue = q;
		} else if (strcmp(key, "snaplen") == 0) {
			if (parse_uint32(value, &snaplen, UINT32_MAX) < 0) {
				capture_err(d, "invalid snaplen '%s'", value);
				return -1;
			}
		} else {
			capture_err(d, "unknown parameter '%s'", key);
			return -1;
		}
	}

	if (cfg->output == NULL) {
		capture_err(d, "missing output parameter");
		return -1;
	}

	cfg->port_id = port_id;

	/*
	 * Default is 256K from tcpdump legacy
	 * using snaplen=0 means everything.
	 */
	cfg->snaplen = snaplen > 0 ? snaplen : UINT32_MAX;
	return 0;
}

static void
capture_link(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_INSERT_TAIL(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

void
capture_unlink(struct capture *cap)
{
	rte_spinlock_lock(&capture_lock);
	TAILQ_REMOVE(&capture_list, cap, next);
	rte_spinlock_unlock(&capture_lock);
}

void
capture_free(struct capture *cap)
{
	if (cap == NULL)
		return;

	free(cap->output);
	__rte_capture_filter_free(cap->filter);
	rte_ring_free(cap->ring);
	rte_mempool_free(cap->mp);
	rte_free(cap);
}

/* Generate unique id for naming and telemetry */
static unsigned int
get_unique_id(void)
{
	static RTE_ATOMIC(unsigned int) capture_instance;

	return rte_atomic_fetch_add_explicit(&capture_instance, 1, rte_memory_order_relaxed);
}

/*
 * Convert configuration into running state
 */
static struct capture *
capture_alloc(const struct capture_config *cfg,
	      const struct rte_eth_dev_info *dev_info,
	      struct rte_tel_data *d)
{
	struct capture *cap;
	char ring_name[RTE_RING_NAMESIZE];
	uint16_t mbuf_size;

	/* try and put capture data struct on same node as device. */
	int socket_id = rte_eth_dev_socket_id(cfg->port_id);
	if (socket_id < 0)
		socket_id = SOCKET_ID_ANY;

	uint16_t num_queues = dev_info->nb_tx_queues + dev_info->nb_rx_queues;
	size_t cb_size = sizeof(*cap) + num_queues * sizeof(cap->cbs[0]);
	cap = rte_zmalloc_socket("capture", cb_size, RTE_CACHE_LINE_SIZE, socket_id);
	if (cap == NULL) {
		capture_err(d, "Could not allocate capture struct");
		goto error;
	}

	rte_spinlock_init(&cap->cbs_lock);
	TAILQ_INIT(&cap->attached);

	cap->idx = get_unique_id();
	snprintf(ring_name, sizeof(ring_name), "capture-%u", cap->idx);
	cap->ring = rte_ring_create(ring_name, CAPTURE_RING_SIZE, socket_id, 0);
	if (cap->ring == NULL) {
		capture_err(d, "Could not create ring");
		goto error;
	}

	/*
	 * If snapshot length is smaller than one mbuf segment then pool
	 * element size can be reduced; otherwise can just use the default
	 * and rte_pktmbuf_copy handle multiple segments.
	 */
	if (cfg->snaplen < RTE_MBUF_DEFAULT_BUF_SIZE)
		mbuf_size = rte_pcapng_mbuf_size(cfg->snaplen);
	else
		mbuf_size = RTE_MBUF_DEFAULT_BUF_SIZE;

	cap->mp = rte_pktmbuf_pool_create_by_ops(ring_name, CAPTURE_POOL_SIZE,
						 MBUF_POOL_CACHE_SIZE, 0, mbuf_size,
						 socket_id, "ring_mp_mc");
	if (cap->mp == NULL) {
		capture_err(d,  "Could not create mempool");
		goto error;
	}

	if (cfg->filter_str) {
		cap->filter = __rte_capture_filter_create(cfg->filter_str);
		if (cap->filter == NULL) {
			capture_err(d,  "Could not compile filter: %s", cfg->filter_str);
			goto error;
		}
	}

	cap->port_id = cfg->port_id;
	cap->output = strdup(cfg->output);
	if (cap->output == NULL) {
		capture_err(d, "Could not strdup '%s'", cfg->output);
		goto error;
	}
	rte_atomic_store_explicit(&cap->running, true, rte_memory_order_relaxed);
	cap->snaplen = cfg->snaplen;
	cap->queue = cfg->queue;
	cap->socket_id = socket_id;
	cap->tx_queues = dev_info->nb_tx_queues;
	cap->rx_queues = dev_info->nb_rx_queues;

	return cap;

error:
	capture_free(cap);
	return NULL;
}
/*
 * Callback handler for telemetry library to start capture.
 *
 * Need to handle: <iface>,snaplen=<n>,filter=<str>
 */
static int
capture_start_req(const char *cmd, const char *params, struct rte_tel_data *d)
{
	struct capture *cap = NULL;
	struct capture_config cfg = { .queue = ALL_QUEUES };
	struct rte_eth_dev_info dev_info;

	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry: %s %s", cmd, params);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		CAPTURE_LOG(ERR, "capture can only be started from primary");
		return -1;
	}

	/* Note: params is const so need non-const copy for parsing
	 * Alternative would be to change telemetry to allow this.
	 */
	char tmp[CAP_CMD_MAX];
	if (strlcpy(tmp, params, CAP_CMD_MAX) >= CAP_CMD_MAX) {
		CAPTURE_LOG(ERR, "params too long");
		return -1;
	}

	if (parse_params(tmp, &cfg, d) < 0)
		return 0;

	/* Lookup number of queues etc, also validates port_id */
	if (rte_eth_dev_info_get(cfg.port_id, &dev_info) < 0) {
		capture_err(d, "can not get info for port %u", cfg.port_id);
		return 0;
	}

	if (cfg.queue != ALL_QUEUES &&
	    cfg.queue >= RTE_MAX(dev_info.nb_rx_queues, dev_info.nb_tx_queues)) {
		capture_err(d, "queue %d out of range", cfg.queue);
		return 0;
	}

	struct stat sb;
	if (lstat(cfg.output, &sb) < 0) {
		capture_err(d, "output %s:%s", cfg.output, strerror(errno));
		return 0;
	}

	if (!is_fifo(&sb)) {
		capture_err(d, "output %s is not empty", cfg.output);
		return 0;
	}

	cap = capture_alloc(&cfg, &dev_info, d);
	if (cap == NULL)
		return 0;

	if (capture_add_callbacks(cap) < 0) {
		capture_err(d, "can not register callbacks");
		goto error_callback_remove;
	}

	/*
	 * Have the secondaries attach to their own queues. A secondary that
	 * cannot is reported but does not fail the capture: what this process
	 * sees is still captured.
	 */
	if (capture_mp_broadcast(cap, CAPTURE_MP_START) < 0)
		CAPTURE_LOG(NOTICE, "capture %u: not all secondaries attached", cap->idx);

	/*
	 * Publish into the active list before starting the drain thread so the
	 * thread is guaranteed to find itself there when it removes itself on
	 * exit (it may exit immediately, e.g. if the FIFO reader is already
	 * gone). On thread-create failure we undo the insertion here.
	 */
	uint32_t idx = cap->idx;
	capture_link(cap);

	/*
	 * Make a new thread to do the capture work
	 * Thread will inherit affinity from the telemetry handler that calls us
	 */
	rte_thread_t thread_id;
	int ret = rte_thread_create(&thread_id, NULL, capture_thread, cap);
	if (ret != 0) {
		capture_err(d, "thread start failed: %s", strerror(ret));
		goto error_unlink;
	}

	rte_thread_detach(thread_id);

	/* Return id back for later use. */
	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "id", idx);
	rte_tel_data_add_dict_string(d, "status", "running");
	return 0;

error_unlink:
	/* the drain thread never ran, so undo the attach here */
	if (capture_mp_broadcast(cap, CAPTURE_MP_STOP) < 0) {
		CAPTURE_LOG(ERR,
			    "capture %u: secondary still attached, leaking ring and pool",
			    cap->idx);
		capture_unlink(cap);
		capture_remove_callbacks(cap);
		return 0;
	}
	capture_unlink(cap);
error_callback_remove:
	capture_remove_callbacks(cap);
	capture_free(cap);

	/* return 0 since error reported "error":"XXX" in response */
	return 0;
}

/* Telemetry: stop active capture. */
static int
capture_stop_req(const char *cmd, const char *params, struct rte_tel_data *d)
{
	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);

	uint32_t idx;
	if (parse_uint32(params, &idx, UINT32_MAX) < 0) {
		capture_err(d, "invalid capture index '%s'", params);
		return 0;
	}

	rte_spinlock_lock(&capture_lock);
	struct capture *cap;
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		rte_spinlock_unlock(&capture_lock);
		CAPTURE_LOG(DEBUG, "capture index %" PRIu32 " not found", idx);
		return 0;
	}

	rte_atomic_store_explicit(&cap->running, false, rte_memory_order_relaxed);
	rte_spinlock_unlock(&capture_lock);

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "status", "stopped");
	return 0;
}

/* Telemetry: list the ids of all active captures. */
static int
capture_list_req(const char *cmd __rte_unused, const char *params __rte_unused,
		 struct rte_tel_data *d)
{
	struct capture *cap;

	CAPTURE_LOG(DEBUG, "telemetry %s", cmd);
	rte_tel_data_start_array(d, RTE_TEL_UINT_VAL);

	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next)
		rte_tel_data_add_array_uint(d, cap->idx);
	rte_spinlock_unlock(&capture_lock);

	return 0;
}


/* Telemetry: report configuration and counters for one capture. */
static int
capture_stats_req(const char *cmd, const char *params,
		  struct rte_tel_data *d)
{
	struct capture *cap;
	struct capture_total t;

	if (params == NULL || *params == '\0') {
		CAPTURE_LOG(ERR, "missing parameters");
		return -1;
	}

	CAPTURE_LOG(DEBUG, "telemetry %s %s", cmd, params);

	uint32_t idx;
	if (parse_uint32(params, &idx, UINT32_MAX) < 0) {
		capture_err(d, "invalid capture index '%s'", params);
		return 0;
	}

	/* Find the instance and snapshot what we need while holding the lock. */
	rte_spinlock_lock(&capture_lock);
	TAILQ_FOREACH(cap, &capture_list, next) {
		if (cap->idx == idx)
			break;
	}
	if (cap == NULL) {
		rte_spinlock_unlock(&capture_lock);
		capture_err(d, "capture index %" PRIu32 " not found", idx);
		return 0;
	}

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint(d, "port_id", cap->port_id);
	if (cap->filter)
		rte_tel_data_add_dict_string(d, "filter",
					     __rte_capture_filter_string(cap->filter));
	rte_tel_data_add_dict_int(d, "running",
				  rte_atomic_load_explicit(&cap->running,
							   rte_memory_order_relaxed));
	rte_tel_data_add_dict_uint(d, "snaplen", cap->snaplen);
	rte_tel_data_add_dict_uint(d, "rx_queues", cap->rx_queues);
	rte_tel_data_add_dict_uint(d, "tx_queues", cap->tx_queues);
	/* cbs_lock nests inside capture_lock, never the other way round */
	rte_spinlock_lock(&cap->cbs_lock);
	capture_sum_stats(cap, &t);
	rte_spinlock_unlock(&cap->cbs_lock);
	rte_spinlock_unlock(&capture_lock);

	rte_tel_data_add_dict_uint(d, "accepted", t.accepted);
	rte_tel_data_add_dict_uint(d, "filtered", t.filtered);
	rte_tel_data_add_dict_uint(d, "nombuf", t.nombuf);
	rte_tel_data_add_dict_uint(d, "ringfull", t.ringfull);

	return 0;
}

RTE_INIT(capture_telemetry)
{
	capture_mp_register();

	rte_telemetry_register_cmd("/ethdev/capture/list", capture_list_req,
		"List ids of active captures. Takes no parameters.");
	rte_telemetry_register_cmd("/ethdev/capture/stats", capture_stats_req,
		"Report configuration and counters for a capture. Parameters: id");
	rte_telemetry_register_cmd("/ethdev/capture/start", capture_start_req,
		"Start capture. Parameters: "
		"port_id,out=<fifo>,snaplen=N(optional),queue=N(optional),filter=string(optional)");
	rte_telemetry_register_cmd("/ethdev/capture/stop", capture_stop_req,
				   "Stop an active capture. Parameters: id");
}
