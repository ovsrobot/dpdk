/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <rte_mbuf_dyn.h>
#include <rte_log.h>
#include <rte_stdatomic.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_metrics.h>
#include <rte_memzone.h>
#include <rte_lcore.h>
#include <rte_time.h>

#include "rte_latencystats.h"

RTE_LOG_REGISTER_DEFAULT(latencystat_logtype, INFO);
#define RTE_LOGTYPE_LATENCY_STATS latencystat_logtype
#define LATENCY_STATS_LOG(level, ...) \
	RTE_LOG_LINE(level, LATENCY_STATS, "" __VA_ARGS__)

static uint64_t timestamp_dynflag;
static int timestamp_dynfield_offset = -1;

static inline rte_mbuf_timestamp_t *
timestamp_dynfield(struct rte_mbuf *mbuf)
{
	return RTE_MBUF_DYNFIELD(mbuf,
			timestamp_dynfield_offset, rte_mbuf_timestamp_t *);
}

static const char MZ_RTE_LATENCY_STATS[] = "rte_latencystats";
static int latency_stats_index;
static uint64_t samp_intvl;

/* Per queue latency information (in cycles) */
struct rte_latency_stats {
	RTE_ATOMIC(uint64_t) min_latency; /* Minimum latency */
	RTE_ATOMIC(uint64_t) avg_latency; /* Average latency */
	RTE_ATOMIC(uint64_t) max_latency; /* Maximum latency */
	RTE_ATOMIC(uint64_t) jitter;      /* Latency variation */
} __rte_cache_aligned;

/* per queue info stored in memxone */
static struct {
	struct rte_latency_stats stats[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];
} *latency_stats;

static struct {
	uint64_t prev_tsc;
	const struct rte_eth_rxtx_callback *cb;
} rx_cbs[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];

static struct {
	uint64_t prev_latency;
	const struct rte_eth_rxtx_callback *cb;
} tx_cbs[RTE_MAX_ETHPORTS][RTE_MAX_QUEUES_PER_PORT];

struct latency_stats_nameoff {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	unsigned int offset;
};

static const struct latency_stats_nameoff lat_stats_strings[] = {
	{"min_latency_ns", offsetof(struct rte_latency_stats, min_latency)},
	{"avg_latency_ns", offsetof(struct rte_latency_stats, avg_latency)},
	{"max_latency_ns", offsetof(struct rte_latency_stats, max_latency)},
	{"jitter_ns", offsetof(struct rte_latency_stats, jitter)},
};

#define NUM_LATENCY_STATS RTE_DIM(lat_stats_strings)

static inline uint64_t
cycles_to_ns(uint64_t cycles)
{
	return (cycles * NSEC_PER_SEC) / rte_get_tsc_hz();
}

static inline uint64_t
latencystat_read_ns(__rte_atomic const uint64_t *stat_ptr)
{
	return cycles_to_ns(rte_atomic_load_explicit(stat_ptr, rte_memory_order_relaxed));
}

static inline void
latencystat_write(__rte_atomic uint64_t *stat_ptr, uint64_t value)
{
	rte_atomic_store_explicit(stat_ptr, value, rte_memory_order_relaxed);
}

/* aggregate data across all ports and queues */
static void
latencystats_collect(uint64_t *values)
{
	unsigned int i, samples = 0;
	uint16_t pid, qid;
	int ret;
	struct rte_latency_stats sum = { };

	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(pid, &dev_info);
		if (ret != 0) {
			LATENCY_STATS_LOG(ERR,
				"Error during getting device (port %u) info: %s",
				pid, strerror(-ret));
			continue;
		}

		for (qid = 0; qid < dev_info.nb_tx_queues; qid++) {
			const struct rte_latency_stats *stats = &latency_stats->stats[pid][qid];
			uint64_t l;

			l = latencystat_read_ns(&stats->min_latency);
			if (l != 0 && (sum.min_latency == 0 || l < sum.min_latency))
				sum.min_latency = l;

			l = latencystat_read_ns(&stats->max_latency);
			if (l < sum.max_latency)
				sum.max_latency = l;

			sum.avg_latency += latencystat_read_ns(&stats->avg_latency);
			sum.jitter += latencystat_read_ns(&stats->jitter);
			++samples;
		}

	}

	/* adjust averages based on number of samples */
	if (samples > 0) {
		sum.avg_latency /= samples;
		sum.jitter /= samples;
	}

	/* convert cycle counts to ns */
	for (i = 0; i < NUM_LATENCY_STATS; i++) {
		uint64_t *stats_ptr = RTE_PTR_ADD(&sum, lat_stats_strings[i].offset);

		values[i] = *stats_ptr;
	}
}

int32_t
rte_latencystats_update(void)
{
	uint64_t values[NUM_LATENCY_STATS] = { 0 };

	latencystats_collect(values);

	return rte_metrics_update_values(RTE_METRICS_GLOBAL, latency_stats_index,
					values, NUM_LATENCY_STATS);
}

static uint16_t
add_time_stamps(uint16_t pid, uint16_t qid,
		struct rte_mbuf **pkts,
		uint16_t nb_pkts,
		uint16_t max_pkts __rte_unused,
		void *user_cb __rte_unused)
{
	unsigned int i;
	uint64_t diff_tsc, now;
	uint64_t *prev_tsc = &rx_cbs[pid][qid].prev_tsc;

	/*
	 * For every sample interval,
	 * time stamp is marked on one received packet.
	 */
	for (i = 0; i < nb_pkts; i++) {
		if ((pkts[i]->ol_flags & timestamp_dynflag) != 0)
			continue;

		now = rte_rdtsc();
		diff_tsc = now - *prev_tsc;
		if (diff_tsc >= samp_intvl) {
			*timestamp_dynfield(pkts[i]) = now;
			pkts[i]->ol_flags |= timestamp_dynflag;
			*prev_tsc = now;
			break;
		}
	}

	return nb_pkts;
}

static uint16_t
calc_latency(uint16_t pid, uint16_t qid,
	     struct rte_mbuf **pkts, uint16_t nb_pkts,
	     void *user_cb __rte_unused)
{
	struct rte_latency_stats *stats = &latency_stats->stats[pid][qid];
	unsigned int i;
	uint64_t now, *prev_latency;

	prev_latency = &tx_cbs[pid][qid].prev_latency;
	now = rte_rdtsc();
	for (i = 0; i < nb_pkts; i++) {
		uint64_t latency;
		int64_t delta;

		if ((pkts[i]->ol_flags & timestamp_dynflag) == 0)
			continue;

		latency = now - *timestamp_dynfield(pkts[i]);

		/*
		 * The jitter is calculated as statistical mean of interpacket
		 * delay variation. The "jitter estimate" is computed by taking
		 * the absolute values of the ipdv sequence and applying an
		 * exponential filter with parameter 1/16 to generate the
		 * estimate. i.e J=J+(|D(i-1,i)|-J)/16. Where J is jitter,
		 * D(i-1,i) is difference in latency of two consecutive packets
		 * i-1 and i.
		 * Reference: Calculated as per RFC 5481, sec 4.1,
		 * RFC 3393 sec 4.5, RFC 1889 sec.
		 */
		delta = *prev_latency - latency;
		*prev_latency = latency;
		latencystat_write(&stats->jitter,
				  stats->jitter + (delta - stats->jitter) / 16);

		if (stats->min_latency == 0 || latency < stats->min_latency)
			latencystat_write(&stats->min_latency, latency);
		else if (latency > stats->max_latency)
			latencystat_write(&stats->max_latency, latency);

		/*
		 * The average latency is measured using exponential moving
		 * average, i.e. using EWMA
		 * https://en.wikipedia.org/wiki/Moving_average
		 */
		delta = latency - stats->avg_latency;
		latency = (delta + 3 * stats->avg_latency) / 4;
		latencystat_write(&stats->avg_latency, latency);
	}

	return nb_pkts;
}

int
rte_latencystats_init(uint64_t app_samp_intvl,
		rte_latency_stats_flow_type_fn user_cb)
{
	unsigned int i;
	uint16_t pid, qid;
	const char *ptr_strings[NUM_LATENCY_STATS];
	const struct rte_memzone *mz;
	int ret;

	if (rte_memzone_lookup(MZ_RTE_LATENCY_STATS))
		return -EEXIST;

	/** Allocate stats in shared memory for multi process support */
	mz = rte_memzone_reserve(MZ_RTE_LATENCY_STATS, sizeof(*latency_stats),
					rte_socket_id(), 0);
	if (mz == NULL) {
		LATENCY_STATS_LOG(ERR, "Cannot reserve memory: %s:%d",
			__func__, __LINE__);
		return -ENOMEM;
	}

	latency_stats = mz->addr;
	samp_intvl = (app_samp_intvl * NSEC_PER_SEC) / rte_get_tsc_hz();

	/* Register latency stats with stats library */
	for (i = 0; i < NUM_LATENCY_STATS; i++)
		ptr_strings[i] = lat_stats_strings[i].name;

	latency_stats_index = rte_metrics_reg_names(ptr_strings,
							NUM_LATENCY_STATS);
	if (latency_stats_index < 0) {
		LATENCY_STATS_LOG(ERR,
			"Failed to register latency stats names");
		return -1;
	}

	/* Register mbuf field and flag for Rx timestamp */
	ret = rte_mbuf_dyn_rx_timestamp_register(&timestamp_dynfield_offset,
			&timestamp_dynflag);
	if (ret != 0) {
		LATENCY_STATS_LOG(ERR,
			"Cannot register mbuf field/flag for timestamp");
		return -rte_errno;
	}

	/** Register Rx/Tx callbacks */
	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_dev_info dev_info;
		const struct rte_eth_rxtx_callback *cb;

		ret = rte_eth_dev_info_get(pid, &dev_info);
		if (ret != 0) {
			LATENCY_STATS_LOG(NOTICE,
				"Error during getting device (port %u) info: %s",
				pid, strerror(-ret));

			continue;
		}

		for (qid = 0; qid < dev_info.nb_rx_queues; qid++) {
			cb = rte_eth_add_first_rx_callback(pid, qid, add_time_stamps, user_cb);
			if (cb)
				rx_cbs[pid][qid].cb = cb;
			else
				LATENCY_STATS_LOG(NOTICE,
						  "Failed to register Rx callback for pid=%d, qid=%d",
						  pid, qid);
		}

		for (qid = 0; qid < dev_info.nb_tx_queues; qid++) {
			cb = rte_eth_add_tx_callback(pid, qid, calc_latency, user_cb);
			if (cb)
				tx_cbs[pid][qid].cb = cb;
			else
				LATENCY_STATS_LOG(NOTICE,
						  "Failed to register Tx callback for pid=%d, qid=%d",
						  pid, qid);
		}

	}
	return 0;
}

int
rte_latencystats_uninit(void)
{
	const struct rte_memzone *mz;
	uint16_t pid, qid;
	int ret;

	/** De register Rx/Tx callbacks */
	RTE_ETH_FOREACH_DEV(pid) {
		struct rte_eth_dev_info dev_info;
		const struct rte_eth_rxtx_callback *cb;

		ret = rte_eth_dev_info_get(pid, &dev_info);
		if (ret != 0) {
			LATENCY_STATS_LOG(NOTICE,
				"Error during getting device (port %u) info: %s",
				pid, strerror(-ret));

			continue;
		}

		for (qid = 0; qid < dev_info.nb_rx_queues; qid++) {
			cb = rx_cbs[pid][qid].cb;
			if (cb == NULL)
				continue;

			ret = rte_eth_remove_rx_callback(pid, qid, cb);
			if (ret)
				LATENCY_STATS_LOG(NOTICE, "Failed to remove Rx callback");
		}

		for (qid = 0; qid < dev_info.nb_tx_queues; qid++) {
			cb = tx_cbs[pid][qid].cb;
			if (cb == NULL)
				continue;

			ret = rte_eth_remove_tx_callback(pid, qid, cb);
			if (ret)
				LATENCY_STATS_LOG(NOTICE, "Failed to remove Tx callback");
		}
	}

	/* free up the memzone */
	mz = rte_memzone_lookup(MZ_RTE_LATENCY_STATS);
	if (mz)
		rte_memzone_free(mz);

	return 0;
}

int
rte_latencystats_get_names(struct rte_metric_name *names, uint16_t size)
{
	unsigned int i;

	if (names == NULL || size < NUM_LATENCY_STATS)
		return NUM_LATENCY_STATS;

	for (i = 0; i < NUM_LATENCY_STATS; i++)
		strlcpy(names[i].name, lat_stats_strings[i].name,
			sizeof(names[i].name));

	return NUM_LATENCY_STATS;
}

int
rte_latencystats_get(struct rte_metric_value *values, uint16_t size)
{
	unsigned int i;
	uint64_t stats[NUM_LATENCY_STATS];

	if (size < NUM_LATENCY_STATS || values == NULL)
		return NUM_LATENCY_STATS;

	if (rte_eal_process_type() == RTE_PROC_SECONDARY) {
		const struct rte_memzone *mz;
		mz = rte_memzone_lookup(MZ_RTE_LATENCY_STATS);
		if (mz == NULL) {
			LATENCY_STATS_LOG(ERR,
				"Latency stats memzone not found");
			return -ENOMEM;
		}

		latency_stats = mz->addr;
	}

	/* Retrieve latency stats */
	latencystats_collect(stats);

	for (i = 0; i < NUM_LATENCY_STATS; i++) {
		values[i].key = i;
		values[i].value = stats[i];
	}


	return NUM_LATENCY_STATS;
}
