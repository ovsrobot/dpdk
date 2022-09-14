/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include <unistd.h>
#include <limits.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_errno.h>
#include <rte_lcore.h>

#ifdef RTE_LCORE_POLL_BUSYNESS
#include <rte_telemetry.h>
#endif

rte_atomic32_t __rte_lcore_poll_telemetry_enabled;

#ifdef RTE_LCORE_POLL_BUSYNESS

#include "eal_private.h"

struct lcore_poll_telemetry {
	int poll_busyness;
	/**< Calculated poll busyness (gets set/returned by the API) */
	int raw_poll_busyness;
	/**< Calculated poll busyness times 100. */
	uint64_t interval_ts;
	/**< when previous telemetry interval started */
	uint64_t empty_cycles;
	/**< empty cycle count since last interval */
	uint64_t last_poll_ts;
	/**< last poll timestamp */
	bool last_empty;
	/**< if last poll was empty */
	unsigned int contig_poll_cnt;
	/**< contiguous (always empty/non empty) poll counter */
} __rte_cache_aligned;

static struct lcore_poll_telemetry *telemetry_data;

#define LCORE_POLL_BUSYNESS_MAX 100
#define LCORE_POLL_BUSYNESS_NOT_SET -1
#define LCORE_POLL_BUSYNESS_MIN 0

#define SMOOTH_COEFF 5
#define STATE_CHANGE_OPT 32

static void lcore_config_init(void)
{
	int lcore_id;

	RTE_LCORE_FOREACH(lcore_id) {
		struct lcore_poll_telemetry *td = &telemetry_data[lcore_id];

		td->interval_ts = 0;
		td->last_poll_ts = 0;
		td->empty_cycles = 0;
		td->last_empty = true;
		td->contig_poll_cnt = 0;
		td->poll_busyness = LCORE_POLL_BUSYNESS_NOT_SET;
		td->raw_poll_busyness = 0;
	}
}

int rte_lcore_poll_busyness(unsigned int lcore_id)
{
	const uint64_t tsc_ms = rte_get_timer_hz() / MS_PER_S;
	/* if more than 1000 busyness periods have passed, this core is considered inactive */
	const uint64_t active_thresh = RTE_LCORE_POLL_BUSYNESS_PERIOD_MS * tsc_ms * 1000;
	struct lcore_poll_telemetry *tdata;

	if (lcore_id >= RTE_MAX_LCORE)
		return -EINVAL;
	tdata = &telemetry_data[lcore_id];

	/* if the lcore is not active */
	if (tdata->interval_ts == 0)
		return LCORE_POLL_BUSYNESS_NOT_SET;
	/* if the core hasn't been active in a while */
	else if ((rte_rdtsc() - tdata->interval_ts) > active_thresh)
		return LCORE_POLL_BUSYNESS_NOT_SET;

	/* this core is active, report its poll busyness */
	return telemetry_data[lcore_id].poll_busyness;
}

int rte_lcore_poll_busyness_enabled(void)
{
	return rte_atomic32_read(&__rte_lcore_poll_telemetry_enabled);
}

void rte_lcore_poll_busyness_enabled_set(bool enable)
{
	int set = rte_atomic32_cmpset((volatile uint32_t *)&__rte_lcore_poll_telemetry_enabled,
			(int)!enable, (int)enable);

	/* Reset counters on successful disable */
	if (set && !enable)
		lcore_config_init();
}

static inline int calc_raw_poll_busyness(const struct lcore_poll_telemetry *tdata,
				    const uint64_t empty, const uint64_t total)
{
	/*
	 * We don't want to use floating point math here, but we want for our poll
	 * busyness to react smoothly to sudden changes, while still keeping the
	 * accuracy and making sure that over time the average follows poll busyness
	 * as measured just-in-time. Therefore, we will calculate the average poll
	 * busyness using integer math, but shift the decimal point two places
	 * to the right, so that 100.0 becomes 10000. This allows us to report
	 * integer values (0..100) while still allowing ourselves to follow the
	 * just-in-time measurements when we calculate our averages.
	 */
	const int max_raw_idle = LCORE_POLL_BUSYNESS_MAX * 100;

	const int prev_raw_idle = max_raw_idle - tdata->raw_poll_busyness;

	/* calculate rate of idle cycles, times 100 */
	const int cur_raw_idle = (int)((empty * max_raw_idle) / total);

	/* smoothen the idleness */
	const int smoothened_idle =
			(cur_raw_idle + prev_raw_idle * (SMOOTH_COEFF - 1)) / SMOOTH_COEFF;

	/* convert idleness to poll busyness */
	return max_raw_idle - smoothened_idle;
}

void __rte_lcore_poll_busyness_timestamp(uint16_t nb_rx)
{
	const unsigned int lcore_id = rte_lcore_id();
	uint64_t interval_ts, empty_cycles, cur_tsc, last_poll_ts;
	struct lcore_poll_telemetry *tdata;
	const bool empty = nb_rx == 0;
	uint64_t diff_int, diff_last;
	bool last_empty;

	/* This telemetry is not supported for unregistered non-EAL threads */
	if (lcore_id >= RTE_MAX_LCORE) {
		RTE_LOG(DEBUG, EAL,
				"Lcore telemetry not supported on unregistered non-EAL thread %d",
				lcore_id);
		return;
	}

	tdata = &telemetry_data[lcore_id];
	last_empty = tdata->last_empty;

	/* optimization: don't do anything if status hasn't changed */
	if (last_empty == empty && tdata->contig_poll_cnt++ < STATE_CHANGE_OPT)
		return;
	/* status changed or we're waiting for too long, reset counter */
	tdata->contig_poll_cnt = 0;

	cur_tsc = rte_rdtsc();

	interval_ts = tdata->interval_ts;
	empty_cycles = tdata->empty_cycles;
	last_poll_ts = tdata->last_poll_ts;

	diff_int = cur_tsc - interval_ts;
	diff_last = cur_tsc - last_poll_ts;

	/* is this the first time we're here? */
	if (interval_ts == 0) {
		tdata->poll_busyness = LCORE_POLL_BUSYNESS_MIN;
		tdata->raw_poll_busyness = 0;
		tdata->interval_ts = cur_tsc;
		tdata->empty_cycles = 0;
		tdata->contig_poll_cnt = 0;
		goto end;
	}

	/* update the empty counter if we got an empty poll earlier */
	if (last_empty)
		empty_cycles += diff_last;

	/* have we passed the interval? */
	uint64_t interval = ((rte_get_tsc_hz() / MS_PER_S) * RTE_LCORE_POLL_BUSYNESS_PERIOD_MS);
	if (diff_int > interval) {
		int raw_poll_busyness;

		/* get updated poll_busyness value */
		raw_poll_busyness = calc_raw_poll_busyness(tdata, empty_cycles, diff_int);

		/* set a new interval, reset empty counter */
		tdata->interval_ts = cur_tsc;
		tdata->empty_cycles = 0;
		tdata->raw_poll_busyness = raw_poll_busyness;
		/* bring poll busyness back to 0..100 range, biased to round up */
		tdata->poll_busyness = (raw_poll_busyness + 50) / 100;
	} else
		/* we may have updated empty counter */
		tdata->empty_cycles = empty_cycles;

end:
	/* update status for next poll */
	tdata->last_poll_ts = cur_tsc;
	tdata->last_empty = empty;
}

static int
lcore_poll_busyness_enable(const char *cmd __rte_unused,
		      const char *params __rte_unused,
		      struct rte_tel_data *d)
{
	rte_lcore_poll_busyness_enabled_set(true);

	rte_tel_data_start_dict(d);

	rte_tel_data_add_dict_int(d, "poll_busyness_enabled", 1);

	return 0;
}

static int
lcore_poll_busyness_disable(const char *cmd __rte_unused,
		       const char *params __rte_unused,
		       struct rte_tel_data *d)
{
	rte_lcore_poll_busyness_enabled_set(false);

	rte_tel_data_start_dict(d);

	rte_tel_data_add_dict_int(d, "poll_busyness_enabled", 0);

	return 0;
}

static int
lcore_handle_poll_busyness(const char *cmd __rte_unused,
		      const char *params __rte_unused, struct rte_tel_data *d)
{
	char corenum[64];
	int i;

	rte_tel_data_start_dict(d);

	RTE_LCORE_FOREACH(i) {
		if (!rte_lcore_is_enabled(i))
			continue;
		snprintf(corenum, sizeof(corenum), "%d", i);
		rte_tel_data_add_dict_int(d, corenum, rte_lcore_poll_busyness(i));
	}

	return 0;
}

static int
lcore_handle_cpuset(const char *cmd __rte_unused,
		    const char *params __rte_unused,
		    struct rte_tel_data *d)
{
	char corenum[64];
	int i;

	rte_tel_data_start_dict(d);

	RTE_LCORE_FOREACH(i) {
		const struct lcore_config *cfg = &lcore_config[i];
		const rte_cpuset_t *cpuset = &cfg->cpuset;
		struct rte_tel_data *ld;
		unsigned int cpu;

		if (!rte_lcore_is_enabled(i))
			continue;

		/* create an array of integers */
		ld = rte_tel_data_alloc();
		if (ld == NULL)
			return -ENOMEM;
		rte_tel_data_start_array(ld, RTE_TEL_INT_VAL);

		/* add cpu ID's from cpuset to the array */
		for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
			if (!CPU_ISSET(cpu, cpuset))
				continue;
			rte_tel_data_add_array_int(ld, cpu);
		}

		/* add array to the per-lcore container */
		snprintf(corenum, sizeof(corenum), "%d", i);

		/* tell telemetry library to free this array automatically */
		rte_tel_data_add_dict_container(d, corenum, ld, 0);
	}

	return 0;
}

void
eal_lcore_poll_telemetry_free(void)
{
	if (telemetry_data != NULL) {
		free(telemetry_data);
		telemetry_data = NULL;
	}
}

RTE_INIT(lcore_init_poll_telemetry)
{
	telemetry_data = calloc(RTE_MAX_LCORE, sizeof(telemetry_data[0]));
	if (telemetry_data == NULL)
		rte_panic("Could not init lcore telemetry data: Out of memory\n");

	lcore_config_init();

	rte_telemetry_register_cmd("/eal/lcore/poll_busyness", lcore_handle_poll_busyness,
				   "return percentage poll busyness of cores");

	rte_telemetry_register_cmd("/eal/lcore/poll_busyness_enable", lcore_poll_busyness_enable,
				   "enable lcore poll busyness measurement");

	rte_telemetry_register_cmd("/eal/lcore/poll_busyness_disable", lcore_poll_busyness_disable,
				   "disable lcore poll busyness measurement");

	rte_telemetry_register_cmd("/eal/lcore/cpuset", lcore_handle_cpuset,
				   "list physical core affinity for each lcore");

	rte_atomic32_set(&__rte_lcore_poll_telemetry_enabled, true);
}

#else

int rte_lcore_poll_busyness(unsigned int lcore_id __rte_unused)
{
	return -ENOTSUP;
}

int rte_lcore_poll_busyness_enabled(void)
{
	return -ENOTSUP;
}

void rte_lcore_poll_busyness_enabled_set(bool enable __rte_unused)
{
}

void __rte_lcore_poll_busyness_timestamp(uint16_t nb_rx __rte_unused)
{
}

void eal_lcore_poll_telemetry_free(void)
{
}

#endif
