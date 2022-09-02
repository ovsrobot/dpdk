/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#ifdef RTE_HAS_JANSSON
#include <jansson.h>
#endif
#include "colors.h"
#include "stats.h"

unsigned int hist_bucket_usec;
struct stats record;
char *hist_filename;

void
init_record(void)
{
	record.max_round_ns = 0;
	record.min_round_ns = MIN_INITIAL;
	record.rounds = 0;
	record.timeouts = 0;
	record.avg_round_ns = 0;
	if (l2reflect_hist) {
		if (!record.hist_size) {
			record.hist =
				calloc(l2reflect_hist_buckets, sizeof(uint64_t));
			record.hist_size = l2reflect_hist_buckets;
		} else {
			memset(record.hist, 0,
			       record.hist_size * sizeof(uint64_t));
		}
	}
	clock_gettime(CLOCK_MONOTONIC, &record.time_start);
}

void
cleanup_record(void)
{
	if (l2reflect_hist) {
		free(record.hist);
		record.hist = NULL;
		record.hist_size = 0;
	}
}

void
output_histogram_snapshot(void)
{
	char *json = serialize_histogram(&record);
	FILE *fd = stderr;
	if (hist_filename)
		fd = fopen(hist_filename, "w");
	fputs(json, fd);
	fputs("\n", fd);
	free(json);
	if (hist_filename)
		fclose(fd);
}

void
print_stats(void)
{
	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
	const uint64_t bytes_in_gib = 0x40000000;
	struct rte_eth_stats stats;
	char mac_str_me[RTE_ETHER_ADDR_FMT_SIZE];
	char mac_str_remote[RTE_ETHER_ADDR_FMT_SIZE];
	char timeout_bound_str[32];
	const char *str_jumbo = l2reflect_pkt_bytes > RTE_ETHER_MTU ?
		"jumbo" : "no-jumbo";
	struct timespec time_now;

	if (l2reflect_interrupt == 0)
		snprintf(timeout_bound_str, sizeof(timeout_bound_str), "     polling");
	else if (l2reflect_sleep_msec == -1u)
		snprintf(timeout_bound_str, sizeof(timeout_bound_str), ">=  infinite");
	else
		snprintf(timeout_bound_str, sizeof(timeout_bound_str), ">%9" PRIu64 "ms",
			l2reflect_sleep_msec);

	rte_eth_stats_get(l2reflect_port_number, &stats);
	rte_ether_format_addr(mac_str_me, sizeof(mac_str_me),
			      &l2reflect_port_eth_addr);
	rte_ether_format_addr(mac_str_remote, sizeof(mac_str_remote),
			      &l2reflect_remote_eth_addr);

	clock_gettime(CLOCK_MONOTONIC, &time_now);
	const uint64_t time_since_start = time_now.tv_sec - record.time_start.tv_sec;

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("%sNetworking Roundtrip Test%s\n", colors->green, colors->reset);
	printf("\n%sPort statistics ====================================%s",
	       colors->magenta, colors->reset);

	printf("\nMe: %s <--> Remote: %s", mac_str_me, mac_str_remote);
	printf("\nStatistics for port %d PID %d on lcore %d ---------"
			"\nState: %-16s %10" PRIu64 " s"
			"\nPackets tx: %22" PRIu64 "\nPackets rx: %22" PRIu64
			"\nBytes tx: %24" PRIu64 "    (%8.2f GiB)"
			"\nBytes rx: %24" PRIu64 "    (%8.2f GiB)"
			"\nErrors tx: %23" PRIu64 "\nErrors rx: %23" PRIu64
			"\nTimeouts rx: %21" PRIu64 "    (%s)"
			"\nPacketsize [Byte]: %15" PRIu64 "    (%12s)",
			l2reflect_port_number, getpid(), rte_lcore_id(),
			runstate_tostring(l2reflect_state),
			time_since_start,
			stats.opackets, stats.ipackets, stats.obytes,
			(double)stats.obytes / bytes_in_gib, stats.ibytes,
			(double)stats.ibytes / bytes_in_gib, stats.oerrors,
			stats.ierrors, record.timeouts,
			timeout_bound_str, l2reflect_pkt_bytes, str_jumbo);
	printf("\n%sPort timing statistics =============================%s",
	       colors->magenta, colors->reset);
	if (l2reflect_state == S_ELECT_LEADER ||
		record.min_round_ns == MIN_INITIAL) {
		printf("\n\nBenchmark not started yet...\n");
	} else {
		printf("\n%sMax%s roundtrip: %19" PRIu64 " us", colors->red,
		       colors->reset, record.max_round_ns / 1000);
		printf("\n%sAvg%s roundtrip: %19" PRIu64 " us", colors->yellow,
		       colors->reset,
		       record.rounds ? (uint64_t)(record.avg_round_ns /
						  record.rounds / 1000) :
				       0);
		printf("\n%sMin%s roundtrip: %19" PRIu64 " us", colors->green,
		       colors->reset, record.min_round_ns / 1000);
	}
	printf("\n%s====================================================%s\n",
	       colors->magenta, colors->reset);
}

void
l2reflect_stats_loop(void)
{
	while (!(l2reflect_state & (S_LOCAL_TERM | S_REMOTE_TERM))) {
		print_stats();
		if (l2reflect_hist && l2reflect_output_hist) {
			output_histogram_snapshot();
			l2reflect_output_hist = 0;
		}
		rte_delay_us_sleep(1000000);
	}
}

char *
serialize_histogram(__rte_unused const struct stats *record)
{
#ifndef RTE_HAS_JANSSON
	return strdup("to print histogram, build with jansson support");
#else
	char *str = NULL;
	char key[8];
	unsigned int i;
	json_t *hist0, *cpu0, *all_cpus, *output;

	output = json_object();
	/* version: 1 */
	json_object_set_new(output, "version", json_integer(1));

	/* cpu 0 histogram */
	hist0 = json_object();
	for (i = 0; i < record->hist_size; ++i) {
		/* only log positive numbers to meet jitterplot format */
		if (record->hist[i] != 0) {
			snprintf(key, 8, "%u", i * hist_bucket_usec);
			json_object_set(hist0, key,
					json_integer(record->hist[i]));
		}
	}

	/* in case of empty histogram, set these values to zero */
	const json_int_t min_round_us =
		record->rounds ? record->min_round_ns / 1000 : 0;
	const json_int_t avg_round_us =
		record->rounds ? record->avg_round_ns / record->rounds / 1000 : 0;
	const json_int_t max_round_us =
		record->rounds ? record->max_round_ns / 1000 : 0;

	/* cpu 0 stats */
	cpu0 = json_object();
	json_object_set_new(cpu0, "histogram", hist0);
	json_object_set_new(cpu0, "count", json_integer(record->rounds));
	json_object_set_new(cpu0, "min", json_integer(min_round_us));
	json_object_set_new(cpu0, "max", json_integer(max_round_us));
	json_object_set_new(cpu0, "avg", json_integer(avg_round_us));

	/* combine objects */
	all_cpus = json_object();
	json_object_set_new(all_cpus, "0", cpu0);
	json_object_set_new(output, "cpu", all_cpus);

	str = json_dumps(output, JSON_ENSURE_ASCII | JSON_INDENT(2));

	/* cleanup */
	json_decref(output);

	return str;
#endif
}

const char *
runstate_tostring(int s)
{
	switch (s) {
	case S_ELECT_LEADER:
		return "Electing";
	case S_RESET_TRX:
		return "Resetting";
	case S_RUNNING:
		return "Running";
	case S_LOCAL_TERM:
		return "Term. local";
	case S_REMOTE_TERM:
		return "Term. remote";
	default:
		return "Preparing";
	}
}
