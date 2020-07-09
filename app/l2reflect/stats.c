/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 *
 * authors:
 *   Felix Moessbauer <felix.moessbauer@siemens.com>
 *   Henning Schild <henning.schild@siemens.com>
 */
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#ifdef RTE_HAS_CJSON
#include <cjson/cJSON.h>
#endif
#include "stats.h"

#define ANSI_BOLD_RED "\x1b[01;31m"
#define ANSI_BOLD_GREEN "\x1b[01;32m"
#define ANSI_BOLD_YELLOW "\x1b[01;33m"
#define ANSI_BOLD_BLUE "\x1b[01;34m"
#define ANSI_BOLD_MAGENTA "\x1b[01;35m"
#define ANSI_BOLD_CYAN "\x1b[01;36m"
#define ANSI_RESET "\x1b[0m"

void
init_record(void)
{
	record.max_round = 0;
	record.min_round = MIN_INITIAL;
	record.rounds = 0;
	record.timeouts = 0;
	record.avg_round = 0;
	if (l2reflect_hist) {
		if (!record.hist_size) {
			record.hist =
				calloc(HIST_NUM_BUCKETS, sizeof(uint64_t));
			record.hist_size = HIST_NUM_BUCKETS;
		} else {
			memset(record.hist, 0,
			       record.hist_size * sizeof(uint64_t));
		}
	}
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
	FILE *fd = stdout;
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

	rte_eth_stats_get(l2reflect_port_number, &stats);

	/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf(ANSI_BOLD_GREEN "Networking Roundtrip Test\n"
			ANSI_RESET);
	printf(ANSI_BOLD_MAGENTA
			"\nPort statistics ===================================="
			ANSI_RESET);

	printf("\nMe: %02X:%02X:%02X:%02X:%02X:%02X <--> "
			"Remote: %02X:%02X:%02X:%02X:%02X:%02X",
			l2reflect_port_eth_addr.addr_bytes[0],
			l2reflect_port_eth_addr.addr_bytes[1],
			l2reflect_port_eth_addr.addr_bytes[2],
			l2reflect_port_eth_addr.addr_bytes[3],
			l2reflect_port_eth_addr.addr_bytes[4],
			l2reflect_port_eth_addr.addr_bytes[5],
			l2reflect_remote_eth_addr.addr_bytes[0],
			l2reflect_remote_eth_addr.addr_bytes[1],
			l2reflect_remote_eth_addr.addr_bytes[2],
			l2reflect_remote_eth_addr.addr_bytes[3],
			l2reflect_remote_eth_addr.addr_bytes[4],
			l2reflect_remote_eth_addr.addr_bytes[5]);
	printf("\nStatistics for port %d PID %d on lcore %d ---------"
			"\nPackets tx: %22" PRIu64 "\nPackets rx: %22" PRIu64
			"\nBytes tx: %24" PRIu64 "    (%8.2f GiB)"
			"\nBytes rx: %24" PRIu64 "    (%8.2f GiB)"
			"\nErrors tx: %23" PRIu64 "\nErrors rx: %23" PRIu64
			"\nTimeouts rx: %21" PRIu64 "    (>%9" PRIu64 "ms)",
			l2reflect_port_number, getpid(), rte_lcore_id(),
			stats.opackets, stats.ipackets, stats.obytes,
			(double)stats.obytes / bytes_in_gib, stats.ibytes,
			(double)stats.ibytes / bytes_in_gib, stats.oerrors,
			stats.ierrors, record.timeouts, l2reflect_sleep_msec);
	printf(ANSI_BOLD_MAGENTA
			"\nPort timing statistics ============================="
			ANSI_RESET);
	if (l2reflect_state == S_ELECT_LEADER ||
		record.min_round == MIN_INITIAL) {
		printf("\n\nBenchmark not started yet...\n");
	} else {
		printf("\n" ANSI_BOLD_RED "Max" ANSI_RESET
				" roundtrip: %19" PRIu64 " us",
				record.max_round / 1000);
		printf("\n" ANSI_BOLD_YELLOW "Avg" ANSI_RESET
				" roundtrip: %19" PRIu64 " us",
				record.rounds ? (uint64_t)(record.avg_round /
				record.rounds / 1000) :
				0);
		printf("\n" ANSI_BOLD_GREEN "Min" ANSI_RESET
				" roundtrip: %19" PRIu64 " us",
				record.min_round / 1000);
	}
	printf(ANSI_BOLD_MAGENTA
			"\n===================================================="
			ANSI_RESET "\n");
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
		sleep(1);
	}
}

char *
serialize_histogram(__rte_unused const struct stats *record)
{
#ifndef RTE_HAS_CJSON
	return strdup("to print histogram, build with cjson support");
#else
	char *str = NULL;
	char key[8];
	unsigned int i;
	cJSON *hist0, *cpu0, *all_cpus, *output;

	output = cJSON_CreateObject();
	/* version: 1 */
	cJSON_AddItemToObject(output, "version", cJSON_CreateNumber(1));

	/* cpu 0 histogram */
	hist0 = cJSON_CreateObject();
	for (i = 0; i < record->hist_size; ++i) {
		/* only log positive numbers to meet jitterplot format */
		if (record->hist[i] != 0) {
			snprintf(key, 8, "%u", i * hist_bucket_usec);
			cJSON_AddNumberToObject(hist0, key, record->hist[i]);
		}
	}

	/* cpu 0 stats */
	cpu0 = cJSON_CreateObject();
	cJSON_AddItemToObject(cpu0, "histogram", hist0);
	cJSON_AddItemToObject(cpu0, "count",
					cJSON_CreateNumber(record->rounds));
	cJSON_AddItemToObject(cpu0, "min",
					cJSON_CreateNumber(record->min_round));
	cJSON_AddItemToObject(cpu0, "max",
					cJSON_CreateNumber(record->max_round));
	cJSON_AddItemToObject(cpu0, "avg",
					cJSON_CreateNumber((record->avg_round /
						record->rounds / 1000)));

	/* combine objects */
	all_cpus = cJSON_CreateObject();
	cJSON_AddItemToObject(all_cpus, "0", cpu0);
	cJSON_AddItemToObject(output, "cpu", all_cpus);

	str = cJSON_Print(output);

	/* cleanup */
	cJSON_Delete(output);

	return str;
#endif
}
