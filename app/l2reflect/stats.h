/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 *
 * authors:
 *   Felix Moessbauer <felix.moessbauer@siemens.com>
 *   Henning Schild <henning.schild@siemens.com>
 */
#ifndef _STATS_H_
#define _STATS_H_
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>

#include <rte_ethdev.h>

#include "l2reflect.h"

#define MIN_INITIAL ULONG_MAX
#define HIST_NUM_BUCKETS 128
#define HIST_CAP_BUCKET (HIST_NUM_BUCKETS - 1)

/* runtime statistics */
struct stats {
	uint64_t max_round;
	uint64_t min_round;
	uint64_t rounds;
	uint64_t timeouts;
	double avg_round;
	unsigned int hist_size;
	/* each slot is 10us */
	uint64_t *hist;
};

/* size of each histogram bucket in usec */
extern unsigned int hist_bucket_usec;
extern struct stats record;
extern char *hist_filename;

void
init_record(void);
void
cleanup_record(void);

void
l2reflect_stats_loop(void);

/*
 * Write the histogram to file / stdio without any locking.
 * When called during the measurement, values are approximations
 * (racy reads).
 */
void
output_histogram_snapshot(void);

/* Print out statistics on packets dropped */
void
print_stats(void);

/*
 * get a JSON representation of the record
 */
char *
serialize_histogram(const struct stats *record);

#endif /* _STATS_H_ */
