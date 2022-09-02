/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Siemens AG
 */
#ifndef _L2REFLECT_STATS_H_
#define _L2REFLECT_STATS_H_
#include <stdint.h>
#include <stdatomic.h>
#include <limits.h>

#include <rte_ethdev.h>

#include "l2reflect.h"

#define MIN_INITIAL ULONG_MAX
#define HIST_NUM_BUCKETS_DEFAULT 128

/* runtime statistics */
struct stats {
	uint64_t max_round_ns;
	uint64_t min_round_ns;
	uint64_t rounds;
	uint64_t timeouts;
	double avg_round_ns;
	unsigned int hist_size;
	/* each slot is 10us */
	uint64_t *hist;
	struct timespec time_start;
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

/*
 * get a string representation of the current runstate
 */
const char *
runstate_tostring(int s);

#endif /* _L2REFLECT_STATS_H_ */
