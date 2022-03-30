/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Ericsson AB
 */

#include <rte_seqlock.h>

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_random.h>

#include <inttypes.h>

#include "test.h"

struct data {
	rte_seqlock_t lock;

	uint64_t a;
	uint64_t b __rte_cache_aligned;
	uint64_t c __rte_cache_aligned;
} __rte_cache_aligned;

struct reader {
	struct data *data;
	uint8_t stop;
};

#define WRITER_RUNTIME (2.0) /* s */

#define WRITER_MAX_DELAY (100) /* us */

#define INTERRUPTED_WRITER_FREQUENCY (1000)
#define WRITER_INTERRUPT_TIME (1) /* us */

static int
writer_start(void *arg)
{
	struct data *data = arg;
	uint64_t deadline;

	deadline = rte_get_timer_cycles() +
		WRITER_RUNTIME * rte_get_timer_hz();

	while (rte_get_timer_cycles() < deadline) {
		bool interrupted;
		uint64_t new_value;
		unsigned int delay;

		new_value = rte_rand();

		interrupted = rte_rand_max(INTERRUPTED_WRITER_FREQUENCY) == 0;

		rte_seqlock_write_begin(&data->lock);

		data->c = new_value;

		/* These compiler barriers (both on the test reader
		 * and the test writer side) are here to ensure that
		 * loads/stores *usually* happen in test program order
		 * (always on a TSO machine). They are arrange in such
		 * a way that the writer stores in a different order
		 * than the reader loads, to emulate an arbitrary
		 * order. A real application using a seqlock does not
		 * require any compiler barriers.
		 */
		rte_compiler_barrier();
		data->b = new_value;

		if (interrupted)
			rte_delay_us_block(WRITER_INTERRUPT_TIME);

		rte_compiler_barrier();
		data->a = new_value;

		rte_seqlock_write_end(&data->lock);

		delay = rte_rand_max(WRITER_MAX_DELAY);

		rte_delay_us_block(delay);
	}

	return 0;
}

#define INTERRUPTED_READER_FREQUENCY (1000)
#define READER_INTERRUPT_TIME (1000) /* us */

static int
reader_start(void *arg)
{
	struct reader *r = arg;
	int rc = 0;

	while (__atomic_load_n(&r->stop, __ATOMIC_RELAXED) == 0 && rc == 0) {
		struct data *data = r->data;
		bool interrupted;
		uint64_t a;
		uint64_t b;
		uint64_t c;
		uint32_t sn;

		interrupted = rte_rand_max(INTERRUPTED_READER_FREQUENCY) == 0;

		do {
			sn = rte_seqlock_read_begin(&data->lock);

			a = data->a;
			/* See writer_start() for an explanation why
			 * these barriers are here.
			 */
			rte_compiler_barrier();

			if (interrupted)
				rte_delay_us_block(READER_INTERRUPT_TIME);

			c = data->c;

			rte_compiler_barrier();
			b = data->b;

		} while (rte_seqlock_read_retry(&data->lock, sn));

		if (a != b || b != c) {
			printf("Reader observed inconsistent data values "
			       "%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
			       a, b, c);
			rc = -1;
		}
	}

	return rc;
}

static void
reader_stop(struct reader *reader)
{
	__atomic_store_n(&reader->stop, 1, __ATOMIC_RELAXED);
}

#define NUM_WRITERS (2)
#define MIN_NUM_READERS (2)
#define MAX_READERS (RTE_MAX_LCORE - NUM_WRITERS - 1)
#define MIN_LCORE_COUNT (NUM_WRITERS + MIN_NUM_READERS + 1)

/* Only a compile-time test */
static rte_seqlock_t __rte_unused static_init_lock = RTE_SEQLOCK_INITIALIZER;

static int
test_seqlock(void)
{
	struct reader readers[MAX_READERS];
	unsigned int num_readers;
	unsigned int num_lcores;
	unsigned int i;
	unsigned int lcore_id;
	unsigned int writer_lcore_ids[NUM_WRITERS] = { 0 };
	unsigned int reader_lcore_ids[MAX_READERS];
	int rc = 0;

	num_lcores = rte_lcore_count();

	if (num_lcores < MIN_LCORE_COUNT)
		return -1;

	num_readers = num_lcores - NUM_WRITERS - 1;

	struct data *data = rte_zmalloc(NULL, sizeof(struct data), 0);

	i = 0;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (i < NUM_WRITERS) {
			rte_eal_remote_launch(writer_start, data, lcore_id);
			writer_lcore_ids[i] = lcore_id;
		} else {
			unsigned int reader_idx = i - NUM_WRITERS;
			struct reader *reader = &readers[reader_idx];

			reader->data = data;
			reader->stop = 0;

			rte_eal_remote_launch(reader_start, reader, lcore_id);
			reader_lcore_ids[reader_idx] = lcore_id;
		}
		i++;
	}

	for (i = 0; i < NUM_WRITERS; i++)
		if (rte_eal_wait_lcore(writer_lcore_ids[i]) != 0)
			rc = -1;

	for (i = 0; i < num_readers; i++) {
		reader_stop(&readers[i]);
		if (rte_eal_wait_lcore(reader_lcore_ids[i]) != 0)
			rc = -1;
	}

	return rc;
}

REGISTER_TEST_COMMAND(seqlock_autotest, test_seqlock);
