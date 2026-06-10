/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 */

#ifndef _TEST_RWLOCK_STRESS_H_
#define _TEST_RWLOCK_STRESS_H_

/**
 * Generic reader-writer lock stress test.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdbool.h>

#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_per_lcore.h>
#include <rte_malloc.h>
#include <rte_pflock.h>
#include <rte_random.h>
#include <rte_rwlock.h>

#include "test.h"

#define TEST_DURATION_SEC 5
#define COUNTER_ARRAY_SIZE 1024
#define DOWNGRADE_TEST 0x1   /* Will attempt to downgrade from write to read lock */
#define DYNAMIC_ROLES  0x2  /* Threads can switch between reader/writer roles */

struct rwlock_stress_lock;

/**
 * Lock operations interface.
 */
struct rwlock_ops {
	const char *name;

	void (*init)(struct rwlock_stress_lock *lock);
	void (*read_lock)(struct rwlock_stress_lock *lock);
	void (*read_unlock)(struct rwlock_stress_lock *lock);
	void (*write_lock)(struct rwlock_stress_lock *lock);
	void (*write_unlock)(struct rwlock_stress_lock *lock);
	void (*write_downgrade)(struct rwlock_stress_lock *lock);
};

/**
 * Generic lock structure.
 */
struct rwlock_stress_lock {
	const struct rwlock_ops *ops;

	union {
		struct rte_pflock pflock;
		rte_rwlock_t rwlock;
	} lock;
};

/**
 * Per-lcore statistics
 */
struct lcore_stats {
	uint64_t reader_ops;
	uint64_t writer_ops;
	uint64_t local_counter;
	uint64_t reader_errors;
	uint64_t writer_errors;
	uint64_t acquire_time;
} __rte_cache_aligned;

/**
 * Test controls
 */
struct test_descriptor {
	const char *name;
	uint32_t num_readers_pct;  /* Percentage of workers as readers (0-100) */
	uint32_t reader_delay_us;  /* Microseconds to delay in reader */
	uint32_t writer_delay_us;  /* Microseconds to delay in writer */
	uint32_t flags;           /* Specialist test behaviour */
};

/**
 * Shared test state.
 */
struct rwlock_test_shared {
	struct rwlock_stress_lock lock;
	volatile uint64_t counter;
	volatile uint64_t counter_array[COUNTER_ARRAY_SIZE];
	volatile bool stop;
	uint32_t num_readers;
	uint32_t num_writers;
	const struct test_descriptor *test;
	struct lcore_stats stats[RTE_MAX_LCORE];
} __rte_cache_aligned;

/* Test descriptors array */
static const struct test_descriptor tests[] = {
	{
		.name = "basic_reader_writer",
		.num_readers_pct = 75,
		.reader_delay_us = 0,
		.writer_delay_us = 0,
	},
	{
		.name = "long_hold",
		.num_readers_pct = 67,
		.reader_delay_us = 100,
		.writer_delay_us = 100,
	},
	{
		.name = "rapid_acquire_release",
		.num_readers_pct = 67,
		.reader_delay_us = 0,
		.writer_delay_us = 0,
	},
	{
		.name = "dynamic_roles",
		.num_readers_pct = 75,
		.reader_delay_us = 0,
		.writer_delay_us = 0,
		.flags = DYNAMIC_ROLES,
	},
};

static inline bool
should_be_writer(uint32_t num_readers, uint32_t flags)
{
	uint32_t total_lcores = rte_lcore_count();
	if (total_lcores <= 1)
		return true;

	if (flags & DYNAMIC_ROLES) {
		uint32_t readers_pct = (num_readers * 100) / (total_lcores - 1);
		return (rte_rand_max(100) >= readers_pct);
	}

	unsigned int idx = rte_lcore_index(rte_lcore_id()) - 1;
	return idx >= num_readers;
}

static void
handle_error(struct rwlock_test_shared *s, unsigned int lcore_id,
		bool write_lock, const char *func, int line)
{
	s->stop = true;
	if (write_lock) {
		s->stats[lcore_id].writer_errors++;
		s->lock.ops->write_unlock(&s->lock);
	} else {
		s->stats[lcore_id].reader_errors++;
		/* Don't unlock here as it's already unlocked by the calling function */
	}
	printf("ERROR: lcore:%u: %s:%d early termination\n", lcore_id, func, line);
}

static int
handle_writer_work(struct rwlock_test_shared *s, unsigned int lcore_id,
		const struct test_descriptor *test, uint64_t delta)
{
	s->lock.ops->write_lock(&s->lock);
	uint64_t old_val = s->counter;
	s->counter += delta;
	s->stats[lcore_id].local_counter += delta;

	/* Verify increment was atomic */
	if (s->counter != old_val + delta) {
		handle_error(s, lcore_id, true, __func__, __LINE__);
		return -1;
	}

	/* Update all array elements */
	for (uint32_t i = 0; i < COUNTER_ARRAY_SIZE; i++) {
		s->counter_array[i] += delta;
		if (s->counter_array[i] != s->counter) {
			handle_error(s, lcore_id, true, __func__, __LINE__);
			return -1;
		}
	}

	if (test->flags & DOWNGRADE_TEST) {
		/* Downgrade to read lock */
		if (s->lock.ops->write_downgrade) {
			s->lock.ops->write_downgrade(&s->lock);
			/* Verify array consistency under read lock */
			for (uint32_t i = 0; i < COUNTER_ARRAY_SIZE; i++) {
				if (s->counter_array[i] != s->counter) {
					handle_error(s, lcore_id, false, __func__, __LINE__);
					return -1;
				}
			}
			s->lock.ops->read_unlock(&s->lock);
		}
	} else {
		if (test->writer_delay_us > 0)
			rte_delay_us_sleep(test->writer_delay_us);
		s->lock.ops->write_unlock(&s->lock);
	}
	s->stats[lcore_id].writer_ops++;
	return 0;
}

static int
handle_reader_work(struct rwlock_test_shared *s, unsigned int lcore_id,
		const struct test_descriptor *test)
{
	uint64_t local_counter;

	s->lock.ops->read_lock(&s->lock);
	local_counter = s->counter;

	/* Verify array consistency */
	for (uint32_t i = 0; i < COUNTER_ARRAY_SIZE; i++) {
		if (s->counter_array[i] != local_counter) {
			handle_error(s, lcore_id, false, __func__, __LINE__);
			return -1;
		}
	}

	if (test->reader_delay_us > 0)
		rte_delay_us_sleep(test->reader_delay_us);

	/* Verify counter didn't change during read */
	if (s->counter != local_counter) {
		handle_error(s, lcore_id, false, __func__, __LINE__);
		return -1;
	}

	s->lock.ops->read_unlock(&s->lock);
	s->stats[lcore_id].reader_ops++;
	return 0;
}

static int
lcore_function(void *arg)
{
	struct rwlock_test_shared *s = arg;
	unsigned int lcore_id = rte_lcore_id();
	bool is_writer = should_be_writer(s->num_readers, s->test->flags);
	const struct test_descriptor *test = s->test;

	while (!s->stop) {
		uint64_t start = rte_get_timer_cycles();
		uint64_t delta = (rte_rand() % 64) + 1;
		int ret;

		if (is_writer)
			ret = handle_writer_work(s, lcore_id, test, delta);
		else
			ret = handle_reader_work(s, lcore_id, test);

		if (ret < 0)
			continue;

		/* Record max acquire time */
		uint64_t wait_time = rte_get_timer_cycles() - start;
		if (wait_time > s->stats[lcore_id].acquire_time)
			s->stats[lcore_id].acquire_time = wait_time;
	}

	return 0;
}

static int
verify(struct rwlock_test_shared *s)
{
	int ret = 0;
	unsigned int lcore_id;
	uint64_t total_reader_errors = 0;
	uint64_t total_writer_errors = 0;
	uint64_t sum_local_counters = 0;

	/* Calculate errors and counters */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		total_reader_errors += s->stats[lcore_id].reader_errors;
		total_writer_errors += s->stats[lcore_id].writer_errors;
		sum_local_counters += s->stats[lcore_id].local_counter;
	}

	/* Verify sum of per-lcore counters matches the shared counter */
	if (s->counter != sum_local_counters) {
		printf("  FAILED: shared counter=%" PRIu64
		       " sum of local counters=%" PRIu64 "\n",
		       s->counter, sum_local_counters);
		ret = -1;
	}

	if (total_reader_errors) {
		printf("  FAILED: reader errors=%" PRIu64 "\n",
		       total_reader_errors);
		ret = -1;
	}

	if (total_writer_errors) {
		printf("  FAILED: writer errors =%" PRIu64 "\n",
		       total_writer_errors);
		ret = -1;
	}

	/* Verify array consistency */
	for (uint32_t i = 0; i < COUNTER_ARRAY_SIZE; i++) {
		if (s->counter_array[i] != s->counter) {
			printf("  FAILED: counter_array[%u]=%" PRIu64 " counter=%" PRIu64 "\n",
			       i, s->counter_array[i], s->counter);
			ret = -1;
			break;
		}
	}

	return ret;
}

static int
test_rwlock_stress_impl(const struct rwlock_ops *ops,
		const struct test_descriptor *ind_test)
{
	struct rwlock_test_shared shared = {0};
	uint64_t start_time, end_time;
	uint64_t total_reader_ops = 0;
	uint64_t total_writer_ops = 0;
	uint64_t max_acquire_time = 0;
	unsigned int lcore_id;
	int ret = 0;

	shared.lock.ops = ops;
	shared.lock.ops->init(&shared.lock);
	shared.test = ind_test;
	shared.num_readers = (ind_test->num_readers_pct * (rte_lcore_count() - 1)) / 100;
	shared.num_writers = (rte_lcore_count() - 1) - shared.num_readers;

	printf("  %u readers, %u writers\n", shared.num_readers, shared.num_writers);

	/* Launch workers */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_remote_launch(lcore_function, &shared, lcore_id);
	}

	/* Run test for duration */
	start_time = rte_get_timer_cycles();
	rte_delay_ms(TEST_DURATION_SEC * 1000);

	/* Stop workers and collect stats */
	shared.stop = true;
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		rte_eal_wait_lcore(lcore_id);
		if (shared.stats[lcore_id].acquire_time > max_acquire_time)
			max_acquire_time = shared.stats[lcore_id].acquire_time;
		total_reader_ops += shared.stats[lcore_id].reader_ops;
		total_writer_ops += shared.stats[lcore_id].writer_ops;
	}
	end_time = rte_get_timer_cycles();

	printf("  %"PRIu64" reader ops, %"PRIu64" writer ops,"
	      "total time: %.2f seconds\n",
	       total_reader_ops, total_writer_ops,
	       (double)(end_time - start_time) / rte_get_timer_hz());

	ret = verify(&shared);
	if (ret == 0) {
		uint64_t hz = rte_get_timer_hz();
		printf("  PASSED: All checks passed (max wait: %.2f us)\n",
		       (double)max_acquire_time * 1000000 / hz);
	}
	return ret;
}

/**
 * Run a test suite with the given title and tests
 */
static int
run_test_suite(const char *title, const struct rwlock_ops *ops,
		const struct test_descriptor suite[], uint32_t count)
{
	uint32_t failed = 0;

	printf("%s\n===================\n\n", title);
	for (uint32_t i = 0; i < count; i++) {
		printf("Test %u/%u: %s\n", i + 1, count, suite[i].name);
		if (test_rwlock_stress_impl(ops, &suite[i]) < 0)
			failed++;
		printf("\n");
	}
	printf("===================\n");
	printf("Results: %u/%u passed, %u failed\n", count - failed, count, failed);

	return failed ? -1 : 0;
}

#endif /* _TEST_RWLOCK_STRESS_H_ */
