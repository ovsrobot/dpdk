/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 */

#include "test_rwlock_stress_impl.h"

/* Pflock operation implementations */
static void
pflock_init_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_init(&lock->lock.pflock);
}

static void
pflock_read_lock_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_read_lock(&lock->lock.pflock);
}

static void
pflock_read_unlock_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_read_unlock(&lock->lock.pflock);
}

static void
pflock_write_lock_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_write_lock(&lock->lock.pflock);
}

static void
pflock_write_unlock_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_write_unlock(&lock->lock.pflock);
}

static void
pflock_write_downgrade_fn(struct rwlock_stress_lock *lock)
{
	rte_pflock_write_downgrade(&lock->lock.pflock);
}

/* Pflock operations table */
static const struct rwlock_ops pflock_ops = {
	.name = "pflock",
	.init = pflock_init_fn,
	.read_lock = pflock_read_lock_fn,
	.read_unlock = pflock_read_unlock_fn,
	.write_lock = pflock_write_lock_fn,
	.write_unlock = pflock_write_unlock_fn,
	.write_downgrade = pflock_write_downgrade_fn,
};

static const struct test_descriptor pflock_specific_tests[] = {
{
		.name = "write_downgrade",
		.num_readers_pct = 50,
		.reader_delay_us = 0,
		.writer_delay_us = 0,
		.flags = DOWNGRADE_TEST,
	},
};

static int
run_pflock_tests(void)
{
	int ret = 0;
	ret |= run_test_suite("PFLOCK Common Stress Tests", &pflock_ops,
			tests, RTE_DIM(tests));
	ret |= run_test_suite("PFLOCK Specific Stress Tests", &pflock_ops,
			pflock_specific_tests, RTE_DIM(pflock_specific_tests));
	return ret ? -1 : 0;
}

REGISTER_STRESS_TEST(pflock_stress_autotest, run_pflock_tests);
