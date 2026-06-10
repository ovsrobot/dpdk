/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Huawei Technologies Co., Ltd
 */

#include "test_rwlock_stress_impl.h"

/* RWLock operation implementations */
static void
rwlock_init_fn(struct rwlock_stress_lock *lock)
{
	rte_rwlock_init(&lock->lock.rwlock);
}

static void
rwlock_read_lock_fn(struct rwlock_stress_lock *lock)
{
	rte_rwlock_read_lock(&lock->lock.rwlock);
}

static void
rwlock_read_unlock_fn(struct rwlock_stress_lock *lock)
{
	rte_rwlock_read_unlock(&lock->lock.rwlock);
}

static void
rwlock_write_lock_fn(struct rwlock_stress_lock *lock)
{
	rte_rwlock_write_lock(&lock->lock.rwlock);
}

static void
rwlock_write_unlock_fn(struct rwlock_stress_lock *lock)
{
	rte_rwlock_write_unlock(&lock->lock.rwlock);
}

/* RWLock operations table */
static const struct rwlock_ops rwlock_ops = {
	.name = "rwlock",
	.init = rwlock_init_fn,
	.read_lock = rwlock_read_lock_fn,
	.read_unlock = rwlock_read_unlock_fn,
	.write_lock = rwlock_write_lock_fn,
	.write_unlock = rwlock_write_unlock_fn,
};

static int
run_rwlock_tests(void)
{
	int ret = 0;

	ret |= run_test_suite("RWLOCK Stress Tests", &rwlock_ops, tests,
			RTE_DIM(tests));

	return ret ? -1 : 0;
}

REGISTER_STRESS_TEST(rwlock_stress_autotest, run_rwlock_tests);
