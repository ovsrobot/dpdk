/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_SPINLOCK_LOONGARCH_H_
#define _RTE_SPINLOCK_LOONGARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include "generic/rte_spinlock.h"

#ifndef RTE_FORCE_INTRINSICS
/*
 * These implementations refer to GLIBC pthread_spin_xxlock().
 */
static inline void
rte_spinlock_lock(rte_spinlock_t *sl)
{
	int val = 0;

	if (rte_atomic32_exchange((volatile uint32_t *)&sl->locked, 1) == 0)
		return;

	do {
		do {
			val = sl->locked;
		} while (val != 0);

	} while (rte_atomic32_exchange((volatile uint32_t *)&sl->locked, 1) == 1);
}

static inline void
rte_spinlock_unlock(rte_spinlock_t *sl)
{
	sl->locked = 0;
}

static inline int
rte_spinlock_trylock(rte_spinlock_t *sl)
{
	return rte_atomic32_exchange((volatile uint32_t *)&sl->locked, 1) == 0;
}
#endif

static inline int rte_tm_supported(void)
{
	return 0;
}

static inline void
rte_spinlock_lock_tm(rte_spinlock_t *sl)
{
	rte_spinlock_lock(sl); /* fall-back */
}

static inline int
rte_spinlock_trylock_tm(rte_spinlock_t *sl)
{
	return rte_spinlock_trylock(sl);
}

static inline void
rte_spinlock_unlock_tm(rte_spinlock_t *sl)
{
	rte_spinlock_unlock(sl);
}

static inline void
rte_spinlock_recursive_lock_tm(rte_spinlock_recursive_t *slr)
{
	rte_spinlock_recursive_lock(slr); /* fall-back */
}

static inline void
rte_spinlock_recursive_unlock_tm(rte_spinlock_recursive_t *slr)
{
	rte_spinlock_recursive_unlock(slr);
}

static inline int
rte_spinlock_recursive_trylock_tm(rte_spinlock_recursive_t *slr)
{
	return rte_spinlock_recursive_trylock(slr);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_SPINLOCK_LOONGARCH_H_ */
