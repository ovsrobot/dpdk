/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_ATOMIC_LOONGARCH_H_
#define _RTE_ATOMIC_LOONGARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "generic/rte_atomic.h"

/**
 * LoongArch Synchronize
 */
static inline void synchronize(void)
{
	__asm__ __volatile__("dbar 0":::"memory");
}

/**
 * General memory barrier.
 *
 * Guarantees that the LOAD and STORE operations generated before the
 * barrier occur before the LOAD and STORE operations generated after.
 * This function is architecture dependent.
 */
#define rte_mb() synchronize()

/**
 * Write memory barrier.
 *
 * Guarantees that the STORE operations generated before the barrier
 * occur before the STORE operations generated after.
 * This function is architecture dependent.
 */
#define rte_wmb() synchronize()

/**
 * Read memory barrier.
 *
 * Guarantees that the LOAD operations generated before the barrier
 * occur before the LOAD operations generated after.
 * This function is architecture dependent.
 */
#define rte_rmb() synchronize()

#define rte_smp_mb() rte_mb()

#define rte_smp_wmb() rte_mb()

#define rte_smp_rmb() rte_mb()

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_mb()

#define rte_io_rmb() rte_mb()

static __rte_always_inline void
rte_atomic_thread_fence(int memorder)
{
	__atomic_thread_fence(memorder);
}

#ifndef RTE_FORCE_INTRINSICS
/*------------------------- 16 bit atomic operations -------------------------*/
static inline int
rte_atomic16_cmpset(volatile uint16_t *dst, uint16_t exp, uint16_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline uint16_t
rte_atomic16_exchange(volatile uint16_t *dst, uint16_t val)
{
#if defined(__clang__)
	return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
	return __atomic_exchange_2(dst, val, __ATOMIC_SEQ_CST);
#endif
}

static inline void
rte_atomic16_inc(rte_atomic16_t *v)
{
	rte_atomic16_add(v, 1);
}

static inline void
rte_atomic16_dec(rte_atomic16_t *v)
{
	rte_atomic16_sub(v, 1);
}

static inline int rte_atomic16_inc_and_test(rte_atomic16_t *v)
{
	return __sync_add_and_fetch(&v->cnt, 1) == 0;
}

static inline int rte_atomic16_dec_and_test(rte_atomic16_t *v)
{
	return __sync_sub_and_fetch(&v->cnt, 1) == 0;
}

static inline int rte_atomic16_test_and_set(rte_atomic16_t *v)
{
	return rte_atomic16_cmpset((volatile uint16_t *)&v->cnt, 0, 1);
}

/*------------------------- 32 bit atomic operations -------------------------*/
static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline uint32_t
rte_atomic32_exchange(volatile uint32_t *dst, uint32_t val)
{
#if defined(__clang__)
	return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
	return __atomic_exchange_4(dst, val, __ATOMIC_SEQ_CST);
#endif
}

static inline void
rte_atomic32_inc(rte_atomic32_t *v)
{
	rte_atomic32_add(v, 1);
}

static inline void
rte_atomic32_dec(rte_atomic32_t *v)
{
	rte_atomic32_sub(v, 1);
}

static inline int rte_atomic32_inc_and_test(rte_atomic32_t *v)
{
	return __sync_add_and_fetch(&v->cnt, 1) == 0;
}

static inline int rte_atomic32_dec_and_test(rte_atomic32_t *v)
{
	return __sync_sub_and_fetch(&v->cnt, 1) == 0;
}

static inline int rte_atomic32_test_and_set(rte_atomic32_t *v)
{
	return rte_atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

/*------------------------- 64 bit atomic operations -------------------------*/
static inline int
rte_atomic64_cmpset(volatile uint64_t *dst, uint64_t exp, uint64_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline uint64_t
rte_atomic64_exchange(volatile uint64_t *dst, uint64_t val)
{
#if defined(__clang__)
	return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
	return __atomic_exchange_8(dst, val, __ATOMIC_SEQ_CST);
#endif
}

static inline void
rte_atomic64_init(rte_atomic64_t *v)
{
	v->cnt = 0;
}

static inline int64_t
rte_atomic64_read(rte_atomic64_t *v)
{
	return v->cnt;
}

static inline void
rte_atomic64_set(rte_atomic64_t *v, int64_t new_value)
{
	v->cnt = new_value;
}

static inline void
rte_atomic64_add(rte_atomic64_t *v, int64_t inc)
{
	__sync_fetch_and_add(&v->cnt, inc);
}

static inline void
rte_atomic64_sub(rte_atomic64_t *v, int64_t dec)
{
	__sync_fetch_and_sub(&v->cnt, dec);
}

static inline void
rte_atomic64_inc(rte_atomic64_t *v)
{
	rte_atomic64_add(v, 1);
}

static inline void
rte_atomic64_dec(rte_atomic64_t *v)
{
	rte_atomic64_sub(v, 1);
}

static inline int64_t
rte_atomic64_add_return(rte_atomic64_t *v, int64_t inc)
{
	return __sync_add_and_fetch(&v->cnt, inc);
}

static inline int64_t
rte_atomic64_sub_return(rte_atomic64_t *v, int64_t dec)
{
	return __sync_sub_and_fetch(&v->cnt, dec);
}

static inline int rte_atomic64_inc_and_test(rte_atomic64_t *v)
{
	return rte_atomic64_add_return(v, 1) == 0;
}

static inline int rte_atomic64_dec_and_test(rte_atomic64_t *v)
{
	return rte_atomic64_sub_return(v, 1) == 0;
}

static inline int rte_atomic64_test_and_set(rte_atomic64_t *v)
{
	return rte_atomic64_cmpset((volatile uint64_t *)&v->cnt, 0, 1);
}

static inline void rte_atomic64_clear(rte_atomic64_t *v)
{
	rte_atomic64_set(v, 0);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ATOMIC_LOONGARCH_H_ */
