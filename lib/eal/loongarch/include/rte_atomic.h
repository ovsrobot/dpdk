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

#define rte_io_mb() rte_mb()

#define rte_cio_wmb() rte_wmb()

#define rte_cio_rmb() rte_rmb()

#define smp_mb__before_llsc()

#define smp_llsc_mb()

static __rte_always_inline void
rte_atomic_thread_fence(int memorder)
{
	__atomic_thread_fence(memorder);
}

/*
 * Helper Functions
 */
#define ATOMIC32_OP(op, I, asm_op)                                    \
static inline void la_atomic32_##op(rte_atomic32_t *v, int32_t i) \
{                                                                     \
	__asm__ __volatile__(                                         \
		"am"#asm_op"_db.w $zero, %[i], %[cnt]\n"     \
		: [cnt] "+ZB" (v->cnt)                                 \
		: [i] "r" (I)                                          \
		: "memory"                                            \
		);                                                    \
}

#define ATOMIC32_OP_RETURN(op, I, asm_op)                                             \
static inline int32_t la_atomic32_##op##_and_return(rte_atomic32_t *v, int32_t i) \
{                                                                                     \
	int32_t result;                                                               \
									\
	__asm__ __volatile__(                                                         \
		"am"#asm_op"_db.w %1, %2, %0\n"                               \
		: "+ZB" (v->cnt), "=&r" (result)                                      \
		: "r" (I)                                                             \
		: "memory"                                                            \
		);                                                                    \
									\
	return result + I;                                               \
}
ATOMIC32_OP(add, i, add)
ATOMIC32_OP(sub, -i, add)
ATOMIC32_OP_RETURN(add, i, add)
ATOMIC32_OP_RETURN(sub, -i, add)

#define ATOMIC64_OP(op, I, asm_op)                                    \
static inline void la_atomic64_##op(rte_atomic64_t *v, int64_t i) \
{                                                                     \
	__asm__ __volatile__(                                         \
		"am"#asm_op"_db.d $zero, %[i], %[cnt]\n"     \
		: [cnt] "+ZB" (v->cnt)                                 \
		: [i] "r" (I)                                          \
		: "memory"                                            \
		);                                                    \
}
#define ATOMIC64_OP_RETURN(op, I, asm_op)                                             \
static inline int64_t la_atomic64_##op##_and_return(rte_atomic64_t *v, int64_t i) \
{                                                                                     \
	int64_t result;                                                               \
									\
	__asm__ __volatile__(                                                         \
		"am"#asm_op"_db.d %1, %2, %0\n"                               \
		: "+ZB" (v->cnt), "=&r" (result)                                      \
		: "r" (I)                                                             \
		: "memory"	                                                      \
		);                                                                    \
									\
	return result + I;                                      \
}
ATOMIC64_OP(add, i, add)
ATOMIC64_OP(sub, -i, add)
ATOMIC64_OP_RETURN(add, i, add)
ATOMIC64_OP_RETURN(sub, -i, add)

static inline int
loongarch_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	uint32_t res = 0, temp = 0;
	__asm__ __volatile__(
		"1: ll.w %[tmp], %[dst]\n"
		"   li.w %[res], 0\n"
		"   bne %[tmp], %[exp], 2f\n"
		"   move %[tmp], %[src]\n"
		"   sc.w %[tmp], %[dst]\n"
		"   li.w %[res], 1\n"
		"   beqz %[tmp], 1b\n"
		"2:\n"
		: [res] "=&r"(res),
		  [tmp] "+&r"(temp),
		  [dst] "+m"(*dst)
		: [src] "r"(src),
		  [exp] "r"(exp),
		  "m"(*dst)
		: "memory"
		);

	return res;
}

static inline int
loongarch_atomic64_cmpset(volatile uint64_t *dst, uint64_t exp, uint64_t src)
{
	uint32_t res = 0;
	uint64_t temp = 0;
	__asm__ __volatile__(
		"1: ll.d %[tmp], %[dst]\n"
		"   li.d %[res], 0\n"
		"   bne %[tmp], %[exp], 2f\n"
		"   move %[tmp], %[src]\n"
		"   sc.d %[tmp], %[dst]\n"
		"   li.d %[res], 1\n"
		"   beqz %[tmp], 1b\n"
		"2:\n"
		: [res] "=&r"(res),
		  [tmp] "+&r"(temp),
		  [dst] "+m"(*dst)
		: [src] "r"(src),
		  [exp] "r"(exp),
		  "m"(*dst)
		: "memory"
		);

	return res;
}

#ifndef RTE_FORCE_INTRINSICS
static inline int
rte_atomic16_cmpset(volatile uint16_t *dst, uint16_t exp, uint16_t src)
{
	return __sync_bool_compare_and_swap(dst, exp, src);
}

static inline int rte_atomic16_test_and_set(rte_atomic16_t *v)
{
	return rte_atomic16_cmpset((volatile uint16_t *)&v->cnt, 0, 1);
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

static inline uint16_t
rte_atomic16_exchange(volatile uint16_t *dst, uint16_t val)
{
	return __atomic_exchange_2(dst, val, __ATOMIC_SEQ_CST);
}

/*------------------------- 32 bit atomic operations -------------------------*/

static inline int
rte_atomic32_cmpset(volatile uint32_t *dst, uint32_t exp, uint32_t src)
{
	return loongarch_atomic32_cmpset(dst, exp, src);
}

static inline int rte_atomic32_test_and_set(rte_atomic32_t *v)
{
	return rte_atomic32_cmpset((volatile uint32_t *)&v->cnt, 0, 1);
}

static inline void
rte_atomic32_inc(rte_atomic32_t *v)
{
	la_atomic32_add(v, 1);
}

static inline void
rte_atomic32_dec(rte_atomic32_t *v)
{
	la_atomic32_sub(v, 1);
}

static inline int rte_atomic32_inc_and_test(rte_atomic32_t *v)
{
	return la_atomic32_add_and_return(v, 1) == 0;
}

static inline int rte_atomic32_dec_and_test(rte_atomic32_t *v)
{
	return la_atomic32_sub_and_return(v, 1) == 0;
}

static inline uint32_t
rte_atomic32_exchange(volatile uint32_t *dst, uint32_t val)
{
	uint32_t retval;

	__asm__ __volatile__ (
		"amswap_db.w %1, %z2, %0\n"
		: "+ZB" (*dst), "=&r" (retval)
		: "Jr" (val)
		: "memory"
		);

	return retval;

}
/*------------------------- 64 bit atomic operations -------------------------*/
static inline int
rte_atomic64_cmpset(volatile uint64_t *dst, uint64_t exp, uint64_t src)
{
	return loongarch_atomic64_cmpset(dst, exp, src);
}

static inline void
rte_atomic64_init(rte_atomic64_t *v)
{
	__asm__ __volatile__(
		"amand_db.d $zero, $zero, %[rj]\n"
		: [rj]"+ZB"(v->cnt)
		);
}

static inline int64_t
rte_atomic64_read(rte_atomic64_t *v)
{
	int64_t res = 0;

	__asm__ __volatile__(
		"amadd_db.d %[res], $zero, %[cnt]\n"
		: [res]"=&r"(res), [cnt]"+ZB"(v->cnt)
		:
		);
	return res;

}

static inline void
rte_atomic64_set(rte_atomic64_t *v, int64_t new_value)
{
	__asm__ __volatile__(
		"amswap_db.d $zero, %[nv], %[cnt]\n"
		: [cnt]"+ZB"(v->cnt)
		: [nv]"r"(new_value)
		);
}

static inline void
rte_atomic64_add(rte_atomic64_t *v, int64_t inc)
{
	la_atomic64_add(v, inc);
}

static inline void
rte_atomic64_sub(rte_atomic64_t *v, int64_t dec)
{
	la_atomic64_sub(v, dec);
}

static inline void
rte_atomic64_inc(rte_atomic64_t *v)
{
	la_atomic64_add(v, 1);
}

static inline void
rte_atomic64_dec(rte_atomic64_t *v)
{
	la_atomic64_sub(v, 1);
}

static inline int64_t
rte_atomic64_add_return(rte_atomic64_t *v, int64_t inc)
{
	return la_atomic64_add_and_return(v, inc);
}

static inline int64_t
rte_atomic64_sub_return(rte_atomic64_t *v, int64_t dec)
{
	return la_atomic64_sub_and_return(v, dec);
}

static inline int rte_atomic64_inc_and_test(rte_atomic64_t *v)
{
	return la_atomic64_add_and_return(v, 1) == 0;
}

static inline int rte_atomic64_dec_and_test(rte_atomic64_t *v)
{
	return la_atomic64_sub_and_return(v, 1) == 0;
}

static inline int rte_atomic64_test_and_set(rte_atomic64_t *v)
{
	return rte_atomic64_cmpset((volatile uint64_t *)&v->cnt, 0, 1);
}

static inline void rte_atomic64_clear(rte_atomic64_t *v)
{
	rte_atomic64_set(v, 0);
}

static inline uint64_t __xchg_u64(volatile uint64_t *m, uint64_t val)
{
	uint64_t retval;
	__asm__ __volatile__ (
		"amswap_db.d %1, %z2, %0\n"
		: "+ZB" (*m), "=&r" (retval)
		: "Jr" (val)
		: "memory"
		);

	return retval;
}

static inline uint64_t
rte_atomic64_exchange(volatile uint64_t *dst, uint64_t val)
{
	return __xchg_u64(dst, val);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ATOMIC_LOONGARCH_H_ */
