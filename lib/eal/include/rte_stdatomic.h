/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Microsoft Corporation
 */

#ifndef _RTE_STDATOMIC_H_
#define _RTE_STDATOMIC_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef int rte_memory_order;

#ifdef RTE_ENABLE_STDATOMIC
#ifdef __STDC_NO_ATOMICS__
#error enable_stdatomics=true but atomics not supported by toolchain
#endif

#include <stdatomic.h>

#define __rte_atomic _Atomic

#define rte_memory_order_relaxed memory_order_relaxed
#ifdef __ATOMIC_RELAXED
_Static_assert(rte_memory_order_relaxed == __ATOMIC_RELAXED,
	"rte_memory_order_relaxed == __ATOMIC_RELAXED");
#endif

#define rte_memory_order_consume memory_order_consume
#ifdef __ATOMIC_CONSUME
_Static_assert(rte_memory_order_consume == __ATOMIC_CONSUME,
	"rte_memory_order_consume == __ATOMIC_CONSUME");
#endif

#define rte_memory_order_acquire memory_order_acquire
#ifdef __ATOMIC_ACQUIRE
_Static_assert(rte_memory_order_acquire == __ATOMIC_ACQUIRE,
	"rte_memory_order_acquire == __ATOMIC_ACQUIRE");
#endif

#define rte_memory_order_release memory_order_release
#ifdef __ATOMIC_RELEASE
_Static_assert(rte_memory_order_release == __ATOMIC_RELEASE,
	"rte_memory_order_release == __ATOMIC_RELEASE");
#endif

#define rte_memory_order_acq_rel memory_order_acq_rel
#ifdef __ATOMIC_ACQ_REL
_Static_assert(rte_memory_order_acq_rel == __ATOMIC_ACQ_REL,
	"rte_memory_order_acq_rel == __ATOMIC_ACQ_REL");
#endif

#define rte_memory_order_seq_cst memory_order_seq_cst
#ifdef __ATOMIC_SEQ_CST
_Static_assert(rte_memory_order_seq_cst == __ATOMIC_SEQ_CST,
	"rte_memory_order_seq_cst == __ATOMIC_SEQ_CST");
#endif

#define rte_atomic_load_explicit(ptr, memorder) \
	atomic_load_explicit(ptr, memorder)

#define rte_atomic_store_explicit(ptr, val, memorder) \
	atomic_store_explicit(ptr, val, memorder)

#define rte_atomic_exchange_explicit(ptr, val, memorder) \
	atomic_exchange_explicit(ptr, val, memorder)

#define rte_atomic_compare_exchange_strong_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder) \
	atomic_compare_exchange_strong_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder)

#define rte_atomic_compare_exchange_weak_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder) \
	atomic_compare_exchange_strong_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder)

#define rte_atomic_fetch_add_explicit(ptr, val, memorder) \
	atomic_fetch_add_explicit(ptr, val, memorder)

#define rte_atomic_fetch_sub_explicit(ptr, val, memorder) \
	atomic_fetch_sub_explicit(ptr, val, memorder)

#define rte_atomic_fetch_and_explicit(ptr, val, memorder) \
	atomic_fetch_and_explicit(ptr, val, memorder)

#define rte_atomic_fetch_xor_explicit(ptr, val, memorder) \
	atomic_fetch_xor_explicit(ptr, val, memorder)

#define rte_atomic_fetch_or_explicit(ptr, val, memorder) \
	atomic_fetch_or_explicit(ptr, val, memorder)

#define rte_atomic_fetch_nand_explicit(ptr, val, memorder) \
	atomic_fetch_nand_explicit(ptr, val, memorder)

#define rte_atomic_flag_test_and_set_explict(ptr, memorder) \
	atomic_flag_test_and_set_explicit(ptr, memorder)

#define rte_atomic_flag_clear_explicit(ptr, memorder) \
	atomic_flag_clear(ptr, memorder)

#else

#define __rte_atomic

#define rte_memory_order_relaxed __ATOMIC_RELAXED
#define rte_memory_order_consume __ATOMIC_CONSUME
#define rte_memory_order_acquire __ATOMIC_ACQUIRE
#define rte_memory_order_release __ATOMIC_RELEASE
#define rte_memory_order_acq_rel __ATOMIC_ACQ_REL
#define rte_memory_order_seq_cst __ATOMIC_SEQ_CST

#define rte_atomic_load_explicit(ptr, memorder) \
	__atomic_load_n(ptr, memorder)

#define rte_atomic_store_explicit(ptr, val, memorder) \
	__atomic_store_n(ptr, val, memorder)

#define rte_atomic_exchange_explicit(ptr, val, memorder) \
	__atomic_exchange_n(ptr, val, memorder)

#define rte_atomic_compare_exchange_strong_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder) \
	__atomic_compare_exchange_n( \
	    ptr, expected, desired, 0, succ_memorder, fail_memorder)

#define rte_atomic_compare_exchange_weak_explicit( \
	    ptr, expected, desired, succ_memorder, fail_memorder) \
	__atomic_compare_exchange_n( \
	    ptr, expected, desired, 1, succ_memorder, fail_memorder)

#define rte_atomic_fetch_add_explicit(ptr, val, memorder) \
	__atomic_fetch_add(ptr, val, memorder)

#define rte_atomic_fetch_sub_explicit(ptr, val, memorder) \
	__atomic_fetch_sub(ptr, val, memorder)

#define rte_atomic_fetch_and_explicit(ptr, val, memorder) \
	__atomic_fetch_and(ptr, val, memorder)

#define rte_atomic_fetch_xor_explicit(ptr, val, memorder) \
	__atomic_fetch_xor(ptr, val, memorder)

#define rte_atomic_fetch_or_explicit(ptr, val, memorder) \
	__atomic_fetch_or(ptr, val, memorder)

#define rte_atomic_fetch_nand_explicit(ptr, val, memorder) \
	__atomic_fetch_nand(ptr, val, memorder)

#define rte_atomic_flag_test_and_set_explicit(ptr, memorder) \
	__atomic_test_and_set(ptr, memorder)

#define rte_atomic_flag_clear_explicit(ptr, memorder) \
	__atomic_clear(ptr, memorder)

#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_STDATOMIC_H_ */
