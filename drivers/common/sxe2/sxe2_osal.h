/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_OSAL_H__
#define __SXE2_OSAL_H__
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_version.h>
#include <rte_bitops.h>

#ifndef __BITS_PER_LONG
#define __BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#endif
#define BIT_WORD(nr)      ((nr) / __BITS_PER_LONG)
#define BIT_MASK(nr)      (1UL << ((nr) % __BITS_PER_LONG))

#define BITS_PER_BYTE 8

#define IS_UNICAST_ETHER_ADDR(addr)			\
	((bool)((((uint8_t *)(addr))[0] % ((uint8_t)0x2)) == 0))

#define STRUCT_SIZE(ptr, field, num) \
	(sizeof(*(ptr)) + sizeof(*(ptr)->field) * (num))

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar) \
	for ((var) = TAILQ_FIRST((head)); \
		(var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
		(var) = (tvar))
#endif

#define SXE2_QUEUE_WAIT_RETRY_CNT    (50)

#define upper_32_bits(n) ((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((uint32_t)((n) & 0xffffffff))

#define FIELD_SIZEOF(t, f) RTE_SIZEOF_FIELD(t, f)
#define ARRAY_SIZE(arr) RTE_DIM(arr)

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) \
			(((n) + (typeof(n))(d) - (typeof(n))1) / (typeof(n))(d))
#endif

enum sxe2_itr_idx {
	SXE2_ITR_IDX_0 = 0,
	SXE2_ITR_IDX_1,
	SXE2_ITR_IDX_2,
	SXE2_ITR_IDX_NONE,
};

#define  ETH_P_8021Q  0x8100
#define  ETH_P_8021AD 0x88a8
#define  ETH_P_QINQ1  0x9100

#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(unsigned long))
#define BITS_TO_U32(nr) DIV_ROUND_UP(nr, 32)

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (__BITS_PER_LONG - 1)))

#define DECLARE_BITMAP(name, bits) \
				unsigned long name[BITS_TO_LONGS(bits)]
#define BITMAP_TYPE unsigned long

static inline void sxe2_set_bit(uint32_t nr, unsigned long *addr)
{
	addr[nr / __BITS_PER_LONG] |= 1UL << (nr % __BITS_PER_LONG);
}

static inline void sxe2_clear_bit(uint32_t nr, unsigned long *addr)
{
	addr[nr / __BITS_PER_LONG] &= ~(1UL << (nr % __BITS_PER_LONG));
}

static inline uint32_t sxe2_test_bit(uint32_t nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (__BITS_PER_LONG-1)));
}

#endif /* __SXE2_OSAL_H */
