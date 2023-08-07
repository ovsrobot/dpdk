#ifndef __RNP_OSDEP_H__
#define __RNP_OSDEP_H__
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#include <stdint.h>

#include <rte_byteorder.h>

#define __iomem
#define _RING_(off)     ((off) + 0x000000)
#define _DMA_(off)      ((off))
#define _GLB_(off)      ((off) + 0x000000)
#define _NIC_(off)      ((off) + 0x000000)
#define _ETH_(off)      ((off))
#define _MAC_(off)      ((off))
#define BIT(n)          (1UL << (n))
#define BIT64(n)        (1ULL << (n))
#define BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;
typedef int32_t     s32;
typedef int16_t     s16;
typedef int8_t      s8;
#endif /* __RNP_OSDEP_H__ */
