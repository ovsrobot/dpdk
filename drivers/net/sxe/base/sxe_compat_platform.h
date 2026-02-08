/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_COMPAT_PLATFORM_H__
#define __SXE_COMPAT_PLATFORM_H__

#include <rte_cycles.h>
#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_io.h>
#include <rte_common.h>

#include "sxe_types.h"

#define  false 0
#define  true  1

#define STATIC static

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif

#define __iomem
#define __force

#ifndef fallthrough
# define fallthrough do {} while (0)
#endif

#define cpu_to_be16(o) rte_cpu_to_be_16(o)
#define cpu_to_be32(o) rte_cpu_to_be_32(o)
#define cpu_to_be64(o) rte_cpu_to_be_64(o)
#define cpu_to_le32(o) rte_cpu_to_le_32(o)
#define be16_to_cpu(o) rte_be_to_cpu_16(o)
#define be32_to_cpu(o) rte_be_to_cpu_32(o)
#define be64_to_cpu(o) rte_be_to_cpu_64(o)
#define le32_to_cpu(o) rte_le_to_cpu_32(o)

#ifndef ntohs
#define ntohs(o) be16_to_cpu(o)
#endif

#ifndef ntohl
#define ntohl(o) be32_to_cpu(o)
#endif

#ifndef htons
#define htons(o) cpu_to_be16(o)
#endif

#ifndef htonl
#define htonl(o) cpu_to_be32(o)
#endif
#define mdelay rte_delay_ms
#define sxe_udelay rte_delay_us
#define usleep_range(min, max) rte_delay_us(min)
#define msleep(x)			 rte_delay_us((x) * 1000)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define BIT(x)	(1UL << (x))
#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL << (n)) - 1))

#define NSEC_PER_SEC	1000000000L

#define ETH_P_1588	0x88F7

#define VLAN_PRIO_SHIFT		13

static inline void
set_bit(unsigned long nr, void *addr)
{
	int *m = ((int *)addr) + (nr >> 5);
	*m |= 1 << (nr & 31);
}

static inline int
test_bit(int nr, const void *addr)
{
	return (1UL & (((const int *)addr)[nr >> 5] >> (nr & 31))) != 0UL;
}

static inline void
clear_bit(unsigned long nr, void *addr)
{
	int *m = ((int *)addr) + (nr >> 5);
	*m &= ~(1 << (nr & 31));
}

static inline int
test_and_clear_bit(unsigned long nr, void *addr)
{
	unsigned long mask = 1 << (nr & 0x1f);
	int *m = ((int *)addr) + (nr >> 5);
	int old = *m;

	*m = old & ~mask;
	return (old & mask) != 0;
}

static __rte_always_inline uint64_t
readq(volatile void *addr)
{
	return rte_le_to_cpu_64(rte_read64(addr));
}

static __rte_always_inline void
writeq(uint64_t value, volatile void *addr)
{
	rte_write64(rte_cpu_to_le_64(value), addr);
}

static inline u32 sxe_read_addr(const volatile void *addr)
{
	return rte_le_to_cpu_32(rte_read32(addr));
}

static inline void  sxe_write_addr(u32 value, volatile void *addr)
{
	rte_write32((rte_cpu_to_le_32(value)), addr);
}

#endif
