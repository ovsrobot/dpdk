/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _IECM_OSDEP_H_
#define _IECM_OSDEP_H_

#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/queue.h>
#include <stdbool.h>

#include <rte_common.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_byteorder.h>
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_log.h>
#include <rte_random.h>
#include <rte_io.h>

#include "../idpf_logs.h"

#define INLINE inline
#define STATIC static

typedef uint8_t		u8;
typedef int8_t		s8;
typedef uint16_t	u16;
typedef int16_t		s16;
typedef uint32_t	u32;
typedef int32_t		s32;
typedef uint64_t	u64;
typedef uint64_t	s64;

typedef enum iecm_status iecm_status;
typedef struct iecm_lock iecm_lock;

#define __iomem
#define hw_dbg(hw, S, A...)	do {} while (0)
#define upper_32_bits(n)	((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n)	((u32)(n))
#define low_16_bits(x)		((x) & 0xFFFF)
#define high_16_bits(x)		(((x) & 0xFFFF0000) >> 16)

#ifndef ETH_ADDR_LEN
#define ETH_ADDR_LEN		6
#endif

#ifndef __le16
#define __le16	uint16_t
#endif
#ifndef __le32
#define __le32	uint32_t
#endif
#ifndef __le64
#define __le64	uint64_t
#endif
#ifndef __be16
#define __be16	uint16_t
#endif
#ifndef __be32
#define __be32	uint32_t
#endif
#ifndef __be64
#define __be64	uint64_t
#endif

#ifndef __always_unused
#define __always_unused  __attribute__((__unused__))
#endif
#ifndef __maybe_unused
#define __maybe_unused  __attribute__((__unused__))
#endif
#ifndef __packed
#define __packed  __attribute__((packed))
#endif

#ifndef BIT_ULL
#define BIT_ULL(a) (1ULL << (a))
#endif

#ifndef BIT
#define BIT(a) (1ULL << (a))
#endif

#define FALSE	0
#define TRUE	1
#define false	0
#define true	1

#define min(a, b) RTE_MIN(a, b)
#define max(a, b) RTE_MAX(a, b)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))
#define FIELD_SIZEOF(t, f) (sizeof(((t *)0)->(f)))
#define MAKEMASK(m, s) ((m) << (s))

#define DEBUGOUT(S) PMD_DRV_LOG_RAW(DEBUG, S)
#define DEBUGOUT2(S, A...) PMD_DRV_LOG_RAW(DEBUG, S, ##A)
#define DEBUGFUNC(F) PMD_DRV_LOG_RAW(DEBUG, F)

#define iecm_debug(h, m, s, ...)					\
	do {								\
		if (((m) & (h)->debug_mask))				\
			PMD_DRV_LOG_RAW(DEBUG, "iecm %02x.%x " s,       \
					(h)->bus.device, (h)->bus.func,	\
					##__VA_ARGS__);			\
	} while (0)

#define iecm_info(hw, fmt, args...) iecm_debug(hw, IECM_DBG_ALL, fmt, ##args)
#define iecm_warn(hw, fmt, args...) iecm_debug(hw, IECM_DBG_ALL, fmt, ##args)
#define iecm_debug_array(hw, type, rowsize, groupsize, buf, len)	\
	do {								\
		struct iecm_hw *hw_l = hw;				\
		u16 len_l = len;					\
		u8 *buf_l = buf;					\
		int i;							\
		for (i = 0; i < len_l; i += 8)				\
			iecm_debug(hw_l, type,				\
				   "0x%04X  0x%016"PRIx64"\n",		\
				   i, *((u64 *)((buf_l) + i)));		\
	} while (0)
#define iecm_snprintf snprintf
#ifndef SNPRINTF
#define SNPRINTF iecm_snprintf
#endif

#define IECM_PCI_REG(reg)     rte_read32(reg)
#define IECM_PCI_REG_ADDR(a, reg)				\
	((volatile uint32_t *)((char *)(a)->hw_addr + (reg)))
#define IECM_PCI_REG64(reg)     rte_read64(reg)
#define IECM_PCI_REG_ADDR64(a, reg)				\
	((volatile uint64_t *)((char *)(a)->hw_addr + (reg)))

#define iecm_wmb() rte_io_wmb()
#define iecm_rmb() rte_io_rmb()
#define iecm_mb() rte_io_mb()

static inline uint32_t iecm_read_addr(volatile void *addr)
{
	return rte_le_to_cpu_32(IECM_PCI_REG(addr));
}

static inline uint64_t iecm_read_addr64(volatile void *addr)
{
	return rte_le_to_cpu_64(IECM_PCI_REG64(addr));
}

#define IECM_PCI_REG_WRITE(reg, value)			\
	rte_write32((rte_cpu_to_le_32(value)), reg)

#define IECM_PCI_REG_WRITE64(reg, value)		\
	rte_write64((rte_cpu_to_le_64(value)), reg)

#define IECM_READ_REG(hw, reg) iecm_read_addr(IECM_PCI_REG_ADDR((hw), (reg)))
#define IECM_WRITE_REG(hw, reg, value)					\
	IECM_PCI_REG_WRITE(IECM_PCI_REG_ADDR((hw), (reg)), (value))

#define rd32(a, reg) iecm_read_addr(IECM_PCI_REG_ADDR((a), (reg)))
#define wr32(a, reg, value)						\
	IECM_PCI_REG_WRITE(IECM_PCI_REG_ADDR((a), (reg)), (value))
#define div64_long(n, d) ((n) / (d))
#define rd64(a, reg) iecm_read_addr64(IECM_PCI_REG_ADDR64((a), (reg)))

#define BITS_PER_BYTE       8

/* memory allocation tracking */
struct iecm_dma_mem {
	void *va;
	u64 pa;
	u32 size;
	const void *zone;
} __attribute__((packed));

struct iecm_virt_mem {
	void *va;
	u32 size;
} __attribute__((packed));

#define iecm_malloc(h, s)	rte_zmalloc(NULL, s, 0)
#define iecm_calloc(h, c, s)	rte_zmalloc(NULL, (c) * (s), 0)
#define iecm_free(h, m)		rte_free(m)

#define iecm_memset(a, b, c, d)	memset((a), (b), (c))
#define iecm_memcpy(a, b, c, d)	rte_memcpy((a), (b), (c))
#define iecm_memdup(a, b, c, d)	rte_memcpy(iecm_malloc(a, c), b, c)

#define CPU_TO_BE16(o) rte_cpu_to_be_16(o)
#define CPU_TO_BE32(o) rte_cpu_to_be_32(o)
#define CPU_TO_BE64(o) rte_cpu_to_be_64(o)
#define CPU_TO_LE16(o) rte_cpu_to_le_16(o)
#define CPU_TO_LE32(s) rte_cpu_to_le_32(s)
#define CPU_TO_LE64(h) rte_cpu_to_le_64(h)
#define LE16_TO_CPU(a) rte_le_to_cpu_16(a)
#define LE32_TO_CPU(c) rte_le_to_cpu_32(c)
#define LE64_TO_CPU(k) rte_le_to_cpu_64(k)

#define NTOHS(a) rte_be_to_cpu_16(a)
#define NTOHL(a) rte_be_to_cpu_32(a)
#define HTONS(a) rte_cpu_to_be_16(a)
#define HTONL(a) rte_cpu_to_be_32(a)

/* SW spinlock */
struct iecm_lock {
	rte_spinlock_t spinlock;
};

static inline void
iecm_init_lock(struct iecm_lock *sp)
{
	rte_spinlock_init(&sp->spinlock);
}

static inline void
iecm_acquire_lock(struct iecm_lock *sp)
{
	rte_spinlock_lock(&sp->spinlock);
}

static inline void
iecm_release_lock(struct iecm_lock *sp)
{
	rte_spinlock_unlock(&sp->spinlock);
}

static inline void
iecm_destroy_lock(__attribute__((unused)) struct iecm_lock *sp)
{
}

struct iecm_hw;

static inline void *
iecm_alloc_dma_mem(__attribute__((unused)) struct iecm_hw *hw,
		   struct iecm_dma_mem *mem, u64 size)
{
	const struct rte_memzone *mz = NULL;
	char z_name[RTE_MEMZONE_NAMESIZE];

	if (!mem)
		return NULL;

	snprintf(z_name, sizeof(z_name), "iecm_dma_%"PRIu64, rte_rand());
	mz = rte_memzone_reserve_aligned(z_name, size, SOCKET_ID_ANY,
					 RTE_MEMZONE_IOVA_CONTIG, RTE_PGSIZE_4K);
	if (!mz)
		return NULL;

	mem->size = size;
	mem->va = mz->addr;
	mem->pa = mz->iova;
	mem->zone = (const void *)mz;
	memset(mem->va, 0, size);

	return mem->va;
}

static inline void
iecm_free_dma_mem(__attribute__((unused)) struct iecm_hw *hw,
		  struct iecm_dma_mem *mem)
{
	rte_memzone_free((const struct rte_memzone *)mem->zone);
	mem->size = 0;
	mem->va = NULL;
	mem->pa = 0;
}

static inline u8
iecm_hweight8(u32 num)
{
	u8 bits = 0;
	u32 i;

	for (i = 0; i < 8; i++) {
		bits += (u8)(num & 0x1);
		num >>= 1;
	}

	return bits;
}

static inline u8
iecm_hweight32(u32 num)
{
	u8 bits = 0;
	u32 i;

	for (i = 0; i < 32; i++) {
		bits += (u8)(num & 0x1);
		num >>= 1;
	}

	return bits;
}

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DELAY(x) rte_delay_us(x)
#define iecm_usec_delay(x) rte_delay_us(x)
#define iecm_msec_delay(x, y) rte_delay_us(1000 * (x))
#define udelay(x) DELAY(x)
#define msleep(x) DELAY(1000 * (x))
#define usleep_range(min, max) msleep(DIV_ROUND_UP(min, 1000))

#ifndef IECM_DBG_TRACE
#define IECM_DBG_TRACE	  BIT_ULL(0)
#endif

#ifndef DIVIDE_AND_ROUND_UP
#define DIVIDE_AND_ROUND_UP(a, b) (((a) + (b) - 1) / (b))
#endif

#ifndef IECM_INTEL_VENDOR_ID
#define IECM_INTEL_VENDOR_ID	    0x8086
#endif

#ifndef IS_UNICAST_ETHER_ADDR
#define IS_UNICAST_ETHER_ADDR(addr)			\
	((bool)((((u8 *)(addr))[0] % ((u8)0x2)) == 0))
#endif

#ifndef IS_MULTICAST_ETHER_ADDR
#define IS_MULTICAST_ETHER_ADDR(addr)			\
	((bool)((((u8 *)(addr))[0] % ((u8)0x2)) == 1))
#endif

#ifndef IS_BROADCAST_ETHER_ADDR
/* Check whether an address is broadcast. */
#define IS_BROADCAST_ETHER_ADDR(addr)			\
	((bool)((((u16 *)(addr))[0] == ((u16)0xffff))))
#endif

#ifndef IS_ZERO_ETHER_ADDR
#define IS_ZERO_ETHER_ADDR(addr)				\
	(((bool)((((u16 *)(addr))[0] == ((u16)0x0)))) &&	\
	 ((bool)((((u16 *)(addr))[1] == ((u16)0x0)))) &&	\
	 ((bool)((((u16 *)(addr))[2] == ((u16)0x0)))))
#endif

#ifndef LIST_HEAD_TYPE
#define LIST_HEAD_TYPE(list_name, type) LIST_HEAD(list_name, type)
#endif

#ifndef LIST_ENTRY_TYPE
#define LIST_ENTRY_TYPE(type)	   LIST_ENTRY(type)
#endif

#ifndef LIST_FOR_EACH_ENTRY_SAFE
#define LIST_FOR_EACH_ENTRY_SAFE(pos, temp, head, entry_type, list)	\
	LIST_FOREACH(pos, head, list)

#endif

#ifndef LIST_FOR_EACH_ENTRY
#define LIST_FOR_EACH_ENTRY(pos, head, entry_type, list)		\
	LIST_FOREACH(pos, head, list)

#endif

#endif /* _IECM_OSDEP_H_ */
