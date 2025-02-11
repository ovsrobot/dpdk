/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */

#ifndef _RNP_OSDEP_H
#define _RNP_OSDEP_H

#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include <rte_io.h>
#include <rte_log.h>
#include <rte_bitops.h>
#include <rte_cycles.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_memzone.h>
#include <rte_memory.h>
#include <rte_string_fns.h>
#include <rte_dev.h>

#include "../rnp_logs.h"

typedef uint8_t u8;
typedef int8_t s8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef rte_iova_t dma_addr_t;

#define mb()	rte_mb()
#define wmb()	rte_wmb()
#define ffs(x) ({ unsigned long __t = (x); rte_fls_u32(__t & -__t); })

#define udelay(x) rte_delay_us(x)
#define mdelay(x) rte_delay_ms(x)

#define spinlock_t			rte_spinlock_t
#define spin_lock_init(spinlock_v)	rte_spinlock_init(spinlock_v)
#define spin_lock(spinlock_v)		rte_spinlock_lock(spinlock_v)
#define spin_unlock(spinlock_v)		rte_spinlock_unlock(spinlock_v)

#define _ETH_(off)	((off) + (0x10000))
#define _NIC_(off)	((off) + (0x30000))
#define _MAC_(off)	((off) + (0x60000))
#define _MSI_(off)	((off) + (0xA0000))

#ifndef _PACKED_ALIGN4
#define _PACKED_ALIGN4 __attribute__((packed, aligned(4)))
#endif

#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	#error "__BIG_ENDIAN is not support now."
#endif

#define FALSE               0
#define TRUE                1

#define __iomem
static inline u32
rnp_reg_read32(volatile void *base, size_t offset)
{
	unsigned int v = rte_read32(((volatile u8 *)base + offset));

	RNP_PMD_REG_LOG(DEBUG, "offset=0x%08lx val=0x%04x",
			(unsigned long)offset, v);
	return v;
}

static inline void
rnp_reg_write32(volatile void *base, size_t offset, u32 val)
{
	RNP_PMD_REG_LOG(DEBUG, "offset=0x%08lx val=0x%08x",
			(unsigned long)offset, val);
	rte_write32(val, ((volatile u8 *)base + offset));
}

struct rnp_dma_mem {
	void *va;
	dma_addr_t pa;
	u32 size;
	const void *mz;
};

struct rnp_hw;

static inline void *
rnp_dma_mem_alloc(__rte_unused struct rnp_hw *hw,
		 struct rnp_dma_mem *mem, u64 size, const char *name)
{
	static RTE_ATOMIC(uint64_t)rnp_dma_memzone_id;
	char z_name[RTE_MEMZONE_NAMESIZE] = "";
	const struct rte_memzone *mz = NULL;

	if (!mem)
		return NULL;
	if (name) {
		rte_strscpy(z_name, name, RTE_MEMZONE_NAMESIZE);
		mz = rte_memzone_lookup((const char *)z_name);
		if (mz)
			return mem->va;
	} else {
		snprintf(z_name, sizeof(z_name), "rnp_dma_%" PRIu64,
				rte_atomic_fetch_add_explicit(&rnp_dma_memzone_id, 1,
				rte_memory_order_relaxed));
	}
	mz = rte_memzone_reserve_bounded(z_name, size, SOCKET_ID_ANY, 0,
			0, RTE_PGSIZE_2M);
	if (!mz)
		return NULL;

	mem->size = size;
	mem->va = mz->addr;
	mem->pa = mz->iova;
	mem->mz = (const void *)mz;
	RNP_PMD_DRV_LOG(DEBUG, "memzone %s allocated with physical address: "
			"%"PRIu64, mz->name, mem->pa);

	return mem->va;
}

static inline void
rnp_dma_mem_free(__rte_unused struct rnp_hw *hw,
		 struct rnp_dma_mem *mem)
{
	RNP_PMD_DRV_LOG(DEBUG, "memzone %s to be freed with physical address: "
			"%"PRIu64, ((const struct rte_memzone *)mem->mz)->name,
			mem->pa);
	if (mem->mz) {
		rte_memzone_free((const struct rte_memzone *)mem->mz);
		mem->mz = NULL;
		mem->va = NULL;
		mem->pa = (dma_addr_t)0;
	}
}

#define RNP_REG_RD(base, offset)	rnp_reg_read32(base, offset)
#define RNP_REG_WR(base, offset, val)	rnp_reg_write32(base, offset, val)
#define RNP_E_REG_WR(hw, off, value)	rnp_reg_write32((hw)->e_ctrl, (off), (value))
#define RNP_E_REG_RD(hw, off)		rnp_reg_read32((hw)->e_ctrl, (off))
#define RNP_MAC_REG_WR(hw, lane, off, value) \
	rnp_reg_write32((hw)->mac_base[lane], (off), (value))
#define RNP_MAC_REG_RD(hw, lane, off) \
	rnp_reg_read32((hw)->mac_base[lane], (off))

#endif /* _RNP_OSDEP_H_ */
