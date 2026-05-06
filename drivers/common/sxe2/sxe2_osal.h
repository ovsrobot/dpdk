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

#include "sxe2_type.h"

#define BIT(nr)             (1UL << (nr))
#ifndef __BITS_PER_LONG
#define __BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#endif
#define BIT_WORD(nr)      ((nr) / __BITS_PER_LONG)
#define BIT_MASK(nr)	  (1UL << ((nr) % __BITS_PER_LONG))

#ifndef BIT_ULL
#define BIT_ULL(a) (1ULL << (a))
#endif

#define BITS_PER_BYTE 8

#define IS_UNICAST_ETHER_ADDR(addr)			\
	((bool)((((u8 *)(addr))[0] % ((u8)0x2)) == 0))

#define STRUCT_SIZE(ptr, field, num) \
	(sizeof(*(ptr)) + sizeof(*(ptr)->field) * (num))

#ifndef TAILQ_FOREACH_SAFE
#define TAILQ_FOREACH_SAFE(var, head, field, tvar) \
	for ((var) = TAILQ_FIRST((head)); \
		(var) && ((tvar) = TAILQ_NEXT((var), field), 1); \
		(var) = (tvar))
#endif

#define SXE2_QUEUE_WAIT_RETRY_CNT    (50)

#define __iomem

#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

#define dma_addr_t rte_iova_t

#define resource_size_t u64

#define FIELD_SIZEOF(t, f) RTE_SIZEOF_FIELD(t, f)
#define ARRAY_SIZE(arr) RTE_DIM(arr)

#define CPU_TO_LE16(o) rte_cpu_to_le_16(o)
#define CPU_TO_LE32(s) rte_cpu_to_le_32(s)
#define CPU_TO_LE64(h) rte_cpu_to_le_64(h)
#define LE16_TO_CPU(a) rte_le_to_cpu_16(a)
#define LE32_TO_CPU(c) rte_le_to_cpu_32(c)
#define LE64_TO_CPU(k) rte_le_to_cpu_64(k)

#define CPU_TO_BE16(o) rte_cpu_to_be_16(o)
#define CPU_TO_BE32(o) rte_cpu_to_be_32(o)
#define CPU_TO_BE64(o) rte_cpu_to_be_64(o)
#define BE16_TO_CPU(o) rte_be_to_cpu_16(o)

#define NTOHS(a) rte_be_to_cpu_16(a)
#define NTOHL(a) rte_be_to_cpu_32(a)
#define HTONS(a) rte_cpu_to_be_16(a)
#define HTONL(a) rte_cpu_to_be_32(a)

#define udelay(x) rte_delay_us(x)

#define mdelay(x) rte_delay_us(1000 * (x))

#define msleep(x) rte_delay_us(1000 * (x))

#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) \
			(((n) + (typeof(n))(d) - (typeof(n))1) / (typeof(n))(d))
#endif

#define usleep_range(min) msleep(DIV_ROUND_UP(min, 1000))

#define __bf_shf(x) ((uint32_t)rte_bsf64(x))

#ifndef BITS_PER_LONG
#define BITS_PER_LONG	32
#endif

#define FIELD_PREP(mask, val) (((typeof(mask))(val) << __bf_shf(mask)) & (mask))
#define FIELD_GET(_mask, _reg) ((typeof(_mask))(((_reg) & (_mask)) >> __bf_shf(_mask)))

#define SXE2_NUM_ROUND_UP(n, d) (DIV_ROUND_UP(n, d) * d)

static inline void sxe2_swap_u16(u16 *a, u16 *b)
{
	*a += *b;
	*b = *a - *b;
	*a -= *b;
}

#define SXE2_SWAP_U16(a, b) sxe2_swap_u16(a, b)

enum sxe2_itr_idx {
	SXE2_ITR_IDX_0 = 0,
	SXE2_ITR_IDX_1,
	SXE2_ITR_IDX_2,
	SXE2_ITR_IDX_NONE,
};

#define MAX_ERRNO	4095
#define IS_ERR_VALUE(x) unlikely((uintptr_t)(void *)(x) >= (uintptr_t)-MAX_ERRNO)
static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((uintptr_t)ptr);
}

#define DMA_BIT_MASK(n)	(((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))

#define SXE2_CTXT_REG_VALUE(value, shift, width)    ((value << shift) & \
						(((1ULL << width) - 1) << shift))

#define  ETH_P_8021Q  0x8100
#define  ETH_P_8021AD 0x88a8
#define  ETH_P_QINQ1  0x9100

#define FLEX_ARRAY_SIZE(_ptr, _mem, cnt) ((cnt) * sizeof(_ptr->_mem[0]))

struct sxe2_lock {
	rte_spinlock_t spinlock;
};
#define sxe2_init_lock(sp) rte_spinlock_init(&(sp)->spinlock)
#define sxe2_acquire_lock(sp) rte_spinlock_lock(&(sp)->spinlock)
#define sxe2_release_lock(sp) rte_spinlock_unlock(&(sp)->spinlock)
#define sxe2_destroy_lock(sp) RTE_SET_USED(sp)

#define COMPILER_BARRIER() \
		{ asm volatile("" ::: "memory"); }

struct sxe2_list_head_type {
	struct sxe2_list_head_type *next, *prev;
};

#define LIST_HEAD_TYPE				sxe2_list_head_type

#define SXE2_LIST_ENTRY(ptr, type, member) container_of(ptr, type, member)
#define LIST_FIRST_ENTRY(ptr, type, member) \
			SXE2_LIST_ENTRY((ptr)->next, type, member)
#define LIST_NEXT_ENTRY(pos, member) \
			SXE2_LIST_ENTRY((pos)->member.next, typeof(*(pos)), member)

static inline void INIT_LIST_HEAD(struct LIST_HEAD_TYPE *list)
{
	list->next = list;
	COMPILER_BARRIER();
	list->prev = list;
	COMPILER_BARRIER();
}

static inline void sxe2_list_add(struct LIST_HEAD_TYPE *curr,
					struct LIST_HEAD_TYPE *prev,
					struct LIST_HEAD_TYPE *next)
{
	next->prev = curr;
	curr->next = next;
	curr->prev = prev;
	COMPILER_BARRIER();
	prev->next = curr;
	COMPILER_BARRIER();
}

#define LIST_ADD(entry, head)    sxe2_list_add(entry, (head), (head)->next)
#define LIST_ADD_TAIL(entry, head)    sxe2_list_add(entry, (head)->prev, head)

static inline void __list_del(struct LIST_HEAD_TYPE *prev, struct LIST_HEAD_TYPE *next)
{
	next->prev = prev;
	COMPILER_BARRIER();
	prev->next = next;
	COMPILER_BARRIER();
}

static inline void __list_del_entry(struct LIST_HEAD_TYPE *entry)
{
	__list_del(entry->prev, entry->next);
}
#define LIST_DEL(entry) __list_del_entry(entry)

static inline bool __list_is_empty(const struct LIST_HEAD_TYPE *head)
{
	COMPILER_BARRIER();
	return head->next == head;
}

#define LIST_IS_EMPTY(head) __list_is_empty(head)

#define LIST_FOR_EACH_ENTRY(pos, head, member)			       \
		for (pos = LIST_FIRST_ENTRY(head, typeof(*pos), member);    \
				&pos->member != (head);                    \
				pos = LIST_NEXT_ENTRY(pos, member))

#define LIST_FOR_EACH_ENTRY_SAFE(pos, n, head, member)		       \
		for (pos = LIST_FIRST_ENTRY(head, typeof(*pos), member),    \
				n = LIST_NEXT_ENTRY(pos, member);            \
				&pos->member != (head);                     \
				pos = n, n = LIST_NEXT_ENTRY(n, member))

struct sxe2_blk_list_head_type {
	struct sxe2_blk_list_head_type *next_blk;
	struct sxe2_blk_list_head_type *next;
	u16 blk_size;
	u16 blk_id;
};

#define BLK_LIST_HEAD_TYPE	sxe2_blk_list_head_type

static inline void sxe2_blk_list_add(struct BLK_LIST_HEAD_TYPE *node,
					struct BLK_LIST_HEAD_TYPE *head)
{
	struct BLK_LIST_HEAD_TYPE *curr = head->next_blk;
	struct BLK_LIST_HEAD_TYPE *prev = head;

	while (curr != NULL && curr->blk_id < node->blk_id) {
		prev = curr;
		curr = curr->next_blk;
	}

	if (prev != head && prev->blk_id + prev->blk_size == node->blk_id) {
		prev->blk_size += node->blk_size;
		node->blk_size = 0;
	} else {
		node->next_blk = curr;
		prev->next_blk = node;
	}

	node = (node->blk_size == 0) ? prev : node;

	if (curr) {

		if (node->blk_id + node->blk_size == curr->blk_id) {
			node->blk_size += curr->blk_size;
			curr->blk_size = 0;
			node->next_blk = curr->next_blk;
		} else {
			node->next_blk = curr;
		}
	}
}

static inline struct BLK_LIST_HEAD_TYPE *sxe2_blk_list_get(
			struct BLK_LIST_HEAD_TYPE *head, u16 blk_size)
{
	struct BLK_LIST_HEAD_TYPE *curr = head->next_blk;
	struct BLK_LIST_HEAD_TYPE *prev = head;
	struct BLK_LIST_HEAD_TYPE *blk_max_node = curr;
	struct BLK_LIST_HEAD_TYPE *blk_max_node_pre = head;
	struct BLK_LIST_HEAD_TYPE *ret = NULL;
	s32 i = blk_size;

	while (curr && curr->blk_size != blk_size) {
		if (curr->blk_size > blk_max_node->blk_size) {
			blk_max_node = curr;
			blk_max_node_pre = prev;
		}
		prev = curr;
		curr = curr->next_blk;
	}

	if (curr != NULL) {
		prev->next_blk = curr->next_blk;
		ret = curr;
		goto l_end;
	}

	if (blk_max_node->blk_size < blk_size)
		goto l_end;

	ret = blk_max_node;
	prev = blk_max_node_pre;

	curr = blk_max_node;
	while (i != 0) {
		curr = curr->next;
		i--;
	}
	curr->blk_size = blk_max_node->blk_size - blk_size;
	blk_max_node->blk_size = blk_size;
	prev->next_blk = curr;

l_end:
	return ret;
}

#define BLK_LIST_ADD(entry, head) sxe2_blk_list_add(entry, head)
#define BLK_LIST_GET(head, blk_size) sxe2_blk_list_get(head, blk_size)

#ifndef BIT_ULL
#define BIT_ULL(nr)		(ULL(1) << (nr))
#endif

static inline bool check_is_pow2(u64 val)
{
	return (val && !(val & (val - 1)));
}

static inline u8 sxe2_setbit_cnt8(u8 num)
{
	u8 bits = 0;
	u32 i;

	for (i = 0; i < 8; i++) {
		bits += (num & 0x1);
		num >>= 1;
	}

	return bits;
}

static inline bool max_set_bit_check(const u8 *mask, u16 size, u16 max)
{
	u16 count = 0;
	u16 i;
	bool ret = false;

	for (i = 0; i < size; i++) {
		if (!mask[i])
			continue;

		if (count == max)
			goto l_end;

		count += sxe2_setbit_cnt8(mask[i]);
		if (count > max)
			goto l_end;
	}

	ret = true;
l_end:
	return ret;
}

#define BITS_TO_LONGS(nr)	DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(unsigned long))
#define BITS_TO_U32(nr) DIV_ROUND_UP(nr, 32)

#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (__BITS_PER_LONG - 1 - (h))))

#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (__BITS_PER_LONG - 1)))

#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#define BITMAP_MEM_ALIGNMENT 8
#else
#define BITMAP_MEM_ALIGNMENT (8 * sizeof(unsigned long))
#endif
#define BITMAP_MEM_MASK (BITMAP_MEM_ALIGNMENT - 1)
#define IS_ALIGNED(x, a) (((x) & ((typeof(x))(a) - 1)) == 0)

#define DECLARE_BITMAP(name, bits) \
				unsigned long name[BITS_TO_LONGS(bits)]
#define BITMAP_TYPE unsigned long
#define small_const_nbits(nbits) \
	(__rte_constant(nbits) && (nbits) <= __BITS_PER_LONG && (nbits) > 0)

static inline void set_bit(u32 nr, unsigned long *addr)
{
	addr[nr / __BITS_PER_LONG] |= 1UL << (nr % __BITS_PER_LONG);
}

static inline void clear_bit(u32 nr, unsigned long *addr)
{
	addr[nr / __BITS_PER_LONG] &= ~(1UL << (nr % __BITS_PER_LONG));
}

static inline u32 test_bit(u32 nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (__BITS_PER_LONG-1)));
}

static inline u32 bitmap_weight(const unsigned long *src, u32 nbits)
{
	u32 cnt = 0;
	u16 i;
	for (i = 0; i < nbits; i++) {
		if (test_bit(i, src))
			cnt++;
	}
	return cnt;
}

static inline bool bitmap_empty(const unsigned long *src, u32 nbits)
{
	u16 i;
	for (i = 0; i < nbits; i++) {
		if (test_bit(i, src))
			return false;
	}
	return true;
}

static inline void bitmap_zero(unsigned long *dst, u32 nbits)
{
	u32 len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memset(dst, 0, len);
}

static bool __bitmap_and(unsigned long *dst, const unsigned long *bitmap1,
		 const unsigned long *bitmap2, u32 bits)
{
	u32 k;
	u32 lim = bits/__BITS_PER_LONG;
	unsigned long result = 0;
	for (k = 0; k < lim; k++)
		result |= (dst[k] = bitmap1[k] & bitmap2[k]);
	if (bits % __BITS_PER_LONG)
		result |= (dst[k] = bitmap1[k] & bitmap2[k] &
				BITMAP_LAST_WORD_MASK(bits));
	return result != 0;
}

static inline bool bitmap_and(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, u32 nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_and(dst, src1, src2, nbits);
}

static void __bitmap_or(unsigned long *dst, const unsigned long *bitmap1,
		 const unsigned long *bitmap2, int bits)
{
	int k;
	int nr = BITS_TO_LONGS(bits);

	for (k = 0; k < nr; k++)
		dst[k] = bitmap1[k] | bitmap2[k];
}

static inline void bitmap_or(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, u32 nbits)
{
	if (small_const_nbits(nbits))
		*dst = *src1 | *src2;
	else
		__bitmap_or(dst, src1, src2, nbits);
}

static int __bitmap_andnot(unsigned long *dst, const unsigned long *bitmap1,
				const unsigned long *bitmap2, u32 bits)
{
	u32 k;
	u32 lim = bits/__BITS_PER_LONG;
	unsigned long result = 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k]);
	if (bits % __BITS_PER_LONG)
		result |= (dst[k] = bitmap1[k] & ~bitmap2[k] &
			   BITMAP_LAST_WORD_MASK(bits));
	return result != 0;
}

static inline int bitmap_andnot(unsigned long *dst, const unsigned long *src1,
			const unsigned long *src2, u32 nbits)
{
	if (small_const_nbits(nbits))
		return (*dst = *src1 & ~(*src2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;
	return __bitmap_andnot(dst, src1, src2, nbits);
}

static bool __bitmap_equal(const unsigned long *bitmap1,
		const unsigned long *bitmap2, u32 bits)
{
	u32 k, lim = bits/__BITS_PER_LONG;
	for (k = 0; k < lim; ++k)
		if (bitmap1[k] != bitmap2[k])
			return false;

	if (bits % __BITS_PER_LONG)
		if ((bitmap1[k] ^ bitmap2[k]) & BITMAP_LAST_WORD_MASK(bits))
			return false;

	return true;
}

static inline bool bitmap_equal(const unsigned long *src1,
		const unsigned long *src2, u32 nbits)
{
	if (small_const_nbits(nbits))
		return !((*src1 ^ *src2) & BITMAP_LAST_WORD_MASK(nbits));
	if (__rte_constant(nbits & BITMAP_MEM_MASK) &&
		IS_ALIGNED(nbits, BITMAP_MEM_ALIGNMENT))
		return !memcmp(src1, src2, nbits / 8);
	return __bitmap_equal(src1, src2, nbits);
}

static inline unsigned long
find_next_bit(const unsigned long *addr, unsigned long size,
		unsigned long offset)
{
	u16 i;

	for (i = offset; i < size; i++) {
		if (test_bit(i, addr))
			break;
	}
	return i;
}

static inline unsigned long
find_next_zero_bit(const unsigned long *addr, unsigned long size,
		unsigned long offset)
{
	u16 i;
	for (i = offset; i < size; i++) {
		if (!test_bit(i, addr))
			break;
	}
	return i;
}

static inline void bitmap_copy(unsigned long *dst, const unsigned long *src,
			u32 nbits)
{
	u32 len = BITS_TO_LONGS(nbits) * sizeof(unsigned long);
	memcpy(dst, src, len);
}

static inline unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
	return find_next_zero_bit(addr, size, 0);
}

static inline unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	return find_next_bit(addr, size, 0);
}

#define for_each_clear_bit(bit, addr, size) \
		for ((bit) = find_first_zero_bit((addr), (size));	\
			(bit) < (size);					\
			(bit) = find_next_zero_bit((addr), (size), (bit) + 1))

#define for_each_set_bit(bit, addr, size) \
		for ((bit) = find_first_bit((addr), (size));	\
			(bit) < (size);					\
			(bit) = find_next_bit((addr), (size), (bit) + 1))

struct sxe2_adapter;

static inline void *sxe2_malloc(__rte_unused struct sxe2_adapter *ad, size_t size)
{
	return rte_zmalloc(NULL, size, 0);
}

static inline void *sxe2_calloc(__rte_unused struct sxe2_adapter *ad, size_t num, size_t size)
{
	return rte_calloc(NULL, num, size, 0);
}

static inline void sxe2_free(__rte_unused struct sxe2_adapter *ad, void *ptr)
{
	rte_free(ptr);
}

static inline void *sxe2_memdup(__rte_unused struct sxe2_adapter *ad,
			const void *src, size_t size)
{
	void *p;

	p = sxe2_malloc(ad, size);
	if (p)
		rte_memcpy(p, src, size);
	return p;
}

#endif
