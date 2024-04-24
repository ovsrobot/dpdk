/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */

#ifndef _RTE_DEQUE_PVT_H_
#define _RTE_DEQUE_PVT_H_

#define __RTE_DEQUE_COUNT(d) ((d->head - d->tail) & d->mask)
#define __RTE_DEQUE_FREE_SPACE(d) (d->capacity - __RTE_DEQUE_COUNT(d))

static __rte_always_inline void
__rte_deque_enqueue_elems_head_32(struct rte_deque *d,
				const unsigned int size,
				uint32_t idx,
				const void *obj_table,
				unsigned int n)
{
	unsigned int i;
	uint32_t *deque = (uint32_t *)&d[1];
	const uint32_t *obj = (const uint32_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x7); i += 8, idx += 8) {
			deque[idx] = obj[i];
			deque[idx + 1] = obj[i + 1];
			deque[idx + 2] = obj[i + 2];
			deque[idx + 3] = obj[i + 3];
			deque[idx + 4] = obj[i + 4];
			deque[idx + 5] = obj[i + 5];
			deque[idx + 6] = obj[i + 6];
			deque[idx + 7] = obj[i + 7];
		}
		switch (n & 0x7) {
		case 7:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 6:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 5:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 4:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 3:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 2:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 1:
			deque[idx++] = obj[i++]; /* fallthrough */
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			deque[idx] = obj[i];
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			deque[idx] = obj[i];
	}
}

static __rte_always_inline void
__rte_deque_enqueue_elems_head_64(struct rte_deque *d,
				const void *obj_table,
				unsigned int n)
{
	unsigned int i;
	const uint32_t size = d->size;
	uint32_t idx = (d->head & d->mask);
	uint64_t *deque = (uint64_t *)&d[1];
	const unaligned_uint64_t *obj = (const unaligned_uint64_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x3); i += 4, idx += 4) {
			deque[idx] = obj[i];
			deque[idx + 1] = obj[i + 1];
			deque[idx + 2] = obj[i + 2];
			deque[idx + 3] = obj[i + 3];
		}
		switch (n & 0x3) {
		case 3:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 2:
			deque[idx++] = obj[i++]; /* fallthrough */
		case 1:
			deque[idx++] = obj[i++]; /* fallthrough */
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			deque[idx] = obj[i];
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			deque[idx] = obj[i];
	}
}

static __rte_always_inline void
__rte_deque_enqueue_elems_head_128(struct rte_deque *d,
				const void *obj_table,
				unsigned int n)
{
	unsigned int i;
	const uint32_t size = d->size;
	uint32_t idx = (d->head & d->mask);
	rte_int128_t *deque = (rte_int128_t *)&d[1];
	const rte_int128_t *obj = (const rte_int128_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x1); i += 2, idx += 2)
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 32);
		switch (n & 0x1) {
		case 1:
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
	}
}

static __rte_always_inline unsigned int
__rte_deque_enqueue_at_head(struct rte_deque *d,
			const void *obj_table,
			unsigned int esize,
			unsigned int n)
{
	/* 8B and 16B copies implemented individually because on some platforms
	 * there are 64 bit and 128 bit registers available for direct copying.
	 */
	if (esize == 8)
		__rte_deque_enqueue_elems_head_64(d, obj_table, n);
	else if (esize == 16)
		__rte_deque_enqueue_elems_head_128(d, obj_table, n);
	else {
		uint32_t idx, scale, nd_idx, nd_num, nd_size;

		/* Normalize to uint32_t */
		scale = esize / sizeof(uint32_t);
		nd_num = n * scale;
		idx = d->head & d->mask;
		nd_idx = idx * scale;
		nd_size = d->size * scale;
		__rte_deque_enqueue_elems_head_32(d, nd_size, nd_idx,
						obj_table, nd_num);
	}
	d->head = (d->head + n) & d->mask;
	return n;
}

static __rte_always_inline void
__rte_deque_enqueue_elems_tail_32(struct rte_deque *d,
				const unsigned int mask,
				uint32_t idx,
				const void *obj_table,
				unsigned int n,
				const unsigned int scale,
				const unsigned int elem_size)
{
	unsigned int i;
	uint32_t *deque = (uint32_t *)&d[1];
	const uint32_t *obj = (const uint32_t *)obj_table;

	if (likely(idx >= n)) {
		for (i = 0; i < n; idx -= scale, i += scale)
			memcpy(&deque[idx], &obj[i], elem_size);
	} else {
		for (i = 0; (int32_t)idx >= 0; idx -= scale, i += scale)
			memcpy(&deque[idx], &obj[i], elem_size);

		/* Start at the ending */
		idx = mask;
		for (; i < n; idx -= scale, i += scale)
			memcpy(&deque[idx], &obj[i], elem_size);
	}
}

static __rte_always_inline void
__rte_deque_enqueue_elems_tail_64(struct rte_deque *d,
				const void *obj_table,
				unsigned int n)
{
	unsigned int i;
	uint32_t idx = (d->tail & d->mask);
	uint64_t *deque = (uint64_t *)&d[1];
	const unaligned_uint64_t *obj = (const unaligned_uint64_t *)obj_table;
	if (likely((int32_t)(idx - n) >= 0)) {
		for (i = 0; i < (n & ~0x3); i += 4, idx -= 4) {
			deque[idx] = obj[i];
			deque[idx - 1] = obj[i + 1];
			deque[idx - 2] = obj[i + 2];
			deque[idx - 3] = obj[i + 3];
		}
		switch (n & 0x3) {
		case 3:
			deque[idx--] = obj[i++]; /* fallthrough */
		case 2:
			deque[idx--] = obj[i++]; /* fallthrough */
		case 1:
			deque[idx--] = obj[i++]; /* fallthrough */
		}
	} else {
		for (i = 0; (int32_t)idx >= 0; i++, idx--)
			deque[idx] = obj[i];
		/* Start at the ending */
		for (idx = d->mask; i < n; i++, idx--)
			deque[idx] = obj[i];
	}
}

static __rte_always_inline void
__rte_deque_enqueue_elems_tail_128(struct rte_deque *d,
				const void *obj_table,
				unsigned int n)
{
	unsigned int i;
	uint32_t idx = (d->tail & d->mask);
	rte_int128_t *deque = (rte_int128_t *)&d[1];
	const rte_int128_t *obj = (const rte_int128_t *)obj_table;
	if (likely((int32_t)(idx - n) >= 0)) {
		for (i = 0; i < (n & ~0x1); i += 2, idx -= 2) {
			deque[idx] = obj[i];
			deque[idx - 1] = obj[i + 1];
		}
		switch (n & 0x1) {
		case 1:
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
		}
	} else {
		for (i = 0; (int32_t)idx >= 0; i++, idx--)
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
		/* Start at the ending */
		for (idx = d->mask; i < n; i++, idx--)
			memcpy((void *)(deque + idx),
				(const void *)(obj + i), 16);
	}
}

static __rte_always_inline unsigned int
__rte_deque_enqueue_at_tail(struct rte_deque *d,
			const void *obj_table,
			unsigned int esize,
			unsigned int n)
{
	/* The tail point must point at an empty cell when enqueuing */
	d->tail--;

	/* 8B and 16B copies implemented individually because on some platforms
	 * there are 64 bit and 128 bit registers available for direct copying.
	 */
	if (esize == 8)
		__rte_deque_enqueue_elems_tail_64(d, obj_table, n);
	else if (esize == 16)
		__rte_deque_enqueue_elems_tail_128(d, obj_table, n);
	else {
		uint32_t idx, scale, nd_idx, nd_num, nd_mask;

		/* Normalize to uint32_t */
		scale = esize / sizeof(uint32_t);
		nd_num = n * scale;
		idx = d->tail & d->mask;
		nd_idx = idx * scale;
		nd_mask = d->mask * scale;
		__rte_deque_enqueue_elems_tail_32(d, nd_mask, nd_idx, obj_table,
						nd_num, scale, esize);
	}

	/* The +1 is because the tail needs to point at a
	 * non-empty memory location after the enqueuing operation.
	 */
	d->tail = (d->tail - n + 1) & d->mask;
	return n;
}

static __rte_always_inline void
__rte_deque_dequeue_elems_32(struct rte_deque *d,
			const unsigned int size,
			uint32_t idx,
			void *obj_table,
			unsigned int n)
{
	unsigned int i;
	const uint32_t *deque = (const uint32_t *)&d[1];
	uint32_t *obj = (uint32_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x7); i += 8, idx += 8) {
			obj[i] = deque[idx];
			obj[i + 1] = deque[idx + 1];
			obj[i + 2] = deque[idx + 2];
			obj[i + 3] = deque[idx + 3];
			obj[i + 4] = deque[idx + 4];
			obj[i + 5] = deque[idx + 5];
			obj[i + 6] = deque[idx + 6];
			obj[i + 7] = deque[idx + 7];
		}
		switch (n & 0x7) {
		case 7:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 6:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 5:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 4:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 3:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 2:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 1:
			obj[i++] = deque[idx++]; /* fallthrough */
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			obj[i] = deque[idx];
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			obj[i] = deque[idx];
	}
}

static __rte_always_inline void
__rte_deque_dequeue_elems_64(struct rte_deque *d, void *obj_table,
			unsigned int n)
{
	unsigned int i;
	const uint32_t size = d->size;
	uint32_t idx = (d->tail & d->mask);
	const uint64_t *deque = (const uint64_t *)&d[1];
	unaligned_uint64_t *obj = (unaligned_uint64_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x3); i += 4, idx += 4) {
			obj[i] = deque[idx];
			obj[i + 1] = deque[idx + 1];
			obj[i + 2] = deque[idx + 2];
			obj[i + 3] = deque[idx + 3];
		}
		switch (n & 0x3) {
		case 3:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 2:
			obj[i++] = deque[idx++]; /* fallthrough */
		case 1:
			obj[i++] = deque[idx++]; /* fallthrough */
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			obj[i] = deque[idx];
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			obj[i] = deque[idx];
	}
}

static __rte_always_inline void
__rte_deque_dequeue_elems_128(struct rte_deque *d,
			void *obj_table,
			unsigned int n)
{
	unsigned int i;
	const uint32_t size = d->size;
	uint32_t idx = (d->tail & d->mask);
	const rte_int128_t *deque = (const rte_int128_t *)&d[1];
	rte_int128_t *obj = (rte_int128_t *)obj_table;
	if (likely(idx + n <= size)) {
		for (i = 0; i < (n & ~0x1); i += 2, idx += 2)
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 32);
		switch (n & 0x1) {
		case 1:
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
		}
	} else {
		for (i = 0; idx < size; i++, idx++)
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
		/* Start at the beginning */
		for (idx = 0; i < n; i++, idx++)
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
	}
}

static __rte_always_inline unsigned int
__rte_deque_dequeue_at_tail(struct rte_deque *d,
			void *obj_table,
			unsigned int esize,
			unsigned int n)
{
	/* 8B and 16B copies implemented individually because on some platforms
	 * there are 64 bit and 128 bit registers available for direct copying.
	 */
	if (esize == 8)
		__rte_deque_dequeue_elems_64(d, obj_table, n);
	else if (esize == 16)
		__rte_deque_dequeue_elems_128(d, obj_table, n);
	else {
		uint32_t idx, scale, nd_idx, nd_num, nd_size;

		/* Normalize to uint32_t */
		scale = esize / sizeof(uint32_t);
		nd_num = n * scale;
		idx = d->tail & d->mask;
		nd_idx = idx * scale;
		nd_size = d->size * scale;
		__rte_deque_dequeue_elems_32(d, nd_size, nd_idx,
					obj_table, nd_num);
	}
	d->tail = (d->tail + n) & d->mask;
	return n;
}

static __rte_always_inline void
__rte_deque_dequeue_elems_head_32(struct rte_deque *d,
				const unsigned int mask,
				uint32_t idx,
				void *obj_table,
				unsigned int n,
				const unsigned int scale,
				const unsigned int elem_size)
{
	unsigned int i;
	const uint32_t *deque = (uint32_t *)&d[1];
	uint32_t *obj = (uint32_t *)obj_table;

	if (likely(idx >= n)) {
		for (i = 0; i < n; idx -= scale, i += scale)
			memcpy(&obj[i], &deque[idx], elem_size);
	} else {
		for (i = 0; (int32_t)idx >= 0; idx -= scale, i += scale)
			memcpy(&obj[i], &deque[idx], elem_size);
		/* Start at the ending */
		idx = mask;
		for (; i < n; idx -= scale, i += scale)
			memcpy(&obj[i], &deque[idx], elem_size);
	}
}

static __rte_always_inline void
__rte_deque_dequeue_elems_head_64(struct rte_deque *d,
				void *obj_table,
				unsigned int n)
{
	unsigned int i;
	uint32_t idx = (d->head & d->mask);
	const uint64_t *deque = (uint64_t *)&d[1];
	unaligned_uint64_t *obj = (unaligned_uint64_t *)obj_table;
	if (likely((int32_t)(idx - n) >= 0)) {
		for (i = 0; i < (n & ~0x3); i += 4, idx -= 4) {
			obj[i] = deque[idx];
			obj[i + 1] = deque[idx - 1];
			obj[i + 2] = deque[idx - 2];
			obj[i + 3] = deque[idx - 3];
		}
		switch (n & 0x3) {
		case 3:
			obj[i++] = deque[idx--];  /* fallthrough */
		case 2:
			obj[i++] = deque[idx--]; /* fallthrough */
		case 1:
			obj[i++] = deque[idx--]; /* fallthrough */
		}
	} else {
		for (i = 0; (int32_t)idx >= 0; i++, idx--)
			obj[i] = deque[idx];
		/* Start at the ending */
		for (idx = d->mask; i < n; i++, idx--)
			obj[i] = deque[idx];
	}
}

static __rte_always_inline void
__rte_deque_dequeue_elems_head_128(struct rte_deque *d,
				void *obj_table,
				unsigned int n)
{
	unsigned int i;
	uint32_t idx = (d->head & d->mask);
	const rte_int128_t *deque = (rte_int128_t *)&d[1];
	rte_int128_t *obj = (rte_int128_t *)obj_table;
	if (likely((int32_t)(idx - n) >= 0)) {
		for (i = 0; i < (n & ~0x1); i += 2, idx -= 2) {
			obj[i] = deque[idx];
			obj[i + 1] = deque[idx - 1];
		}
		switch (n & 0x1) {
		case 1:
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
		}
	} else {
		for (i = 0; (int32_t)idx >= 0; i++, idx--)
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
		/* Start at the ending */
		for (idx = d->mask; i < n; i++, idx--)
			memcpy((void *)(obj + i),
				(const void *)(deque + idx), 16);
	}
}

static __rte_always_inline unsigned int
__rte_deque_dequeue_at_head(struct rte_deque *d,
			void *obj_table,
			unsigned int esize,
			unsigned int n)
{
	/* The head must point at an empty cell when dequeueing */
	d->head--;

	/* 8B and 16B copies implemented individually because on some platforms
	 * there are 64 bit and 128 bit registers available for direct copying.
	 */
	if (esize == 8)
		__rte_deque_dequeue_elems_head_64(d, obj_table, n);
	else if (esize == 16)
		__rte_deque_dequeue_elems_head_128(d, obj_table, n);
	else {
		uint32_t idx, scale, nd_idx, nd_num, nd_mask;

		/* Normalize to uint32_t */
		scale = esize / sizeof(uint32_t);
		nd_num = n * scale;
		idx = d->head & d->mask;
		nd_idx = idx * scale;
		nd_mask = d->mask * scale;
		__rte_deque_dequeue_elems_head_32(d, nd_mask, nd_idx, obj_table,
						nd_num, scale, esize);
	}

	/* The +1 is because the head needs to point at a
	 * empty memory location after the dequeueing operation.
	 */
	d->head = (d->head - n + 1) & d->mask;
	return n;
}
#endif /* _RTE_DEQUEU_PVT_H_ */
