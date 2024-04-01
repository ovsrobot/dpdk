/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Arm Limited
 */


#include "test.h"

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_deque.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_random.h>

struct rte_deque *deque;

static const int esize[] = {4, 8, 16, 20};
#define DEQUE_SIZE 4096
#define MAX_BULK 32
#define TEST_DEQUE_FULL_EMPTY_ITER 8

/*
 * Validate the return value of test cases and print details of the
 * deque if validation fails
 *
 * @param exp
 *   Expression to validate return value.
 * @param r
 *   A pointer to the deque structure.
 */
#define TEST_DEQUE_VERIFY(exp, d, errst) do {				\
	if (!(exp)) {							\
		printf("error at %s:%d\tcondition " #exp " failed\n",	\
			__func__, __LINE__);				\
		rte_deque_dump(stdout, (d));				\
		errst;							\
	}								\
} while (0)

static int
test_deque_mem_cmp(void *src, void *dst, unsigned int size)
{
	int ret;

	ret = memcmp(src, dst, size);
	if (ret) {
		rte_hexdump(stdout, "src", src, size);
		rte_hexdump(stdout, "dst", dst, size);
		printf("data after dequeue is not the same\n");
	}

	return ret;
}

static int
test_deque_mem_cmp_rvs(void *src, void *dst,
		unsigned int count, unsigned int esize)
{
	int ret = 0;
	uint32_t *src32 = ((uint32_t *)src), *dst32 = ((uint32_t *)dst);
	uint32_t scale = esize/(sizeof(uint32_t));

	/* Start at the end of the dst and compare from there.*/
	dst32 += (count - 1) * scale;
	for (unsigned int i = 0; i < count; i++) {
		for (unsigned int j = 0; j < scale; j++) {
			if (src32[j] != dst32[j]) {
				ret = -1;
				break;
			}
		}
		if (ret)
			break;
		dst32 -= scale;
		src32 += scale;
	}
	if (ret) {
		rte_hexdump(stdout, "src", src, count * esize);
		rte_hexdump(stdout, "dst", dst, count * esize);
		printf("data after dequeue is not the same\n");
	}

	return ret;
}

static inline void *
test_deque_calloc(unsigned int dsize, int esize)
{
	void *p;

	p = rte_zmalloc(NULL, dsize * esize, RTE_CACHE_LINE_SIZE);
	if (p == NULL)
		printf("Failed to allocate memory\n");

	return p;
}

static void
test_deque_mem_init(void *obj, unsigned int count, int esize)
{
	for (unsigned int i = 0; i < (count * esize / sizeof(uint32_t)); i++)
		((uint32_t *)obj)[i] = i;
}

static inline void *
test_deque_inc_ptr(void *obj, int esize, unsigned int n)
{
	return (void *)((uint32_t *)obj + (n * esize / sizeof(uint32_t)));
}

/* Copy to the deque memory */
static inline void
test_deque_zc_copy_to_deque(struct rte_deque_zc_data *zcd, const void *src, int esize,
	unsigned int num)
{
	memcpy(zcd->ptr1, src, esize * zcd->n1);
	if (zcd->n1 != num) {
		const void *inc_src = (const void *)((const char *)src +
						(zcd->n1 * esize));
		memcpy(zcd->ptr2, inc_src, esize * (num - zcd->n1));
	}
}

static inline void
test_deque_zc_copy_to_deque_rev(struct rte_deque_zc_data *zcd, const void *src,
					int esize, unsigned int num)
{
	void *ptr1 = zcd->ptr1;
	for (unsigned int i = 0; i < zcd->n1; i++) {
		memcpy(ptr1, src, esize);
		src = (const void *)((const char *)src + esize);
		ptr1 = (void *)((char *)ptr1 - esize);
	}
	if (zcd->n1 != num) {
		void *ptr2 = zcd->ptr2;
		for (unsigned int i = 0; i < (num - zcd->n1); i++) {
			memcpy(ptr2, src, esize);
			src = (const void *)((const char *)src + esize);
			ptr2 = (void *)((char *)ptr2 - esize);
		}
	}
}

/* Copy from the deque memory */
static inline void
test_deque_zc_copy_from_deque(struct rte_deque_zc_data *zcd, void *dst, int esize,
	unsigned int num)
{
	memcpy(dst, zcd->ptr1, esize * zcd->n1);

	if (zcd->n1 != num) {
		dst = test_deque_inc_ptr(dst, esize, zcd->n1);
		memcpy(dst, zcd->ptr2, esize * (num - zcd->n1));
	}
}

static inline void
test_deque_zc_copy_from_deque_rev(struct rte_deque_zc_data *zcd, void *dst, int esize,
	unsigned int num)
{
	void *ptr1 = zcd->ptr1;
	for (unsigned int i = 0; i < zcd->n1; i++) {
		memcpy(dst, ptr1, esize);
		dst = (void *)((char *)dst + esize);
		ptr1 = (void *)((char *)ptr1 - esize);
	}
	if (zcd->n1 != num) {
		void *ptr2 = zcd->ptr2;
		for (unsigned int i = 0; i < (num - zcd->n1); i++) {
			memcpy(dst, ptr2, esize);
			dst = (void *)((char *)dst + esize);
			ptr2 = (void *)((char *)ptr2 - esize);
		}
	}
}

/* Wrappers around the zero-copy APIs. The wrappers match
 * the normal enqueue/dequeue API declarations.
 */
static unsigned int
test_deque_enqueue_zc_bulk_elem(struct rte_deque *d, const void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *free_space)
{
	uint32_t ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_enqueue_zc_bulk_elem_start(d, esize, n,
						&zcd, free_space);
	if (ret != 0) {
		/* Copy the data to the deque */
		test_deque_zc_copy_to_deque(&zcd, obj_table, esize, ret);
		rte_deque_enqueue_zc_elem_finish(d, ret);
	}

	return ret;
}

static unsigned int
test_deque_dequeue_zc_bulk_elem(struct rte_deque *d, void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *available)
{
	unsigned int ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_dequeue_zc_bulk_elem_start(d, esize, n,
				&zcd, available);
	if (ret != 0) {
		/* Copy the data from the deque */
		test_deque_zc_copy_from_deque(&zcd, obj_table, esize, ret);
		rte_deque_dequeue_zc_elem_finish(d, ret);
	}

	return ret;
}

static unsigned int
test_deque_enqueue_zc_burst_elem(struct rte_deque *d, const void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *free_space)
{
	uint32_t ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_enqueue_zc_burst_elem_start(d, esize, n,
						&zcd, free_space);
	if (ret != 0) {
		/* Copy the data to the deque */
		test_deque_zc_copy_to_deque(&zcd, obj_table, esize, ret);
		rte_deque_enqueue_zc_elem_finish(d, ret);
	}

	return ret;
}

static unsigned int
test_deque_dequeue_zc_burst_elem(struct rte_deque *d, void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *available)
{
	unsigned int ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_dequeue_zc_burst_elem_start(d, esize, n,
				&zcd, available);
	if (ret != 0) {
		/* Copy the data from the deque */
		test_deque_zc_copy_from_deque(&zcd, obj_table, esize, ret);
		rte_deque_dequeue_zc_elem_finish(d, ret);
	}
	return ret;
}

static unsigned int
test_deque_enqueue_zc_bulk_elem_tail(struct rte_deque *d, const void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *free_space)
{
	uint32_t ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_enqueue_zc_bulk_elem_tail_start(d, esize, n,
							&zcd, free_space);
	if (ret != 0) {
		/* Copy the data to the deque */
		test_deque_zc_copy_to_deque_rev(&zcd, obj_table, esize, ret);
		rte_deque_enqueue_zc_elem_tail_finish(d, ret);
	}

	return ret;
}

static unsigned int
test_deque_dequeue_zc_bulk_elem_head(struct rte_deque *d, void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *available)
{
	unsigned int ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_dequeue_zc_bulk_elem_head_start(d, esize, n,
				&zcd, available);
	if (ret != 0) {
		/* Copy the data from the deque */
		test_deque_zc_copy_from_deque_rev(&zcd, obj_table, esize, ret);
		rte_deque_dequeue_zc_elem_head_finish(d, ret);
	}
	return ret;
}

static unsigned int
test_deque_enqueue_zc_burst_elem_tail(struct rte_deque *d,
	const void *obj_table, unsigned int esize, unsigned int n,
	unsigned int *free_space)
{
	uint32_t ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_enqueue_zc_burst_elem_tail_start(d, esize, n,
							&zcd, free_space);
	if (ret != 0) {
		/* Copy the data to the deque */
		test_deque_zc_copy_to_deque_rev(&zcd, obj_table, esize, ret);
		rte_deque_enqueue_zc_elem_tail_finish(d, ret);
	}

	return ret;
}

static unsigned int
test_deque_dequeue_zc_burst_elem_head(struct rte_deque *d, void *obj_table,
	unsigned int esize, unsigned int n, unsigned int *available)
{
	unsigned int ret;
	struct rte_deque_zc_data zcd;

	ret = rte_deque_dequeue_zc_burst_elem_head_start(d, esize, n,
				&zcd, available);
	if (ret != 0) {
		/* Copy the data from the deque */
		test_deque_zc_copy_from_deque_rev(&zcd, obj_table, esize, ret);
		rte_deque_dequeue_zc_elem_head_finish(d, ret);
	}
	return ret;
}

#define TEST_DEQUE_ELEM_BULK 8
#define TEST_DEQUE_ELEM_BURST 16
static const struct {
	const char *desc;
	const int api_flags;
	unsigned int (*enq)(struct rte_deque *d, const void *obj_table,
		unsigned int esize, unsigned int n,
		unsigned int *free_space);
	unsigned int (*deq)(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available);
	/* This dequeues in the opposite direction of enqueue.
	 * This is used for testing stack behavior
	 */
	unsigned int (*deq_opp)(struct rte_deque *d, void *obj_table,
			unsigned int esize, unsigned int n,
			unsigned int *available);
} test_enqdeq_impl[] = {
	{
		.desc = "Deque forward direction bulkmode",
		.api_flags = TEST_DEQUE_ELEM_BULK,
		.enq = rte_deque_enqueue_bulk_elem,
		.deq = rte_deque_dequeue_bulk_elem,
		.deq_opp = rte_deque_dequeue_at_head_bulk_elem,
	},
	{
		.desc = "Deque forward direction burstmode",
		.api_flags = TEST_DEQUE_ELEM_BURST,
		.enq = rte_deque_enqueue_burst_elem,
		.deq = rte_deque_dequeue_burst_elem,
		.deq_opp = rte_deque_dequeue_at_head_burst_elem,
	},
	{
		.desc = "Deque reverse direction bulkmode",
		.api_flags = TEST_DEQUE_ELEM_BULK,
		.enq = rte_deque_enqueue_at_tail_bulk_elem,
		.deq = rte_deque_dequeue_at_head_bulk_elem,
		.deq_opp = rte_deque_dequeue_bulk_elem,
	},
	{
		.desc = "Deque reverse direction burstmode",
		.api_flags = TEST_DEQUE_ELEM_BURST,
		.enq = rte_deque_enqueue_at_tail_burst_elem,
		.deq = rte_deque_dequeue_at_head_burst_elem,
		.deq_opp = rte_deque_dequeue_burst_elem,
	},
	{
		.desc = "Deque forward direction bulkmode zero copy",
		.api_flags = TEST_DEQUE_ELEM_BULK,
		.enq = test_deque_enqueue_zc_bulk_elem,
		.deq = test_deque_dequeue_zc_bulk_elem,
		.deq_opp = test_deque_dequeue_zc_bulk_elem_head,
	},
	{
		.desc = "Deque forward direction burstmode zero copy",
		.api_flags = TEST_DEQUE_ELEM_BURST,
		.enq = test_deque_enqueue_zc_burst_elem,
		.deq = test_deque_dequeue_zc_burst_elem,
		.deq_opp = test_deque_dequeue_zc_burst_elem_head,
	},
	{
		.desc = "Deque reverse direction bulkmode zero copy",
		.api_flags = TEST_DEQUE_ELEM_BULK,
		.enq = test_deque_enqueue_zc_bulk_elem_tail,
		.deq = test_deque_dequeue_zc_bulk_elem_head,
		.deq_opp = test_deque_dequeue_zc_bulk_elem,
	},
	{
		.desc = "Deque reverse direction burstmode zero copy",
		.api_flags = TEST_DEQUE_ELEM_BURST,
		.enq = test_deque_enqueue_zc_burst_elem_tail,
		.deq = test_deque_dequeue_zc_burst_elem_head,
		.deq_opp = test_deque_dequeue_zc_burst_elem,
	},
};

/*
 * Burst and bulk operations in regular mode and zero copy mode.
 * Random number of elements are enqueued and dequeued.
 */
static int
test_deque_burst_bulk_tests1(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	unsigned int ret;
	unsigned int i, j, temp_sz, free_space, available;
	const unsigned int dsz = DEQUE_SIZE - 1;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Over the boundary deque.";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;

		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		printf("Random full/empty test\n");

		for (j = 0; j != TEST_DEQUE_FULL_EMPTY_ITER; j++) {
			/* random shift in the deque */
			int rand = RTE_MAX(rte_rand() % DEQUE_SIZE, 1UL);
			printf("%s: iteration %u, random shift: %u;\n",
				__func__, i, rand);
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
							rand, &free_space);
			TEST_DEQUE_VERIFY(ret == (unsigned int)rand, d, goto fail);

			ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
							rand, &available);
			TEST_DEQUE_VERIFY(ret == (unsigned int)rand, d, goto fail);

			/* fill the deque */
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src,
							esize[i], dsz,
							&free_space);
			TEST_DEQUE_VERIFY(ret == (int)dsz, d, goto fail);

			TEST_DEQUE_VERIFY(rte_deque_free_count(d) == 0, d,
					goto fail);
			TEST_DEQUE_VERIFY(dsz == rte_deque_count(d), d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_full(d), d, goto fail);
			TEST_DEQUE_VERIFY(rte_deque_empty(d) == 0, d, goto fail);

			/* empty the deque */
			ret = test_enqdeq_impl[test_idx].deq(d, cur_dst,
							esize[i], dsz,
							&available);
			TEST_DEQUE_VERIFY(ret == (int)dsz, d, goto fail);

			TEST_DEQUE_VERIFY(dsz == rte_deque_free_count(d), d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_count(d) == 0, d, goto fail);
			TEST_DEQUE_VERIFY(rte_deque_full(d) == 0, d, goto fail);
			TEST_DEQUE_VERIFY(rte_deque_empty(d), d, goto fail);

			/* check data */
			temp_sz = dsz * esize[i];
			TEST_DEQUE_VERIFY(test_deque_mem_cmp(src, dst, temp_sz) == 0,
							d, goto fail);
		}

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/*
 * Burst and bulk operations with regular & zero copy mode.
 * Sequence of simple enqueues/dequeues and validate the enqueued and
 * dequeued data.
 */
static int
test_deque_burst_bulk_tests2(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	int ret;
	unsigned int i, free_space, available;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
		esize[i]);


		/* Create the deque */
		static const char *DEQUE_NAME = "Multiple enqs, deqs.";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;

		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		printf("enqueue 1 obj\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						1, &free_space);
		TEST_DEQUE_VERIFY(ret == 1, d, goto fail);
		cur_src = test_deque_inc_ptr(cur_src, esize[i], 1);

		printf("enqueue 2 objs\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						2, &free_space);
		TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
		cur_src = test_deque_inc_ptr(cur_src, esize[i], 2);

		printf("enqueue MAX_BULK objs\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						MAX_BULK, &free_space);
		TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);

		printf("dequeue 1 obj\n");
		ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
						1, &available);
		TEST_DEQUE_VERIFY(ret == 1, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], 1);

		printf("dequeue 2 objs\n");
		ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
						2, &available);
		TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], 2);

		printf("dequeue MAX_BULK objs\n");
		ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
						MAX_BULK, &available);
		TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], MAX_BULK);

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp(src, dst,
				RTE_PTR_DIFF(cur_dst, dst)) == 0,
				d, goto fail);

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/*
 * Burst and bulk operations with normal mode & zero copy mode.
 * Enqueue and dequeue to cover the entire deque length.
 */
static int
test_deque_burst_bulk_tests3(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	int ret;
	unsigned int i, j, free_space, available;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Full deque length test";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;
		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		printf("fill and empty the deque\n");
		for (j = 0; j < DEQUE_SIZE / MAX_BULK; j++) {
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src,
							esize[i], MAX_BULK,
							&free_space);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i],
								MAX_BULK);

			ret = test_enqdeq_impl[test_idx].deq(d, cur_dst,
							esize[i], MAX_BULK,
							&available);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_dst = test_deque_inc_ptr(cur_dst, esize[i],
								MAX_BULK);
		}

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp(src, dst,
					RTE_PTR_DIFF(cur_dst, dst)) == 0,
					d, goto fail);

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/*
 * Burst and bulk operations with normal mode & zero copy mode.
 * Enqueue till the deque is full and dequeue till the deque becomes empty.
 */
static int
test_deque_burst_bulk_tests4(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	int ret;
	unsigned int i, j, available, free_space;
	unsigned int num_elems, api_type;
	api_type = test_enqdeq_impl[test_idx].api_flags;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Full deque length test";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;
		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		printf("Test enqueue without enough memory space\n");
		for (j = 0; j < (DEQUE_SIZE/MAX_BULK - 1); j++) {
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src,
							esize[i], MAX_BULK,
							&free_space);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i],
								MAX_BULK);
		}

		printf("Enqueue 2 objects, free entries = MAX_BULK - 2\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						2, &free_space);
		TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
		cur_src = test_deque_inc_ptr(cur_src, esize[i], 2);

		printf("Enqueue the remaining entries = MAX_BULK - 3\n");
		/* Bulk APIs enqueue exact number of elements */
		if ((api_type & TEST_DEQUE_ELEM_BULK))
			num_elems = MAX_BULK - 3;
		else
			num_elems = MAX_BULK;
		/* Always one free entry left */
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						num_elems, &free_space);
		TEST_DEQUE_VERIFY(ret == (MAX_BULK - 3), d, goto fail);
		cur_src = test_deque_inc_ptr(cur_src, esize[i],
							(MAX_BULK - 3));

		printf("Test if deque is full\n");
		TEST_DEQUE_VERIFY(rte_deque_full(d) == 1, d, goto fail);

		printf("Test enqueue for a full entry\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						1, &free_space);
		TEST_DEQUE_VERIFY(ret == 0, d, goto fail);

		printf("Test dequeue without enough objects\n");
		for (j = 0; j < DEQUE_SIZE / MAX_BULK - 1; j++) {
			ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
							MAX_BULK, &available);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_dst = test_deque_inc_ptr(cur_dst, esize[i],
						MAX_BULK);
		}

		/* Available memory space for the exact MAX_BULK entries */
		ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
						2, &available);
		TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], 2);

		/* Bulk APIs enqueue exact number of elements */
		if ((api_type & TEST_DEQUE_ELEM_BULK))
			num_elems = MAX_BULK - 3;
		else
			num_elems = MAX_BULK;
		ret = test_enqdeq_impl[test_idx].deq(d, cur_dst, esize[i],
						num_elems, &available);
		TEST_DEQUE_VERIFY(ret == MAX_BULK - 3, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], MAX_BULK - 3);

		printf("Test if deque is empty\n");
		/* Check if deque is empty */
		TEST_DEQUE_VERIFY(rte_deque_empty(d) == 1, d, goto fail);

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp(src, dst,
					RTE_PTR_DIFF(cur_dst, dst)) == 0,
					d, goto fail);

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/*
 * Basic test cases with exact size deque.
 */
static int
test_deque_with_exact_size(void)
{
	struct rte_deque *std_d = NULL, *exact_sz_d = NULL;
	void *src_orig = NULL, *dst_orig = NULL;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	const unsigned int deque_sz = 16;
	unsigned int i, j, free_space, available;
	int ret = -1;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("\nTest exact size deque. Esize: %d\n", esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "std sized deque";
		std_d = rte_deque_create(DEQUE_NAME, esize[i], deque_sz, 0, 0);

		if (std_d == NULL) {
			printf("%s: error, can't create std deque\n", __func__);
			goto test_fail;
		}
		static const char *DEQUE_NAME2 = "Exact sized deque";
		exact_sz_d = rte_deque_create(DEQUE_NAME2, esize[i], deque_sz,
					0, RTE_DEQUE_F_EXACT_SZ);
		if (exact_sz_d == NULL) {
			printf("%s: error, can't create exact size deque\n",
					__func__);
			goto test_fail;
		}

		/* alloc object pointers. Allocate one extra object
		 * and create an unaligned address.
		 */
		src_orig = test_deque_calloc(17, esize[i]);
		if (src_orig == NULL)
			goto test_fail;
		test_deque_mem_init(src_orig, 17, esize[i]);
		src = (void *)((uintptr_t)src_orig + 1);
		cur_src = src;

		dst_orig = test_deque_calloc(17, esize[i]);
		if (dst_orig == NULL)
			goto test_fail;
		dst = (void *)((uintptr_t)dst_orig + 1);
		cur_dst = dst;

		/*
		 * Check that the exact size deque is bigger than the
		 * standard deque
		 */
		TEST_DEQUE_VERIFY(rte_deque_get_size(std_d) <=
				rte_deque_get_size(exact_sz_d),
				std_d, goto test_fail);

		/*
		 * check that the exact_sz_deque can hold one more element
		 * than the standard deque. (16 vs 15 elements)
		 */
		for (j = 0; j < deque_sz - 1; j++) {
			ret = test_enqdeq_impl[0].enq(std_d, cur_src, esize[i],
						1, &free_space);
			TEST_DEQUE_VERIFY(ret == 1, std_d, goto test_fail);
			ret = test_enqdeq_impl[0].enq(exact_sz_d, cur_src,
						esize[i], 1, &free_space);
			TEST_DEQUE_VERIFY(ret == 1, exact_sz_d, goto test_fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i], 1);
		}
		ret = test_enqdeq_impl[0].enq(std_d, cur_src, esize[i], 1,
					&free_space);
		TEST_DEQUE_VERIFY(ret == 0, std_d, goto test_fail);
		ret = test_enqdeq_impl[0].enq(exact_sz_d, cur_src, esize[i], 1,
					&free_space);
		TEST_DEQUE_VERIFY(ret == 1, exact_sz_d, goto test_fail);

		/* check that dequeue returns the expected number of elements */
		ret = test_enqdeq_impl[0].deq(exact_sz_d, cur_dst, esize[i],
					deque_sz, &available);
		TEST_DEQUE_VERIFY(ret == (int)deque_sz, exact_sz_d,
				goto test_fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], deque_sz);

		/* check that the capacity function returns expected value */
		TEST_DEQUE_VERIFY(rte_deque_get_capacity(exact_sz_d) == deque_sz,
				exact_sz_d, goto test_fail);

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp(src, dst,
					RTE_PTR_DIFF(cur_dst, dst)) == 0,
					exact_sz_d, goto test_fail);

		rte_free(src_orig);
		rte_free(dst_orig);
		rte_deque_free(std_d);
		rte_deque_free(exact_sz_d);
		src_orig = NULL;
		dst_orig = NULL;
		std_d = NULL;
		exact_sz_d = NULL;
	}

	return 0;

test_fail:
	rte_free(src_orig);
	rte_free(dst_orig);
	rte_deque_free(std_d);
	rte_deque_free(exact_sz_d);
	return -1;
}

/*
 * Burst and bulk operations in regular mode and zero copy mode.
 * Random number of elements are enqueued and dequeued first.
 * Which would bring both head and tail to somewhere in the middle of
 * the deque. From that point, stack behavior of the deque is tested.
 */
static int
test_deque_stack_random_tests1(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	unsigned int ret;
	unsigned int i, j, free_space, available;
	const unsigned int dsz = DEQUE_SIZE - 1;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("Stackmode tests1.\n");
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Over the boundary deque.";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;

		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		printf("Random starting point stack test\n");

		for (j = 0; j != TEST_DEQUE_FULL_EMPTY_ITER; j++) {
			/* random shift in the deque */
			int rand = RTE_MAX(rte_rand() % DEQUE_SIZE, 1UL);
			printf("%s: iteration %u, random shift: %u;\n",
				__func__, i, rand);
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src,
							esize[i], rand,
							&free_space);
			TEST_DEQUE_VERIFY(ret != 0, d, goto fail);

			ret = test_enqdeq_impl[test_idx].deq(d, cur_dst,
							esize[i], rand,
							&available);
			TEST_DEQUE_VERIFY(ret == (unsigned int)rand, d,
					goto fail);

			/* fill the deque */
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
							dsz, &free_space);
			TEST_DEQUE_VERIFY(ret != 0, d, goto fail);

			TEST_DEQUE_VERIFY(rte_deque_free_count(d) == 0, d,
					goto fail);
			TEST_DEQUE_VERIFY(dsz == rte_deque_count(d), d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_full(d), d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_empty(d) == 0, d,
					goto fail);

			/* empty the deque */
			ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst,
								esize[i], dsz,
								&available);
			TEST_DEQUE_VERIFY(ret == (int)dsz, d, goto fail);

			TEST_DEQUE_VERIFY(dsz == rte_deque_free_count(d), d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_count(d) == 0, d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_full(d) == 0, d,
					goto fail);
			TEST_DEQUE_VERIFY(rte_deque_empty(d), d, goto fail);

			/* check data */
			TEST_DEQUE_VERIFY(test_deque_mem_cmp_rvs(src, dst,
					dsz, esize[i]) == 0, d, goto fail);
		}

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/* Tests both standard mode and zero-copy mode.
 * Keep enqueuing 1, 2, MAX_BULK elements till the deque is full.
 * Then deque them all and make sure the data is opposite of what
 * was enqued.
 */
static int
test_deque_stack_random_tests2(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	unsigned int ret;
	unsigned int i, free_space, available;
	const unsigned int dsz = DEQUE_SIZE - 1;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("Stackmode tests2.\n");
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Multiple enqs, deqs.";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;

		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;


		printf("Enqueue objs till the deque is full.\n");
		unsigned int count = 0;
		const unsigned int perIterCount = 1 + 2 + MAX_BULK;
		while (count + perIterCount < DEQUE_SIZE - 1) {
			ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
							1, &free_space);
			TEST_DEQUE_VERIFY(ret == 1, d, goto fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i], 1);

			ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
							2, &free_space);
			TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i], 2);

			ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
							MAX_BULK, &free_space);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_src = test_deque_inc_ptr(cur_src, esize[i], MAX_BULK);
			count += perIterCount;
		}
		unsigned int leftOver = DEQUE_SIZE - 1 - count;
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						leftOver, &free_space);
		TEST_DEQUE_VERIFY(ret == leftOver, d, goto fail);
		cur_src = test_deque_inc_ptr(cur_src, esize[i], leftOver);

		printf("Deque all the enqued objs.\n");
		count = 0;
		while (count + perIterCount < DEQUE_SIZE - 1) {
			ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst,
							esize[i], 1, &available);
			TEST_DEQUE_VERIFY(ret == 1, d, goto fail);
			cur_dst = test_deque_inc_ptr(cur_dst, esize[i], 1);

			ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst,
								esize[i], 2,
								&available);
			TEST_DEQUE_VERIFY(ret == 2, d, goto fail);
			cur_dst = test_deque_inc_ptr(cur_dst, esize[i], 2);

			ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst,
								esize[i],
								MAX_BULK,
								&available);
			TEST_DEQUE_VERIFY(ret == MAX_BULK, d, goto fail);
			cur_dst = test_deque_inc_ptr(cur_dst, esize[i], MAX_BULK);
			count += perIterCount;
		}
		leftOver = DEQUE_SIZE - 1 - count;
		ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst, esize[i],
							leftOver, &available);
		TEST_DEQUE_VERIFY(ret == leftOver, d, goto fail);
		cur_dst = test_deque_inc_ptr(cur_dst, esize[i], leftOver);

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp_rvs(src, dst,
						dsz, esize[i]) == 0, d,
						goto fail);

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

/*
 * Tests both normal mode and zero-copy mode.
 * Fill up the whole deque, and drain the deque.
 * Make sure the data matches in reverse order.
 */
static int
test_deque_stack_random_tests3(unsigned int test_idx)
{
	struct rte_deque *d;
	void *src = NULL, *cur_src = NULL, *dst = NULL, *cur_dst = NULL;
	int ret;
	unsigned int i, available, free_space;
	const unsigned int dsz = DEQUE_SIZE - 1;

	for (i = 0; i < RTE_DIM(esize); i++) {
		printf("Stackmode tests3.\n");
		printf("\n%s, esize: %d\n", test_enqdeq_impl[test_idx].desc,
			esize[i]);

		/* Create the deque */
		static const char *DEQUE_NAME = "Full deque length test";
		d = rte_deque_create(DEQUE_NAME, esize[i], DEQUE_SIZE, 0, 0);

		/* alloc dummy object pointers */
		src = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (src == NULL)
			goto fail;
		test_deque_mem_init(src, DEQUE_SIZE * 2, esize[i]);
		cur_src = src;

		/* alloc some room for copied objects */
		dst = test_deque_calloc(DEQUE_SIZE * 2, esize[i]);
		if (dst == NULL)
			goto fail;
		cur_dst = dst;

		/* fill the deque */
		printf("Fill the whole deque using 1 "
		"single enqueue operation.\n");
		ret = test_enqdeq_impl[test_idx].enq(d, cur_src, esize[i],
						dsz, &free_space);
		TEST_DEQUE_VERIFY(ret == (int)dsz, d, goto fail);

		TEST_DEQUE_VERIFY(rte_deque_free_count(d) == 0, d, goto fail);
		TEST_DEQUE_VERIFY(dsz == rte_deque_count(d), d, goto fail);
		TEST_DEQUE_VERIFY(rte_deque_full(d), d, goto fail);
		TEST_DEQUE_VERIFY(rte_deque_empty(d) == 0, d, goto fail);

		/* empty the deque */
		printf("Empty the whole deque.\n");
		ret = test_enqdeq_impl[test_idx].deq_opp(d, cur_dst, esize[i],
							dsz, &available);
		TEST_DEQUE_VERIFY(ret == (int)dsz, d, goto fail);

		TEST_DEQUE_VERIFY(dsz == rte_deque_free_count(d), d, goto fail);
		TEST_DEQUE_VERIFY(rte_deque_count(d) == 0, d, goto fail);
		TEST_DEQUE_VERIFY(rte_deque_full(d) == 0, d, goto fail);
		TEST_DEQUE_VERIFY(rte_deque_empty(d), d, goto fail);

		/* check data */
		TEST_DEQUE_VERIFY(test_deque_mem_cmp_rvs(src, dst,
					dsz, esize[i]) == 0, d, goto fail);

		/* Free memory before test completed */
		rte_deque_free(d);
		rte_free(src);
		rte_free(dst);
		d = NULL;
		src = NULL;
		dst = NULL;
	}

	return 0;
fail:
	rte_deque_free(d);
	rte_free(src);
	rte_free(dst);
	return -1;
}

static int
deque_enqueue_dequeue_autotest_fn(void)
{
	if (test_deque_with_exact_size() != 0)
		goto fail;
	int (*test_fns[])(unsigned int test_fn_idx) = {
		test_deque_burst_bulk_tests1,
		test_deque_burst_bulk_tests2,
		test_deque_burst_bulk_tests3,
		test_deque_burst_bulk_tests4,
		test_deque_stack_random_tests1,
		test_deque_stack_random_tests2,
		test_deque_stack_random_tests3
	};
	for (unsigned int test_impl_idx = 0;
		test_impl_idx < RTE_DIM(test_enqdeq_impl); test_impl_idx++) {
		for (unsigned int test_fn_idx = 0;
			test_fn_idx < RTE_DIM(test_fns); test_fn_idx++) {
			if (test_fns[test_fn_idx](test_impl_idx) != 0)
				goto fail;
		}
	}
	return 0;
fail:
		return -1;
}

REGISTER_FAST_TEST(deque_enqueue_dequeue_autotest, true, true,
		deque_enqueue_dequeue_autotest_fn);
