/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>

/* API type to call
 * rte_ring_<sp/mp or sc/mc>_enqueue_<bulk/burst>
 * TEST_RING_THREAD_DEF - Uses configured SPSC/MPMC calls
 * TEST_RING_THREAD_SPSC - Calls SP or SC API
 * TEST_RING_THREAD_MPMC - Calls MP or MC API
 */
#define TEST_RING_THREAD_DEF 1
#define TEST_RING_THREAD_SPSC 2
#define TEST_RING_THREAD_MPMC 4

/* API type to call
 * TEST_RING_ELEM_SINGLE - Calls single element APIs
 * TEST_RING_ELEM_BULK - Calls bulk APIs
 * TEST_RING_ELEM_BURST - Calls burst APIs
 */
#define TEST_RING_ELEM_SINGLE 8
#define TEST_RING_ELEM_BULK 16
#define TEST_RING_ELEM_BURST 32

#define TEST_RING_IGNORE_API_TYPE ~0U

/* This function is placed here as it is required for both
 * performance and functional tests.
 */
static inline struct rte_ring*
test_ring_create(const char *name, int esize, unsigned int count,
		int socket_id, unsigned int flags)
{
	/* Legacy queue APIs? */
	if ((esize) == -1)
		return rte_ring_create((name), (count), (socket_id), (flags));
	else
		return rte_ring_create_elem((name), (esize), (count),
						(socket_id), (flags));
}

static __rte_always_inline unsigned int
test_ring_enqueue(struct rte_ring *r, void **obj, int esize, unsigned int n,
			unsigned int api_type)
{
	/* Legacy queue APIs? */
	if ((esize) == -1)
		switch (api_type) {
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_SINGLE):
			return rte_ring_enqueue(r, *obj);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_SINGLE):
			return rte_ring_sp_enqueue(r, *obj);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_SINGLE):
			return rte_ring_mp_enqueue(r, *obj);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BULK):
			return rte_ring_enqueue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BULK):
			return rte_ring_sp_enqueue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BULK):
			return rte_ring_mp_enqueue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BURST):
			return rte_ring_enqueue_burst(r, obj, n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BURST):
			return rte_ring_sp_enqueue_burst(r, obj, n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BURST):
			return rte_ring_mp_enqueue_burst(r, obj, n, NULL);
		default:
			printf("Invalid API type\n");
			return 0;
		}
	else
		switch (api_type) {
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_SINGLE):
			return rte_ring_enqueue_elem(r, obj, esize);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_SINGLE):
			return rte_ring_sp_enqueue_elem(r, obj, esize);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_SINGLE):
			return rte_ring_mp_enqueue_elem(r, obj, esize);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BULK):
			return rte_ring_enqueue_bulk_elem(r, obj, esize, n,
								NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BULK):
			return rte_ring_sp_enqueue_bulk_elem(r, obj, esize, n,
								NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BULK):
			return rte_ring_mp_enqueue_bulk_elem(r, obj, esize, n,
								NULL);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BURST):
			return rte_ring_enqueue_burst_elem(r, obj, esize, n,
								NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BURST):
			return rte_ring_sp_enqueue_burst_elem(r, obj, esize, n,
								NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BURST):
			return rte_ring_mp_enqueue_burst_elem(r, obj, esize, n,
								NULL);
		default:
			printf("Invalid API type\n");
			return 0;
		}
}

static __rte_always_inline unsigned int
test_ring_dequeue(struct rte_ring *r, void **obj, int esize, unsigned int n,
			unsigned int api_type)
{
	/* Legacy queue APIs? */
	if ((esize) == -1)
		switch (api_type) {
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_SINGLE):
			return rte_ring_dequeue(r, obj);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_SINGLE):
			return rte_ring_sc_dequeue(r, obj);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_SINGLE):
			return rte_ring_mc_dequeue(r, obj);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BULK):
			return rte_ring_dequeue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BULK):
			return rte_ring_sc_dequeue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BULK):
			return rte_ring_mc_dequeue_bulk(r, obj, n, NULL);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BURST):
			return rte_ring_dequeue_burst(r, obj, n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BURST):
			return rte_ring_sc_dequeue_burst(r, obj, n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BURST):
			return rte_ring_mc_dequeue_burst(r, obj, n, NULL);
		default:
			printf("Invalid API type\n");
			return 0;
		}
	else
		switch (api_type) {
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_SINGLE):
			return rte_ring_dequeue_elem(r, obj, esize);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_SINGLE):
			return rte_ring_sc_dequeue_elem(r, obj, esize);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_SINGLE):
			return rte_ring_mc_dequeue_elem(r, obj, esize);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BULK):
			return rte_ring_dequeue_bulk_elem(r, obj, esize,
								n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BULK):
			return rte_ring_sc_dequeue_bulk_elem(r, obj, esize,
								n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BULK):
			return rte_ring_mc_dequeue_bulk_elem(r, obj, esize,
								n, NULL);
		case (TEST_RING_THREAD_DEF | TEST_RING_ELEM_BURST):
			return rte_ring_dequeue_burst_elem(r, obj, esize,
								n, NULL);
		case (TEST_RING_THREAD_SPSC | TEST_RING_ELEM_BURST):
			return rte_ring_sc_dequeue_burst_elem(r, obj, esize,
								n, NULL);
		case (TEST_RING_THREAD_MPMC | TEST_RING_ELEM_BURST):
			return rte_ring_mc_dequeue_burst_elem(r, obj, esize,
								n, NULL);
		default:
			printf("Invalid API type\n");
			return 0;
		}
}

/* This function is placed here as it is required for both
 * performance and functional tests.
 */
static __rte_always_inline void *
test_ring_calloc(unsigned int rsize, int esize)
{
	unsigned int sz;
	void *p;

	/* Legacy queue APIs? */
	if (esize == -1)
		sz = sizeof(void *);
	else
		sz = esize;

	p = rte_zmalloc(NULL, rsize * sz, RTE_CACHE_LINE_SIZE);
	if (p == NULL)
		printf("Failed to allocate memory\n");

	return p;
}
