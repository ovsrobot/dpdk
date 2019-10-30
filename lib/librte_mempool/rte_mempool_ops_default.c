/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016 Intel Corporation.
 * Copyright(c) 2016 6WIND S.A.
 * Copyright(c) 2018 Solarflare Communications Inc.
 */

#include <rte_mempool.h>

ssize_t
rte_mempool_op_calc_mem_size_default(const struct rte_mempool *mp,
				     uint32_t obj_num, uint32_t pg_shift,
				     size_t *min_chunk_size, size_t *align)
{
	size_t total_elt_sz;
	size_t obj_per_page, pg_sz, objs_in_last_page;
	size_t mem_size;

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;
	if (total_elt_sz == 0) {
		mem_size = 0;
	} else if (pg_shift == 0) {
		mem_size = total_elt_sz * obj_num;
	} else {
		pg_sz = (size_t)1 << pg_shift;
		obj_per_page = pg_sz / total_elt_sz;
		if (obj_per_page == 0) {
			/*
			 * Note that if object size is bigger than page size,
			 * then it is assumed that pages are grouped in subsets
			 * of physically continuous pages big enough to store
			 * at least one object.
			 */
			mem_size =
				RTE_ALIGN_CEIL(total_elt_sz, pg_sz) * obj_num;
		} else {
			/* In the best case, the allocator will return a
			 * page-aligned address. For example, with 5 objs,
			 * the required space is as below:
			 *  |     page0     |     page1     |  page2 (last) |
			 *  |obj0 |obj1 |xxx|obj2 |obj3 |xxx|obj4|
			 *  <------------- mem_size ------------->
			 */
			objs_in_last_page = ((obj_num - 1) % obj_per_page) + 1;
			/* room required for the last page */
			mem_size = objs_in_last_page * total_elt_sz;
			/* room required for other pages */
			mem_size += ((obj_num - objs_in_last_page) /
				obj_per_page) << pg_shift;

			/* In the worst case, the allocator returns a
			 * non-aligned pointer, wasting up to
			 * total_elt_sz. Add a margin for that.
			 */
			 mem_size += total_elt_sz - 1;
		}
	}

	*min_chunk_size = total_elt_sz;
	*align = RTE_CACHE_LINE_SIZE;

	return mem_size;
}

/* Returns -1 if object crosses a page boundary, else returns 0 */
static int
check_obj_bounds(char *obj, size_t pg_sz, size_t elt_sz)
{
	if (pg_sz == 0)
		return 0;
	if (elt_sz > pg_sz)
		return 0;
	if (RTE_PTR_ALIGN(obj, pg_sz) != RTE_PTR_ALIGN(obj + elt_sz - 1, pg_sz))
		return -1;
	return 0;
}

int
rte_mempool_op_populate_default(struct rte_mempool *mp, unsigned int max_objs,
		void *vaddr, rte_iova_t iova, size_t len,
		rte_mempool_populate_obj_cb_t *obj_cb, void *obj_cb_arg)
{
	char *va = vaddr;
	size_t total_elt_sz, pg_sz;
	size_t off;
	unsigned int i;
	void *obj;
	int ret;

	ret = rte_mempool_get_page_size(mp, &pg_sz);
	if (ret < 0)
		return ret;

	total_elt_sz = mp->header_size + mp->elt_size + mp->trailer_size;

	for (off = 0, i = 0; i < max_objs; i++) {
		/* avoid objects to cross page boundaries */
		if (check_obj_bounds(va + off, pg_sz, total_elt_sz) < 0)
			off += RTE_PTR_ALIGN_CEIL(va + off, pg_sz) - (va + off);

		if (off + total_elt_sz > len)
			break;

		off += mp->header_size;
		obj = va + off;
		obj_cb(mp, obj_cb_arg, obj,
		       (iova == RTE_BAD_IOVA) ? RTE_BAD_IOVA : (iova + off));
		rte_mempool_ops_enqueue_bulk(mp, &obj, 1);
		off += mp->elt_size + mp->trailer_size;
	}

	return i;
}
