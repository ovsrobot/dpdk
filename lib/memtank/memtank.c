/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 * Copyright(c) 2025 Huawei Technologies Co., Ltd
 */

#include "memtank.h"
#include <rte_bitops.h>
#include <rte_errno.h>
#include <eal_export.h>

#define MEMTANK_OBJ_BULK	0x100
#define MEMTANK_CHUNK_BULK	0x100

#define	ALIGN_MUL_CEIL(v, mul)	\
	((typeof(v))(((uint64_t)(v) + (mul) - 1) / (mul)))


static inline size_t
memtank_meta_size(uint32_t nb_free)
{
	size_t sz;
	static const struct rte_memtank *mt;

	sz = sizeof(*mt) + nb_free * sizeof(mt->mtf.free[0]);
	sz = RTE_ALIGN_CEIL(sz, alignof(typeof(*mt)));
	return sz;
}

static inline size_t
memchunk_meta_size(uint32_t nb_obj)
{
	size_t sz;
	static const struct memchunk *ch;

	sz = sizeof(*ch) +  nb_obj * sizeof(ch->free[0]);
	sz = RTE_ALIGN_CEIL(sz, alignof(typeof(*ch)));
	return sz;
}

static inline size_t
memobj_size(uint32_t obj_size, uint32_t obj_align)
{
	size_t sz;
	static const struct memobj *obj;

	sz = sizeof(*obj) + obj_size;
	sz = RTE_ALIGN_CEIL(sz, obj_align);
	return sz;
}

static inline size_t
memchunk_size(uint32_t nb_obj, uint32_t obj_size, uint32_t obj_align)
{
	size_t algn, sz;
	static const struct memchunk *ch;

	algn = RTE_MAX(alignof(typeof(*ch)), obj_align);
	sz = memchunk_meta_size(nb_obj);
	sz += nb_obj * memobj_size(obj_size, obj_align);
	sz = RTE_ALIGN_CEIL(sz + algn - 1, algn);
	return sz;
}

static void
init_chunk(struct rte_memtank *mt, struct memchunk *ch)
{
	uint32_t i, n, sz;
	uintptr_t p;
	struct memobj *obj;

	const struct memobj cobj = {
		.red_zone1 = RED_ZONE_V1,
		.chunk = ch,
		.red_zone2 = RED_ZONE_V2,
	};

	n = mt->prm.nb_obj_chunk;
	sz = mt->obj_size;

	/* get start of memobj array */
	p = (uintptr_t)ch + memchunk_meta_size(n);
	p = RTE_ALIGN_CEIL(p, mt->prm.obj_align);

	for (i = 0; i != n; i++) {
		obj = obj_pub_full(p, sz);
		obj[0] = cobj;
		ch->free[i] = (void *)p;
		p += sz;
	}

	ch->nb_total = n;
	ch->nb_free = n;

	if (mt->prm.init != NULL)
		mt->prm.init(ch->free, n, mt->prm.udata);
}

static __rte_always_inline void
copy_objs(void *dst[], void * const src[], uint32_t num)
{
	memcpy(dst, src, num * sizeof(dst[0]));
}

static inline uint32_t
get_free(struct memtank_free *t, void *obj[], uint32_t num)
{
	uint32_t len, n;

	rte_spinlock_lock(&t->lock);

	len = t->nb_free;
	n = RTE_MIN(num, len);
	len -= n;
	copy_objs(obj, t->free + len, n);
	t->nb_free = len;

	rte_spinlock_unlock(&t->lock);
	return n;
}

static inline uint32_t
put_free(struct memtank_free *t, void * const obj[], uint32_t num)
{
	uint32_t len, n;

	rte_spinlock_lock(&t->lock);

	len = t->nb_free;
	n = t->max_free - len;
	n = RTE_MIN(num, n);
	copy_objs(t->free + len, obj, n);
	t->nb_free = len + n;

	rte_spinlock_unlock(&t->lock);
	return n;
}

static inline void
fill_free(struct rte_memtank *mt, uint32_t num, uint32_t flags)
{
	uint32_t i, l, k, n;
	void *free[MEMTANK_OBJ_BULK];

	for (i = 0; i != num; i += n) {
		/* how many objects we need to add into @free */
		n = RTE_MIN(num - i, RTE_DIM(free));
		k = rte_memtank_chunk_alloc(mt, free, n, flags);
		l = put_free(&mt->mtf, free, k);

		/* @free is full, return allocated objects back to chunks */
		if (l != k)
			rte_memtank_chunk_free(mt, free + l, k - l, 0);

		/* either free is full, or chunks are empty */
		if (l != n)
			break;
	}
}

static void
put_chunk(struct rte_memtank *mt, struct memchunk *ch, void * const obj[],
	uint32_t num)
{
	uint32_t k, n;
	struct mchunk_list *ls;

	/* chunk should be in the *used* list */
	k = MC_USED;
	ls = &mt->chl[k];
	rte_spinlock_lock(&ls->lock);

	n = ch->nb_free;
	RTE_ASSERT(n + num <= ch->nb_total);

	copy_objs(ch->free + n, obj, num);
	ch->nb_free = n + num;

	/* chunk is full now */
	if (ch->nb_free == ch->nb_total) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		k = MC_FULL;
	/* chunk is not empty anymore, move it to the head */
	} else if (n == 0) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		TAILQ_INSERT_HEAD(&ls->chunk, ch, link);
	}

	rte_spinlock_unlock(&ls->lock);

	/* insert this chunk into the *full* list */
	if (k == MC_FULL) {
		ls = &mt->chl[k];
		rte_spinlock_lock(&ls->lock);
		TAILQ_INSERT_HEAD(&ls->chunk, ch, link);
		rte_spinlock_unlock(&ls->lock);
	}
}

static inline uint32_t
_shrink_chunk(struct rte_memtank *mt, struct memchunk *ch[MEMTANK_CHUNK_BULK],
	uint32_t num)
{
	uint32_t i, k;
	struct mchunk_list *ls;

	ls = &mt->chl[MC_FULL];
	rte_spinlock_lock(&ls->lock);

	for (k = 0; k != num; k++) {
		ch[k] = TAILQ_LAST(&ls->chunk, mchunk_head);
		if (ch[k] == NULL)
			break;
		TAILQ_REMOVE(&ls->chunk, ch[k], link);
	}

	rte_spinlock_unlock(&ls->lock);

	rte_atomic_fetch_sub_explicit(&mt->nb_chunks, k,
		rte_memory_order_acq_rel);

	for (i = 0; i != k; i++)
		mt->prm.free(ch[i]->raw, mt->prm.udata);

	return k;
}


static uint32_t
shrink_chunk(struct rte_memtank *mt, uint32_t num)
{
	uint32_t i, k, n;
	struct memchunk *ch[MEMTANK_CHUNK_BULK];

	k = 0;
	n = 0;
	for (i = 0; i != num && n != k; i += k) {
		n = RTE_MIN(num - i, RTE_DIM(ch));
		k = _shrink_chunk(mt, ch, n);
	}

	return i;
}

static struct memchunk *
alloc_chunk(struct rte_memtank *mt)
{
	void *p;
	struct memchunk *ch;

	p = mt->prm.alloc(mt->chunk_size, mt->prm.udata);
	if (p == NULL)
		return NULL;
	ch = RTE_PTR_ALIGN_CEIL(p, alignof(typeof(*ch)));
	ch->raw = p;
	return ch;
}

/* Determine by how many chunks we can actually grow */
static inline uint32_t
grow_num(struct rte_memtank *mt, uint32_t num)
{
	uint32_t k, n, max;

	max = mt->max_chunk;
	n = num + rte_atomic_fetch_add_explicit(&mt->nb_chunks, num,
			rte_memory_order_acq_rel);

	if (n <= max)
		return num;

	k = n - max;
	return (k >= num) ? 0 : num - k;
}

static uint32_t
grow_chunk(struct rte_memtank *mt, uint32_t num)
{
	uint32_t k, n;
	struct mchunk_list *fls;
	struct mchunk_head ls;
	struct memchunk *ch;

	/* check can we grow further */
	k = grow_num(mt, num);

	TAILQ_INIT(&ls);

	for (n = 0; n != k; n++) {
		ch = alloc_chunk(mt);
		if (ch == NULL)
			break;
		init_chunk(mt, ch);
		TAILQ_INSERT_HEAD(&ls, ch, link);
	}

	if (n != 0) {
		fls = &mt->chl[MC_FULL];
		rte_spinlock_lock(&fls->lock);
		TAILQ_CONCAT(&fls->chunk, &ls, link);
		rte_spinlock_unlock(&fls->lock);
	}

	if (n != num)
		rte_atomic_fetch_sub_explicit(&mt->nb_chunks, num - n,
			rte_memory_order_acq_rel);

	return n;
}

static void
obj_dbg_alloc(struct rte_memtank *mt, void * const obj[], uint32_t nb_obj)
{
	uint32_t i, sz;
	struct memobj *po;

	sz = mt->obj_size;
	for (i = 0; i != nb_obj; i++) {
		po = obj_pub_full((uintptr_t)obj[i], sz);
		RTE_VERIFY(memobj_verify(po, 0) == 0);
		po->dbg.nb_alloc++;
	}
}

static void
obj_dbg_free(struct rte_memtank *mt, void * const obj[], uint32_t nb_obj)
{
	uint32_t i, sz;
	struct memobj *po;

	sz = mt->obj_size;
	for (i = 0; i != nb_obj; i++) {
		po = obj_pub_full((uintptr_t)obj[i], sz);
		RTE_VERIFY(memobj_verify(po, 1) == 0);
		po->dbg.nb_free++;
	}
}


RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_chunk_free, 26.11)
void
rte_memtank_chunk_free(struct rte_memtank *mt, void * const obj[],
	uint32_t nb_obj, uint32_t flags)
{
	size_t csz;
	uint32_t i, j, k, osz;
	struct memobj *mo;
	struct memchunk *ch;

	csz = mt->chunk_size;
	osz = mt->obj_size;

	if (mt->flags & RTE_MTANK_OBJ_DBG)
		obj_dbg_free(mt, obj, nb_obj);

	k = 0;
	for (i = 0; i != nb_obj; i = j) {

		mo = obj_pub_full((uintptr_t)obj[i], osz);
		ch = mo->chunk;

		/* find number of consequtive objs from the same chunk */
		for (j = i + 1; j != nb_obj; j++) {
			if (obj_check_chunk((uintptr_t)obj[j], osz,
					(uintptr_t)ch, csz) != 0)
				break;
			RTE_ASSERT(ch ==
				obj_pub_full((uintptr_t)obj[j], osz)->chunk);
		}

		put_chunk(mt, ch, obj + i, j - i);
		k++;
	}

	if (flags & RTE_MTANK_FREE_SHRINK)
		shrink_chunk(mt, k);
}

static uint32_t
get_chunk(struct mchunk_list *ls, struct mchunk_head *els,
	struct mchunk_head *uls, void *obj[], uint32_t nb_obj)
{
	uint32_t l, k, n;
	struct memchunk *ch, *nch;

	rte_spinlock_lock(&ls->lock);

	n = 0;
	for (ch = TAILQ_FIRST(&ls->chunk);
			n != nb_obj && ch != NULL && ch->nb_free != 0;
			ch = nch, n += k) {

		k = RTE_MIN(nb_obj - n, ch->nb_free);
		l = ch->nb_free - k;
		copy_objs(obj + n, ch->free + l, k);
		ch->nb_free = l;

		nch = TAILQ_NEXT(ch, link);

		/* chunk is empty now */
		if (l == 0) {
			TAILQ_REMOVE(&ls->chunk, ch, link);
			TAILQ_INSERT_TAIL(els, ch, link);
		} else if (uls != NULL) {
			TAILQ_REMOVE(&ls->chunk, ch, link);
			TAILQ_INSERT_HEAD(uls, ch, link);
		}
	}

	rte_spinlock_unlock(&ls->lock);
	return n;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_chunk_alloc, 26.11)
uint32_t
rte_memtank_chunk_alloc(struct rte_memtank *mt, void *obj[], uint32_t nb_obj,
	uint32_t flags)
{
	uint32_t k, n;
	struct mchunk_head els, uls;

	/* walk though the *used* list first */
	n = get_chunk(&mt->chl[MC_USED], &mt->chl[MC_USED].chunk, NULL,
		obj, nb_obj);

	if (n != nb_obj) {

		TAILQ_INIT(&els);
		TAILQ_INIT(&uls);

		/* walk though the *full* list */
		n += get_chunk(&mt->chl[MC_FULL], &els, &uls,
			obj + n, nb_obj - n);

		if (n != nb_obj && (flags & RTE_MTANK_ALLOC_GROW) != 0) {

			/*
			 * try to allocate extra memchunks.
			 * note that at rare situations with really high load
			 * when number of allocated chunks is close to the
			 * max allowed limit, when multiple threads are
			 * trying to do grow_chunk() simultaneously, it
			 * can fail for some of them leading to a failure
			 * to allocate new elements.
			 */
			k = ALIGN_MUL_CEIL(nb_obj - n,
				mt->prm.nb_obj_chunk);
			k = grow_chunk(mt, k);

			/* walk through the *full* list again */
			if (k != 0)
				n += get_chunk(&mt->chl[MC_FULL], &els, &uls,
					obj + n, nb_obj - n);
		}

		/* concatenate with *used* list our temporary lists */
		rte_spinlock_lock(&mt->chl[MC_USED].lock);

		/* put new non-emtpy elems at head of the *used* list */
		TAILQ_CONCAT(&uls, &mt->chl[MC_USED].chunk, link);
		TAILQ_CONCAT(&mt->chl[MC_USED].chunk, &uls, link);

		/* put new emtpy elems at tail of the *used* list */
		TAILQ_CONCAT(&mt->chl[MC_USED].chunk, &els, link);

		rte_spinlock_unlock(&mt->chl[MC_USED].lock);
	}

	if (mt->flags & RTE_MTANK_OBJ_DBG)
		obj_dbg_alloc(mt, obj, n);

	return n;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_grow, 26.11)
int
rte_memtank_grow(struct rte_memtank *mt)
{
	uint32_t k, n, num;
	struct memtank_free *t;

	t = &mt->mtf;

	/* how many chunks we need to grow */
	k = t->min_free - t->nb_free;
	if ((int32_t)k <= 0)
		return 0;

	num = ALIGN_MUL_CEIL(k, mt->prm.nb_obj_chunk);

	/* try to grow and refill the *free* */
	n = grow_chunk(mt, num);
	if (n != 0)
		fill_free(mt, k, 0);

	return n;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_shrink, 26.11)
int
rte_memtank_shrink(struct rte_memtank *mt)
{
	uint32_t n;
	struct memtank_free *t;

	t = &mt->mtf;

	/* how many chunks we need to shrink */
	if (t->nb_free < t->max_free)
		return 0;

	/* how many chunks we need to free */
	n = ALIGN_MUL_CEIL(t->min_free, mt->prm.nb_obj_chunk);

	/* free up to *num* chunks */
	return shrink_chunk(mt, n);
}

static int
check_param(const struct rte_memtank_prm *prm)
{
	if (prm->alloc == NULL || prm->free == NULL ||
			prm->min_free > prm->max_free ||
			prm->max_free > prm->max_obj ||
			rte_is_power_of_2(prm->obj_align) == 0 ||
			prm->min_free == 0 ||
			prm->nb_obj_chunk == 0)
		return -EINVAL;
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_create, 26.11)
struct rte_memtank *
rte_memtank_create(const struct rte_memtank_prm *prm)
{
	int32_t rc;
	size_t sz;
	void *p;
	struct rte_memtank *mt;

	rc = check_param(prm);
	if (rc != 0) {
		rte_errno = -rc;
		return NULL;
	}

	sz = memtank_meta_size(prm->max_free);
	p = prm->alloc(sz, prm->udata);
	if (p == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	mt = RTE_PTR_ALIGN_CEIL(p, alignof(typeof(*mt)));

	memset(mt, 0, sizeof(*mt));
	mt->prm = *prm;

	mt->raw = p;
	mt->chunk_size = memchunk_size(prm->nb_obj_chunk, prm->obj_size,
		prm->obj_align);
	mt->obj_size = memobj_size(prm->obj_size, prm->obj_align);
	mt->max_chunk = ALIGN_MUL_CEIL(prm->max_obj, prm->nb_obj_chunk);
	mt->flags = prm->flags;

	mt->mtf.min_free = prm->min_free;
	mt->mtf.max_free = prm->max_free;

	TAILQ_INIT(&mt->chl[MC_FULL].chunk);
	TAILQ_INIT(&mt->chl[MC_USED].chunk);

	return mt;
}

static void
free_mchunk_list(struct rte_memtank *mt, struct mchunk_list *ls)
{
	struct memchunk *ch;

	for (ch = TAILQ_FIRST(&ls->chunk); ch != NULL;
			ch = TAILQ_FIRST(&ls->chunk)) {
		TAILQ_REMOVE(&ls->chunk, ch, link);
		mt->prm.free(ch->raw, mt->prm.udata);
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_destroy, 26.11)
void
rte_memtank_destroy(struct rte_memtank *mt)
{
	if (mt != NULL) {
		free_mchunk_list(mt, &mt->chl[MC_FULL]);
		free_mchunk_list(mt, &mt->chl[MC_USED]);
		mt->prm.free(mt->raw, mt->prm.udata);
	}
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_alloc, 26.11)
uint32_t
rte_memtank_alloc(struct rte_memtank *mt, void *obj[], uint32_t num,
	uint32_t flags)
{
	uint32_t n;
	struct memtank_free *t;

	t = &mt->mtf;
	n = get_free(t, obj, num);

	/* not enough free objects, try to allocate via memchunks */
	if (n != num && flags != 0) {
		n += rte_memtank_chunk_alloc(mt, obj + n, num - n, flags);

		/* refill *free* tank */
		if (n == num)
			fill_free(mt, t->min_free, flags);
	}

	return n;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_memtank_free, 26.11)
void
rte_memtank_free(struct rte_memtank *t, void * const obj[], uint32_t num,
	uint32_t flags)
{
	uint32_t n;

	n = put_free(&t->mtf, obj, num);
	if (n != num)
		rte_memtank_chunk_free(t, obj + n, num - n, flags);
}
