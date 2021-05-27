/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#include <rte_malloc.h>

#include <mlx5_malloc.h>

#include "mlx5_utils.h"


/********************* Cache list ************************/

static struct mlx5_cache_entry *
mlx5_clist_default_create_cb(struct mlx5_cache_list *list,
			     struct mlx5_cache_entry *entry __rte_unused,
			     void *ctx __rte_unused)
{
	return mlx5_malloc(MLX5_MEM_ZERO, list->entry_sz, 0, SOCKET_ID_ANY);
}

static void
mlx5_clist_default_remove_cb(struct mlx5_cache_list *list __rte_unused,
			     struct mlx5_cache_entry *entry)
{
	mlx5_free(entry);
}

int
mlx5_cache_list_init(struct mlx5_cache_list *list, const char *name,
		     uint32_t entry_size, void *ctx,
		     mlx5_cache_create_cb cb_create,
		     mlx5_cache_match_cb cb_match,
		     mlx5_cache_remove_cb cb_remove)
{
	MLX5_ASSERT(list);
	if (!cb_match || (!cb_create ^ !cb_remove))
		return -1;
	if (name)
		snprintf(list->name, sizeof(list->name), "%s", name);
	list->entry_sz = entry_size;
	list->ctx = ctx;
	list->cb_create = cb_create ? cb_create : mlx5_clist_default_create_cb;
	list->cb_match = cb_match;
	list->cb_remove = cb_remove ? cb_remove : mlx5_clist_default_remove_cb;
	rte_rwlock_init(&list->lock);
	DRV_LOG(DEBUG, "Cache list %s initialized.", list->name);
	LIST_INIT(&list->head);
	return 0;
}

static struct mlx5_cache_entry *
__cache_lookup(struct mlx5_cache_list *list, void *ctx, bool reuse)
{
	struct mlx5_cache_entry *entry;

	LIST_FOREACH(entry, &list->head, next) {
		if (list->cb_match(list, entry, ctx))
			continue;
		if (reuse) {
			__atomic_add_fetch(&entry->ref_cnt, 1,
					   __ATOMIC_RELAXED);
			DRV_LOG(DEBUG, "Cache list %s entry %p ref++: %u.",
				list->name, (void *)entry, entry->ref_cnt);
		}
		break;
	}
	return entry;
}

static struct mlx5_cache_entry *
cache_lookup(struct mlx5_cache_list *list, void *ctx, bool reuse)
{
	struct mlx5_cache_entry *entry;

	rte_rwlock_read_lock(&list->lock);
	entry = __cache_lookup(list, ctx, reuse);
	rte_rwlock_read_unlock(&list->lock);
	return entry;
}

struct mlx5_cache_entry *
mlx5_cache_lookup(struct mlx5_cache_list *list, void *ctx)
{
	return cache_lookup(list, ctx, false);
}

struct mlx5_cache_entry *
mlx5_cache_register(struct mlx5_cache_list *list, void *ctx)
{
	struct mlx5_cache_entry *entry;
	uint32_t prev_gen_cnt = 0;

	MLX5_ASSERT(list);
	prev_gen_cnt = __atomic_load_n(&list->gen_cnt, __ATOMIC_ACQUIRE);
	/* Lookup with read lock, reuse if found. */
	entry = cache_lookup(list, ctx, true);
	if (entry)
		return entry;
	/* Not found, append with write lock - block read from other threads. */
	rte_rwlock_write_lock(&list->lock);
	/* If list changed by other threads before lock, search again. */
	if (prev_gen_cnt != __atomic_load_n(&list->gen_cnt, __ATOMIC_ACQUIRE)) {
		/* Lookup and reuse w/o read lock. */
		entry = __cache_lookup(list, ctx, true);
		if (entry)
			goto done;
	}
	entry = list->cb_create(list, entry, ctx);
	if (!entry) {
		DRV_LOG(ERR, "Failed to init cache list %s entry %p.",
			list->name, (void *)entry);
		goto done;
	}
	entry->ref_cnt = 1;
	LIST_INSERT_HEAD(&list->head, entry, next);
	__atomic_add_fetch(&list->gen_cnt, 1, __ATOMIC_RELEASE);
	__atomic_add_fetch(&list->count, 1, __ATOMIC_ACQUIRE);
	DRV_LOG(DEBUG, "Cache list %s entry %p new: %u.",
		list->name, (void *)entry, entry->ref_cnt);
done:
	rte_rwlock_write_unlock(&list->lock);
	return entry;
}

int
mlx5_cache_unregister(struct mlx5_cache_list *list,
		      struct mlx5_cache_entry *entry)
{
	rte_rwlock_write_lock(&list->lock);
	MLX5_ASSERT(entry && entry->next.le_prev);
	DRV_LOG(DEBUG, "Cache list %s entry %p ref--: %u.",
		list->name, (void *)entry, entry->ref_cnt);
	if (--entry->ref_cnt) {
		rte_rwlock_write_unlock(&list->lock);
		return 1;
	}
	__atomic_add_fetch(&list->gen_cnt, 1, __ATOMIC_ACQUIRE);
	__atomic_sub_fetch(&list->count, 1, __ATOMIC_ACQUIRE);
	LIST_REMOVE(entry, next);
	list->cb_remove(list, entry);
	rte_rwlock_write_unlock(&list->lock);
	DRV_LOG(DEBUG, "Cache list %s entry %p removed.",
		list->name, (void *)entry);
	return 0;
}

void
mlx5_cache_list_destroy(struct mlx5_cache_list *list)
{
	struct mlx5_cache_entry *entry;

	MLX5_ASSERT(list);
	/* no LIST_FOREACH_SAFE, using while instead */
	while (!LIST_EMPTY(&list->head)) {
		entry = LIST_FIRST(&list->head);
		LIST_REMOVE(entry, next);
		list->cb_remove(list, entry);
		DRV_LOG(DEBUG, "Cache list %s entry %p destroyed.",
			list->name, (void *)entry);
	}
	memset(list, 0, sizeof(*list));
}

uint32_t
mlx5_cache_list_get_entry_num(struct mlx5_cache_list *list)
{
	MLX5_ASSERT(list);
	return __atomic_load_n(&list->count, __ATOMIC_RELAXED);
}

/********************* Indexed pool **********************/

static inline void
mlx5_ipool_lock(struct mlx5_indexed_pool *pool)
{
	if (pool->cfg.need_lock)
		rte_spinlock_lock(&pool->lock);
}

static inline void
mlx5_ipool_unlock(struct mlx5_indexed_pool *pool)
{
	if (pool->cfg.need_lock)
		rte_spinlock_unlock(&pool->lock);
}

static inline uint32_t
mlx5_trunk_idx_get(struct mlx5_indexed_pool *pool, uint32_t entry_idx)
{
	struct mlx5_indexed_pool_config *cfg = &pool->cfg;
	uint32_t trunk_idx = 0;
	uint32_t i;

	if (!cfg->grow_trunk)
		return entry_idx / cfg->trunk_size;
	if (entry_idx >= pool->grow_tbl[cfg->grow_trunk - 1]) {
		trunk_idx = (entry_idx - pool->grow_tbl[cfg->grow_trunk - 1]) /
			    (cfg->trunk_size << (cfg->grow_shift *
			    cfg->grow_trunk)) + cfg->grow_trunk;
	} else {
		for (i = 0; i < cfg->grow_trunk; i++) {
			if (entry_idx < pool->grow_tbl[i])
				break;
		}
		trunk_idx = i;
	}
	return trunk_idx;
}

static inline uint32_t
mlx5_trunk_size_get(struct mlx5_indexed_pool *pool, uint32_t trunk_idx)
{
	struct mlx5_indexed_pool_config *cfg = &pool->cfg;

	return cfg->trunk_size << (cfg->grow_shift *
	       (trunk_idx > cfg->grow_trunk ? cfg->grow_trunk : trunk_idx));
}

static inline uint32_t
mlx5_trunk_idx_offset_get(struct mlx5_indexed_pool *pool, uint32_t trunk_idx)
{
	struct mlx5_indexed_pool_config *cfg = &pool->cfg;
	uint32_t offset = 0;

	if (!trunk_idx)
		return 0;
	if (!cfg->grow_trunk)
		return cfg->trunk_size * trunk_idx;
	if (trunk_idx < cfg->grow_trunk)
		offset = pool->grow_tbl[trunk_idx - 1];
	else
		offset = pool->grow_tbl[cfg->grow_trunk - 1] +
			 (cfg->trunk_size << (cfg->grow_shift *
			 cfg->grow_trunk)) * (trunk_idx - cfg->grow_trunk);
	return offset;
}

struct mlx5_indexed_pool *
mlx5_ipool_create(struct mlx5_indexed_pool_config *cfg)
{
	struct mlx5_indexed_pool *pool;
	uint32_t i;

	if (!cfg || (!cfg->malloc ^ !cfg->free) ||
	    (cfg->trunk_size && ((cfg->trunk_size & (cfg->trunk_size - 1)) ||
	    ((__builtin_ffs(cfg->trunk_size) + TRUNK_IDX_BITS) > 32))))
		return NULL;
	pool = mlx5_malloc(MLX5_MEM_ZERO, sizeof(*pool) + cfg->grow_trunk *
			   sizeof(pool->grow_tbl[0]), RTE_CACHE_LINE_SIZE,
			   SOCKET_ID_ANY);
	if (!pool)
		return NULL;
	pool->cfg = *cfg;
	if (!pool->cfg.trunk_size)
		pool->cfg.trunk_size = MLX5_IPOOL_DEFAULT_TRUNK_SIZE;
	if (!cfg->malloc && !cfg->free) {
		pool->cfg.malloc = mlx5_malloc;
		pool->cfg.free = mlx5_free;
	}
	pool->free_list = TRUNK_INVALID;
	if (pool->cfg.need_lock)
		rte_spinlock_init(&pool->lock);
	/*
	 * Initialize the dynamic grow trunk size lookup table to have a quick
	 * lookup for the trunk entry index offset.
	 */
	for (i = 0; i < cfg->grow_trunk; i++) {
		pool->grow_tbl[i] = cfg->trunk_size << (cfg->grow_shift * i);
		if (i > 0)
			pool->grow_tbl[i] += pool->grow_tbl[i - 1];
	}
	if (!pool->cfg.max_idx)
		pool->cfg.max_idx =
			mlx5_trunk_idx_offset_get(pool, TRUNK_MAX_IDX + 1);
	if (cfg->per_core_cache) {
		char cache_name[64] = { 0 };

		for (i = 0; i < MLX5_IPOOL_MAX_CORES; i++) {
			snprintf(cache_name, RTE_DIM(cache_name),
				 "Ipool_cache-%p-%u", (void *)pool, i);
			pool->l_idx_c[i] = rte_ring_create(cache_name,
				cfg->per_core_cache, SOCKET_ID_ANY,
				RING_F_SC_DEQ | RING_F_SP_ENQ);
			if (!pool->l_idx_c[i]) {
				printf("Ipool allocate ring failed:%d\n", i);
				mlx5_free(pool);
				return NULL;
			}
		}
	}
	return pool;
}

static int
mlx5_ipool_grow(struct mlx5_indexed_pool *pool)
{
	struct mlx5_indexed_trunk *trunk;
	struct mlx5_indexed_trunk **trunk_tmp;
	struct mlx5_indexed_trunk **p;
	size_t trunk_size = 0;
	size_t data_size;
	size_t bmp_size;
	uint32_t idx, cur_max_idx, i;

	cur_max_idx = mlx5_trunk_idx_offset_get(pool, pool->n_trunk_valid);
	if (pool->n_trunk_valid == TRUNK_MAX_IDX ||
	    cur_max_idx >= pool->cfg.max_idx)
		return -ENOMEM;
	if (pool->n_trunk_valid == pool->n_trunk) {
		/* No free trunk flags, expand trunk list. */
		int n_grow = pool->n_trunk_valid ? pool->n_trunk :
			     RTE_CACHE_LINE_SIZE / sizeof(void *);

		p = pool->cfg.malloc(0, (pool->n_trunk_valid + n_grow) *
				     sizeof(struct mlx5_indexed_trunk *),
				     RTE_CACHE_LINE_SIZE, rte_socket_id());
		if (!p)
			return -ENOMEM;
		if (pool->trunks)
			memcpy(p, pool->trunks, pool->n_trunk_valid *
			       sizeof(struct mlx5_indexed_trunk *));
		memset(RTE_PTR_ADD(p, pool->n_trunk_valid * sizeof(void *)), 0,
		       n_grow * sizeof(void *));
		trunk_tmp = pool->trunks;
		pool->trunks = p;
		if (trunk_tmp)
			pool->cfg.free(trunk_tmp);
		pool->n_trunk += n_grow;
	}
	if (!pool->cfg.release_mem_en) {
		idx = pool->n_trunk_valid;
	} else {
		/* Find the first available slot in trunk list */
		for (idx = 0; idx < pool->n_trunk; idx++)
			if (pool->trunks[idx] == NULL)
				break;
	}
	trunk_size += sizeof(*trunk);
	data_size = mlx5_trunk_size_get(pool, idx);
	bmp_size = rte_bitmap_get_memory_footprint(data_size);
	/* rte_bitmap requires memory cacheline aligned. */
	trunk_size += RTE_CACHE_LINE_ROUNDUP(data_size * pool->cfg.size);
	trunk_size += bmp_size;
	trunk = pool->cfg.malloc(0, trunk_size,
				 RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!trunk)
		return -ENOMEM;
	pool->trunks[idx] = trunk;
	trunk->idx = idx;
	trunk->free = data_size;
	trunk->prev = TRUNK_INVALID;
	trunk->next = TRUNK_INVALID;
	MLX5_ASSERT(pool->free_list == TRUNK_INVALID);
	pool->free_list = idx;
	/* Mark all entries as available. */
	trunk->bmp = rte_bitmap_init_with_all_set(data_size, &trunk->data
		     [RTE_CACHE_LINE_ROUNDUP(data_size * pool->cfg.size)],
		     bmp_size);
	/* Clear the overhead bits in the trunk if it happens. */
	if (cur_max_idx + data_size > pool->cfg.max_idx) {
		for (i = pool->cfg.max_idx - cur_max_idx; i < data_size; i++)
			rte_bitmap_clear(trunk->bmp, i);
	}
	MLX5_ASSERT(trunk->bmp);
	pool->n_trunk_valid++;
#ifdef POOL_DEBUG
	pool->trunk_new++;
	pool->trunk_avail++;
#endif
	return 0;
}

static struct mlx5_indexed_trunk *
mlx5_ipool_grow_cache(struct mlx5_indexed_pool *pool)
{
	struct mlx5_indexed_trunk *trunk;
	struct mlx5_indexed_cache *p, *pi;
	size_t trunk_size = 0;
	size_t data_size;
	uint32_t cur_max_idx, trunk_idx;
	int n_grow;
	int cidx = 0;
	char cache_name[64] = { 0 };

	cur_max_idx = mlx5_trunk_idx_offset_get(pool, pool->n_trunk_valid);
	if (pool->n_trunk_valid == TRUNK_MAX_IDX ||
	    cur_max_idx >= pool->cfg.max_idx)
		return NULL;
	cidx = rte_lcore_index(rte_lcore_id());
	if (cidx == -1 || cidx > (MLX5_IPOOL_MAX_CORES - 1))
		cidx = 0;
	trunk_idx = __atomic_fetch_add(&pool->n_trunk_valid, 1,
				__ATOMIC_ACQUIRE);
	/* Have enough space in trunk array. Allocate the trunk directly. */
	if (trunk_idx < __atomic_load_n(&pool->n_trunk, __ATOMIC_ACQUIRE))
		goto allocate_trunk;
	mlx5_ipool_lock(pool);
	/* Double check if trunks array has been resized. */
	if (trunk_idx < __atomic_load_n(&pool->n_trunk, __ATOMIC_ACQUIRE)) {
		mlx5_ipool_unlock(pool);
		goto allocate_trunk;
	}
	n_grow = trunk_idx ? pool->n_trunk :
			     RTE_CACHE_LINE_SIZE / sizeof(void *);
	cur_max_idx = mlx5_trunk_idx_offset_get(pool, pool->n_trunk + n_grow);
	/* Resize the trunk array. */
	p = pool->cfg.malloc(MLX5_MEM_ZERO, ((trunk_idx + n_grow) *
			     sizeof(struct mlx5_indexed_trunk *)) + sizeof(*p),
			     RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!p) {
		mlx5_ipool_unlock(pool);
		return NULL;
	}
	p->trunks = (struct mlx5_indexed_trunk **)(p + 1);
	if (pool->trunks_g)
		memcpy(p->trunks, pool->trunks_g->trunks, trunk_idx *
		       sizeof(struct mlx5_indexed_trunk *));
	memset(RTE_PTR_ADD(p->trunks, trunk_idx * sizeof(void *)), 0,
	       n_grow * sizeof(void *));
	/* Resize the global index cache ring. */
	pi = pool->cfg.malloc(MLX5_MEM_ZERO, sizeof(*pi), 0, rte_socket_id());
	if (!pi) {
		mlx5_free(p);
		mlx5_ipool_unlock(pool);
		return NULL;
	}
	snprintf(cache_name, RTE_DIM(cache_name), "Idxc-%p-%u",
		 (void *)pool, trunk_idx);
	pi->ring = rte_ring_create(cache_name, rte_align32pow2(cur_max_idx),
		SOCKET_ID_ANY, RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!pi->ring) {
		mlx5_free(p);
		mlx5_free(pi);
		mlx5_ipool_unlock(pool);
		return NULL;
	}
	p->ref_cnt = 1;
	pool->trunks_g = p;
	pi->ref_cnt = 1;
	pool->idx_g = pi;
	/* Check if trunks array is not used any more. */
	if (pool->trunks_c[cidx] && (!(--pool->trunks_c[cidx]->ref_cnt)))
		mlx5_free(pool->trunks_c[cidx]);
	/* Check if index cache is not used any more. */
	if (pool->idx_c[cidx] &&
	    (!(--pool->idx_c[cidx]->ref_cnt))) {
		rte_ring_free(pool->idx_c[cidx]->ring);
		mlx5_free(pool->idx_c[cidx]);
	}
	pool->trunks_c[cidx] = p;
	pool->idx_c[cidx] = pi;
	__atomic_fetch_add(&pool->n_trunk, n_grow, __ATOMIC_ACQUIRE);
	mlx5_ipool_unlock(pool);
	/* Pre-allocate the bitmap. */
	if (pool->ibmp)
		pool->cfg.free(pool->ibmp);
	data_size = sizeof(*pool->ibmp);
	data_size += rte_bitmap_get_memory_footprint(cur_max_idx);
	/* rte_bitmap requires memory cacheline aligned. */
	pool->ibmp = pool->cfg.malloc(MLX5_MEM_ZERO, data_size,
			RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!pool->ibmp)
		return NULL;
	pool->ibmp->num = cur_max_idx;
	pool->ibmp->mem_size = data_size - sizeof(*pool->ibmp);
	pool->ibmp->mem = (void *)(pool->ibmp + 1);
	pool->ibmp->bmp = rte_bitmap_init(pool->ibmp->num,
			pool->ibmp->mem, pool->ibmp->mem_size);
allocate_trunk:
	/* Initialize the new trunk. */
	trunk_size = sizeof(*trunk);
	data_size = mlx5_trunk_size_get(pool, trunk_idx);
	trunk_size += RTE_CACHE_LINE_ROUNDUP(data_size * pool->cfg.size);
	trunk = pool->cfg.malloc(0, trunk_size,
				 RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!trunk)
		return NULL;
	pool->trunks_g->trunks[trunk_idx] = trunk;
	trunk->idx = trunk_idx;
	trunk->free = data_size;
#ifdef POOL_DEBUG
	pool->trunk_new++;
#endif
	return trunk;
}

static void *
mlx5_ipool_get_cache(struct mlx5_indexed_pool *pool, uint32_t idx)
{
	struct mlx5_indexed_trunk *trunk;
	uint32_t trunk_idx;
	uint32_t entry_idx;
	int cidx = 0;

	if (!idx)
		return NULL;
	cidx = rte_lcore_index(rte_lcore_id());
	if (cidx == -1)
		cidx = 0;
	if (pool->trunks_c[cidx] != pool->trunks_g) {
		mlx5_ipool_lock(pool);
		/* Rlease the old ring if we are the last thread cache it. */
		if (pool->trunks_c[cidx] &&
		    !(--pool->trunks_c[cidx]->ref_cnt))
			mlx5_free(pool->trunks_c[cidx]);
		pool->trunks_c[cidx] = pool->trunks_g;
		pool->trunks_c[cidx]->ref_cnt++;
		mlx5_ipool_unlock(pool);
	}
	idx -= 1;
	trunk_idx = mlx5_trunk_idx_get(pool, idx);
	trunk = pool->trunks_c[cidx]->trunks[trunk_idx];
	if (!trunk)
		return NULL;
	entry_idx = idx - mlx5_trunk_idx_offset_get(pool, trunk->idx);
	return &trunk->data[entry_idx * pool->cfg.size];
}

static void *
mlx5_ipool_malloc_cache(struct mlx5_indexed_pool *pool, uint32_t *idx)
{
	struct mlx5_indexed_trunk *trunk;
	uint32_t i, ts_idx, fetch_size;
	int cidx = 0;
	union mlx5_indexed_qd qd;

	cidx = rte_lcore_index(rte_lcore_id());
	if (cidx == -1)
		cidx = 0;
	/* Try local cache firstly. */
	if (!rte_ring_dequeue(pool->l_idx_c[cidx], &qd.ptr)) {
		*idx = qd.idx;
		return mlx5_ipool_get_cache(pool, qd.idx);
	}
	if (pool->idx_g) {
		/*
		 * Try fetch from the global cache. Check if global cache ring
		 * updated first.
		 */
		if (pool->idx_c[cidx] != pool->idx_g) {
			mlx5_ipool_lock(pool);
			/* Rlease the old ring as last user. */
			if (pool->idx_c[cidx] &&
			    !(--pool->idx_c[cidx]->ref_cnt)) {
				rte_ring_free(pool->idx_c[cidx]->ring);
				pool->cfg.free(pool->idx_c[cidx]);
			}
			pool->idx_c[cidx] = pool->idx_g;
			pool->idx_c[cidx]->ref_cnt++;
			mlx5_ipool_unlock(pool);
		}
		fetch_size = pool->cfg.trunk_size;
		while (!rte_ring_dequeue(pool->idx_g->ring, &qd.ptr)) {
			if (unlikely(!(--fetch_size))) {
				*idx = qd.idx;
				return mlx5_ipool_get_cache(pool, qd.idx);
			}
			rte_ring_enqueue(pool->l_idx_c[cidx], qd.ptr);
		}
	}
	/* Not enough idx in global cache. Keep fetching from new trunk. */
	trunk = mlx5_ipool_grow_cache(pool);
	if (!trunk)
		return NULL;
	/* Get trunk start index. */
	ts_idx = mlx5_trunk_idx_offset_get(pool, trunk->idx);
	/* Enqueue trunk_size - 1 to local cache ring. */
	for (i = 0; i < trunk->free - 1; i++) {
		qd.idx = ts_idx + i + 1;
		rte_ring_enqueue(pool->l_idx_c[cidx], qd.ptr);
	}
	/* Return trunk's final entry. */
	*idx = ts_idx + i + 1;
	return &trunk->data[i * pool->cfg.size];
}

static void
mlx5_ipool_free_cache(struct mlx5_indexed_pool *pool, uint32_t idx)
{
	int cidx;
	uint32_t i, reclaim_num = 0;
	union mlx5_indexed_qd qd;

	if (!idx)
		return;
	cidx = rte_lcore_index(rte_lcore_id());
	if (cidx == -1)
		cidx = 0;
	qd.idx = idx;
	/* Try to enqueue to local index cache. */
	if (!rte_ring_enqueue(pool->l_idx_c[cidx], qd.ptr))
		return;
	/* Update the global index cache ring if needed. */
	if (pool->idx_c[cidx] != pool->idx_g) {
		mlx5_ipool_lock(pool);
		/* Rlease the old ring if we are the last thread cache it. */
		if (!(--pool->idx_c[cidx]->ref_cnt))
			rte_ring_free(pool->idx_c[cidx]->ring);
		pool->idx_c[cidx] = pool->idx_g;
		pool->idx_c[cidx]->ref_cnt++;
		mlx5_ipool_unlock(pool);
	}
	reclaim_num = pool->cfg.per_core_cache >> 4;
	/* Local index cache full, try with global index cache. */
	rte_ring_enqueue(pool->idx_c[cidx]->ring, qd.ptr);
	/* Dequeue the index from local cache to global. */
	for (i = 0; i < reclaim_num; i++) {
		/* No need to check the return value. */
		rte_ring_dequeue(pool->l_idx_c[cidx], &qd.ptr);
		rte_ring_enqueue(pool->idx_c[cidx]->ring, qd.ptr);
	}
}

void *
mlx5_ipool_malloc(struct mlx5_indexed_pool *pool, uint32_t *idx)
{
	struct mlx5_indexed_trunk *trunk;
	uint64_t slab = 0;
	uint32_t iidx = 0;
	void *p;

	if (pool->cfg.per_core_cache)
		return mlx5_ipool_malloc_cache(pool, idx);
	mlx5_ipool_lock(pool);
	if (pool->free_list == TRUNK_INVALID) {
		/* If no available trunks, grow new. */
		if (mlx5_ipool_grow(pool)) {
			mlx5_ipool_unlock(pool);
			return NULL;
		}
	}
	MLX5_ASSERT(pool->free_list != TRUNK_INVALID);
	trunk = pool->trunks[pool->free_list];
	MLX5_ASSERT(trunk->free);
	if (!rte_bitmap_scan(trunk->bmp, &iidx, &slab)) {
		mlx5_ipool_unlock(pool);
		return NULL;
	}
	MLX5_ASSERT(slab);
	iidx += __builtin_ctzll(slab);
	MLX5_ASSERT(iidx != UINT32_MAX);
	MLX5_ASSERT(iidx < mlx5_trunk_size_get(pool, trunk->idx));
	rte_bitmap_clear(trunk->bmp, iidx);
	p = &trunk->data[iidx * pool->cfg.size];
	/*
	 * The ipool index should grow continually from small to big,
	 * some features as metering only accept limited bits of index.
	 * Random index with MSB set may be rejected.
	 */
	iidx += mlx5_trunk_idx_offset_get(pool, trunk->idx);
	iidx += 1; /* non-zero index. */
	trunk->free--;
#ifdef POOL_DEBUG
	pool->n_entry++;
#endif
	if (!trunk->free) {
		/* Full trunk will be removed from free list in imalloc. */
		MLX5_ASSERT(pool->free_list == trunk->idx);
		pool->free_list = trunk->next;
		if (trunk->next != TRUNK_INVALID)
			pool->trunks[trunk->next]->prev = TRUNK_INVALID;
		trunk->prev = TRUNK_INVALID;
		trunk->next = TRUNK_INVALID;
#ifdef POOL_DEBUG
		pool->trunk_empty++;
		pool->trunk_avail--;
#endif
	}
	*idx = iidx;
	mlx5_ipool_unlock(pool);
	return p;
}

void *
mlx5_ipool_zmalloc(struct mlx5_indexed_pool *pool, uint32_t *idx)
{
	void *entry = mlx5_ipool_malloc(pool, idx);

	if (entry && pool->cfg.size)
		memset(entry, 0, pool->cfg.size);
	return entry;
}

void
mlx5_ipool_free(struct mlx5_indexed_pool *pool, uint32_t idx)
{
	struct mlx5_indexed_trunk *trunk;
	uint32_t trunk_idx;
	uint32_t entry_idx;

	if (!idx)
		return;
	if (pool->cfg.per_core_cache)
		return mlx5_ipool_free_cache(pool, idx);
	idx -= 1;
	mlx5_ipool_lock(pool);
	trunk_idx = mlx5_trunk_idx_get(pool, idx);
	if ((!pool->cfg.release_mem_en && trunk_idx >= pool->n_trunk_valid) ||
	    (pool->cfg.release_mem_en && trunk_idx >= pool->n_trunk))
		goto out;
	trunk = pool->trunks[trunk_idx];
	if (!trunk)
		goto out;
	entry_idx = idx - mlx5_trunk_idx_offset_get(pool, trunk->idx);
	if (trunk_idx != trunk->idx ||
	    rte_bitmap_get(trunk->bmp, entry_idx))
		goto out;
	rte_bitmap_set(trunk->bmp, entry_idx);
	trunk->free++;
	if (pool->cfg.release_mem_en && trunk->free == mlx5_trunk_size_get
	   (pool, trunk->idx)) {
		if (pool->free_list == trunk->idx)
			pool->free_list = trunk->next;
		if (trunk->next != TRUNK_INVALID)
			pool->trunks[trunk->next]->prev = trunk->prev;
		if (trunk->prev != TRUNK_INVALID)
			pool->trunks[trunk->prev]->next = trunk->next;
		pool->cfg.free(trunk);
		pool->trunks[trunk_idx] = NULL;
		pool->n_trunk_valid--;
#ifdef POOL_DEBUG
		pool->trunk_avail--;
		pool->trunk_free++;
#endif
		if (pool->n_trunk_valid == 0) {
			pool->cfg.free(pool->trunks);
			pool->trunks = NULL;
			pool->n_trunk = 0;
		}
	} else if (trunk->free == 1) {
		/* Put into free trunk list head. */
		MLX5_ASSERT(pool->free_list != trunk->idx);
		trunk->next = pool->free_list;
		trunk->prev = TRUNK_INVALID;
		if (pool->free_list != TRUNK_INVALID)
			pool->trunks[pool->free_list]->prev = trunk->idx;
		pool->free_list = trunk->idx;
#ifdef POOL_DEBUG
		pool->trunk_empty--;
		pool->trunk_avail++;
#endif
	}
#ifdef POOL_DEBUG
	pool->n_entry--;
#endif
out:
	mlx5_ipool_unlock(pool);
}

void *
mlx5_ipool_get(struct mlx5_indexed_pool *pool, uint32_t idx)
{
	struct mlx5_indexed_trunk *trunk;
	void *p = NULL;
	uint32_t trunk_idx;
	uint32_t entry_idx;

	if (!idx)
		return NULL;
	if (pool->cfg.per_core_cache)
		return mlx5_ipool_get_cache(pool, idx);
	idx -= 1;
	mlx5_ipool_lock(pool);
	trunk_idx = mlx5_trunk_idx_get(pool, idx);
	if ((!pool->cfg.release_mem_en && trunk_idx >= pool->n_trunk_valid) ||
	    (pool->cfg.release_mem_en && trunk_idx >= pool->n_trunk))
		goto out;
	trunk = pool->trunks[trunk_idx];
	if (!trunk)
		goto out;
	entry_idx = idx - mlx5_trunk_idx_offset_get(pool, trunk->idx);
	if (trunk_idx != trunk->idx ||
	    rte_bitmap_get(trunk->bmp, entry_idx))
		goto out;
	p = &trunk->data[entry_idx * pool->cfg.size];
out:
	mlx5_ipool_unlock(pool);
	return p;
}

int
mlx5_ipool_destroy(struct mlx5_indexed_pool *pool)
{
	struct mlx5_indexed_trunk **trunks;
	uint32_t i;

	MLX5_ASSERT(pool);
	mlx5_ipool_lock(pool);
	if (pool->cfg.per_core_cache)
		trunks = pool->trunks_g->trunks;
	else
		trunks = pool->trunks;
	for (i = 0; i < pool->n_trunk; i++) {
		if (trunks[i])
			pool->cfg.free(trunks[i]);
	}
	if (!pool->trunks)
		pool->cfg.free(pool->trunks);
	mlx5_ipool_unlock(pool);
	mlx5_free(pool);
	return 0;
}

void
mlx5_ipool_flush_cache(struct mlx5_indexed_pool *pool)
{
	uint32_t i;
	struct rte_ring *ring_c;
	char cache_name[64];
	union mlx5_indexed_qd qd;
	uint32_t bmp_num, mem_size;
	uint32_t num = 0;

	/* Create a new ring to save all cached index. */
	snprintf(cache_name, RTE_DIM(cache_name), "Ip_%p",
		 (void *)pool->idx_g->ring);
	ring_c = rte_ring_create(cache_name, pool->ibmp->num,
			SOCKET_ID_ANY, RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (!ring_c)
		return;
	/* Reset bmp. */
	bmp_num = mlx5_trunk_idx_offset_get(pool, pool->n_trunk_valid);
	mem_size = rte_bitmap_get_memory_footprint(bmp_num);
	pool->ibmp->bmp = rte_bitmap_init_with_all_set(bmp_num,
			pool->ibmp->mem, mem_size);
	/* Flush core cache. */
	for (i = 0; i < MLX5_IPOOL_MAX_CORES; i++) {
		while (!rte_ring_dequeue(pool->l_idx_c[i], &qd.ptr)) {
			rte_bitmap_clear(pool->ibmp->bmp, (qd.idx - 1));
			rte_ring_enqueue(ring_c, qd.ptr);
			num++;
		}
	}
	/* Flush global cache. */
	while (!rte_ring_dequeue(pool->idx_g->ring, &qd.ptr)) {
		rte_bitmap_clear(pool->ibmp->bmp, (qd.idx - 1));
		rte_ring_enqueue(ring_c, qd.ptr);
		num++;
	}
	rte_ring_free(pool->idx_g->ring);
	pool->idx_g->ring = ring_c;
}

void *
mlx5_ipool_get_next(struct mlx5_indexed_pool *pool, uint32_t *pos)
{
	uint64_t slab = 0;
	uint32_t iidx = *pos;

	if (!pool->ibmp || !rte_bitmap_scan(pool->ibmp->bmp, &iidx, &slab))
		return NULL;
	iidx += __builtin_ctzll(slab);
	rte_bitmap_clear(pool->ibmp->bmp, iidx);
	iidx++;
	*pos = iidx;
	return mlx5_ipool_get(pool, iidx);
}

void
mlx5_ipool_dump(struct mlx5_indexed_pool *pool)
{
	printf("Pool %s entry size %u, trunks %u, %d entry per trunk, "
	       "total: %d\n",
	       pool->cfg.type, pool->cfg.size, pool->n_trunk_valid,
	       pool->cfg.trunk_size, pool->n_trunk_valid);
#ifdef POOL_DEBUG
	printf("Pool %s entry %u, trunk alloc %u, empty: %u, "
	       "available %u free %u\n",
	       pool->cfg.type, pool->n_entry, pool->trunk_new,
	       pool->trunk_empty, pool->trunk_avail, pool->trunk_free);
#endif
}

struct mlx5_l3t_tbl *
mlx5_l3t_create(enum mlx5_l3t_type type)
{
	struct mlx5_l3t_tbl *tbl;
	struct mlx5_indexed_pool_config l3t_ip_cfg = {
		.trunk_size = 16,
		.grow_trunk = 6,
		.grow_shift = 1,
		.need_lock = 0,
		.release_mem_en = 1,
		.malloc = mlx5_malloc,
		.free = mlx5_free,
	};

	if (type >= MLX5_L3T_TYPE_MAX) {
		rte_errno = EINVAL;
		return NULL;
	}
	tbl = mlx5_malloc(MLX5_MEM_ZERO, sizeof(struct mlx5_l3t_tbl), 1,
			  SOCKET_ID_ANY);
	if (!tbl) {
		rte_errno = ENOMEM;
		return NULL;
	}
	tbl->type = type;
	switch (type) {
	case MLX5_L3T_TYPE_WORD:
		l3t_ip_cfg.size = sizeof(struct mlx5_l3t_entry_word);
		l3t_ip_cfg.type = "mlx5_l3t_e_tbl_w";
		break;
	case MLX5_L3T_TYPE_DWORD:
		l3t_ip_cfg.size = sizeof(struct mlx5_l3t_entry_dword);
		l3t_ip_cfg.type = "mlx5_l3t_e_tbl_dw";
		break;
	case MLX5_L3T_TYPE_QWORD:
		l3t_ip_cfg.size = sizeof(struct mlx5_l3t_entry_qword);
		l3t_ip_cfg.type = "mlx5_l3t_e_tbl_qw";
		break;
	default:
		l3t_ip_cfg.size = sizeof(struct mlx5_l3t_entry_ptr);
		l3t_ip_cfg.type = "mlx5_l3t_e_tbl_tpr";
		break;
	}
	rte_spinlock_init(&tbl->sl);
	tbl->eip = mlx5_ipool_create(&l3t_ip_cfg);
	if (!tbl->eip) {
		rte_errno = ENOMEM;
		mlx5_free(tbl);
		tbl = NULL;
	}
	return tbl;
}

void
mlx5_l3t_destroy(struct mlx5_l3t_tbl *tbl)
{
	struct mlx5_l3t_level_tbl *g_tbl, *m_tbl;
	uint32_t i, j;

	if (!tbl)
		return;
	g_tbl = tbl->tbl;
	if (g_tbl) {
		for (i = 0; i < MLX5_L3T_GT_SIZE; i++) {
			m_tbl = g_tbl->tbl[i];
			if (!m_tbl)
				continue;
			for (j = 0; j < MLX5_L3T_MT_SIZE; j++) {
				if (!m_tbl->tbl[j])
					continue;
				MLX5_ASSERT(!((struct mlx5_l3t_entry_word *)
					    m_tbl->tbl[j])->ref_cnt);
				mlx5_ipool_free(tbl->eip,
						((struct mlx5_l3t_entry_word *)
						m_tbl->tbl[j])->idx);
				m_tbl->tbl[j] = 0;
				if (!(--m_tbl->ref_cnt))
					break;
			}
			MLX5_ASSERT(!m_tbl->ref_cnt);
			mlx5_free(g_tbl->tbl[i]);
			g_tbl->tbl[i] = 0;
			if (!(--g_tbl->ref_cnt))
				break;
		}
		MLX5_ASSERT(!g_tbl->ref_cnt);
		mlx5_free(tbl->tbl);
		tbl->tbl = 0;
	}
	mlx5_ipool_destroy(tbl->eip);
	mlx5_free(tbl);
}

static int32_t
__l3t_get_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx,
		union mlx5_l3t_data *data)
{
	struct mlx5_l3t_level_tbl *g_tbl, *m_tbl;
	struct mlx5_l3t_entry_word *w_e_tbl;
	struct mlx5_l3t_entry_dword *dw_e_tbl;
	struct mlx5_l3t_entry_qword *qw_e_tbl;
	struct mlx5_l3t_entry_ptr *ptr_e_tbl;
	void *e_tbl;
	uint32_t entry_idx;

	g_tbl = tbl->tbl;
	if (!g_tbl)
		return -1;
	m_tbl = g_tbl->tbl[(idx >> MLX5_L3T_GT_OFFSET) & MLX5_L3T_GT_MASK];
	if (!m_tbl)
		return -1;
	e_tbl = m_tbl->tbl[(idx >> MLX5_L3T_MT_OFFSET) & MLX5_L3T_MT_MASK];
	if (!e_tbl)
		return -1;
	entry_idx = idx & MLX5_L3T_ET_MASK;
	switch (tbl->type) {
	case MLX5_L3T_TYPE_WORD:
		w_e_tbl = (struct mlx5_l3t_entry_word *)e_tbl;
		data->word = w_e_tbl->entry[entry_idx].data;
		if (w_e_tbl->entry[entry_idx].data)
			w_e_tbl->entry[entry_idx].ref_cnt++;
		break;
	case MLX5_L3T_TYPE_DWORD:
		dw_e_tbl = (struct mlx5_l3t_entry_dword *)e_tbl;
		data->dword = dw_e_tbl->entry[entry_idx].data;
		if (dw_e_tbl->entry[entry_idx].data)
			dw_e_tbl->entry[entry_idx].ref_cnt++;
		break;
	case MLX5_L3T_TYPE_QWORD:
		qw_e_tbl = (struct mlx5_l3t_entry_qword *)e_tbl;
		data->qword = qw_e_tbl->entry[entry_idx].data;
		if (qw_e_tbl->entry[entry_idx].data)
			qw_e_tbl->entry[entry_idx].ref_cnt++;
		break;
	default:
		ptr_e_tbl = (struct mlx5_l3t_entry_ptr *)e_tbl;
		data->ptr = ptr_e_tbl->entry[entry_idx].data;
		if (ptr_e_tbl->entry[entry_idx].data)
			ptr_e_tbl->entry[entry_idx].ref_cnt++;
		break;
	}
	return 0;
}

int32_t
mlx5_l3t_get_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx,
		   union mlx5_l3t_data *data)
{
	int ret;

	rte_spinlock_lock(&tbl->sl);
	ret = __l3t_get_entry(tbl, idx, data);
	rte_spinlock_unlock(&tbl->sl);
	return ret;
}

int32_t
mlx5_l3t_clear_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx)
{
	struct mlx5_l3t_level_tbl *g_tbl, *m_tbl;
	struct mlx5_l3t_entry_word *w_e_tbl;
	struct mlx5_l3t_entry_dword *dw_e_tbl;
	struct mlx5_l3t_entry_qword *qw_e_tbl;
	struct mlx5_l3t_entry_ptr *ptr_e_tbl;
	void *e_tbl;
	uint32_t entry_idx;
	uint64_t ref_cnt;
	int32_t ret = -1;

	rte_spinlock_lock(&tbl->sl);
	g_tbl = tbl->tbl;
	if (!g_tbl)
		goto out;
	m_tbl = g_tbl->tbl[(idx >> MLX5_L3T_GT_OFFSET) & MLX5_L3T_GT_MASK];
	if (!m_tbl)
		goto out;
	e_tbl = m_tbl->tbl[(idx >> MLX5_L3T_MT_OFFSET) & MLX5_L3T_MT_MASK];
	if (!e_tbl)
		goto out;
	entry_idx = idx & MLX5_L3T_ET_MASK;
	switch (tbl->type) {
	case MLX5_L3T_TYPE_WORD:
		w_e_tbl = (struct mlx5_l3t_entry_word *)e_tbl;
		MLX5_ASSERT(w_e_tbl->entry[entry_idx].ref_cnt);
		ret = --w_e_tbl->entry[entry_idx].ref_cnt;
		if (ret)
			goto out;
		w_e_tbl->entry[entry_idx].data = 0;
		ref_cnt = --w_e_tbl->ref_cnt;
		break;
	case MLX5_L3T_TYPE_DWORD:
		dw_e_tbl = (struct mlx5_l3t_entry_dword *)e_tbl;
		MLX5_ASSERT(dw_e_tbl->entry[entry_idx].ref_cnt);
		ret = --dw_e_tbl->entry[entry_idx].ref_cnt;
		if (ret)
			goto out;
		dw_e_tbl->entry[entry_idx].data = 0;
		ref_cnt = --dw_e_tbl->ref_cnt;
		break;
	case MLX5_L3T_TYPE_QWORD:
		qw_e_tbl = (struct mlx5_l3t_entry_qword *)e_tbl;
		MLX5_ASSERT(qw_e_tbl->entry[entry_idx].ref_cnt);
		ret = --qw_e_tbl->entry[entry_idx].ref_cnt;
		if (ret)
			goto out;
		qw_e_tbl->entry[entry_idx].data = 0;
		ref_cnt = --qw_e_tbl->ref_cnt;
		break;
	default:
		ptr_e_tbl = (struct mlx5_l3t_entry_ptr *)e_tbl;
		MLX5_ASSERT(ptr_e_tbl->entry[entry_idx].ref_cnt);
		ret = --ptr_e_tbl->entry[entry_idx].ref_cnt;
		if (ret)
			goto out;
		ptr_e_tbl->entry[entry_idx].data = NULL;
		ref_cnt = --ptr_e_tbl->ref_cnt;
		break;
	}
	if (!ref_cnt) {
		mlx5_ipool_free(tbl->eip,
				((struct mlx5_l3t_entry_word *)e_tbl)->idx);
		m_tbl->tbl[(idx >> MLX5_L3T_MT_OFFSET) & MLX5_L3T_MT_MASK] =
									NULL;
		if (!(--m_tbl->ref_cnt)) {
			mlx5_free(m_tbl);
			g_tbl->tbl
			[(idx >> MLX5_L3T_GT_OFFSET) & MLX5_L3T_GT_MASK] = NULL;
			if (!(--g_tbl->ref_cnt)) {
				mlx5_free(g_tbl);
				tbl->tbl = 0;
			}
		}
	}
out:
	rte_spinlock_unlock(&tbl->sl);
	return ret;
}

static int32_t
__l3t_set_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx,
		union mlx5_l3t_data *data)
{
	struct mlx5_l3t_level_tbl *g_tbl, *m_tbl;
	struct mlx5_l3t_entry_word *w_e_tbl;
	struct mlx5_l3t_entry_dword *dw_e_tbl;
	struct mlx5_l3t_entry_qword *qw_e_tbl;
	struct mlx5_l3t_entry_ptr *ptr_e_tbl;
	void *e_tbl;
	uint32_t entry_idx, tbl_idx = 0;

	/* Check the global table, create it if empty. */
	g_tbl = tbl->tbl;
	if (!g_tbl) {
		g_tbl = mlx5_malloc(MLX5_MEM_ZERO,
				    sizeof(struct mlx5_l3t_level_tbl) +
				    sizeof(void *) * MLX5_L3T_GT_SIZE, 1,
				    SOCKET_ID_ANY);
		if (!g_tbl) {
			rte_errno = ENOMEM;
			return -1;
		}
		tbl->tbl = g_tbl;
	}
	/*
	 * Check the middle table, create it if empty. Ref_cnt will be
	 * increased if new sub table created.
	 */
	m_tbl = g_tbl->tbl[(idx >> MLX5_L3T_GT_OFFSET) & MLX5_L3T_GT_MASK];
	if (!m_tbl) {
		m_tbl = mlx5_malloc(MLX5_MEM_ZERO,
				    sizeof(struct mlx5_l3t_level_tbl) +
				    sizeof(void *) * MLX5_L3T_MT_SIZE, 1,
				    SOCKET_ID_ANY);
		if (!m_tbl) {
			rte_errno = ENOMEM;
			return -1;
		}
		g_tbl->tbl[(idx >> MLX5_L3T_GT_OFFSET) & MLX5_L3T_GT_MASK] =
									m_tbl;
		g_tbl->ref_cnt++;
	}
	/*
	 * Check the entry table, create it if empty. Ref_cnt will be
	 * increased if new sub entry table created.
	 */
	e_tbl = m_tbl->tbl[(idx >> MLX5_L3T_MT_OFFSET) & MLX5_L3T_MT_MASK];
	if (!e_tbl) {
		e_tbl = mlx5_ipool_zmalloc(tbl->eip, &tbl_idx);
		if (!e_tbl) {
			rte_errno = ENOMEM;
			return -1;
		}
		((struct mlx5_l3t_entry_word *)e_tbl)->idx = tbl_idx;
		m_tbl->tbl[(idx >> MLX5_L3T_MT_OFFSET) & MLX5_L3T_MT_MASK] =
									e_tbl;
		m_tbl->ref_cnt++;
	}
	entry_idx = idx & MLX5_L3T_ET_MASK;
	switch (tbl->type) {
	case MLX5_L3T_TYPE_WORD:
		w_e_tbl = (struct mlx5_l3t_entry_word *)e_tbl;
		if (w_e_tbl->entry[entry_idx].data) {
			data->word = w_e_tbl->entry[entry_idx].data;
			w_e_tbl->entry[entry_idx].ref_cnt++;
			rte_errno = EEXIST;
			return -1;
		}
		w_e_tbl->entry[entry_idx].data = data->word;
		w_e_tbl->entry[entry_idx].ref_cnt = 1;
		w_e_tbl->ref_cnt++;
		break;
	case MLX5_L3T_TYPE_DWORD:
		dw_e_tbl = (struct mlx5_l3t_entry_dword *)e_tbl;
		if (dw_e_tbl->entry[entry_idx].data) {
			data->dword = dw_e_tbl->entry[entry_idx].data;
			dw_e_tbl->entry[entry_idx].ref_cnt++;
			rte_errno = EEXIST;
			return -1;
		}
		dw_e_tbl->entry[entry_idx].data = data->dword;
		dw_e_tbl->entry[entry_idx].ref_cnt = 1;
		dw_e_tbl->ref_cnt++;
		break;
	case MLX5_L3T_TYPE_QWORD:
		qw_e_tbl = (struct mlx5_l3t_entry_qword *)e_tbl;
		if (qw_e_tbl->entry[entry_idx].data) {
			data->qword = qw_e_tbl->entry[entry_idx].data;
			qw_e_tbl->entry[entry_idx].ref_cnt++;
			rte_errno = EEXIST;
			return -1;
		}
		qw_e_tbl->entry[entry_idx].data = data->qword;
		qw_e_tbl->entry[entry_idx].ref_cnt = 1;
		qw_e_tbl->ref_cnt++;
		break;
	default:
		ptr_e_tbl = (struct mlx5_l3t_entry_ptr *)e_tbl;
		if (ptr_e_tbl->entry[entry_idx].data) {
			data->ptr = ptr_e_tbl->entry[entry_idx].data;
			ptr_e_tbl->entry[entry_idx].ref_cnt++;
			rte_errno = EEXIST;
			return -1;
		}
		ptr_e_tbl->entry[entry_idx].data = data->ptr;
		ptr_e_tbl->entry[entry_idx].ref_cnt = 1;
		ptr_e_tbl->ref_cnt++;
		break;
	}
	return 0;
}

int32_t
mlx5_l3t_set_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx,
		   union mlx5_l3t_data *data)
{
	int ret;

	rte_spinlock_lock(&tbl->sl);
	ret = __l3t_set_entry(tbl, idx, data);
	rte_spinlock_unlock(&tbl->sl);
	return ret;
}

int32_t
mlx5_l3t_prepare_entry(struct mlx5_l3t_tbl *tbl, uint32_t idx,
		       union mlx5_l3t_data *data,
		       mlx5_l3t_alloc_callback_fn cb, void *ctx)
{
	int32_t ret;

	rte_spinlock_lock(&tbl->sl);
	/* Check if entry data is ready. */
	ret = __l3t_get_entry(tbl, idx, data);
	if (!ret) {
		switch (tbl->type) {
		case MLX5_L3T_TYPE_WORD:
			if (data->word)
				goto out;
			break;
		case MLX5_L3T_TYPE_DWORD:
			if (data->dword)
				goto out;
			break;
		case MLX5_L3T_TYPE_QWORD:
			if (data->qword)
				goto out;
			break;
		default:
			if (data->ptr)
				goto out;
			break;
		}
	}
	/* Entry data is not ready, use user callback to create it. */
	ret = cb(ctx, data);
	if (ret)
		goto out;
	/* Save the new allocated data to entry. */
	ret = __l3t_set_entry(tbl, idx, data);
out:
	rte_spinlock_unlock(&tbl->sl);
	return ret;
}
