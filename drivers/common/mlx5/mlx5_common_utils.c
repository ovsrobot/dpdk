/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Mellanox Technologies, Ltd
 */

#include <rte_malloc.h>
#include <rte_hash_crc.h>
#include <rte_errno.h>

#include <mlx5_malloc.h>

#include "mlx5_common_utils.h"
#include "mlx5_common_log.h"

/********************* mlx5 list ************************/

static int
mlx5_list_init(struct mlx5_list *list, const char *name, void *ctx,
	       bool lcores_share, struct mlx5_list_cache *gc,
	       mlx5_list_create_cb cb_create,
	       mlx5_list_match_cb cb_match,
	       mlx5_list_remove_cb cb_remove,
	       mlx5_list_clone_cb cb_clone,
	       mlx5_list_clone_free_cb cb_clone_free)
{
	if (!cb_match || !cb_create || !cb_remove || !cb_clone ||
	    !cb_clone_free) {
		rte_errno = EINVAL;
		return -EINVAL;
	}
	if (name)
		snprintf(list->name, sizeof(list->name), "%s", name);
	list->ctx = ctx;
	list->lcores_share = lcores_share;
	list->cb_create = cb_create;
	list->cb_match = cb_match;
	list->cb_remove = cb_remove;
	list->cb_clone = cb_clone;
	list->cb_clone_free = cb_clone_free;
	rte_rwlock_init(&list->lock);
	if (lcores_share) {
		list->cache[RTE_MAX_LCORE] = gc;
		LIST_INIT(&list->cache[RTE_MAX_LCORE]->h);
	}
	DRV_LOG(DEBUG, "mlx5 list %s initialized.", list->name);
	return 0;
}

struct mlx5_list *
mlx5_list_create(const char *name, void *ctx, bool lcores_share,
		 mlx5_list_create_cb cb_create,
		 mlx5_list_match_cb cb_match,
		 mlx5_list_remove_cb cb_remove,
		 mlx5_list_clone_cb cb_clone,
		 mlx5_list_clone_free_cb cb_clone_free)
{
	struct mlx5_list *list;
	struct mlx5_list_cache *gc = NULL;

	list = mlx5_malloc(MLX5_MEM_ZERO,
			   sizeof(*list) + (lcores_share ? sizeof(*gc) : 0),
			   0, SOCKET_ID_ANY);
	if (!list)
		return NULL;
	if (lcores_share)
		gc = (struct mlx5_list_cache *)(list + 1);
	if (mlx5_list_init(list, name, ctx, lcores_share, gc,
			   cb_create, cb_match, cb_remove, cb_clone,
			   cb_clone_free) != 0) {
		mlx5_free(list);
		return NULL;
	}
	return list;
}

static struct mlx5_list_entry *
__list_lookup(struct mlx5_list *list, int lcore_index, void *ctx, bool reuse)
{
	struct mlx5_list_entry *entry =
				LIST_FIRST(&list->cache[lcore_index]->h);
	uint32_t ret;

	while (entry != NULL) {
		if (list->cb_match(list->ctx, entry, ctx) == 0) {
			if (reuse) {
				ret = __atomic_add_fetch(&entry->ref_cnt, 1,
							 __ATOMIC_RELAXED) - 1;
				DRV_LOG(DEBUG, "mlx5 list %s entry %p ref: %u.",
					list->name, (void *)entry,
					entry->ref_cnt);
			} else if (lcore_index < RTE_MAX_LCORE) {
				ret = __atomic_load_n(&entry->ref_cnt,
						      __ATOMIC_RELAXED);
			}
			if (likely(ret != 0 || lcore_index == RTE_MAX_LCORE))
				return entry;
			if (reuse && ret == 0)
				entry->ref_cnt--; /* Invalid entry. */
		}
		entry = LIST_NEXT(entry, next);
	}
	return NULL;
}

struct mlx5_list_entry *
mlx5_list_lookup(struct mlx5_list *list, void *ctx)
{
	struct mlx5_list_entry *entry = NULL;
	int i;

	rte_rwlock_read_lock(&list->lock);
	for (i = 0; i < RTE_MAX_LCORE; i++) {
		entry = __list_lookup(list, i, ctx, false);
		if (entry)
			break;
	}
	rte_rwlock_read_unlock(&list->lock);
	return entry;
}

static struct mlx5_list_entry *
mlx5_list_cache_insert(struct mlx5_list *list, int lcore_index,
		       struct mlx5_list_entry *gentry, void *ctx)
{
	struct mlx5_list_entry *lentry = list->cb_clone(list->ctx, gentry, ctx);

	if (unlikely(!lentry))
		return NULL;
	lentry->ref_cnt = 1u;
	lentry->gentry = gentry;
	lentry->lcore_idx = (uint32_t)lcore_index;
	LIST_INSERT_HEAD(&list->cache[lcore_index]->h, lentry, next);
	return lentry;
}

static void
__list_cache_clean(struct mlx5_list *list, int lcore_index)
{
	struct mlx5_list_cache *c = list->cache[lcore_index];
	struct mlx5_list_entry *entry = LIST_FIRST(&c->h);
	uint32_t inv_cnt = __atomic_exchange_n(&c->inv_cnt, 0,
					       __ATOMIC_RELAXED);

	while (inv_cnt != 0 && entry != NULL) {
		struct mlx5_list_entry *nentry = LIST_NEXT(entry, next);

		if (__atomic_load_n(&entry->ref_cnt, __ATOMIC_RELAXED) == 0) {
			LIST_REMOVE(entry, next);
			if (list->lcores_share)
				list->cb_clone_free(list->ctx, entry);
			else
				list->cb_remove(list->ctx, entry);
			inv_cnt--;
		}
		entry = nentry;
	}
}

struct mlx5_list_entry *
mlx5_list_register(struct mlx5_list *list, void *ctx)
{
	struct mlx5_list_entry *entry = NULL, *local_entry;
	volatile uint32_t prev_gen_cnt = 0;
	int lcore_index = rte_lcore_index(rte_lcore_id());

	MLX5_ASSERT(list);
	MLX5_ASSERT(lcore_index < RTE_MAX_LCORE);
	if (unlikely(lcore_index == -1)) {
		rte_errno = ENOTSUP;
		return NULL;
	}
	if (unlikely(!list->cache[lcore_index])) {
		list->cache[lcore_index] = mlx5_malloc(0,
					sizeof(struct mlx5_list_cache),
					RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
		if (!list->cache[lcore_index]) {
			rte_errno = ENOMEM;
			return NULL;
		}
		list->cache[lcore_index]->inv_cnt = 0;
		LIST_INIT(&list->cache[lcore_index]->h);
	}
	/* 0. Free entries that was invalidated by other lcores. */
	__list_cache_clean(list, lcore_index);
	/* 1. Lookup in local cache. */
	local_entry = __list_lookup(list, lcore_index, ctx, true);
	if (local_entry)
		return local_entry;
	if (list->lcores_share) {
		/* 2. Lookup with read lock on global list, reuse if found. */
		rte_rwlock_read_lock(&list->lock);
		entry = __list_lookup(list, RTE_MAX_LCORE, ctx, true);
		if (likely(entry)) {
			rte_rwlock_read_unlock(&list->lock);
			return mlx5_list_cache_insert(list, lcore_index, entry,
						      ctx);
		}
		prev_gen_cnt = list->gen_cnt;
		rte_rwlock_read_unlock(&list->lock);
	}
	/* 3. Prepare new entry for global list and for cache. */
	entry = list->cb_create(list->ctx, ctx);
	if (unlikely(!entry))
		return NULL;
	entry->ref_cnt = 1u;
	if (!list->lcores_share) {
		entry->lcore_idx = (uint32_t)lcore_index;
		LIST_INSERT_HEAD(&list->cache[lcore_index]->h, entry, next);
		__atomic_add_fetch(&list->count, 1, __ATOMIC_RELAXED);
		DRV_LOG(DEBUG, "MLX5 list %s c%d entry %p new: %u.",
			list->name, lcore_index, (void *)entry, entry->ref_cnt);
		return entry;
	}
	local_entry = list->cb_clone(list->ctx, entry, ctx);
	if (unlikely(!local_entry)) {
		list->cb_remove(list->ctx, entry);
		return NULL;
	}
	local_entry->ref_cnt = 1u;
	local_entry->gentry = entry;
	local_entry->lcore_idx = (uint32_t)lcore_index;
	rte_rwlock_write_lock(&list->lock);
	/* 4. Make sure the same entry was not created before the write lock. */
	if (unlikely(prev_gen_cnt != list->gen_cnt)) {
		struct mlx5_list_entry *oentry = __list_lookup(list,
							       RTE_MAX_LCORE,
							       ctx, true);

		if (unlikely(oentry)) {
			/* 4.5. Found real race!!, reuse the old entry. */
			rte_rwlock_write_unlock(&list->lock);
			list->cb_remove(list->ctx, entry);
			list->cb_clone_free(list->ctx, local_entry);
			return mlx5_list_cache_insert(list, lcore_index, oentry,
						      ctx);
		}
	}
	/* 5. Update lists. */
	LIST_INSERT_HEAD(&list->cache[RTE_MAX_LCORE]->h, entry, next);
	list->gen_cnt++;
	rte_rwlock_write_unlock(&list->lock);
	LIST_INSERT_HEAD(&list->cache[lcore_index]->h, local_entry, next);
	__atomic_add_fetch(&list->count, 1, __ATOMIC_RELAXED);
	DRV_LOG(DEBUG, "mlx5 list %s entry %p new: %u.", list->name,
		(void *)entry, entry->ref_cnt);
	return local_entry;
}

int
mlx5_list_unregister(struct mlx5_list *list,
		      struct mlx5_list_entry *entry)
{
	struct mlx5_list_entry *gentry = entry->gentry;
	int lcore_idx;

	if (__atomic_sub_fetch(&entry->ref_cnt, 1, __ATOMIC_RELAXED) != 0)
		return 1;
	lcore_idx = rte_lcore_index(rte_lcore_id());
	MLX5_ASSERT(lcore_idx < RTE_MAX_LCORE);
	if (entry->lcore_idx == (uint32_t)lcore_idx) {
		LIST_REMOVE(entry, next);
		if (list->lcores_share)
			list->cb_clone_free(list->ctx, entry);
		else
			list->cb_remove(list->ctx, entry);
	} else if (likely(lcore_idx != -1)) {
		__atomic_add_fetch(&list->cache[entry->lcore_idx]->inv_cnt, 1,
				   __ATOMIC_RELAXED);
	} else {
		return 0;
	}
	if (!list->lcores_share) {
		__atomic_sub_fetch(&list->count, 1, __ATOMIC_RELAXED);
		DRV_LOG(DEBUG, "mlx5 list %s entry %p removed.",
			list->name, (void *)entry);
		return 0;
	}
	if (__atomic_sub_fetch(&gentry->ref_cnt, 1, __ATOMIC_RELAXED) != 0)
		return 1;
	rte_rwlock_write_lock(&list->lock);
	if (likely(gentry->ref_cnt == 0)) {
		LIST_REMOVE(gentry, next);
		rte_rwlock_write_unlock(&list->lock);
		list->cb_remove(list->ctx, gentry);
		__atomic_sub_fetch(&list->count, 1, __ATOMIC_RELAXED);
		DRV_LOG(DEBUG, "mlx5 list %s entry %p removed.",
			list->name, (void *)gentry);
		return 0;
	}
	rte_rwlock_write_unlock(&list->lock);
	return 1;
}

static void
mlx5_list_uninit(struct mlx5_list *list)
{
	struct mlx5_list_entry *entry;
	int i;

	MLX5_ASSERT(list);
	for (i = 0; i <= RTE_MAX_LCORE; i++) {
		if (!list->cache[i])
			continue;
		while (!LIST_EMPTY(&list->cache[i]->h)) {
			entry = LIST_FIRST(&list->cache[i]->h);
			LIST_REMOVE(entry, next);
			if (i == RTE_MAX_LCORE) {
				list->cb_remove(list->ctx, entry);
				DRV_LOG(DEBUG, "mlx5 list %s entry %p "
					"destroyed.", list->name,
					(void *)entry);
			} else {
				list->cb_clone_free(list->ctx, entry);
			}
		}
		if (i != RTE_MAX_LCORE)
			mlx5_free(list->cache[i]);
	}
}

void
mlx5_list_destroy(struct mlx5_list *list)
{
	mlx5_list_uninit(list);
	mlx5_free(list);
}

uint32_t
mlx5_list_get_entry_num(struct mlx5_list *list)
{
	MLX5_ASSERT(list);
	return __atomic_load_n(&list->count, __ATOMIC_RELAXED);
}

/********************* Hash List **********************/

struct mlx5_hlist *
mlx5_hlist_create(const char *name, uint32_t size, bool direct_key,
		  bool lcores_share, void *ctx, mlx5_list_create_cb cb_create,
		  mlx5_list_match_cb cb_match,
		  mlx5_list_remove_cb cb_remove,
		  mlx5_list_clone_cb cb_clone,
		  mlx5_list_clone_free_cb cb_clone_free)
{
	struct mlx5_hlist *h;
	struct mlx5_list_cache *gc;
	uint32_t act_size;
	uint32_t alloc_size;
	uint32_t i;

	/* Align to the next power of 2, 32bits integer is enough now. */
	if (!rte_is_power_of_2(size)) {
		act_size = rte_align32pow2(size);
		DRV_LOG(WARNING, "Size 0x%" PRIX32 " is not power of 2, will "
			"be aligned to 0x%" PRIX32 ".", size, act_size);
	} else {
		act_size = size;
	}
	alloc_size = sizeof(struct mlx5_hlist) +
		     sizeof(struct mlx5_hlist_bucket)  * act_size;
	if (lcores_share)
		alloc_size += sizeof(struct mlx5_list_cache)  * act_size;
	/* Using zmalloc, then no need to initialize the heads. */
	h = mlx5_malloc(MLX5_MEM_ZERO, alloc_size, RTE_CACHE_LINE_SIZE,
			SOCKET_ID_ANY);
	if (!h) {
		DRV_LOG(ERR, "No memory for hash list %s creation",
			name ? name : "None");
		return NULL;
	}
	h->mask = act_size - 1;
	h->lcores_share = lcores_share;
	h->direct_key = direct_key;
	gc = (struct mlx5_list_cache *)&h->buckets[act_size];
	for (i = 0; i < act_size; i++) {
		if (mlx5_list_init(&h->buckets[i].l, name, ctx, lcores_share,
				   lcores_share ? &gc[i] : NULL,
				   cb_create, cb_match, cb_remove, cb_clone,
				   cb_clone_free) != 0) {
			mlx5_free(h);
			return NULL;
		}
	}
	DRV_LOG(DEBUG, "Hash list %s with size 0x%" PRIX32 " was created.",
		name, act_size);
	return h;
}

struct mlx5_list_entry *
mlx5_hlist_lookup(struct mlx5_hlist *h, uint64_t key, void *ctx)
{
	uint32_t idx;

	if (h->direct_key)
		idx = (uint32_t)(key & h->mask);
	else
		idx = rte_hash_crc_8byte(key, 0) & h->mask;
	return mlx5_list_lookup(&h->buckets[idx].l, ctx);
}

struct mlx5_list_entry*
mlx5_hlist_register(struct mlx5_hlist *h, uint64_t key, void *ctx)
{
	uint32_t idx;
	struct mlx5_list_entry *entry;

	if (h->direct_key)
		idx = (uint32_t)(key & h->mask);
	else
		idx = rte_hash_crc_8byte(key, 0) & h->mask;
	entry = mlx5_list_register(&h->buckets[idx].l, ctx);
	if (likely(entry)) {
		if (h->lcores_share)
			entry->gentry->bucket_idx = idx;
		else
			entry->bucket_idx = idx;
	}
	return entry;
}

int
mlx5_hlist_unregister(struct mlx5_hlist *h, struct mlx5_list_entry *entry)
{
	uint32_t idx = h->lcores_share ? entry->gentry->bucket_idx :
							      entry->bucket_idx;

	return mlx5_list_unregister(&h->buckets[idx].l, entry);
}

void
mlx5_hlist_destroy(struct mlx5_hlist *h)
{
	uint32_t i;

	for (i = 0; i <= h->mask; i++)
		mlx5_list_uninit(&h->buckets[i].l);
	mlx5_free(h);
}
