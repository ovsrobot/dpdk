/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Maxime Leroy, Free Mobile
 */

#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <eal_export.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_errno.h>
#include <rte_malloc.h>

#include "fib_log.h"
#include "fib_tbl8_pool.h"

static void
pool_init_free_list(struct rte_fib_tbl8_pool *pool)
{
	uint32_t i;

	/* put entire range of indexes to the tbl8 pool */
	for (i = 0; i < pool->num_tbl8s; i++)
		pool->free_list[i] = i;

	pool->cur_tbl8s = 0;
}

int32_t
fib_tbl8_pool_get(struct rte_fib_tbl8_pool *pool)
{
	if (pool->cur_tbl8s == pool->num_tbl8s)
		/* no more free tbl8 */
		return -ENOSPC;

	/* next index */
	return pool->free_list[pool->cur_tbl8s++];
}

void
fib_tbl8_pool_put(struct rte_fib_tbl8_pool *pool, uint32_t idx)
{
	RTE_ASSERT(pool->cur_tbl8s > 0);
	pool->free_list[--pool->cur_tbl8s] = idx;
}

void
fib_tbl8_pool_cleanup_and_free(struct rte_fib_tbl8_pool *pool, uint64_t idx)
{
	uint8_t *ptr = (uint8_t *)pool->tbl8 +
		((idx * FIB_TBL8_GRP_NUM_ENT) << pool->nh_sz);

	memset(ptr, 0, FIB_TBL8_GRP_NUM_ENT << pool->nh_sz);
	fib_tbl8_pool_put(pool, idx);
}

void
fib_tbl8_pool_rcu_free_cb(void *p, void *data,
			  unsigned int n __rte_unused)
{
	struct rte_fib_tbl8_pool *pool = p;
	uint64_t tbl8_idx = *(uint64_t *)data;

	fib_tbl8_pool_cleanup_and_free(pool, tbl8_idx);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_tbl8_pool_resize, 26.07)
int
rte_fib_tbl8_pool_resize(struct rte_fib_tbl8_pool *pool,
			 uint32_t new_num_tbl8)
{
	uint32_t new_num, old_num;
	uint64_t *new_tbl8;
	uint32_t *new_fl;
	char mem_name[64];
	struct fib_tbl8_consumer *c;

	if (pool == NULL)
		return -EINVAL;
	if (pool->v == NULL)
		return -EINVAL;

	old_num = pool->num_tbl8s;
	new_num = new_num_tbl8;
	if (pool->max_tbl8s != 0 && new_num > pool->max_tbl8s)
		new_num = pool->max_tbl8s;
	if (new_num <= old_num)
		return -ENOSPC;

	FIB_LOG(INFO, "Resizing tbl8 pool from %u to %u groups",
		old_num, new_num);

	snprintf(mem_name, sizeof(mem_name), "TBL8_%u", new_num);
	new_tbl8 = rte_zmalloc_socket(mem_name,
		FIB_TBL8_GRP_NUM_ENT * (1ULL << pool->nh_sz) * (new_num + 1),
		RTE_CACHE_LINE_SIZE, pool->socket_id);
	if (new_tbl8 == NULL)
		return -ENOMEM;

	snprintf(mem_name, sizeof(mem_name), "TBL8_FL_%u", new_num);
	new_fl = rte_zmalloc_socket(mem_name,
		sizeof(uint32_t) * new_num,
		RTE_CACHE_LINE_SIZE, pool->socket_id);
	if (new_fl == NULL) {
		rte_free(new_tbl8);
		return -ENOMEM;
	}

	/* Copy existing tbl8 data */
	memcpy(new_tbl8, pool->tbl8,
		FIB_TBL8_GRP_NUM_ENT * (1ULL << pool->nh_sz) * (old_num + 1));

	/*
	 * Rebuild the free list: copy the existing in-use portion,
	 * then append new indices at the top.
	 */
	memcpy(new_fl, pool->free_list, sizeof(uint32_t) * old_num);
	uint32_t i;
	for (i = old_num; i < new_num; i++)
		new_fl[i] = i;

	uint64_t *old_tbl8 = pool->tbl8;
	uint32_t *old_fl = pool->free_list;

	pool->free_list = new_fl;
	pool->num_tbl8s = new_num;

	/*
	 * Ensure copied tbl8 contents are visible before publishing
	 * the new pointer on weakly ordered architectures.
	 */
	atomic_thread_fence(memory_order_release);

	pool->tbl8 = new_tbl8;

	/* Update all registered consumer tbl8 pointers */
	SLIST_FOREACH(c, &pool->consumers, next)
		*c->tbl8_ptr = new_tbl8;

	/*
	 * If RCU is configured, readers may still be accessing old_tbl8.
	 * Synchronize before freeing.
	 */
	if (pool->v != NULL)
		rte_rcu_qsbr_synchronize(pool->v, RTE_QSBR_THRID_INVALID);

	rte_free(old_tbl8);
	rte_free(old_fl);

	return 0;
}

int
fib_tbl8_pool_alloc(struct rte_fib_tbl8_pool *pool, uint64_t nh,
		    struct rte_rcu_qsbr_dq *dq)
{
	int32_t tbl8_idx;
	uint8_t *tbl8_ptr;

	tbl8_idx = fib_tbl8_pool_get(pool);

	/* If there are no tbl8 groups try to reclaim one. */
	if (unlikely(tbl8_idx == -ENOSPC && dq &&
			!rte_rcu_qsbr_dq_reclaim(dq, 1, NULL, NULL, NULL)))
		tbl8_idx = fib_tbl8_pool_get(pool);

	/* Still full -- try to grow the pool */
	if (unlikely(tbl8_idx == -ENOSPC &&
			rte_fib_tbl8_pool_resize(pool, pool->num_tbl8s * 2) == 0))
		tbl8_idx = fib_tbl8_pool_get(pool);

	if (tbl8_idx < 0)
		return tbl8_idx;

	tbl8_ptr = (uint8_t *)pool->tbl8 +
		((tbl8_idx * FIB_TBL8_GRP_NUM_ENT) << pool->nh_sz);
	/* Init tbl8 entries with nexthop */
	fib_tbl8_write((void *)tbl8_ptr, nh, pool->nh_sz,
		       FIB_TBL8_GRP_NUM_ENT);
	return tbl8_idx;
}

int
fib_tbl8_pool_register(struct rte_fib_tbl8_pool *pool, uint64_t **tbl8_ptr)
{
	struct fib_tbl8_consumer *c;

	c = calloc(1, sizeof(*c));
	if (c == NULL)
		return -ENOMEM;

	c->tbl8_ptr = tbl8_ptr;
	SLIST_INSERT_HEAD(&pool->consumers, c, next);
	return 0;
}

void
fib_tbl8_pool_unregister(struct rte_fib_tbl8_pool *pool, uint64_t **tbl8_ptr)
{
	struct fib_tbl8_consumer *c;

	SLIST_FOREACH(c, &pool->consumers, next) {
		if (c->tbl8_ptr == tbl8_ptr) {
			SLIST_REMOVE(&pool->consumers, c,
				fib_tbl8_consumer, next);
			free(c);
			return;
		}
	}
}

void
fib_tbl8_pool_ref(struct rte_fib_tbl8_pool *pool)
{
	pool->refcnt++;
}

static void
pool_free(struct rte_fib_tbl8_pool *pool)
{
	RTE_ASSERT(SLIST_EMPTY(&pool->consumers));
	rte_free(pool->free_list);
	rte_free(pool->tbl8);
	rte_free(pool);
}

void
fib_tbl8_pool_unref(struct rte_fib_tbl8_pool *pool)
{
	if (--pool->refcnt == 0)
		pool_free(pool);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_tbl8_pool_create, 26.07)
struct rte_fib_tbl8_pool *
rte_fib_tbl8_pool_create(const char *name,
			 const struct rte_fib_tbl8_pool_conf *conf)
{
	struct rte_fib_tbl8_pool *pool;
	char mem_name[64];

	if (name == NULL || conf == NULL || conf->num_tbl8 == 0 ||
	    conf->nh_sz > 3 ||
	    (conf->max_tbl8 != 0 &&
	     conf->max_tbl8 < conf->num_tbl8)) {
		rte_errno = EINVAL;
		return NULL;
	}

	snprintf(mem_name, sizeof(mem_name), "TBL8_POOL_%s", name);
	pool = rte_zmalloc_socket(mem_name, sizeof(*pool),
		RTE_CACHE_LINE_SIZE, conf->socket_id);
	if (pool == NULL) {
		rte_errno = ENOMEM;
		return NULL;
	}

	pool->nh_sz = conf->nh_sz;
	pool->num_tbl8s = conf->num_tbl8;
	pool->max_tbl8s = conf->max_tbl8;
	pool->socket_id = conf->socket_id;
	pool->refcnt = 1;
	SLIST_INIT(&pool->consumers);

	snprintf(mem_name, sizeof(mem_name), "TBL8_%s", name);
	pool->tbl8 = rte_zmalloc_socket(mem_name,
		FIB_TBL8_GRP_NUM_ENT * (1ULL << pool->nh_sz) *
		(pool->num_tbl8s + 1),
		RTE_CACHE_LINE_SIZE, conf->socket_id);
	if (pool->tbl8 == NULL) {
		rte_errno = ENOMEM;
		rte_free(pool);
		return NULL;
	}

	snprintf(mem_name, sizeof(mem_name), "TBL8_FL_%s", name);
	pool->free_list = rte_zmalloc_socket(mem_name,
		sizeof(uint32_t) * pool->num_tbl8s,
		RTE_CACHE_LINE_SIZE, conf->socket_id);
	if (pool->free_list == NULL) {
		rte_errno = ENOMEM;
		rte_free(pool->tbl8);
		rte_free(pool);
		return NULL;
	}

	pool_init_free_list(pool);

	return pool;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_tbl8_pool_free, 26.07)
void
rte_fib_tbl8_pool_free(struct rte_fib_tbl8_pool *pool)
{
	if (pool == NULL)
		return;

	fib_tbl8_pool_unref(pool);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_fib_tbl8_pool_rcu_qsbr_add, 26.07)
int
rte_fib_tbl8_pool_rcu_qsbr_add(struct rte_fib_tbl8_pool *pool,
			       const struct rte_fib_tbl8_pool_rcu_config *cfg)
{
	if (pool == NULL || cfg == NULL || cfg->v == NULL)
		return -EINVAL;

	if (pool->v != NULL)
		return -EEXIST;

	if (pool->max_tbl8s == 0)
		return -ENOTSUP;

	pool->v = cfg->v;
	return 0;
}
