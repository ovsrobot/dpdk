/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 HiSilicon Limited
 */

#include <stdio.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memarea.h>
#include <rte_spinlock.h>

#include "memarea_private.h"

static int
memarea_check_param(const struct rte_memarea_param *init)
{
	size_t len;

	len = strnlen(init->name, RTE_MEMAREA_NAMESIZE);
	if (len == 0 || len >= RTE_MEMAREA_NAMESIZE) {
		RTE_LOG(ERR, MEMAREA, "memarea name invalid!\n");
		return -EINVAL;
	}

	if (init->source >= RTE_MEMAREA_SOURCE_BUTT) {
		RTE_LOG(ERR, MEMAREA, "memarea source invalid!\n");
		return -EINVAL;
	}

	if (init->total_sz <= sizeof(struct memarea_elem)) {
		RTE_LOG(ERR, MEMAREA, "memarea total size invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR && init->user_addr == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided addr invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR &&
	    ((uintptr_t)init->user_addr & (RTE_CACHE_LINE_SIZE - 1))) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided addr align invalid!\n");
		return -EINVAL;
	}

	if (init->source == RTE_MEMAREA_SOURCE_USER_MEMAREA && init->user_memarea == NULL) {
		RTE_LOG(ERR, MEMAREA, "memarea user provided memarea invalid!\n");
		return -EINVAL;
	}

	return 0;
}

static void *
memarea_alloc_from_system_api(size_t size)
{
	void *ptr = NULL;
	int ret;

	ret = posix_memalign(&ptr, RTE_CACHE_LINE_SIZE, size);
	if (ret)
		return NULL;
	return ptr;
}

static void *
memarea_alloc_area(const struct rte_memarea_param *init)
{
	void *ptr = NULL;

	if (init->source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		ptr = memarea_alloc_from_system_api(init->total_sz);
	else if (init->source == RTE_MEMAREA_SOURCE_USER_ADDR)
		ptr = init->user_addr;

	if (ptr == NULL)
		RTE_LOG(ERR, MEMAREA, "memarea alloc memory area fail!\n");

	return ptr;
}

struct rte_memarea *
rte_memarea_create(const struct rte_memarea_param *init)
{
	struct memarea_private *priv;
	struct memarea_elem *elem;
	struct rte_memarea *ma;
	void *addr;
	int ret;

	ret = memarea_check_param(init);
	if (ret)
		return NULL;

	addr = memarea_alloc_area(init);
	if (addr == NULL)
		return NULL;

	ma = rte_zmalloc(NULL, sizeof(struct rte_memarea), RTE_CACHE_LINE_SIZE);
	priv = rte_zmalloc(NULL, sizeof(struct memarea_private), RTE_CACHE_LINE_SIZE);
	if (ma == NULL || priv == NULL) {
		RTE_LOG(ERR, MEMAREA, "malloc memarea management obj fail!\n");
		rte_free(ma);
		rte_free(priv);
		return NULL;
	}

	ma->private_data = priv;
	priv->init = *init;
	rte_spinlock_init(&priv->lock);
	TAILQ_INIT(&priv->elem_list);
	TAILQ_INIT(&priv->free_list);
	priv->area_addr = addr;
	elem = addr;
	elem->size = init->total_sz - sizeof(struct memarea_elem);
	elem->cookie = MEMAREA_FREE_ELEM_COOKIE;
	elem->refcnt = 0;
	TAILQ_INSERT_TAIL(&priv->elem_list, elem, elem_node);
	TAILQ_INSERT_TAIL(&priv->free_list, elem, free_node);

	return ma;
}

static void
memarea_free_area(struct memarea_private *priv)
{
	if (priv->init.source == RTE_MEMAREA_SOURCE_SYSTEM_API)
		free(priv->area_addr);
}

void
rte_memarea_destroy(struct rte_memarea *ma)
{
	if (ma == NULL)
		return;
	memarea_free_area(ma->private_data);
	rte_free(ma->private_data);
	rte_free(ma);
}
