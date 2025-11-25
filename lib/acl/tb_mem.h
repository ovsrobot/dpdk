/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _TB_MEM_H_
#define _TB_MEM_H_

/**
 * @file
 *
 * RTE ACL temporary (build phase) memory management.
 * Contains structures and functions to manage temporary (used by build only)
 * memory. Memory allocated in large blocks to speed 'free' when trie is
 * destructed (finish of build phase).
 */

#include <rte_acl_osdep.h>
#include <setjmp.h>

struct tb_mem_block {
	struct tb_mem_block *next;
	struct tb_mem_pool  *pool;
	size_t               size;
	uint8_t             *mem;
};

typedef void *(*rte_tb_alloc_t)(size_t, sigjmp_buf, void *);
typedef void (*rte_tb_reset_t)(void *);

struct tb_mem_pool {
	struct tb_mem_block *block;
	size_t               alignment;
	size_t               min_alloc;
	size_t               alloc;
	rte_tb_alloc_t       alloc_cb;
	rte_tb_reset_t       reset_cb;
	void                 *cb_ctx;
	/* jump target in case of memory allocation failure. */
	sigjmp_buf           fail;
};

void *tb_alloc(struct tb_mem_pool *pool, size_t size);
void tb_free_pool(struct tb_mem_pool *pool);

#endif /* _TB_MEM_H_ */
