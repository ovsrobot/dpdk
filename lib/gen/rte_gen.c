/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include "rte_gen.h"

#include <rte_malloc.h>

/** Structure that represents a traffic generator. */
struct rte_gen {
	/* Mempool that buffers are retrieved from. */
	struct rte_mempool *mp;
};

/* Allocate and initialize a traffic generator instance. */
struct rte_gen *
rte_gen_create(struct rte_mempool *mempool)
{
	struct rte_gen *gen = rte_zmalloc(NULL, sizeof(*gen), 0);
	if (gen == NULL)
		return NULL;

	gen->mp = mempool;

	return gen;
}

/* Free a traffic generator instance. */
void
rte_gen_destroy(struct rte_gen *gen)
{
	rte_free(gen);
}
