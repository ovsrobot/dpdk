/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_common.h"

uint32_t __rte_atomic nbl_dma_memzone_id;

/**
 * @brief: used to alloc continuous dma memory region for cmd buffer
 * @mem: output, the memory object containing va, pa and size of memory
 * @size: input, memory size in bytes
 * @return: memory virtual address for cpu usage
 */
void *nbl_alloc_dma_mem(struct nbl_dma_mem *mem, uint32_t size)
{
	const struct rte_memzone *mz = NULL;
	char z_name[RTE_MEMZONE_NAMESIZE];

	if (!mem)
		return NULL;

	snprintf(z_name, sizeof(z_name), "nbl_dma_%u",
		rte_atomic_fetch_add_explicit(&nbl_dma_memzone_id, 1, rte_memory_order_relaxed));
	mz = rte_memzone_reserve_bounded(z_name, size, SOCKET_ID_ANY, 0,
					 0, RTE_PGSIZE_2M);
	if (!mz)
		return NULL;

	mem->size = size;
	mem->va = mz->addr;
	mem->pa = mz->iova;
	mem->zone = (const void *)mz;

	return mem->va;
}

/**
 * @brief: used to free dma memory region
 * @mem: input, the memory object
 */
void nbl_free_dma_mem(struct nbl_dma_mem *mem)
{
	rte_memzone_free((const struct rte_memzone *)mem->zone);
	mem->zone = NULL;
	mem->va = NULL;
	mem->pa = (uint64_t)0;
}
