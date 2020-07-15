/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <errno.h>
#include <rte_malloc.h>
#include <malloc.h>
#include <stdbool.h>
#include <string.h>

#include "mlx5_common_utils.h"
#include "mlx5_malloc.h"

struct mlx5_sys_mem {
	uint32_t init:1; /* Memory allocator initialized. */
	uint32_t enable:1; /* System memory select. */
	uint32_t reserve:30; /* Reserve. */
	struct rte_memseg_list *last_msl;
	/* last allocated rte memory memseg list. */
};

/* Initialize default as not */
static struct mlx5_sys_mem mlx5_sys_mem = {
	.init = 0,
	.enable = 0,
};

/**
 * Check if the address belongs to memory seg list.
 *
 * @param addr
 *   Memory address to be ckeced.
 * @param msl
 *   Memory seg list.
 *
 * @return
 *   True if it belongs, false otherwise.
 */
static bool
mlx5_mem_check_msl(void *addr, struct rte_memseg_list *msl)
{
	void *start, *end;

	if (!msl)
		return false;
	start = msl->base_va;
	end = RTE_PTR_ADD(start, msl->len);
	if (addr >= start && addr < end)
		return true;
	return false;
}

/**
 * Update the msl if memory belongs to new msl.
 *
 * @param addr
 *   Memory address.
 */
static void
mlx5_mem_update_msl(void *addr)
{
	/*
	 * Update the cache msl if the new addr comes from the new msl
	 * different with the cached msl.
	 */
	if (addr && !mlx5_mem_check_msl(addr, mlx5_sys_mem.last_msl))
		mlx5_sys_mem.last_msl = rte_mem_virt2memseg_list(addr);
}

/**
 * Check if the address belongs to rte memory.
 *
 * @param addr
 *   Memory address to be ckeced.
 *
 * @return
 *   True if it belongs, false otherwise.
 */
static bool
mlx5_mem_is_rte(void *addr)
{
	/*
	 * Check if the last cache msl matches. Drop to slow path
	 * to check if the memory belongs to rte memory.
	 */
	if (mlx5_mem_check_msl(addr, mlx5_sys_mem.last_msl) ||
	    rte_mem_virt2memseg_list(addr))
		return true;
	return false;
}

/**
 * Allocate memory with alignment.
 *
 * @param size
 *   Memory size to be allocated.
 * @param align
 *   Memory alignment.
 * @param zero
 *   Clear the allocated memory or not.
 *
 * @return
 *   Pointer of the allocated memory, NULL otherwise.
 */
static void *
mlx5_alloc_align(size_t size, unsigned int align, unsigned int zero)
{
	void *buf;
	buf = memalign(align, size);
	if (!buf) {
		DRV_LOG(ERR, "Couldn't allocate buf.\n");
		return NULL;
	}
	if (zero)
		memset(buf, 0, size);
	return buf;
}

void *
mlx5_malloc(uint32_t flags, size_t size, unsigned int align, int socket)
{
	void *addr;
	bool rte_mem;

	/*
	 * If neither system memory nor rte memory is required, allocate
	 * memory according to mlx5_sys_mem.enable.
	 */
	if (flags & MLX5_MEM_RTE)
		rte_mem = true;
	else if (flags & MLX5_MEM_SYS)
		rte_mem = false;
	else
		rte_mem = mlx5_sys_mem.enable ? false : true;
	if (rte_mem) {
		if (flags & MLX5_MEM_ZERO)
			addr = rte_zmalloc_socket(NULL, size, align, socket);
		else
			addr = rte_malloc_socket(NULL, size, align, socket);
		mlx5_mem_update_msl(addr);
		return addr;
	}
	/* The memory will be allocated from system. */
	if (align)
		return mlx5_alloc_align(size, align, !!(flags & MLX5_MEM_ZERO));
	else if (flags & MLX5_MEM_ZERO)
		return calloc(1, size);
	return malloc(size);
}

void *
mlx5_realloc(void *addr, uint32_t flags, size_t size, unsigned int align,
	     int socket)
{
	void *new_addr;
	bool rte_mem;

	/* Allocate directly if old memory address is NULL. */
	if (!addr)
		return mlx5_malloc(flags, size, align, socket);
	/* Get the memory type. */
	if (flags & MLX5_MEM_RTE)
		rte_mem = true;
	else if (flags & MLX5_MEM_SYS)
		rte_mem = false;
	else
		rte_mem = mlx5_sys_mem.enable ? false : true;
	/* Check if old memory and to be allocated memory are the same type. */
	if (rte_mem != mlx5_mem_is_rte(addr)) {
		DRV_LOG(ERR, "Couldn't reallocate to different memory type.");
		return NULL;
	}
	/* Allocate memory from rte memory. */
	if (rte_mem) {
		new_addr = rte_realloc_socket(addr, size, align, socket);
		mlx5_mem_update_msl(new_addr);
		return new_addr;
	}
	/* Align is not supported for system memory. */
	if (align) {
		DRV_LOG(ERR, "Couldn't reallocate with alignment");
		return NULL;
	}
	return realloc(addr, size);
}

void
mlx5_free(void *addr)
{
	if (!mlx5_mem_is_rte(addr))
		free(addr);
	else
		rte_free(addr);
}

void
mlx5_malloc_mem_select(uint32_t sys_mem_en)
{
	/*
	 * The initialization should be called only once and all devices
	 * should use the same memory type. Otherwise, when new device is
	 * being attached with some different memory allocation configuration,
	 * the memory will get wrong behavior or a failure will be raised.
	 */
	if (!mlx5_sys_mem.init) {
		if (sys_mem_en)
			mlx5_sys_mem.enable = 1;
		mlx5_sys_mem.init = 1;
		DRV_LOG(INFO, "%s is selected.", sys_mem_en ? "SYS_MEM" : "RTE_MEM");
	} else if (mlx5_sys_mem.enable != sys_mem_en) {
		DRV_LOG(WARNING, "%s is already selected.",
			mlx5_sys_mem.enable ? "SYS_MEM" : "RTE_MEM");
	}
}
