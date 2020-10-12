/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_common.h>
#include <rte_memzone.h>
#include <rte_vfio.h>

#include "test.h"

/*
 * Memory
 * ======
 *
 * - Dump the mapped memory. The python-expect script checks that at
 *   least one line is dumped.
 *
 * - Check that memory size is different than 0.
 *
 * - Try to read all memory; it should not segfault.
 */

static int
check_mem(const struct rte_memseg_list *msl __rte_unused,
		const struct rte_memseg *ms, void *arg __rte_unused)
{
	volatile uint8_t *mem = (volatile uint8_t *) ms->addr;
	size_t i, max = ms->len;

	for (i = 0; i < max; i++, mem++)
		*mem;
	return 0;
}

static int
check_seg_fds(const struct rte_memseg_list *msl, const struct rte_memseg *ms,
		void *arg __rte_unused)
{
	size_t offset;
	int ret;

	/* skip external segments */
	if (msl->external)
		return 0;

	/* try segment fd first. we're in a callback, so thread-unsafe */
	ret = rte_memseg_get_fd_thread_unsafe(ms);
	if (ret < 0) {
		/* ENOTSUP means segment is valid, but there is not support for
		 * segment fd API (e.g. on FreeBSD).
		 */
		if (errno == ENOTSUP)
			return 1;
		/* all other errors are treated as failures */
		return -1;
	}

	/* we're able to get memseg fd - try getting its offset */
	ret = rte_memseg_get_fd_offset_thread_unsafe(ms, &offset);
	if (ret < 0) {
		if (errno == ENOTSUP)
			return 1;
		return -1;
	}
	return 0;
}

static int
test_memory_vfio_dma_map(void)
{
	uint64_t sz = 2 * sysconf(_SC_PAGESIZE), sz1, sz2;
	uint64_t unmap1, unmap2;
	uint8_t *mem;
	int ret;

	/* Check if vfio is enabled in both kernel and eal */
	ret = rte_vfio_is_enabled("vfio");
	if (!ret)
		return 1;

	/* Allocate twice size of page */
	mem = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		printf("Failed to allocate memory for external heap\n");
		return -1;
	}

	/* Force page allocation */
	memset(mem, 0, sz);

	/* map the whole region */
	ret = rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD,
					 (uint64_t)mem, (rte_iova_t)mem, sz);
	if (ret) {
		printf("Failed to dma map whole region, ret=%d\n", ret);
		goto fail;
	}

	unmap1 = (uint64_t)mem + (sz / 2);
	sz1 = sz / 2;
	unmap2 = (uint64_t)mem;
	sz2 = sz / 2;
	/* unmap the partial region */
	ret = rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
					   unmap1, (rte_iova_t)unmap1, sz1);
	if (ret) {
		if (rte_errno == ENOTSUP) {
			printf("Partial dma unmap not supported\n");
			unmap2 = (uint64_t)mem;
			sz2 = sz;
		} else {
			printf("Failed to unmap send half region, ret=%d(%d)\n",
			       ret, rte_errno);
			goto fail;
		}
	}

	/* unmap the remaining region */
	ret = rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
					   unmap2, (rte_iova_t)unmap2, sz2);
	if (ret) {
		printf("Failed to unmap remaining region, ret=%d(%d)\n", ret,
		       rte_errno);
		goto fail;
	}

fail:
	munmap(mem, sz);
	return ret;
}

static int
test_memory(void)
{
	uint64_t s;
	int ret;

	/*
	 * dump the mapped memory: the python-expect script checks
	 * that at least one line is dumped
	 */
	printf("Dump memory layout\n");
	rte_dump_physmem_layout(stdout);

	/* check that memory size is != 0 */
	s = rte_eal_get_physmem_size();
	if (s == 0) {
		printf("No memory detected\n");
		return -1;
	}

	/* try to read memory (should not segfault) */
	rte_memseg_walk(check_mem, NULL);

	/* check segment fd support */
	ret = rte_memseg_walk(check_seg_fds, NULL);
	if (ret == 1) {
		printf("Segment fd API is unsupported\n");
	} else if (ret == -1) {
		printf("Error getting segment fd's\n");
		return -1;
	}

	/* test for vfio dma map/unmap */
	ret = test_memory_vfio_dma_map();
	if (ret == 1) {
		printf("VFIO dma map/unmap unsupported\n");
	} else if (ret < 0) {
		printf("Error vfio dma map/unmap, ret=%d\n", ret);
		return -1;
	}

	return 0;
}

REGISTER_TEST_COMMAND(memory_autotest, test_memory);
