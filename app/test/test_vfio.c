/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell.
 */

#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_eal.h>
#include <rte_eal_paging.h>
#include <rte_errno.h>
#include <rte_memory.h>
#include <rte_vfio.h>

#include "test.h"

static int
test_memory_vfio_dma_map(void)
{
	uint64_t sz1, sz2, sz = 2 * rte_mem_page_size();
	uint64_t unmap1, unmap2;
	uint8_t *alloc_mem;
	uint8_t *mem;
	int ret;

	/* Allocate twice size of requirement from heap to align later */
	alloc_mem = malloc(sz * 2);
	if (!alloc_mem) {
		printf("Skipping test as unable to alloc %"PRIx64"B from heap\n",
		       sz * 2);
		return 1;
	}

	/* Force page allocation */
	memset(alloc_mem, 0, sz * 2);

	mem = RTE_PTR_ALIGN(alloc_mem, rte_mem_page_size());

	/* map the whole region */
	ret = rte_vfio_container_dma_map(RTE_VFIO_DEFAULT_CONTAINER_FD,
					 (uintptr_t)mem, (rte_iova_t)mem, sz);
	if (ret) {
		/* Check if VFIO is not available or no device is probed */
		if (rte_errno == ENOTSUP || rte_errno == ENODEV) {
			ret = 1;
			goto fail;
		}
		printf("Failed to dma map whole region, ret=%d(%s)\n",
		       ret, rte_strerror(rte_errno));
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
			printf("Failed to unmap second half region, ret=%d(%s)\n",
			       ret, rte_strerror(rte_errno));
			goto fail;
		}
	}

	/* unmap the remaining region */
	ret = rte_vfio_container_dma_unmap(RTE_VFIO_DEFAULT_CONTAINER_FD,
					   unmap2, (rte_iova_t)unmap2, sz2);
	if (ret) {
		printf("Failed to unmap remaining region, ret=%d(%s)\n", ret,
		       rte_strerror(rte_errno));
		goto fail;
	}

fail:
	free(alloc_mem);
	return ret;
}

static int
test_vfio(void)
{
	int ret;

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

REGISTER_TEST_COMMAND(vfio_autotest, test_vfio);
