/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdio.h>
#include <assert.h>

#include <rte_malloc.h>

#include "ntlog.h"
#include "nt_util.h"

static struct nt_util_vfio_impl vfio_cb;

void nt_util_vfio_init(struct nt_util_vfio_impl *impl)
{
	vfio_cb = *impl;
}

struct nt_dma_s *nt_dma_alloc(uint64_t size, uint64_t align, int numa)
{
	int res;
	struct nt_dma_s *vfio_addr;

	vfio_addr = rte_malloc(NULL, sizeof(struct nt_dma_s), 0);
	if (!vfio_addr) {
		NT_LOG(ERR, GENERAL, "VFIO rte_malloc failed\n");
		return NULL;
	}
	void *addr = rte_malloc_socket(NULL, size, align, numa);

	if (!addr) {
		rte_free(vfio_addr);
		NT_LOG(ERR, GENERAL, "VFIO rte_malloc_socket failed\n");
		return NULL;
	}
	res = vfio_cb.vfio_dma_map(0, addr, &vfio_addr->iova,
				   ALIGN_SIZE(size));
	if (res != 0) {
		rte_free(addr);
		rte_free(vfio_addr);
		NT_LOG(ERR, GENERAL, "VFIO nt_dma_map failed\n");
		return NULL;
	}

	vfio_addr->addr = (uint64_t)addr;
	vfio_addr->size = ALIGN_SIZE(size);

	NT_LOG(DBG, GENERAL,
	       "VFIO DMA alloc addr=%" PRIX64 ", iova=%" PRIX64
	       ", size=%u, align=0x%X\n",
	       vfio_addr->addr, vfio_addr->iova, vfio_addr->size, align);

	return vfio_addr;
}

void nt_dma_free(struct nt_dma_s *vfio_addr)
{
	NT_LOG(DBG, GENERAL,
	       "VFIO DMA free addr=%" PRIX64 ", iova=%" PRIX64 ", size=%u\n",
	       vfio_addr->addr, vfio_addr->iova, vfio_addr->size);

	int res = vfio_cb.vfio_dma_unmap(0, (void *)(vfio_addr->addr),
					 vfio_addr->iova, vfio_addr->size);
	if (res != 0) {
		NT_LOG(WRN, GENERAL,
		       "VFIO DMA free FAILED addr=%" PRIX64 ", iova=%" PRIX64
		       ", size=%u\n",
		       vfio_addr->addr, vfio_addr->iova, vfio_addr->size);
	}
	rte_free((void *)(vfio_addr->addr));
	rte_free(vfio_addr);
}
