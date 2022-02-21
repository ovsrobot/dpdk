/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#ifndef _CUDA_GDRCOPY_H_
#define _CUDA_GDRCOPY_H_

#include <dlfcn.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_errno.h>

#ifdef DRIVERS_GPU_CUDA_GDRCOPY_H
	#include <gdrapi.h>
#else
	struct gdr;
	typedef struct gdr *gdr_t;
	struct gdr_mh_s;
	typedef struct gdr_mh_s gdr_mh_t;
#endif

int gdrcopy_pin(gdr_t *gdrc_h, __rte_unused gdr_mh_t *mh, uint64_t d_addr, size_t size, void **h_addr);
int gdrcopy_unpin(gdr_t gdrc_h, __rte_unused gdr_mh_t mh, void *d_addr, size_t size);

#endif

