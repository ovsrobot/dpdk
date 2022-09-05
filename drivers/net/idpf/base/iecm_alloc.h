/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2022 Intel Corporation
 */

#ifndef _IECM_ALLOC_H_
#define _IECM_ALLOC_H_

/* Memory types */
enum iecm_memset_type {
	IECM_NONDMA_MEM = 0,
	IECM_DMA_MEM
};

/* Memcpy types */
enum iecm_memcpy_type {
	IECM_NONDMA_TO_NONDMA = 0,
	IECM_NONDMA_TO_DMA,
	IECM_DMA_TO_DMA,
	IECM_DMA_TO_NONDMA
};

#endif /* _IECM_ALLOC_H_ */
