/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#ifndef _RTE_THASH_GFNI_H_
#define _RTE_THASH_GFNI_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef RTE_ARCH_X86

#include <rte_thash_x86_gfni.h>

#endif

#ifndef RTE_THASH_GFNI_DEFINED

#include <rte_debug.h>

/**
 * Calculate Toeplitz hash.
 *
 * @param m
 *  Pointer to the matrices generated from the corresponding
 *  RSS hash key using rte_thash_complete_matrix().
 * @param tuple
 *  Pointer to the data to be hashed. Data must be in network byte order.
 * @param len
 *  Length of the data to be hashed.
 * @return
 *   Calculated hash value.
 */
static inline uint32_t
rte_thash_gfni(const uint64_t *mtrx __rte_unused,
	const uint8_t *key __rte_unused, int len __rte_unused)
{
	/*
	 * This stub always panics because the application should be calling
	 * rte_thash_gfni_supported() to check if the arch supports this.
	 */
	rte_panic("%s is undefined under given arch\n", __func__);
}

/**
 * Bulk implementation for Toeplitz hash.
 *
 * @param m
 *  Pointer to the matrices generated from the corresponding
 *  RSS hash key using rte_thash_complete_matrix().
 * @param len
 *  Length of the largest data buffer to be hashed.
 * @param tuple
 *  Array of the pointers on data to be hashed.
 *  Data must be in network byte order.
 * @param val
 *  Array of uint32_t where to put calculated Toeplitz hash values
 * @param num
 *  Number of tuples to hash.
 */
static inline void
rte_thash_gfni_bulk(const uint64_t *mtrx __rte_unused,
	int len __rte_unused, uint8_t *tuple[] __rte_unused,
	uint32_t val[] __rte_unused, uint32_t num __rte_unused)
{
	/*
	 * This stub always panics because the application should be calling
	 * rte_thash_gfni_supported() to check if the arch supports this.
	 */
	rte_panic("%s is undefined under given arch\n", __func__);
}

#endif /* RTE_THASH_GFNI_DEFINED */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_THASH_GFNI_H_ */
