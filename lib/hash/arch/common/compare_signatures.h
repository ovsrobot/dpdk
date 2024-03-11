/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright(c) 2018-2024 Arm Limited
 */

/*
 * The generic version could use either a dense or sparsely packed hitmask buffer,
 * but the dense one is slightly faster.
 */

#include <inttypes.h>
#include <rte_common.h>
#include <rte_vect.h>
#include "rte_cuckoo_hash.h"

#define DENSE_HASH_BULK_LOOKUP 1

static inline void
compare_signatures_dense(uint16_t *hitmask_buffer,
			const uint16_t *prim_bucket_sigs,
			const uint16_t *sec_bucket_sigs,
			uint16_t sig,
			enum rte_hash_sig_compare_function sig_cmp_fn)
{
	(void) sig_cmp_fn;

	static_assert(sizeof(*hitmask_buffer) >= 2*(RTE_HASH_BUCKET_ENTRIES/8),
	"The hitmask must be exactly wide enough to accept the whole hitmask if it is dense");

	/* For match mask every bits indicates the match */
	for (unsigned int i = 0; i < RTE_HASH_BUCKET_ENTRIES; i++) {
		*hitmask_buffer |=
			((sig == prim_bucket_sigs[i]) << i);
		*hitmask_buffer |=
			((sig == sec_bucket_sigs[i]) << i) << RTE_HASH_BUCKET_ENTRIES;
	}

}
