/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2017 Intel Corporation
 */

efd_value_t efd_lookup_internal_avx2(const efd_hashfunc_t *group_hash_idx,
		const efd_lookuptbl_t *group_lookup_table,
		const uint32_t hash_val_a, const uint32_t hash_val_b);
