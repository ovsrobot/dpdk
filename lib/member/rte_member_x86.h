/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Intel Corporation
 */

#ifndef _RTE_MEMBER_X86_H_
#define _RTE_MEMBER_X86_H_

#include "rte_member_ht.h"

int update_entry_search_avx(uint32_t bucket_id, member_sig_t tmp_sig,
		struct member_ht_bucket *buckets,
		member_set_t set_id);

int search_bucket_single_avx(uint32_t bucket_id, member_sig_t tmp_sig,
		struct member_ht_bucket *buckets,
		member_set_t *set_id);

void search_bucket_multi_avx(uint32_t bucket_id, member_sig_t tmp_sig,
				struct member_ht_bucket *buckets,
				uint32_t *counter,
				uint32_t match_per_key,
				member_set_t *set_id);

#endif /* _RTE_MEMBER_X86_H_ */
