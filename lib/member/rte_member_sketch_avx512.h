/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_MEMBER_SKETCH_AVX512_H_
#define _RTE_MEMBER_SKETCH_AVX512_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_vect.h>
#include "rte_member.h"
#include "rte_member_sketch.h"

#define NUM_ROW_VEC 8

void
sketch_update_avx512(const struct rte_member_setsum *ss,
		     const void *key,
		     uint32_t count);

uint64_t
sketch_lookup_avx512(const struct rte_member_setsum *ss,
		     const void *key);

void
sketch_delete_avx512(const struct rte_member_setsum *ss,
		     const void *key);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_MEMBER_SKETCH_AVX512_H_ */
