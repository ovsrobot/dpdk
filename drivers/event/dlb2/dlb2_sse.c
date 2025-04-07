/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include "dlb2_priv.h"
/*
 * This source file is only used when the compiler on the build machine
 * does not support AVX512.
 */

void dlb2_build_qes_sse(struct dlb2_enqueue_qe *qe, const struct rte_event ev[],
			uint16_t *cmd_weight, uint16_t *sched_word)
{
	__m128i shuffle_mask =
	    _mm_set_epi8(0xFF, 0xFF, /* zero out cmd word */
			 1, 0,	     /* low 16-bits of flow id */
			 0xFF, 0xFF, /* zero QID, sched_type etc fields to be filled later */
			 3, 2,	     /* top of flow id, event type and subtype */
			 15, 14, 13, 12, 11, 10, 9, 8 /* data from end of event goes at start */
	    );

	for (int i = 0; i < 4; ++i) {
		/* event may not be 16 byte aligned. Use 16 byte unaligned load */
		__m128i tmp = _mm_lddqu_si128((const __m128i *)&ev[i]);

		tmp = _mm_shuffle_epi8(tmp, shuffle_mask);
		/* set the cmd field */
		tmp = _mm_insert_epi16(tmp, cmd_weight[i], 7);
		/* insert missing 16-bits with qid, sched_type and priority */
		tmp = _mm_insert_epi16(tmp, sched_word[i], 5);
		/* Finally, store to qes*/
		_mm_storeu_si128((__m128i *)&qe[i], tmp);
	}
}
