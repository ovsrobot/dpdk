/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */
#include "dlb2_priv.h"

/*
 * This source file is used when the compiler on the build machine
 * supports AVX512VL. We will perform a runtime check before actually
 * executing those instructions.
 */

void dlb2_build_qes_avx512(struct dlb2_enqueue_qe *qe, const struct rte_event ev[],
			   uint16_t *cmd_weight, uint16_t *sched_word)
{
	/* _mm512_shuffle_epi8() shuffles within each 128-bit lane. So set the same mask for each
	 * 128-bit lane.
	 */
	__m512i shuffle_mask = _mm512_set_epi8(
				0XFF, 0xFF, 1, 0, 0xFF, 0xFF, 3, 2, 15, 14, 13, 12, 11, 10, 9, 8,
				0XFF, 0xFF, 1, 0, 0xFF, 0xFF, 3, 2, 15, 14, 13, 12, 11, 10, 9, 8,
				0XFF, 0xFF, 1, 0, 0xFF, 0xFF, 3, 2, 15, 14, 13, 12, 11, 10, 9, 8,
				0XFF, 0xFF, 1, 0, 0xFF, 0xFF, 3, 2, 15, 14, 13, 12, 11, 10, 9, 8);

	__m512i sched_cmd = _mm512_set_epi16(cmd_weight[3], 0, sched_word[3], 0, 0, 0, 0, 0,
					     cmd_weight[2], 0, sched_word[2], 0, 0, 0, 0, 0,
					     cmd_weight[1], 0, sched_word[1], 0, 0, 0, 0, 0,
					     cmd_weight[0], 0, sched_word[0], 0, 0, 0, 0, 0);
	__m512i tmp = _mm512_loadu_epi8((const __m512i *)ev);

	tmp = _mm512_shuffle_epi8(tmp, shuffle_mask);
	tmp = _mm512_or_si512(tmp, sched_cmd);

	_mm512_storeu_si512(qe, tmp);
}
