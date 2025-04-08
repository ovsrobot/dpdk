/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */
#include "dlb2_priv.h"

/*
 * This source file is used when the compiler on the build machine
 * supports AVX512VL. We will perform a runtime check before actually
 * executing those instructions.
 */

/* Upper 64-bits of mask to set flow-id, event type, subtype with zeroed out
 * cmd word, QID, sched_type etc.
 */
#define UMASK 0xffff0100ffff0302
/* Lower 64-bits of mask setting event data */
#define LMASK 0xf0e0d0c0b0a0908

#define SET_SCH_CMD(a, b) (((uint64_t)a << 48) | b << 16)

void dlb2_build_qes_avx512(struct dlb2_enqueue_qe *qe, const struct rte_event ev[],
			   uint16_t *cmd_weight, uint16_t *sched_word)
{
	/* _mm512_shuffle_epi8() shuffles within each 128-bit lane. So set the same mask for each
	 * 128-bit lane.
	 */
	__m512i shuffle_mask = _mm512_set_epi64(UMASK, LMASK, UMASK, LMASK,
						UMASK, LMASK, UMASK, LMASK);
	__m512i sched_cmd = _mm512_set_epi64(SET_SCH_CMD(cmd_weight[3], sched_word[3]), 0,
					     SET_SCH_CMD(cmd_weight[2], sched_word[2]), 0,
					     SET_SCH_CMD(cmd_weight[1], sched_word[1]), 0,
					     SET_SCH_CMD(cmd_weight[0], sched_word[0]), 0);
	__m512i tmp = _mm512_loadu_si512((const __m512i *)ev);

	tmp = _mm512_shuffle_epi8(tmp, shuffle_mask);
	tmp = _mm512_or_si512(tmp, sched_cmd);

	_mm512_storeu_si512(qe, tmp);
}
