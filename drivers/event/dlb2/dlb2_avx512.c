/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */
#include "dlb2_priv.h"

/*
 * This source file is used when the compiler on the build machine
 * supports AVX512VL. We will perform a runtime check before actually
 * executing those instructions.
 */

void
dlb2_build_qes_avx512(struct dlb2_enqueue_qe *qe, const struct rte_event ev[], __m128i sse_qe[])
{
	/*
	 * 1) Build avx512 QE store and build each QE individualy as XMM register
	 * 2) Merge the 4 XMM registers/QEs into single AVX512 register
	 * 3) Store single avx512 register to &qe[0] (4x QEs stored in 1x store)
	 */

	__m128i v_qe0 = _mm_setzero_si128();
	uint64_t meta = _mm_extract_epi64(sse_qe[0], 0);
	v_qe0 = _mm_insert_epi64(v_qe0, ev[0].u64, 0);
	v_qe0 = _mm_insert_epi64(v_qe0, meta, 1);

	__m128i v_qe1 = _mm_setzero_si128();
	meta = _mm_extract_epi64(sse_qe[0], 1);
	v_qe1 = _mm_insert_epi64(v_qe1, ev[1].u64, 0);
	v_qe1 = _mm_insert_epi64(v_qe1, meta, 1);

	__m128i v_qe2 = _mm_setzero_si128();
	meta = _mm_extract_epi64(sse_qe[1], 0);
	v_qe2 = _mm_insert_epi64(v_qe2, ev[2].u64, 0);
	v_qe2 = _mm_insert_epi64(v_qe2, meta, 1);

	__m128i v_qe3 = _mm_setzero_si128();
	meta = _mm_extract_epi64(sse_qe[1], 1);
	v_qe3 = _mm_insert_epi64(v_qe3, ev[3].u64, 0);
	v_qe3 = _mm_insert_epi64(v_qe3, meta, 1);

	/* we have 4x XMM registers, one per QE. */
	__m512i v_all_qes = _mm512_setzero_si512();
	v_all_qes = _mm512_inserti32x4(v_all_qes, v_qe0, 0);
	v_all_qes = _mm512_inserti32x4(v_all_qes, v_qe1, 1);
	v_all_qes = _mm512_inserti32x4(v_all_qes, v_qe2, 2);
	v_all_qes = _mm512_inserti32x4(v_all_qes, v_qe3, 3);

	/* store the 4x QEs in a single register to the scratch space of the PMD */
	_mm512_store_si512(&qe[0], v_all_qes);
}
