/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Intel Corporation
 */

#include "dlb2_priv.h"
/*
 * This source file is only used when the compiler on the build machine
 * does not support AVX512VL.
 */

void
dlb2_build_qes_sse(struct dlb2_enqueue_qe *qe, const struct rte_event ev[], __m128i sse_qe[])
{
		/*
		 * Store the metadata to memory (use the double-precision
		 * _mm_storeh_pd because there is no integer function for
		 * storing the upper 64b):
		 * qe[0] metadata = sse_qe[0][63:0]
		 * qe[1] metadata = sse_qe[0][127:64]
		 * qe[2] metadata = sse_qe[1][63:0]
		 * qe[3] metadata = sse_qe[1][127:64]
		 */
		_mm_storel_epi64((__m128i *)&qe[0].u.opaque_data, sse_qe[0]);
		_mm_storeh_pd((double *)&qe[1].u.opaque_data, (__m128d)sse_qe[0]);
		_mm_storel_epi64((__m128i *)&qe[2].u.opaque_data, sse_qe[1]);
		_mm_storeh_pd((double *)&qe[3].u.opaque_data, (__m128d)sse_qe[1]);

		qe[0].data = ev[0].u64;
		qe[1].data = ev[1].u64;
		qe[2].data = ev[2].u64;
		qe[3].data = ev[3].u64;
}
