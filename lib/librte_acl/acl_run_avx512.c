/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include "acl_run_sse.h"

/*sizeof(uint32_t) << match_log == sizeof(struct rte_acl_match_results)*/
static const uint32_t match_log = 5;

struct acl_flow_avx512 {
	uint32_t num_packets;       /* number of packets processed */
	uint32_t total_packets;     /* max number of packets to process */
	uint32_t root_index;        /* current root index */
	const uint64_t *trans;      /* transition table */
	const uint32_t *data_index; /* input data indexes */
	const uint8_t **idata;      /* input data */
	uint32_t *matches;          /* match indexes */
};

static inline void
acl_set_flow_avx512(struct acl_flow_avx512 *flow, const struct rte_acl_ctx *ctx,
	uint32_t trie, const uint8_t *data[], uint32_t *matches,
	uint32_t total_packets)
{
	flow->num_packets = 0;
	flow->total_packets = total_packets;
	flow->root_index = ctx->trie[trie].root_index;
	flow->trans = ctx->trans_table;
	flow->data_index = ctx->trie[trie].data_index;
	flow->idata = data;
	flow->matches = matches;
}

/*
 * Resolve matches for multiple categories (LE 8, use 128b instuctions/regs)
 */
static inline void
resolve_mcle8_avx512x1(uint32_t result[],
	const struct rte_acl_match_results pr[], const uint32_t match[],
	uint32_t nb_pkt, uint32_t nb_cat, uint32_t nb_trie)
{
	const int32_t *pri;
	const uint32_t *pm, *res;
	uint32_t i, j, k, mi, mn;
	__mmask8 msk;
	xmm_t cp, cr, np, nr;

	res = pr->results;
	pri = pr->priority;

	for (k = 0; k != nb_pkt; k++, result += nb_cat) {

		mi = match[k] << match_log;

		for (j = 0; j != nb_cat; j += RTE_ACL_RESULTS_MULTIPLIER) {

			cr = _mm_loadu_si128((const xmm_t *)(res + mi + j));
			cp = _mm_loadu_si128((const xmm_t *)(pri + mi + j));

			for (i = 1, pm = match + nb_pkt; i != nb_trie;
				i++, pm += nb_pkt) {

				mn = j + (pm[k] << match_log);

				nr = _mm_loadu_si128((const xmm_t *)(res + mn));
				np = _mm_loadu_si128((const xmm_t *)(pri + mn));

				msk = _mm_cmpgt_epi32_mask(cp, np);
				cr = _mm_mask_mov_epi32(nr, msk, cr);
				cp = _mm_mask_mov_epi32(np, msk, cp);
			}

			_mm_storeu_si128((xmm_t *)(result + j), cr);
		}
	}
}

/*
 * Resolve matches for multiple categories (GT 8, use 512b instuctions/regs)
 */
static inline void
resolve_mcgt8_avx512x1(uint32_t result[],
	const struct rte_acl_match_results pr[], const uint32_t match[],
	uint32_t nb_pkt, uint32_t nb_cat, uint32_t nb_trie)
{
	const int32_t *pri;
	const uint32_t *pm, *res;
	uint32_t i, k, mi;
	__mmask16 cm, sm;
	__m512i cp, cr, np, nr;

	const uint32_t match_log = 5;

	res = pr->results;
	pri = pr->priority;

	cm = (1 << nb_cat) - 1;

	for (k = 0; k != nb_pkt; k++, result += nb_cat) {

		mi = match[k] << match_log;

		cr = _mm512_maskz_loadu_epi32(cm, res + mi);
		cp = _mm512_maskz_loadu_epi32(cm, pri + mi);

		for (i = 1, pm = match + nb_pkt; i != nb_trie;
				i++, pm += nb_pkt) {

			mi = pm[k] << match_log;

			nr = _mm512_maskz_loadu_epi32(cm, res + mi);
			np = _mm512_maskz_loadu_epi32(cm, pri + mi);

			sm = _mm512_cmpgt_epi32_mask(cp, np);
			cr = _mm512_mask_mov_epi32(nr, sm, cr);
			cp = _mm512_mask_mov_epi32(np, sm, cp);
		}

		_mm512_mask_storeu_epi32(result, cm, cr);
	}
}

#include "acl_run_avx512x8.h"

int
rte_acl_classify_avx512(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t num, uint32_t categories)
{
	if (num >= MAX_SEARCHES_AVX16)
		return search_avx512x8x2(ctx, data, results, num, categories);
	if (num >= MAX_SEARCHES_SSE8)
		return search_sse_8(ctx, data, results, num, categories);
	if (num >= MAX_SEARCHES_SSE4)
		return search_sse_4(ctx, data, results, num, categories);

	return rte_acl_classify_scalar(ctx, data, results, num, categories);
}
