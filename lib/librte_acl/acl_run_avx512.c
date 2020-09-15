/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include "acl_run_sse.h"

#define	MASK16_BIT	(sizeof(__mmask16) * CHAR_BIT)

#define NUM_AVX512X16X2	(2 * MASK16_BIT)
#define MSK_AVX512X16X2	(NUM_AVX512X16X2 - 1)

/*sizeof(uint32_t) << match_log == sizeof(struct rte_acl_match_results)*/
static const uint32_t match_log = 5;

struct acl_flow_avx512 {
	uint32_t num_packets;       /* number of packets processed */
	uint32_t total_packets;     /* max number of packets to process */
	uint32_t root_index;        /* current root index */
	uint32_t first_load_sz;     /* first load size for new packet */
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
	flow->first_load_sz = ctx->first_load_sz;
	flow->root_index = ctx->trie[trie].root_index;
	flow->trans = ctx->trans_table;
	flow->data_index = ctx->trie[trie].data_index;
	flow->idata = data;
	flow->matches = matches;
}

/*
 * Update flow and result masks based on the number of unprocessed flows.
 */
static inline uint32_t
update_flow_mask(const struct acl_flow_avx512 *flow, uint32_t *fmsk,
	uint32_t *rmsk)
{
	uint32_t i, j, k, m, n;

	fmsk[0] ^= rmsk[0];
	m = rmsk[0];

	k = __builtin_popcount(m);
	n = flow->total_packets - flow->num_packets;

	if (n < k) {
		/* reduce mask */
		for (i = k - n; i != 0; i--) {
			j = sizeof(m) * CHAR_BIT - 1 - __builtin_clz(m);
			m ^= 1 << j;
		}
	} else
		n = k;

	rmsk[0] = m;
	fmsk[0] |= rmsk[0];

	return n;
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

/*
 * unfortunately current AVX512 ISA doesn't provide ability for
 * gather load on a byte quantity. So we have to mimic it in SW,
 * by doing 8x1B scalar loads.
 */
static inline ymm_t
_m512_mask_gather_epi8x8(__m512i pdata, __mmask8 mask)
{
	__m512i t;
	rte_ymm_t v;
	__rte_x86_zmm_t p;

	static const uint32_t zero;

	t = _mm512_set1_epi64((uintptr_t)&zero);
	p.z = _mm512_mask_mov_epi64(t, mask, pdata);

	v.u32[0] = *(uint8_t *)p.u64[0];
	v.u32[1] = *(uint8_t *)p.u64[1];
	v.u32[2] = *(uint8_t *)p.u64[2];
	v.u32[3] = *(uint8_t *)p.u64[3];
	v.u32[4] = *(uint8_t *)p.u64[4];
	v.u32[5] = *(uint8_t *)p.u64[5];
	v.u32[6] = *(uint8_t *)p.u64[6];
	v.u32[7] = *(uint8_t *)p.u64[7];

	return v.y;
}

/*
 * resolve match index to actual result/priority offset.
 */
static inline __m512i
resolve_match_idx_avx512x16(__m512i mi)
{
	RTE_BUILD_BUG_ON(sizeof(struct rte_acl_match_results) !=
		1 << (match_log + 2));
	return _mm512_slli_epi32(mi, match_log);
}

/*
 * Resolve multiple matches for the same flow based on priority.
 */
static inline __m512i
resolve_pri_avx512x16(const int32_t res[], const int32_t pri[],
	const uint32_t match[], __mmask16 msk, uint32_t nb_trie,
	uint32_t nb_skip)
{
	uint32_t i;
	const uint32_t *pm;
	__mmask16 m;
	__m512i cp, cr, np, nr, mch;

	const __m512i zero = _mm512_set1_epi32(0);

	/* get match indexes */
	mch = _mm512_maskz_loadu_epi32(msk, match);
	mch = resolve_match_idx_avx512x16(mch);

	/* read result and priority values for first trie */
	cr = _mm512_mask_i32gather_epi32(zero, msk, mch, res, sizeof(res[0]));
	cp = _mm512_mask_i32gather_epi32(zero, msk, mch, pri, sizeof(pri[0]));

	/*
	 * read result and priority values for next tries and select one
	 * with highest priority.
	 */
	for (i = 1, pm = match + nb_skip; i != nb_trie;
			i++, pm += nb_skip) {

		mch = _mm512_maskz_loadu_epi32(msk, pm);
		mch = resolve_match_idx_avx512x16(mch);

		nr = _mm512_mask_i32gather_epi32(zero, msk, mch, res,
			sizeof(res[0]));
		np = _mm512_mask_i32gather_epi32(zero, msk, mch, pri,
			sizeof(pri[0]));

		m = _mm512_cmpgt_epi32_mask(cp, np);
		cr = _mm512_mask_mov_epi32(nr, m, cr);
		cp = _mm512_mask_mov_epi32(np, m, cp);
	}

	return cr;
}

/*
 * Resolve num (<= 16) matches for single category
 */
static inline void
resolve_sc_avx512x16(uint32_t result[], const int32_t res[],
	const int32_t pri[], const uint32_t match[], uint32_t nb_pkt,
	uint32_t nb_trie, uint32_t nb_skip)
{
	__mmask16 msk;
	__m512i cr;

	msk = (1 << nb_pkt) - 1;
	cr = resolve_pri_avx512x16(res, pri, match, msk, nb_trie, nb_skip);
	_mm512_mask_storeu_epi32(result, msk, cr);
}

/*
 * Resolve matches for single category
 */
static inline void
resolve_sc_avx512x16x2(uint32_t result[],
	const struct rte_acl_match_results pr[], const uint32_t match[],
	uint32_t nb_pkt, uint32_t nb_trie)
{
	uint32_t j, k, n;
	const int32_t *res, *pri;
	__m512i cr[2];

	res = (const int32_t *)pr->results;
	pri = pr->priority;

	for (k = 0; k != (nb_pkt & ~MSK_AVX512X16X2); k += NUM_AVX512X16X2) {

		j = k + MASK16_BIT;

		cr[0] = resolve_pri_avx512x16(res, pri, match + k, UINT16_MAX,
				nb_trie, nb_pkt);
		cr[1] = resolve_pri_avx512x16(res, pri, match + j, UINT16_MAX,
				nb_trie, nb_pkt);

		_mm512_storeu_si512(result + k, cr[0]);
		_mm512_storeu_si512(result + j, cr[1]);
	}

	n = nb_pkt - k;
	if (n != 0) {
		if (n > MASK16_BIT) {
			resolve_sc_avx512x16(result + k, res, pri, match + k,
				MASK16_BIT, nb_trie, nb_pkt);
			k += MASK16_BIT;
			n -= MASK16_BIT;
		}
		resolve_sc_avx512x16(result + k, res, pri, match + k, n,
				nb_trie, nb_pkt);
	}
}

#include "acl_run_avx512x8.h"
#include "acl_run_avx512x16.h"

int
rte_acl_classify_avx512(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t num, uint32_t categories)
{
	const uint32_t max_iter = MAX_SEARCHES_AVX16 * MAX_SEARCHES_AVX16;

	/* split huge lookup (gt 256) into series of fixed size ones */
	while (num > max_iter) {
		search_avx512x16x2(ctx, data, results, max_iter, categories);
		data += max_iter;
		results += max_iter * categories;
		num -= max_iter;
	}

	/* select classify method based on number of remainig requests */
	if (num >= 2 * MAX_SEARCHES_AVX16)
		return search_avx512x16x2(ctx, data, results, num, categories);
	if (num >= MAX_SEARCHES_AVX16)
		return search_avx512x8x2(ctx, data, results, num, categories);
	if (num >= MAX_SEARCHES_SSE8)
		return search_sse_8(ctx, data, results, num, categories);
	if (num >= MAX_SEARCHES_SSE4)
		return search_sse_4(ctx, data, results, num, categories);

	return rte_acl_classify_scalar(ctx, data, results, num, categories);
}
