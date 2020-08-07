/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#define	MASK16_BIT	(sizeof(__mmask16) * CHAR_BIT)

#define NUM_AVX512X16X2	(2 * MASK16_BIT)
#define MSK_AVX512X16X2	(NUM_AVX512X16X2 - 1)

static const __rte_x86_zmm_t zmm_match_mask = {
	.u32 = {
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
		RTE_ACL_NODE_MATCH,
	},
};

static const __rte_x86_zmm_t zmm_index_mask = {
	.u32 = {
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
		RTE_ACL_NODE_INDEX,
	},
};

static const __rte_x86_zmm_t zmm_trlo_idle = {
	.u32 = {
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
		RTE_ACL_DFA_SIZE | RTE_ACL_NODE_SINGLE,
	},
};

static const __rte_x86_zmm_t zmm_trhi_idle = {
	.u32 = {
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
	},
};

static const __rte_x86_zmm_t zmm_shuffle_input = {
	.u32 = {
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
	},
};

static const __rte_x86_zmm_t zmm_four_32 = {
	.u32 = {
		4, 4, 4, 4,
		4, 4, 4, 4,
		4, 4, 4, 4,
		4, 4, 4, 4,
	},
};

static const __rte_x86_zmm_t zmm_idx_add = {
	.u32 = {
		0, 1, 2, 3,
		4, 5, 6, 7,
		8, 9, 10, 11,
		12, 13, 14, 15,
	},
};

static const __rte_x86_zmm_t zmm_range_base = {
	.u32 = {
		0xffffff00, 0xffffff04, 0xffffff08, 0xffffff0c,
		0xffffff00, 0xffffff04, 0xffffff08, 0xffffff0c,
		0xffffff00, 0xffffff04, 0xffffff08, 0xffffff0c,
		0xffffff00, 0xffffff04, 0xffffff08, 0xffffff0c,
	},
};

/*
 * Calculate the address of the next transition for
 * all types of nodes. Note that only DFA nodes and range
 * nodes actually transition to another node. Match
 * nodes not supposed to be encountered here.
 * For quad range nodes:
 * Calculate number of range boundaries that are less than the
 * input value. Range boundaries for each node are in signed 8 bit,
 * ordered from -128 to 127.
 * This is effectively a popcnt of bytes that are greater than the
 * input byte.
 * Single nodes are processed in the same ways as quad range nodes.
 */
static __rte_always_inline __m512i
calc_addr16(__m512i index_mask, __m512i next_input, __m512i shuffle_input,
	__m512i four_32, __m512i range_base, __m512i tr_lo, __m512i tr_hi)
{
	__mmask64 qm;
	__mmask16 dfa_msk;
	__m512i addr, in, node_type, r, t;
	__m512i dfa_ofs, quad_ofs;

	t = _mm512_xor_si512(index_mask, index_mask);
	in = _mm512_shuffle_epi8(next_input, shuffle_input);

	/* Calc node type and node addr */
	node_type = _mm512_andnot_si512(index_mask, tr_lo);
	addr = _mm512_and_si512(index_mask, tr_lo);

	/* mask for DFA type(0) nodes */
	dfa_msk = _mm512_cmpeq_epi32_mask(node_type, t);

	/* DFA calculations. */
	r = _mm512_srli_epi32(in, 30);
	r = _mm512_add_epi8(r, range_base);
	t = _mm512_srli_epi32(in, 24);
	r = _mm512_shuffle_epi8(tr_hi, r);

	dfa_ofs = _mm512_sub_epi32(t, r);

	/* QUAD/SINGLE calculations. */
	qm = _mm512_cmpgt_epi8_mask(in, tr_hi);
	t = _mm512_maskz_set1_epi8(qm, (uint8_t)UINT8_MAX);
	t = _mm512_lzcnt_epi32(t);
	t = _mm512_srli_epi32(t, 3);
	quad_ofs = _mm512_sub_epi32(four_32, t);

	/* blend DFA and QUAD/SINGLE. */
	t = _mm512_mask_mov_epi32(quad_ofs, dfa_msk, dfa_ofs);

	/* calculate address for next transitions. */
	addr = _mm512_add_epi32(addr, t);
	return addr;
}

/*
 * Process 8 transitions in parallel.
 * tr_lo contains low 32 bits for 8 transition.
 * tr_hi contains high 32 bits for 8 transition.
 * next_input contains up to 4 input bytes for 8 flows.
 */
static __rte_always_inline __m512i
transition16(__m512i next_input, const uint64_t *trans, __m512i *tr_lo,
	__m512i *tr_hi)
{
	const int32_t *tr;
	__m512i addr;

	tr = (const int32_t *)(uintptr_t)trans;

	/* Calculate the address (array index) for all 8 transitions. */
	addr = calc_addr16(zmm_index_mask.z, next_input, zmm_shuffle_input.z,
		zmm_four_32.z, zmm_range_base.z, *tr_lo, *tr_hi);

	/* load lower 32 bits of 8 transactions at once. */
	*tr_lo = _mm512_i32gather_epi32(addr, tr, sizeof(trans[0]));

	next_input = _mm512_srli_epi32(next_input, CHAR_BIT);

	/* load high 32 bits of 8 transactions at once. */
	*tr_hi = _mm512_i32gather_epi32(addr, (tr + 1), sizeof(trans[0]));

	return next_input;
}

static __rte_always_inline void
first_trans16(const struct acl_flow_avx512 *flow, __m512i next_input,
	__mmask16 msk, __m512i *tr_lo, __m512i *tr_hi)
{
	const int32_t *tr;
	__m512i addr, root;

	tr = (const int32_t *)(uintptr_t)flow->trans;

	addr = _mm512_set1_epi32(UINT8_MAX);
	root = _mm512_set1_epi32(flow->root_index);

	addr = _mm512_and_si512(next_input, addr);
	addr = _mm512_add_epi32(root, addr);

	/* load lower 32 bits of 8 transactions at once. */
	*tr_lo = _mm512_mask_i32gather_epi32(*tr_lo, msk, addr, tr,
		sizeof(flow->trans[0]));

	/* load high 32 bits of 8 transactions at once. */
	*tr_hi = _mm512_mask_i32gather_epi32(*tr_hi, msk, addr, (tr + 1),
		sizeof(flow->trans[0]));
}

static inline __m512i
get_next_4bytes_avx512x16(const struct acl_flow_avx512 *flow, __m512i pdata[2],
	uint32_t msk, __m512i *di)
{
	const int32_t *div;
	__m512i one, zero, t, p[2];
	ymm_t inp[2];

	static const __rte_x86_zmm_t zmm_pminp = {
		.u32 = {
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		},
	};

	const __mmask16 pmidx_msk = 0x5555;

	static const __rte_x86_zmm_t zmm_pmidx[2] = {
		[0] = {
			.u32 = {
				0, 0, 1, 0, 2, 0, 3, 0,
				4, 0, 5, 0, 6, 0, 7, 0,
			},
		},
		[1] = {
			.u32 = {
				8, 0, 9, 0, 10, 0, 11, 0,
				12, 0, 13, 0, 14, 0, 15, 0,
			},
		},
	};

	div = (const int32_t *)flow->data_index;

	one = _mm512_set1_epi32(1);
	zero = _mm512_xor_si512(one, one);

	t = _mm512_mask_i32gather_epi32(zero, msk, *di, div, sizeof(div[0]));

	*di = _mm512_mask_add_epi32(*di, msk, *di, one);

	p[0] = _mm512_maskz_permutexvar_epi32(pmidx_msk, zmm_pmidx[0].z, t);
	p[1] = _mm512_maskz_permutexvar_epi32(pmidx_msk, zmm_pmidx[1].z, t);

	p[0] = _mm512_add_epi64(p[0], pdata[0]);
	p[1] = _mm512_add_epi64(p[1], pdata[1]);

	inp[0] = _mm512_mask_i64gather_epi32(_mm512_castsi512_si256(zero),
		(msk & UINT8_MAX), p[0], NULL, sizeof(uint8_t));
	inp[1] = _mm512_mask_i64gather_epi32(_mm512_castsi512_si256(zero),
		(msk >> CHAR_BIT), p[1], NULL, sizeof(uint8_t));

	return _mm512_permutex2var_epi32(_mm512_castsi256_si512(inp[0]),
			zmm_pminp.z, _mm512_castsi256_si512(inp[1]));
}

static inline void
start_flow16(struct acl_flow_avx512 *flow, uint32_t num, uint32_t msk,
	__m512i pdata[2], __m512i *idx, __m512i *di)
{
	uint32_t n, nm[2];
	__m512i ni, nd[2];

	n = __builtin_popcount(msk & UINT8_MAX);
	nm[0] = (1 << n) - 1;
	nm[1] = (1 << (num - n)) - 1;

	nd[0] = _mm512_maskz_loadu_epi64(nm[0],
		flow->idata + flow->num_packets);
	nd[1] = _mm512_maskz_loadu_epi64(nm[1],
		flow->idata + flow->num_packets + n);

	ni = _mm512_set1_epi32(flow->num_packets);
	ni = _mm512_add_epi32(ni, zmm_idx_add.z);

	pdata[0] = _mm512_mask_expand_epi64(pdata[0], (msk & UINT8_MAX), nd[0]);
	pdata[1] = _mm512_mask_expand_epi64(pdata[1], (msk >> CHAR_BIT), nd[1]);

	*idx = _mm512_mask_expand_epi32(*idx, msk, ni);
	*di = _mm512_maskz_mov_epi32(msk ^ UINT16_MAX, *di);

	flow->num_packets += num;
}

static inline uint32_t
update_flow_mask16(const struct acl_flow_avx512 *flow, __mmask16 *fmsk,
	__mmask16 *rmsk)
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

static inline uint32_t
match_process_avx512x16(struct acl_flow_avx512 *flow, __mmask16 *fmsk,
	__mmask16 *rmsk, __m512i pdata[2], __m512i *di, __m512i *idx,
	__m512i *tr_lo, __m512i *tr_hi)
{
	uint32_t n;
	__m512i res;

	if (rmsk[0] == 0)
		return 0;

	/* extract match indexes */
	res = _mm512_and_si512(tr_lo[0], zmm_index_mask.z);

	/* mask  matched transitions to nop */
	tr_lo[0] = _mm512_mask_mov_epi32(tr_lo[0], rmsk[0], zmm_trlo_idle.z);
	tr_hi[0] = _mm512_mask_mov_epi32(tr_hi[0], rmsk[0], zmm_trhi_idle.z);

	/* save found match indexes */
	_mm512_mask_i32scatter_epi32(flow->matches, rmsk[0],
		idx[0], res, sizeof(flow->matches[0]));

	/* update masks and start new flows for matches */
	n = update_flow_mask16(flow, fmsk, rmsk);
	start_flow16(flow, n, rmsk[0], pdata, idx, di);

	return n;
}

static inline void
match_check_process_avx512x16x2(struct acl_flow_avx512 *flow, __mmask16 fm[2],
	__m512i pdata[4], __m512i di[2], __m512i idx[2], __m512i inp[2],
	__m512i tr_lo[2], __m512i tr_hi[2])
{
	uint32_t n[2];
	__mmask16 rm[2];

	/* check for matches */
	rm[0] = _mm512_test_epi32_mask(tr_lo[0], zmm_match_mask.z);
	rm[1] = _mm512_test_epi32_mask(tr_lo[1], zmm_match_mask.z);

	while ((rm[0] | rm[1]) != 0) {

		n[0] = match_process_avx512x16(flow, &fm[0], &rm[0], &pdata[0],
			&di[0], &idx[0], &tr_lo[0], &tr_hi[0]);
		n[1] = match_process_avx512x16(flow, &fm[1], &rm[1], &pdata[2],
			&di[1], &idx[1], &tr_lo[1], &tr_hi[1]);

		if (n[0] != 0) {
			inp[0] = get_next_4bytes_avx512x16(flow, &pdata[0],
				rm[0], &di[0]);
			first_trans16(flow, inp[0], rm[0], &tr_lo[0],
				&tr_hi[0]);
			rm[0] = _mm512_test_epi32_mask(tr_lo[0],
				zmm_match_mask.z);
		}

		if (n[1] != 0) {
			inp[1] = get_next_4bytes_avx512x16(flow, &pdata[2],
				rm[1], &di[1]);
			first_trans16(flow, inp[1], rm[1], &tr_lo[1],
				&tr_hi[1]);
			rm[1] = _mm512_test_epi32_mask(tr_lo[1],
				zmm_match_mask.z);
		}
	}
}

static inline void
search_trie_avx512x16x2(struct acl_flow_avx512 *flow)
{
	__mmask16 fm[2];
	__m512i di[2], idx[2], in[2], pdata[4], tr_lo[2], tr_hi[2];

	/* first 1B load */
	start_flow16(flow, MASK16_BIT, UINT16_MAX, &pdata[0], &idx[0], &di[0]);
	start_flow16(flow, MASK16_BIT, UINT16_MAX, &pdata[2], &idx[1], &di[1]);

	in[0] = get_next_4bytes_avx512x16(flow, &pdata[0], UINT16_MAX, &di[0]);
	in[1] = get_next_4bytes_avx512x16(flow, &pdata[2], UINT16_MAX, &di[1]);

	first_trans16(flow, in[0], UINT16_MAX, &tr_lo[0], &tr_hi[0]);
	first_trans16(flow, in[1], UINT16_MAX, &tr_lo[1], &tr_hi[1]);

	fm[0] = UINT16_MAX;
	fm[1] = UINT16_MAX;

	/* match check */
	match_check_process_avx512x16x2(flow, fm, pdata, di, idx, in,
		tr_lo, tr_hi);

	while ((fm[0] | fm[1]) != 0) {

		/* load next 4B */

		in[0] = get_next_4bytes_avx512x16(flow, &pdata[0], fm[0],
			&di[0]);
		in[1] = get_next_4bytes_avx512x16(flow, &pdata[2], fm[1],
			&di[1]);

		/* main 4B loop */

		in[0] = transition16(in[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		in[1] = transition16(in[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		in[0] = transition16(in[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		in[1] = transition16(in[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		in[0] = transition16(in[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		in[1] = transition16(in[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		in[0] = transition16(in[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		in[1] = transition16(in[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		/* check for matches */
		match_check_process_avx512x16x2(flow, fm, pdata, di, idx, in,
			tr_lo, tr_hi);
	}
}

static inline __m512i
resolve_match_idx_avx512x16(__m512i mi)
{
	RTE_BUILD_BUG_ON(sizeof(struct rte_acl_match_results) !=
		1 << (match_log + 2));
	return _mm512_slli_epi32(mi, match_log);
}

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

	mch = _mm512_maskz_loadu_epi32(msk, match);
	mch = resolve_match_idx_avx512x16(mch);

	cr = _mm512_mask_i32gather_epi32(zero, msk, mch, res, sizeof(res[0]));
	cp = _mm512_mask_i32gather_epi32(zero, msk, mch, pri, sizeof(pri[0]));

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
	uint32_t i, j, k, n;
	const uint32_t *pm;
	const int32_t *res, *pri;
	__mmask16 m[2];
	__m512i cp[2], cr[2], np[2], nr[2], mch[2];

	res = (const int32_t *)pr->results;
	pri = pr->priority;

	for (k = 0; k != (nb_pkt & ~MSK_AVX512X16X2); k += NUM_AVX512X16X2) {

		j = k + MASK16_BIT;

		/* load match indexes for first trie */
		mch[0] = _mm512_loadu_si512(match + k);
		mch[1] = _mm512_loadu_si512(match + j);

		mch[0] = resolve_match_idx_avx512x16(mch[0]);
		mch[1] = resolve_match_idx_avx512x16(mch[1]);

		/* load matches and their priorities for first trie */

		cr[0] = _mm512_i32gather_epi32(mch[0], res, sizeof(res[0]));
		cr[1] = _mm512_i32gather_epi32(mch[1], res, sizeof(res[0]));

		cp[0] = _mm512_i32gather_epi32(mch[0], pri, sizeof(pri[0]));
		cp[1] = _mm512_i32gather_epi32(mch[1], pri, sizeof(pri[0]));

		/* select match with highest priority */
		for (i = 1, pm = match + nb_pkt; i != nb_trie;
				i++, pm += nb_pkt) {

			mch[0] = _mm512_loadu_si512(pm + k);
			mch[1] = _mm512_loadu_si512(pm + j);

			mch[0] = resolve_match_idx_avx512x16(mch[0]);
			mch[1] = resolve_match_idx_avx512x16(mch[1]);

			nr[0] = _mm512_i32gather_epi32(mch[0], res,
				sizeof(res[0]));
			nr[1] = _mm512_i32gather_epi32(mch[1], res,
				sizeof(res[0]));

			np[0] = _mm512_i32gather_epi32(mch[0], pri,
				sizeof(pri[0]));
			np[1] = _mm512_i32gather_epi32(mch[1], pri,
				sizeof(pri[0]));

			m[0] = _mm512_cmpgt_epi32_mask(cp[0], np[0]);
			m[1] = _mm512_cmpgt_epi32_mask(cp[1], np[1]);

			cr[0] = _mm512_mask_mov_epi32(nr[0], m[0], cr[0]);
			cr[1] = _mm512_mask_mov_epi32(nr[1], m[1], cr[1]);

			cp[0] = _mm512_mask_mov_epi32(np[0], m[0], cp[0]);
			cp[1] = _mm512_mask_mov_epi32(np[1], m[1], cp[1]);
		}

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

static inline int
search_avx512x16x2(const struct rte_acl_ctx *ctx, const uint8_t **data,
	uint32_t *results, uint32_t total_packets, uint32_t categories)
{
	uint32_t i, *pm;
	const struct rte_acl_match_results *pr;
	struct acl_flow_avx512 flow;
	uint32_t match[ctx->num_tries * total_packets];

	for (i = 0, pm = match; i != ctx->num_tries; i++, pm += total_packets) {

		/* setup for next trie */
		acl_set_flow_avx512(&flow, ctx, i, data, pm, total_packets);

		/* process the trie */
		search_trie_avx512x16x2(&flow);
	}

	/* resolve matches */
	pr = (const struct rte_acl_match_results *)
		(ctx->trans_table + ctx->match_index);

	if (categories == 1)
		resolve_sc_avx512x16x2(results, pr, match, total_packets,
			ctx->num_tries);
	else if (categories <= RTE_ACL_MAX_CATEGORIES / 2)
		resolve_mcle8_avx512x1(results, pr, match, total_packets,
			categories, ctx->num_tries);
	else
		resolve_mcgt8_avx512x1(results, pr, match, total_packets,
			categories, ctx->num_tries);

	return 0;
}
