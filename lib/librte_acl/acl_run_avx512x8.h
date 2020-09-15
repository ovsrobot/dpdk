/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#define NUM_AVX512X8X2	(2 * CHAR_BIT)
#define MSK_AVX512X8X2	(NUM_AVX512X8X2 - 1)

static const rte_ymm_t ymm_match_mask = {
	.u32 = {
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

static const rte_ymm_t ymm_index_mask = {
	.u32 = {
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

static const rte_ymm_t ymm_trlo_idle = {
	.u32 = {
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
		RTE_ACL_IDLE_NODE,
	},
};

static const rte_ymm_t ymm_trhi_idle = {
	.u32 = {
		0, 0, 0, 0,
		0, 0, 0, 0,
	},
};

static const rte_ymm_t ymm_shuffle_input = {
	.u32 = {
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
		0x00000000, 0x04040404, 0x08080808, 0x0c0c0c0c,
	},
};

static const rte_ymm_t ymm_four_32 = {
	.u32 = {
		4, 4, 4, 4,
		4, 4, 4, 4,
	},
};

static const rte_ymm_t ymm_idx_add = {
	.u32 = {
		0, 1, 2, 3,
		4, 5, 6, 7,
	},
};

static const rte_ymm_t ymm_range_base = {
	.u32 = {
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
static __rte_always_inline ymm_t
calc_addr8(ymm_t index_mask, ymm_t next_input, ymm_t shuffle_input,
	ymm_t four_32, ymm_t range_base, ymm_t tr_lo, ymm_t tr_hi)
{
	ymm_t addr, in, node_type, r, t;
	ymm_t dfa_msk, dfa_ofs, quad_ofs;

	t = _mm256_xor_si256(index_mask, index_mask);
	in = _mm256_shuffle_epi8(next_input, shuffle_input);

	/* Calc node type and node addr */
	node_type = _mm256_andnot_si256(index_mask, tr_lo);
	addr = _mm256_and_si256(index_mask, tr_lo);

	/* mask for DFA type(0) nodes */
	dfa_msk = _mm256_cmpeq_epi32(node_type, t);

	/* DFA calculations. */
	r = _mm256_srli_epi32(in, 30);
	r = _mm256_add_epi8(r, range_base);
	t = _mm256_srli_epi32(in, 24);
	r = _mm256_shuffle_epi8(tr_hi, r);

	dfa_ofs = _mm256_sub_epi32(t, r);

	/* QUAD/SINGLE calculations. */
	t = _mm256_cmpgt_epi8(in, tr_hi);
	t = _mm256_lzcnt_epi32(t);
	t = _mm256_srli_epi32(t, 3);
	quad_ofs = _mm256_sub_epi32(four_32, t);

	/* blend DFA and QUAD/SINGLE. */
	t = _mm256_blendv_epi8(quad_ofs, dfa_ofs, dfa_msk);

	/* calculate address for next transitions. */
	addr = _mm256_add_epi32(addr, t);
	return addr;
}

/*
 * Process 8 transitions in parallel.
 * tr_lo contains low 32 bits for 8 transitions.
 * tr_hi contains high 32 bits for 8 transitions.
 * next_input contains up to 4 input bytes for 8 flows.
 */
static __rte_always_inline ymm_t
transition8(ymm_t next_input, const uint64_t *trans, ymm_t *tr_lo, ymm_t *tr_hi)
{
	const int32_t *tr;
	ymm_t addr;

	tr = (const int32_t *)(uintptr_t)trans;

	/* Calculate the address (array index) for all 8 transitions. */
	addr = calc_addr8(ymm_index_mask.y, next_input, ymm_shuffle_input.y,
		ymm_four_32.y, ymm_range_base.y, *tr_lo, *tr_hi);

	/* load lower 32 bits of 8 transactions at once. */
	*tr_lo = _mm256_i32gather_epi32(tr, addr, sizeof(trans[0]));

	next_input = _mm256_srli_epi32(next_input, CHAR_BIT);

	/* load high 32 bits of 8 transactions at once. */
	*tr_hi = _mm256_i32gather_epi32(tr + 1, addr, sizeof(trans[0]));

	return next_input;
}

/*
 * Execute first transition for up to 8 flows in parallel.
 * next_input should contain one input byte for up to 8 flows.
 * msk - mask of active flows.
 * tr_lo contains low 32 bits for up to 8 transitions.
 * tr_hi contains high 32 bits for up to 8 transitions.
 */
static __rte_always_inline void
first_trans8(const struct acl_flow_avx512 *flow, ymm_t next_input,
	__mmask8 msk, ymm_t *tr_lo, ymm_t *tr_hi)
{
	const int32_t *tr;
	ymm_t addr, root;

	tr = (const int32_t *)(uintptr_t)flow->trans;

	addr = _mm256_set1_epi32(UINT8_MAX);
	root = _mm256_set1_epi32(flow->root_index);

	addr = _mm256_and_si256(next_input, addr);
	addr = _mm256_add_epi32(root, addr);

	/* load lower 32 bits of 8 transactions at once. */
	*tr_lo = _mm256_mmask_i32gather_epi32(*tr_lo, msk, addr, tr,
		sizeof(flow->trans[0]));

	/* load high 32 bits of 8 transactions at once. */
	*tr_hi = _mm256_mmask_i32gather_epi32(*tr_hi, msk, addr, (tr + 1),
		sizeof(flow->trans[0]));
}

/*
 * Load and return next 4 input bytes for up to 8 flows in parallel.
 * pdata - 8 pointers to flow input data
 * mask - mask of active flows.
 * di - data indexes for these 8 flows.
 */
static inline ymm_t
get_next_bytes_avx512x8(const struct acl_flow_avx512 *flow, __m512i pdata,
	__mmask8 mask, ymm_t *di, uint32_t bnum)
{
	const int32_t *div;
	ymm_t one, zero;
	ymm_t inp, t;
	__m512i p;

	div = (const int32_t *)flow->data_index;

	one = _mm256_set1_epi32(1);
	zero = _mm256_xor_si256(one, one);

	/* load data offsets for given indexes */
	t = _mm256_mmask_i32gather_epi32(zero, mask, *di, div, sizeof(div[0]));

	/* increment data indexes */
	*di = _mm256_mask_add_epi32(*di, mask, *di, one);

	p = _mm512_cvtepu32_epi64(t);
	p = _mm512_add_epi64(p, pdata);

	/* load input byte(s), either one or four */
	if (bnum == sizeof(uint8_t))
		inp = _m512_mask_gather_epi8x8(p, mask);
	else
		inp = _mm512_mask_i64gather_epi32(zero, mask, p, NULL,
			sizeof(uint8_t));
	return inp;
}

/*
 * Start up to 8 new flows.
 * num - number of flows to start
 * msk - mask of new flows.
 * pdata - pointers to flow input data
 * di - data indexes for these flows.
 */
static inline void
start_flow8(struct acl_flow_avx512 *flow, uint32_t num, uint32_t msk,
	__m512i *pdata, ymm_t *idx, ymm_t *di)
{
	uint32_t nm;
	ymm_t ni;
	__m512i nd;

	/* load input data pointers for new flows */
	nm = (1 << num) - 1;
	nd = _mm512_maskz_loadu_epi64(nm, flow->idata + flow->num_packets);

	/* calculate match indexes of new flows */
	ni = _mm256_set1_epi32(flow->num_packets);
	ni = _mm256_add_epi32(ni, ymm_idx_add.y);

	/* merge new and existing flows data */
	*pdata = _mm512_mask_expand_epi64(*pdata, msk, nd);
	*idx = _mm256_mask_expand_epi32(*idx, msk, ni);
	*di = _mm256_maskz_mov_epi32(msk ^ UINT8_MAX, *di);

	flow->num_packets += num;
}

/*
 * Process found matches for up to 8 flows.
 * fmsk - mask of active flows
 * rmsk - mask of found matches
 * pdata - pointers to flow input data
 * di - data indexes for these flows
 * idx - match indexed for given flows
 * tr_lo contains low 32 bits for up to 8 transitions.
 * tr_hi contains high 32 bits for up to 8 transitions.
 */
static inline uint32_t
match_process_avx512x8(struct acl_flow_avx512 *flow, uint32_t *fmsk,
	uint32_t *rmsk,	__m512i *pdata, ymm_t *di, ymm_t *idx,
	ymm_t *tr_lo, ymm_t *tr_hi)
{
	uint32_t n;
	ymm_t res;

	if (rmsk[0] == 0)
		return 0;

	/* extract match indexes */
	res = _mm256_and_si256(tr_lo[0], ymm_index_mask.y);

	/* mask  matched transitions to nop */
	tr_lo[0] = _mm256_mask_mov_epi32(tr_lo[0], rmsk[0], ymm_trlo_idle.y);
	tr_hi[0] = _mm256_mask_mov_epi32(tr_hi[0], rmsk[0], ymm_trhi_idle.y);

	/* save found match indexes */
	_mm256_mask_i32scatter_epi32(flow->matches, rmsk[0],
		idx[0], res, sizeof(flow->matches[0]));

	/* update masks and start new flows for matches */
	n = update_flow_mask(flow, fmsk, rmsk);
	start_flow8(flow, n, rmsk[0], pdata, idx, di);

	return n;
}


static inline void
match_check_process_avx512x8x2(struct acl_flow_avx512 *flow, uint32_t fm[2],
	__m512i pdata[2], ymm_t di[2], ymm_t idx[2], ymm_t inp[2],
	ymm_t tr_lo[2], ymm_t tr_hi[2])
{
	uint32_t n[2];
	uint32_t rm[2];

	/* check for matches */
	rm[0] = _mm256_test_epi32_mask(tr_lo[0], ymm_match_mask.y);
	rm[1] = _mm256_test_epi32_mask(tr_lo[1], ymm_match_mask.y);

	/* till unprocessed matches exist */
	while ((rm[0] | rm[1]) != 0) {

		/* process matches and start new flows */
		n[0] = match_process_avx512x8(flow, &fm[0], &rm[0], &pdata[0],
			&di[0], &idx[0], &tr_lo[0], &tr_hi[0]);
		n[1] = match_process_avx512x8(flow, &fm[1], &rm[1], &pdata[1],
			&di[1], &idx[1], &tr_lo[1], &tr_hi[1]);

		/* execute first transition for new flows, if any */

		if (n[0] != 0) {
			inp[0] = get_next_bytes_avx512x8(flow, pdata[0], rm[0],
				&di[0], sizeof(uint8_t));
			first_trans8(flow, inp[0], rm[0], &tr_lo[0], &tr_hi[0]);

			rm[0] = _mm256_test_epi32_mask(tr_lo[0],
				ymm_match_mask.y);
		}

		if (n[1] != 0) {
			inp[1] = get_next_bytes_avx512x8(flow, pdata[1], rm[1],
				&di[1], sizeof(uint8_t));
			first_trans8(flow, inp[1], rm[1], &tr_lo[1], &tr_hi[1]);

			rm[1] = _mm256_test_epi32_mask(tr_lo[1],
				ymm_match_mask.y);
		}
	}
}

/*
 * Perform search for up to 16 flows in parallel.
 * Use two sets of metadata, each serves 8 flows max.
 * So in fact we perform search for 2x8 flows.
 */
static inline void
search_trie_avx512x8x2(struct acl_flow_avx512 *flow)
{
	uint32_t fm[2];
	__m512i pdata[2];
	ymm_t di[2], idx[2], inp[2], tr_lo[2], tr_hi[2];

	/* first 1B load */
	start_flow8(flow, CHAR_BIT, UINT8_MAX, &pdata[0], &idx[0], &di[0]);
	start_flow8(flow, CHAR_BIT, UINT8_MAX, &pdata[1], &idx[1], &di[1]);

	inp[0] = get_next_bytes_avx512x8(flow, pdata[0], UINT8_MAX, &di[0],
		sizeof(uint8_t));
	inp[1] = get_next_bytes_avx512x8(flow, pdata[1], UINT8_MAX, &di[1],
		sizeof(uint8_t));

	first_trans8(flow, inp[0], UINT8_MAX, &tr_lo[0], &tr_hi[0]);
	first_trans8(flow, inp[1], UINT8_MAX, &tr_lo[1], &tr_hi[1]);

	fm[0] = UINT8_MAX;
	fm[1] = UINT8_MAX;

	/* match check */
	match_check_process_avx512x8x2(flow, fm, pdata, di, idx, inp,
		tr_lo, tr_hi);

	while ((fm[0] | fm[1]) != 0) {

		/* load next 4B */

		inp[0] = get_next_bytes_avx512x8(flow, pdata[0], fm[0],
			&di[0], sizeof(uint32_t));
		inp[1] = get_next_bytes_avx512x8(flow, pdata[1], fm[1],
			&di[1], sizeof(uint32_t));

		/* main 4B loop */

		inp[0] = transition8(inp[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		inp[1] = transition8(inp[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		inp[0] = transition8(inp[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		inp[1] = transition8(inp[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		inp[0] = transition8(inp[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		inp[1] = transition8(inp[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		inp[0] = transition8(inp[0], flow->trans, &tr_lo[0], &tr_hi[0]);
		inp[1] = transition8(inp[1], flow->trans, &tr_lo[1], &tr_hi[1]);

		/* check for matches */
		match_check_process_avx512x8x2(flow, fm, pdata, di, idx, inp,
			tr_lo, tr_hi);
	}
}

static inline int
search_avx512x8x2(const struct rte_acl_ctx *ctx, const uint8_t **data,
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
		search_trie_avx512x8x2(&flow);
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
