#include <stdalign.h>

#include "acl_run.h"

#include <riscv_vector.h>


static const uint8_t idx_const[16] = {
	0, 0, 0, 0, 4, 4, 4, 4,
	8, 8, 8, 8, 12, 12, 12, 12
};

/*
 * Resolve priority for multiple results (scalar version).
 * This consists comparing the priority of the current traversal with the
 * running set of results for the packet.
 * For each result, keep a running array of the result (rule number) and
 * its priority for each category.
 */
static inline void
resolve_priority_rvv(uint64_t transition, int n,
						const struct rte_acl_ctx *ctx,
						struct parms *parms,
						const struct rte_acl_match_results *p,
						uint32_t categories)
{
	uint32_t x;

	for (x = 0; x < categories; x += RTE_ACL_RESULTS_MULTIPLIER) {

		int32_t *saved_results  = (int32_t *)&parms[n].cmplt->results[x];
		int32_t *saved_priority = (int32_t *)&parms[n].cmplt->priority[x];

		const int32_t *cur_results  = (const int32_t *)&p[transition].results[x];
		const int32_t *cur_priority = (const int32_t *)&p[transition].priority[x];

		size_t vl = __riscv_vsetvl_e32m1(RTE_ACL_RESULTS_MULTIPLIER);

		/* load current trie results / priority */
		vint32m1_t v_results  = __riscv_vle32_v_i32m1(cur_results, vl);
		vint32m1_t v_priority = __riscv_vle32_v_i32m1(cur_priority, vl);

		if (parms[n].cmplt->count != ctx->num_tries) {

			/* load running best */
			vint32m1_t v_results1  = __riscv_vle32_v_i32m1(saved_results, vl);
			vint32m1_t v_priority1 = __riscv_vle32_v_i32m1(saved_priority, vl);

			/* selector = priority1 > priority */
			vbool32_t mask = __riscv_vmsgt_vv_i32m1_b32(v_priority1, v_priority, vl);

			/* results = mask ? results1 : results */
			v_results  = __riscv_vmerge_vvm_i32m1(v_results, v_results1, mask, vl);
			v_priority = __riscv_vmerge_vvm_i32m1(v_priority, v_priority1, mask, vl);
		}

		/* store back running best */
		__riscv_vse32_v_i32m1(saved_results,  v_results,  vl);
		__riscv_vse32_v_i32m1(saved_priority, v_priority, vl);
	}
}

vuint32m1_t
transition4_rvv(vuint32m1_t next_input,
				const uint64_t *trans,
				uint64_t transitions[4])
{
	size_t vl = 4;

	vuint64m2_t vtr = __riscv_vle64_v_u64m2(transitions, vl);

	vuint32m1_t lo = __riscv_vnsrl_wx_u32m1(vtr, 0, vl);
	vuint32m1_t hi = __riscv_vnsrl_wx_u32m1(vtr, 32, vl);

	vuint32m1_t addr =
		__riscv_vxor_vv_u32m1(lo, __riscv_vand_vx_u32m1(lo, ~RTE_ACL_NODE_INDEX, vl), vl);

	vuint32m1_t node_type =
		__riscv_vand_vx_u32m1(lo, ~RTE_ACL_NODE_INDEX, vl);

	vbool32_t m_dfa =
		__riscv_vmseq_vx_u32m1_b32(node_type, 0, vl);

	vuint32m1_t input =
		__riscv_vand_vx_u32m1(next_input, 0xff, vl);

	/* ---------------- DFA ---------------- */

	vuint32m1_t grp =
		__riscv_vsrl_vx_u32m1(input, 6, vl);

	vuint32m1_t shift =
		__riscv_vmul_vx_u32m1(grp, RTE_ACL_DFA_GR64_BIT, vl);

	vuint32m1_t dfa_base =
		__riscv_vsrl_vv_u32m1(hi, shift, vl);

	vuint32m1_t dfa_x =
		__riscv_vsub_vv_u32m1(input,
			__riscv_vand_vx_u32m1(dfa_base, UINT8_MAX, vl),
			vl);

	/* ---------------- QRANGE ---------------- */
	vuint8m1_t mask = __riscv_vle8_v_u8m1(idx_const, 16);

	vuint8m1_t in =
		__riscv_vrgather_vv_u8m1(
			__riscv_vreinterpret_v_u32m1_u8m1(next_input),
			mask,
			16);

	vint8m1_t in_s8 =
		__riscv_vreinterpret_v_u8m1_i8m1(in);

	vuint8m1_t ranges_u8 =
		__riscv_vreinterpret_v_u32m1_u8m1(hi);

	vint8m1_t ranges_s8 =
		__riscv_vreinterpret_v_u8m1_i8m1(ranges_u8);

	vbool8_t cmp =
		__riscv_vmsgt_vv_i8m1_b8(in_s8, ranges_s8, 16);
	int32_t q_1 = __riscv_vcpop_m_b8(cmp, 4);
	int32_t q_2 = __riscv_vcpop_m_b8(cmp, 8);
	int32_t q_3 = __riscv_vcpop_m_b8(cmp, 12);
	int32_t q_4 = __riscv_vcpop_m_b8(cmp, 16);
	uint32_t q_scalar[4] = {q_1, q_2 - q_1, q_3 - q_2, q_4 - q_3};
	vuint32m1_t q_x = __riscv_vle32_v_u32m1(q_scalar, 4);


	vuint32m1_t x =
		__riscv_vmerge_vvm_u32m1(q_x, dfa_x, m_dfa, vl);

	addr = __riscv_vadd_vv_u32m1(addr, x, vl);

	vuint64m2_t addr64 =
		__riscv_vwmulu_vx_u64m2(addr, sizeof(uint64_t), vl);
	vuint64m2_t next =
		__riscv_vloxei64_v_u64m2(trans, addr64, vl);

	__riscv_vse64_v_u64m2(transitions, next, vl);

	return __riscv_vsrl_vx_u32m1(next_input, 8, vl);
}

/*
 * Check for any match in 4 transitions
 */
static __rte_always_inline uint32_t
check_any_match_x4(uint64_t val[])
{
	return (val[0] | val[1] | val[2] | val[3]) & RTE_ACL_NODE_MATCH;
}

static __rte_always_inline void
acl_match_check_x4(int slot, const struct rte_acl_ctx *ctx, struct parms *parms,
			struct acl_flow_data *flows, uint64_t transitions[])
{
	while (check_any_match_x4(transitions)) {
		transitions[0] = acl_match_check(transitions[0], slot, ctx,
			parms, flows, resolve_priority_rvv);
		transitions[1] = acl_match_check(transitions[1], slot + 1, ctx,
			parms, flows, resolve_priority_rvv);
		transitions[2] = acl_match_check(transitions[2], slot + 2, ctx,
			parms, flows, resolve_priority_rvv);
		transitions[3] = acl_match_check(transitions[3], slot + 3, ctx,
			parms, flows, resolve_priority_rvv);
	}
}

static inline int
search_rvv_4(const struct rte_acl_ctx *ctx,
			const uint8_t **data,
			uint32_t *results,
			int total_packets,
			uint32_t categories)
{
	struct acl_flow_data flows;
	uint64_t index_array[4];
	struct completion cmplt[4];
	struct parms parms[4];
	vuint32m1_t input;

	acl_set_flow(&flows, cmplt, RTE_DIM(cmplt), data,
				results, total_packets,
				categories, ctx->trans_table);

	for (int i = 0; i < 4; i++)
		index_array[i] =
			acl_start_next_trie(&flows, parms, i, ctx);

	acl_match_check_x4(0, ctx, parms, &flows, index_array);

	while (flows.started > 0) {
		input = __riscv_vmv_v_x_u32m1(GET_NEXT_4BYTES(parms, 0), 4);
		input = __riscv_vslide1down_vx_u32m1(
				input, GET_NEXT_4BYTES(parms, 1), 4);
		input = __riscv_vslide1down_vx_u32m1(
				input, GET_NEXT_4BYTES(parms, 2), 4);
		input = __riscv_vslide1down_vx_u32m1(
				input, GET_NEXT_4BYTES(parms, 3), 4);

		input = transition4_rvv(input, flows.trans, index_array);
		input = transition4_rvv(input, flows.trans, index_array);
		input = transition4_rvv(input, flows.trans, index_array);
		input = transition4_rvv(input, flows.trans, index_array);
		acl_match_check_x4(0, ctx, parms, &flows, index_array);
	}
	return 0;
}
