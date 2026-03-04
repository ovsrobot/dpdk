/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Institute of Software Chinese Academy of Sciences (ISCAS).
 */

#ifndef __RTE_EFD_RISCV_H__
#define __RTE_EFD_RISCV_H__

#include <riscv_vector.h>

static inline efd_value_t
efd_lookup_internal_rvv(const efd_hashfunc_t *group_hash_idx,
				const efd_lookuptbl_t *group_lookup_table,
				const uint32_t hash_val_a, const uint32_t hash_val_b)
{
		efd_value_t value = 0;
		const uint32_t N = RTE_EFD_VALUE_NUM_BITS;
		size_t vl = 4;
		vuint32m1_t vhash_val_a = __riscv_vmv_v_x_u32m1(hash_val_a, vl);
		vuint32m1_t vhash_val_b = __riscv_vmv_v_x_u32m1(hash_val_b, vl);
		vuint32m1_t vshift = __riscv_vid_v_u32m1(vl);
		vuint32m1_t vmask = __riscv_vmv_v_x_u32m1(0x1, vl);
		vuint32m1_t vincr = __riscv_vmv_v_x_u32m1(4, vl);
		for (unsigned int i = 0; i < N; i += vl) {
			vuint16mf2_t vhash_idx16 =
				__riscv_vle16_v_u16mf2(
					(const uint16_t *)&group_hash_idx[i], vl);

			vuint32m1_t vhash_idx =
				__riscv_vwcvtu_x_x_v_u32m1(vhash_idx16, vl);

			vuint16mf2_t vlookup16 =
				__riscv_vle16_v_u16mf2(
					(const uint16_t *)&group_lookup_table[i], vl);

			vuint32m1_t vlookup =
				__riscv_vwcvtu_x_x_v_u32m1(vlookup16, vl);

			vuint32m1_t vhash =
				__riscv_vmadd_vv_u32m1(vhash_idx, vhash_val_b, vhash_val_a, vl);

			vuint32m1_t vbucket =
				__riscv_vsrl_vx_u32m1(vhash, EFD_LOOKUPTBL_SHIFT, vl);

			vuint32m1_t vresult =
				__riscv_vsrl_vv_u32m1(vlookup, vbucket, vl);

			vresult = __riscv_vand_vv_u32m1(vresult, vmask, vl);

			vresult = __riscv_vsll_vv_u32m1(vresult, vshift, vl);

			vuint32m1_t vzero = __riscv_vmv_v_x_u32m1(0, vl);

			vuint32m1_t vsum =
				__riscv_vredsum_vs_u32m1_u32m1(vresult, vzero, vl);

			value |= __riscv_vmv_x_s_u32m1_u32(vsum);

			vshift = __riscv_vadd_vv_u32m1(vshift, vincr, vl);
		}

		return value;
}

#endif /* __RTE_EFD_RISCV_H__ */
