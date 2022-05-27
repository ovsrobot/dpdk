/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 StarFive
 * Copyright(c) 2022 SiFive
 * Copyright(c) 2022 Semihalf
 */

#ifndef _RTE_LPM_SCALAR_H_
#define _RTE_LPM_SCALAR_H_

#include <rte_branch_prediction.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_vect.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline void
rte_lpm_lookupx4(const struct rte_lpm *lpm, xmm_t ip, uint32_t hop[4],
		uint32_t defv)
{
	uint32_t nh;
	int i, ret;

	for (i = 0; i < 4; i++) {
		ret = rte_lpm_lookup(lpm, ((rte_xmm_t)ip).u32[i], &nh);
		hop[i] = (ret == 0) ? nh : defv;
	}
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_LPM_SCALAR_H_ */
