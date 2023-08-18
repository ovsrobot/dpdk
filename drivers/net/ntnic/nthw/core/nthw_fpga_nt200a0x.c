/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"

#include "nthw_fpga.h"
#include "nthw_fpga_nt200a0x.h"

int nthw_fpga_nt200a0x_init(struct fpga_info_s *p_fpga_info)
{
	assert(p_fpga_info);

	const char *const p_adapter_id_str = p_fpga_info->mp_adapter_id_str;
	struct nthw_fpga_rst_nt200a0x rst;
	int res = -1;

	/* reset common */
	res = nthw_fpga_rst_nt200a0x_init(p_fpga_info, &rst);
	if (res) {
		NT_LOG(ERR, NTHW, "%s: %s: loc=%u: FPGA=%04d res=%d\n",
		       p_adapter_id_str, __func__, __LINE__,
		       p_fpga_info->n_fpga_prod_id, res);
		return res;
	}

	/* reset specific */
	switch (p_fpga_info->n_fpga_prod_id) {
	case 9563:
		res = nthw_fpga_rst9563_init(p_fpga_info, &rst);
		break;
	default:
		NT_LOG(ERR, NTHW, "%s: Unsupported FPGA product: %04d\n",
		       p_adapter_id_str, p_fpga_info->n_fpga_prod_id);
		res = -1;
		break;
	}
	if (res) {
		NT_LOG(ERR, NTHW, "%s: %s: loc=%u: FPGA=%04d res=%d\n",
		       p_adapter_id_str, __func__, __LINE__,
		       p_fpga_info->n_fpga_prod_id, res);
		return res;
	}

	return res;
}
