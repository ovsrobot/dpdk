/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nthw_drv.h"
#include "nt4ga_adapter.h"
#include "nthw_fpga.h"
#include "nt4ga_tfg.h"

int nt4ga_tfg_init(struct adapter_info_s *p_adapter_info)
{
	const char *const p_adapter_id_str = p_adapter_info->mp_adapter_id_str;

	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	nthw_fpga_t *p_fpga = fpga_info->mp_fpga;
	nt4ga_tfg_t *p_nt4ga_tfg = &p_adapter_info->nt4ga_tfg;

	nthw_gfg_t *p_nthw_gfg = nthw_gfg_new();

	if (p_nthw_gfg) {
		int res = nthw_gfg_init(p_nthw_gfg, p_fpga, 0);

		if (res) {
			NT_LOG(WRN, ETHDEV, "%s: TFG/GFG capability is not available\n",
				p_adapter_id_str);
			free(p_nthw_gfg);
			p_nthw_gfg = NULL;
		}
	}

	p_nt4ga_tfg->mp_nthw_gfg = p_nthw_gfg;

	return p_nthw_gfg ? 0 : -1;
}

int nt4ga_tfg_setup(struct adapter_info_s *p_adapter_info, const int n_intf_no,
	const int n_cmd_start_stop, const int n_frame_count, const int n_frame_size,
	const int n_frame_fill_mode, const int n_frame_stream_id)
{
	fpga_info_t *fpga_info = &p_adapter_info->fpga_info;
	nt4ga_tfg_t *p_nt4ga_tfg = &p_adapter_info->nt4ga_tfg;

	nthw_gfg_t *p_nthw_gfg = p_nt4ga_tfg->mp_nthw_gfg;

	if (p_nthw_gfg) {
		nthw_fpga_t *p_fpga = fpga_info->mp_fpga;

		/* Does FPGA have GMF module? */
		if (nthw_gmf_init(NULL, p_fpga, n_intf_no) == 0) {
			/* Yes, FPGA has GMF module */
			nthw_gmf_t gmf;

			if (nthw_gmf_init(&gmf, p_fpga, n_intf_no) == 0)
				nthw_gmf_set_ifg_speed_percent(&gmf, n_cmd_start_stop);
		}

		if (n_cmd_start_stop) {
			nthw_gfg_start(p_nthw_gfg, n_intf_no, n_frame_count, n_frame_size,
				n_frame_fill_mode, n_frame_stream_id);

		} else {
			nthw_gfg_stop(p_nthw_gfg, n_intf_no);
		}
	}

	return 0;
}
