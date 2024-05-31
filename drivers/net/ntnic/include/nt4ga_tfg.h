/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT4GA_TFG_H_
#define NT4GA_TFG_H_

typedef struct nt4ga_tfg_s {
	nthw_gfg_t *mp_nthw_gfg;
	nthw_gmf_t *mp_nthw_gmf;
	nthw_mac_tfg_t *mp_nthw_mac_tfg;
} nt4ga_tfg_t;

int nt4ga_tfg_init(struct adapter_info_s *p_adapter_info);
int nt4ga_tfg_setup(struct adapter_info_s *p_adapter_info, const int n_intf_no,
	const int n_cmd_start_stop, const int n_frame_count, const int n_frame_size,
	const int n_frame_fill_mode, const int n_frame_stream_id);

#endif	/* NT4GA_TFG_H_ */
