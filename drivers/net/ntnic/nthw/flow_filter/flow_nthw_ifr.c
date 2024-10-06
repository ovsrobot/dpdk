/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdlib.h>
#include <string.h>

#include "ntlog.h"
#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_ifr.h"

struct ifr_nthw *ifr_nthw_new(void)
{
	struct ifr_nthw *p = malloc(sizeof(struct ifr_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));

	return p;
}

int ifr_nthw_init(struct ifr_nthw *p, nthw_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nthw_module_t *p_mod = nthw_fpga_query_module(p_fpga, MOD_IFR, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: Ifr %d: no such instance\n", p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_ifr = nthw_fpga_query_module(p_fpga, MOD_IFR, n_instance);

	p->mp_rcp_ctrl = nthw_module_get_register(p->m_ifr, IFR_RCP_CTRL);
	p->mp_rcp_addr = nthw_register_get_field(p->mp_rcp_ctrl, IFR_RCP_CTRL_ADR);
	p->mp_rcp_cnt = nthw_register_get_field(p->mp_rcp_ctrl, IFR_RCP_CTRL_CNT);

	p->mp_rcp_data = nthw_module_get_register(p->m_ifr, IFR_RCP_DATA);
	p->mp_rcp_data_ipv4_en = nthw_register_query_field(p->mp_rcp_data, IFR_RCP_DATA_IPV4_EN);
	p->mp_rcp_data_ipv6_en = nthw_register_query_field(p->mp_rcp_data, IFR_RCP_DATA_IPV6_EN);
	p->mp_rcp_data_mtu = nthw_register_get_field(p->mp_rcp_data, IFR_RCP_DATA_MTU);
	p->mp_rcp_data_ipv4_df_drop =
		nthw_register_query_field(p->mp_rcp_data, IFR_RCP_DATA_IPV4_DF_DROP);
	p->mp_rcp_data_ipv6_drop =
		nthw_register_query_field(p->mp_rcp_data, IFR_RCP_DATA_IPV6_DROP);

	p->mp_df_buf_ctrl = nthw_module_get_register(p->m_ifr, IFR_DF_BUF_CTRL);
	p->mp_df_buf_ctrl_available =
		nthw_register_get_field(p->mp_df_buf_ctrl, IFR_DF_BUF_CTRL_AVAILABLE);
	p->mp_df_buf_ctrl_mtu_profile =
		nthw_register_get_field(p->mp_df_buf_ctrl, IFR_DF_BUF_CTRL_MTU_PROFILE);

	p->mp_df_buf_data = nthw_module_get_register(p->m_ifr, IFR_DF_BUF_DATA);
	p->mp_df_buf_data_fifo_dat =
		nthw_register_get_field(p->mp_df_buf_data, IFR_DF_BUF_DATA_FIFO_DAT);

	return 0;
}
