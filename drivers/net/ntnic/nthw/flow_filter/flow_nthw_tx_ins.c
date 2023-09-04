/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "ntlog.h"
#include "nthw_drv.h"
#include "nthw_register.h"

#include "flow_nthw_tx_ins.h"

#include <stdlib.h>
#include <string.h>

void tx_ins_nthw_set_debug_mode(struct tx_ins_nthw *p, unsigned int n_debug_mode)
{
	module_set_debug_mode(p->m_tx_ins, n_debug_mode);
}

struct tx_ins_nthw *tx_ins_nthw_new(void)
{
	struct tx_ins_nthw *p = malloc(sizeof(struct tx_ins_nthw));

	if (p)
		(void)memset(p, 0, sizeof(*p));
	return p;
}

void tx_ins_nthw_delete(struct tx_ins_nthw *p)
{
	if (p) {
		(void)memset(p, 0, sizeof(*p));
		free(p);
	}
}

int tx_ins_nthw_init(struct tx_ins_nthw *p, nt_fpga_t *p_fpga, int n_instance)
{
	const char *const p_adapter_id_str = p_fpga->p_fpga_info->mp_adapter_id_str;
	nt_module_t *p_mod = fpga_query_module(p_fpga, MOD_TX_INS, n_instance);

	assert(n_instance >= 0 && n_instance < 256);

	if (p == NULL)
		return p_mod == NULL ? -1 : 0;

	if (p_mod == NULL) {
		NT_LOG(ERR, NTHW, "%s: TxIns %d: no such instance\n",
		       p_adapter_id_str, n_instance);
		return -1;
	}

	p->mp_fpga = p_fpga;
	p->m_physical_adapter_no = (uint8_t)n_instance;
	p->m_tx_ins = fpga_query_module(p_fpga, MOD_TX_INS, n_instance);

	p->mp_rcp_ctrl = module_get_register(p->m_tx_ins, INS_RCP_CTRL);
	p->mp_rcp_addr = register_get_field(p->mp_rcp_ctrl, INS_RCP_CTRL_ADR);
	p->mp_rcp_cnt = register_get_field(p->mp_rcp_ctrl, INS_RCP_CTRL_CNT);
	p->mp_rcp_data = module_get_register(p->m_tx_ins, INS_RCP_DATA);
	p->mp_rcp_data_dyn = register_get_field(p->mp_rcp_data, INS_RCP_DATA_DYN);
	p->mp_rcp_data_ofs = register_get_field(p->mp_rcp_data, INS_RCP_DATA_OFS);
	p->mp_rcp_data_len = register_get_field(p->mp_rcp_data, INS_RCP_DATA_LEN);

	return 0;
}

void tx_ins_nthw_rcp_select(const struct tx_ins_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_addr, val);
}

void tx_ins_nthw_rcp_cnt(const struct tx_ins_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_cnt, val);
}

void tx_ins_nthw_rcp_dyn(const struct tx_ins_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_dyn, val);
}

void tx_ins_nthw_rcp_ofs(const struct tx_ins_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_ofs, val);
}

void tx_ins_nthw_rcp_len(const struct tx_ins_nthw *p, uint32_t val)
{
	field_set_val32(p->mp_rcp_data_len, val);
}

void tx_ins_nthw_rcp_flush(const struct tx_ins_nthw *p)
{
	register_flush(p->mp_rcp_ctrl, 1);
	register_flush(p->mp_rcp_data, 1);
}
