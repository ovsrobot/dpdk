/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_QSL_H__
#define __FLOW_NTHW_QSL_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct qsl_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_qsl;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_discard;
	nt_field_t *mp_rcp_data_drop;
	nt_field_t *mp_rcp_data_tbl_lo;
	nt_field_t *mp_rcp_data_tbl_hi;
	nt_field_t *mp_rcp_data_tbl_idx;
	nt_field_t *mp_rcp_data_tbl_msk;
	nt_field_t *mp_rcp_data_cao;
	nt_field_t *mp_rcp_data_lr;
	nt_field_t *mp_rcp_data_tsa;
	nt_field_t *mp_rcp_data_vli;

	nt_register_t *mp_ltx_ctrl;
	nt_field_t *mp_ltx_addr;
	nt_field_t *mp_ltx_cnt;
	nt_register_t *mp_ltx_data;
	nt_field_t *mp_ltx_data_lr;
	nt_field_t *mp_ltx_data_tx_port;
	nt_field_t *mp_ltx_data_tsa;

	nt_register_t *mp_qst_ctrl;
	nt_field_t *mp_qst_addr;
	nt_field_t *mp_qst_cnt;
	nt_register_t *mp_qst_data;
	nt_field_t *mp_qst_data_queue;
	nt_field_t *mp_qst_data_en;
	nt_field_t *mp_qst_data_tx_port;
	nt_field_t *mp_qst_data_lre;
	nt_field_t *mp_qst_data_tci;
	nt_field_t *mp_qst_data_ven;

	nt_register_t *mp_qen_ctrl;
	nt_field_t *mp_qen_addr;
	nt_field_t *mp_qen_cnt;
	nt_register_t *mp_qen_data;
	nt_field_t *mp_qen_data_en;

	nt_register_t *mp_unmq_ctrl;
	nt_field_t *mp_unmq_addr;
	nt_field_t *mp_unmq_cnt;
	nt_register_t *mp_unmq_data;
	nt_field_t *mp_unmq_data_dest_queue;
	nt_field_t *mp_unmq_data_en;
};

typedef struct qsl_nthw qsl_nthw_t;

struct qsl_nthw *qsl_nthw_new(void);
void qsl_nthw_delete(struct qsl_nthw *p);
int qsl_nthw_init(struct qsl_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int qsl_nthw_setup(struct qsl_nthw *p, int n_idx, int n_idx_cnt);
void qsl_nthw_set_debug_mode(struct qsl_nthw *p, unsigned int n_debug_mode);

/* RCP */
void qsl_nthw_rcp_select(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_cnt(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_discard(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_drop(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_tbl_lo(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_tbl_hi(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_tbl_idx(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_tbl_msk(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_cao(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_lr(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_tsa(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_vli(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_rcp_flush(const struct qsl_nthw *p);

/* LTX */
void qsl_nthw_ltx_select(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_ltx_cnt(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_ltx_lr(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_ltx_tx_port(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_ltx_tsa(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_ltx_flush(const struct qsl_nthw *p);

/* QST */
void qsl_nthw_qst_select(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_cnt(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_queue(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_en(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_tx_port(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_lre(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_tci(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_ven(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qst_flush(const struct qsl_nthw *p);

/* QEN */
void qsl_nthw_qen_select(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qen_cnt(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qen_en(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_qen_flush(const struct qsl_nthw *p);

/* UNMQ */
void qsl_nthw_unmq_select(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_unmq_cnt(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_unmq_dest_queue(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_unmq_en(const struct qsl_nthw *p, uint32_t val);
void qsl_nthw_unmq_flush(const struct qsl_nthw *p);

#endif /* __FLOW_NTHW_QSL_H__ */
