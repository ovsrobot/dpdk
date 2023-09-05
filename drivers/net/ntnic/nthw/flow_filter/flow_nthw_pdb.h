/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_NTHW_PDB_H__
#define __FLOW_NTHW_PDB_H__

#include <stdint.h> /* uint32_t */
#include "nthw_fpga_model.h"

struct pdb_nthw {
	uint8_t m_physical_adapter_no;
	nt_fpga_t *mp_fpga;

	nt_module_t *m_pdb;

	nt_register_t *mp_rcp_ctrl;
	nt_field_t *mp_rcp_addr;
	nt_field_t *mp_rcp_cnt;
	nt_register_t *mp_rcp_data;
	nt_field_t *mp_rcp_data_descriptor;
	nt_field_t *mp_rcp_data_desc_len;
	nt_field_t *mp_rcp_data_tx_port;
	nt_field_t *mp_rcp_data_tx_ignore;
	nt_field_t *mp_rcp_data_tx_now;
	nt_field_t *mp_rcp_data_crc_overwrite;
	nt_field_t *mp_rcp_data_align;
	nt_field_t *mp_rcp_data_ofs0_dyn;
	nt_field_t *mp_rcp_data_ofs0_rel;
	nt_field_t *mp_rcp_data_ofs1_dyn;
	nt_field_t *mp_rcp_data_ofs1_rel;
	nt_field_t *mp_rcp_data_ofs2_dyn;
	nt_field_t *mp_rcp_data_ofs2_rel;
	nt_field_t *mp_rcp_data_ip_prot_tnl;
	nt_field_t *mp_rcp_data_ppc_hsh;
	nt_field_t *mp_rcp_data_duplicate_en;
	nt_field_t *mp_rcp_data_duplicate_bit;
	nt_field_t *mp_rcp_data_pcap_keep_fcs;

	nt_register_t *mp_config;
	nt_field_t *mp_config_ts_format;
	nt_field_t *mp_config_port_ofs;
};

typedef struct pdb_nthw pdb_nthw_t;

struct pdb_nthw *pdb_nthw_new(void);
void pdb_nthw_delete(struct pdb_nthw *p);
int pdb_nthw_init(struct pdb_nthw *p, nt_fpga_t *p_fpga, int n_instance);

int pdb_nthw_setup(struct pdb_nthw *p, int n_idx, int n_idx_cnt);
void pdb_nthw_set_debug_mode(struct pdb_nthw *p, unsigned int n_debug_mode);

/* RCP */
void pdb_nthw_rcp_select(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_cnt(const struct pdb_nthw *p, uint32_t val);

void pdb_nthw_rcp_descriptor(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_desc_len(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_tx_port(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_tx_ignore(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_tx_now(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_crc_overwrite(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_align(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_ofs0_dyn(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_ofs0_rel(const struct pdb_nthw *p, int32_t val);
void pdb_nthw_rcp_ofs1_dyn(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_ofs1_rel(const struct pdb_nthw *p, int32_t val);
void pdb_nthw_rcp_ofs2_dyn(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_ofs2_rel(const struct pdb_nthw *p, int32_t val);
void pdb_nthw_rcp_ip_prot_tnl(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_ppc_hsh(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_duplicate_en(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_duplicate_bit(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_data_pcap_keep_fcs(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_rcp_flush(const struct pdb_nthw *p);

/* CONFIG */
void pdb_nthw_config_ts_format(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_config_port_ofs(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_config_port_ofs(const struct pdb_nthw *p, uint32_t val);
void pdb_nthw_config_flush(const struct pdb_nthw *p);

#endif /* __FLOW_NTHW_PDB_H__ */
