/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_STAT_H__
#define __NTHW_STAT_H__

struct nthw_stat {
	nt_fpga_t *mp_fpga;
	nt_module_t *mp_mod_stat;
	int mn_instance;

	int mn_stat_layout_version;

	bool mb_is_vswitch;
	bool mb_has_tx_stats;

	int m_nb_phy_ports;
	int m_nb_nim_ports;

	int m_nb_rx_ports;
	int m_nb_tx_ports;

	int m_nb_rx_host_buffers;
	int m_nb_tx_host_buffers;

	int m_dbs_present;

	int m_rx_port_replicate;

	int m_nb_color_counters;

	int m_nb_rx_hb_counters;
	int m_nb_tx_hb_counters;

	int m_nb_rx_port_counters;
	int m_nb_tx_port_counters;

	int m_nb_counters;

	nt_field_t *mp_fld_dma_ena;
	nt_field_t *mp_fld_cnt_clear;

	nt_field_t *mp_fld_tx_disable;

	nt_field_t *mp_fld_cnt_freeze;

	nt_field_t *mp_fld_stat_toggle_missed;

	nt_field_t *mp_fld_dma_lsb;
	nt_field_t *mp_fld_dma_msb;

	uint64_t m_stat_dma_physical;
	uint32_t *mp_stat_dma_virtual;

	uint64_t last_ts;

	uint64_t *mp_timestamp;
};

typedef struct nthw_stat nthw_stat_t;
typedef struct nthw_stat nthw_stat;

nthw_stat_t *nthw_stat_new(void);
int nthw_stat_init(nthw_stat_t *p, nt_fpga_t *p_fpga, int n_instance);
void nthw_stat_delete(nthw_stat_t *p);

int nthw_stat_set_dma_address(nthw_stat_t *p, uint64_t stat_dma_physical,
			   uint32_t *p_stat_dma_virtual);
int nthw_stat_trigger(nthw_stat_t *p);

#endif /* __NTHW_STAT_H__ */
