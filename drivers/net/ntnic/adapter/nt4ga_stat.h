/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NT4GA_STAT_H_
#define NT4GA_STAT_H_

#include "nt_util.h"
#include "common_adapter_defs.h"

#define NT_MAX_COLOR_FLOW_STATS 0x400

struct color_counters {
	uint64_t color_packets;
	uint64_t color_bytes;
	uint8_t tcp_flags;
};

struct host_buffer_counters {
	uint64_t flush_packets;
	uint64_t drop_packets;
	uint64_t fwd_packets;
	uint64_t dbs_drop_packets;
	uint64_t flush_bytes;
	uint64_t drop_bytes;
	uint64_t fwd_bytes;
	uint64_t dbs_drop_bytes;
};

struct port_counters_v2 {
	/* Rx/Tx common port counters */
	uint64_t drop_events;
	uint64_t pkts;
	/* FPGA counters */
	uint64_t octets;
	uint64_t broadcast_pkts;
	uint64_t multicast_pkts;
	uint64_t unicast_pkts;
	uint64_t pkts_alignment;
	uint64_t pkts_code_violation;
	uint64_t pkts_crc;
	uint64_t undersize_pkts;
	uint64_t oversize_pkts;
	uint64_t fragments;
	uint64_t jabbers_not_truncated;
	uint64_t jabbers_truncated;
	uint64_t pkts_64_octets;
	uint64_t pkts_65_to_127_octets;
	uint64_t pkts_128_to_255_octets;
	uint64_t pkts_256_to_511_octets;
	uint64_t pkts_512_to_1023_octets;
	uint64_t pkts_1024_to_1518_octets;
	uint64_t pkts_1519_to_2047_octets;
	uint64_t pkts_2048_to_4095_octets;
	uint64_t pkts_4096_to_8191_octets;
	uint64_t pkts_8192_to_max_octets;
	uint64_t mac_drop_events;
	uint64_t pkts_lr;
	/* Rx only port counters */
	uint64_t duplicate;
	uint64_t pkts_ip_chksum_error;
	uint64_t pkts_udp_chksum_error;
	uint64_t pkts_tcp_chksum_error;
	uint64_t pkts_giant_undersize;
	uint64_t pkts_baby_giant;
	uint64_t pkts_not_isl_vlan_mpls;
	uint64_t pkts_isl;
	uint64_t pkts_vlan;
	uint64_t pkts_isl_vlan;
	uint64_t pkts_mpls;
	uint64_t pkts_isl_mpls;
	uint64_t pkts_vlan_mpls;
	uint64_t pkts_isl_vlan_mpls;
	uint64_t pkts_no_filter;
	uint64_t pkts_dedup_drop;
	uint64_t pkts_filter_drop;
	uint64_t pkts_overflow;
	uint64_t pkts_dbs_drop;
	uint64_t octets_no_filter;
	uint64_t octets_dedup_drop;
	uint64_t octets_filter_drop;
	uint64_t octets_overflow;
	uint64_t octets_dbs_drop;
	uint64_t ipft_first_hit;
	uint64_t ipft_first_not_hit;
	uint64_t ipft_mid_hit;
	uint64_t ipft_mid_not_hit;
	uint64_t ipft_last_hit;
	uint64_t ipft_last_not_hit;
};

struct port_counters_vswitch_v1 {
	/* Rx/Tx common port counters */
	uint64_t octets;
	uint64_t pkts;
	uint64_t drop_events;
	uint64_t qos_drop_octets;
	uint64_t qos_drop_pkts;
};

struct flm_counters_v1 {
	/* FLM 0.17 */
	uint64_t current;
	uint64_t learn_done;
	uint64_t learn_ignore;
	uint64_t learn_fail;
	uint64_t unlearn_done;
	uint64_t unlearn_ignore;
	uint64_t auto_unlearn_done;
	uint64_t auto_unlearn_ignore;
	uint64_t auto_unlearn_fail;
	uint64_t timeout_unlearn_done;
	uint64_t rel_done;
	uint64_t rel_ignore;
	/* FLM 0.20 */
	uint64_t prb_done;
	uint64_t prb_ignore;
	uint64_t sta_done;
	uint64_t inf_done;
	uint64_t inf_skip;
	uint64_t pck_hit;
	uint64_t pck_miss;
	uint64_t pck_unh;
	uint64_t pck_dis;
	uint64_t csh_hit;
	uint64_t csh_miss;
	uint64_t csh_unh;
	uint64_t cuc_start;
	uint64_t cuc_move;
};

struct nt4ga_stat_s {
	nthw_stat_t *mp_nthw_stat;
	nthw_rmc_t *mp_nthw_rmc;
	struct nt_dma_s *p_stat_dma;
	uint32_t *p_stat_dma_virtual;
	uint32_t n_stat_size;

	uint64_t last_timestamp;

	int mn_rx_host_buffers;
	int mn_tx_host_buffers;

	int mn_rx_ports;
	int mn_tx_ports;

	struct color_counters *mp_stat_structs_color;
	/* For calculating increments between stats polls */
	struct color_counters a_stat_structs_color_base[NT_MAX_COLOR_FLOW_STATS];

	union {
		/*Port counters for VSWITCH/inline */
		struct {
			struct port_counters_vswitch_v1 *mp_stat_structs_port_rx;
			struct port_counters_vswitch_v1 *mp_stat_structs_port_tx;
		} virt;
		struct {
			struct port_counters_v2 *mp_stat_structs_port_rx;
			struct port_counters_v2 *mp_stat_structs_port_tx;
		} cap;
	};

	struct host_buffer_counters *mp_stat_structs_hb;

	int flm_stat_ver;
	struct flm_counters_v1 *mp_stat_structs_flm;

	/* Rx/Tx totals: */
	uint64_t n_totals_reset_timestamp; /* timestamp for last totals reset */

	uint64_t a_port_rx_octets_total[NUM_ADAPTER_PORTS_MAX];
	/* Base is for calculating increments between statistics reads */
	uint64_t a_port_rx_octets_base[NUM_ADAPTER_PORTS_MAX];

	uint64_t a_port_rx_packets_total[NUM_ADAPTER_PORTS_MAX];
	uint64_t a_port_rx_packets_base[NUM_ADAPTER_PORTS_MAX];

	uint64_t a_port_rx_drops_total[NUM_ADAPTER_PORTS_MAX];
	uint64_t a_port_rx_drops_base[NUM_ADAPTER_PORTS_MAX];

	uint64_t a_port_tx_octets_total[NUM_ADAPTER_PORTS_MAX];
	uint64_t a_port_tx_octets_base[NUM_ADAPTER_PORTS_MAX];

	uint64_t a_port_tx_packets_base[NUM_ADAPTER_PORTS_MAX];
	uint64_t a_port_tx_packets_total[NUM_ADAPTER_PORTS_MAX];

	uint64_t a_port_tx_drops_base[NUM_ADAPTER_PORTS_MAX];
	uint64_t a_port_tx_drops_total[NUM_ADAPTER_PORTS_MAX];
};

typedef struct nt4ga_stat_s nt4ga_stat_t;

int nt4ga_stat_init(struct adapter_info_s *p_adapter_info);
int nt4ga_stat_setup(struct adapter_info_s *p_adapter_info);
int nt4ga_stat_stop(struct adapter_info_s *p_adapter_info);

int nt4ga_stat_dump(struct adapter_info_s *p_adapter_info, FILE *pfh);

int nt4ga_stat_collect(struct adapter_info_s *p_adapter_info,
		      nt4ga_stat_t *p_nt4ga_stat);

#endif /* NT4GA_STAT_H_ */
