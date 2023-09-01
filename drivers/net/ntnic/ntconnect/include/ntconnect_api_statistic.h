/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTCONNECT_API_STATISTIC_H_
#define _NTCONNECT_API_STATISTIC_H_

/*
 * Supported defined statistic records for Stat layout version 6 - defined in nthw_stat module
 */
#define NUM_STAT_RECORD_TYPE_COLOR \
	(sizeof(struct color_type_fields_s) / sizeof(uint64_t))
struct color_type_fields_s {
	uint64_t pkts;
	uint64_t octets;
	uint64_t tcp_flgs;
};

#define NUM_STAT_RECORD_TYPE_FLOWMATCHER \
	(sizeof(struct flowmatcher_type_fields_s) / sizeof(uint64_t))
struct flowmatcher_type_fields_s {
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
	uint64_t prb_done;
	uint64_t prb_ignore;
	/* FLM 0.20 */
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

#define NUM_STAT_RECORD_TYPE_QUEUE \
	(sizeof(struct queue_type_fields_s) / sizeof(uint64_t))
struct queue_type_fields_s {
	uint64_t flush_pkts;
	uint64_t drop_pkts;
	uint64_t fwd_pkts;
	uint64_t dbs_drop_pkts;
	uint64_t flush_octets;
	uint64_t drop_octets;
	uint64_t fwd_octets;
	uint64_t dbs_drop_octets;
};

/*
 * Port stat counters for virtualization NICS with virtual ports support
 */
#define NUM_STAT_RECORD_TYPE_RX_PORT_VIRT \
	(sizeof(struct rtx_type_fields_virt_s) / sizeof(uint64_t))
/* same for Rx and Tx counters on Virt */
#define NUM_STAT_RECORD_TYPE_TX_PORT_VIRT NUM_STAT_RECORD_TYPE_RX_PORT_VIRT
struct rtx_type_fields_virt_s {
	uint64_t octets;
	uint64_t pkts;
	uint64_t drop_events;
	uint64_t qos_drop_octets;
	uint64_t qos_drop_pkts;
};

/*
 * Port RMON counters for Cap devices
 */
struct stat_rmon_s {
	/* Sums that are calculated by software */
	uint64_t drop_events;
	uint64_t pkts;
	/* Read from FPGA */
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
};

#define NUM_STAT_RECORD_TYPE_RX_PORT_CAP \
	(sizeof(struct rx_type_fields_cap_s) / sizeof(uint64_t))
struct rx_type_fields_cap_s {
	struct stat_rmon_s rmon;
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

#define NUM_STAT_RECORD_TYPE_TX_PORT_CAP \
	(sizeof(struct tx_type_fields_cap_s) / sizeof(uint64_t))
struct tx_type_fields_cap_s {
	struct stat_rmon_s rmon;
};

/*
 * stat get,colors
 * stat get,queues
 * stat get,rx_counters
 * stat get,tx_counters
 */
#define STAT_INFO_ELEMENTS \
	(sizeof(struct ntc_stat_get_data_s) / sizeof(uint64_t))

struct ntc_stat_get_data_s {
	uint64_t nb_counters;
	uint64_t timestamp;
	uint64_t is_virt;
	uint64_t data[];
};

#endif /* _NTCONNECT_API_STATISTIC_H_ */
