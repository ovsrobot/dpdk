/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _HW_MOD_FLM_V17_H_
#define _HW_MOD_FLM_V17_H_

struct flm_v17_mbr_idx_overlay {
	uint64_t a : 28;
	uint64_t b : 28;
	uint64_t pad : 4;
};

struct flm_v17_control_s {
	uint32_t enable;
	uint32_t init;
	uint32_t lds;
	uint32_t lfs;
	uint32_t lis;
	uint32_t uds;
	uint32_t uis;
	uint32_t rds;
	uint32_t ris;
	uint32_t pds;
	uint32_t pis;
	uint32_t crcwr;
	uint32_t crcrd;
	uint32_t rbl;
	uint32_t eab;
	uint32_t split_sdram_usage;
};

struct flm_v17_status_s {
	uint32_t calibdone;
	uint32_t initdone;
	uint32_t idle;
	uint32_t critical;
	uint32_t panic;
	uint32_t crcerr;
	uint32_t eft_bp;
};

struct flm_v17_timeout_s {
	uint32_t t;
};

struct flm_v17_scrub_s {
	uint32_t i;
};

struct flm_v17_load_bin_s {
	uint32_t bin;
};

struct flm_v17_load_pps_s {
	uint32_t pps;
};

struct flm_v17_load_lps_s {
	uint32_t lps;
};

struct flm_v17_load_aps_s {
	uint32_t aps;
};

struct flm_v17_prio_s {
	uint32_t limit0;
	uint32_t ft0;
	uint32_t limit1;
	uint32_t ft1;
	uint32_t limit2;
	uint32_t ft2;
	uint32_t limit3;
	uint32_t ft3;
};

struct flm_v17_pst_s {
	uint32_t bp;
	uint32_t pp;
	uint32_t tp;
};

struct flm_v17_rcp_s {
	uint32_t lookup;
	uint32_t qw0_dyn;
	uint32_t qw0_ofs;
	uint32_t qw0_sel;
	uint32_t qw4_dyn;
	uint32_t qw4_ofs;
	uint32_t sw8_dyn;
	uint32_t sw8_ofs;
	uint32_t sw8_sel;
	uint32_t sw9_dyn;
	uint32_t sw9_ofs;
	uint32_t mask[10];
	uint32_t kid;
	uint32_t opn;
	uint32_t ipn;
	uint32_t byt_dyn;
	uint32_t byt_ofs;
	uint32_t txplm;
	uint32_t auto_ipv4_mask;
};

struct flm_v17_buf_ctrl_s {
	uint32_t lrn_free;
	uint32_t inf_avail;
	uint32_t sta_avail;
};

#pragma pack(1)
struct flm_v17_lrn_data_s {
	uint32_t sw9; /* 31:0 (32) */
	uint32_t sw8; /* 63:32 (32) */
	uint32_t qw4[4]; /* 191:64 (128) */
	uint32_t qw0[4]; /* 319:192 (128) */
	uint8_t prot; /* 327:320 (8) */
	uint8_t kid; /* 335:328 (8) */
	uint32_t nat_ip; /* 367:336 (32) */
	uint32_t teid; /* 399:368 (32) */
	uint16_t nat_port; /* 415:400 (16) */
	uint16_t rate; /* 431:416 (16) */
	uint16_t size; /* 447:432 (16) */
	uint32_t color; /* 479:448 (32) */
	uint32_t adj; /* 511:480 (32) */
	uint8_t id[9]; /* 583:512 (72) */
	uint16_t fill : 12; /* 595:584 (12) */
	uint16_t ft : 4; /* 599:596 (4) */
	uint8_t ft_mbr : 4; /* 603:600 (4) */
	uint8_t ft_miss : 4; /* 607:604 (5) */

	/* 635:608, 663:636, 691:664, 719:692 (4 x 28) Get/set with macros FLM_V17_MBR_IDx */
	uint8_t mbr_idx[14];
	uint32_t vol_idx : 3; /* 722:720 (3) */
	uint32_t stat_prof : 4; /* 726:723 (4) */
	uint32_t prio : 2; /* 728:727 (2) */
	uint32_t ent : 1; /* 729:729 (1) */
	uint32_t op : 4; /* 733:730 (4) */
	uint32_t dscp : 6; /* 739:734 (6) */
	uint32_t qfi : 6; /* 745:740 (6) */
	uint32_t rqi : 1; /* 746:746 (1) */
	uint32_t nat_en : 1; /* 747:747 (1) */
	uint32_t pad0 : 4; /* 751:748 (4) */
	uint16_t pad1 : 15; /* 752:766 (15) */
	uint16_t eor : 1; /* 767:767 (1) */
};

struct flm_v17_inf_data_s {
	uint64_t bytes;
	uint64_t packets;
	uint64_t ts;
	uint64_t id0; /* id0 and id1 results in a 72-bit int */
	uint32_t id1 : 8;
	uint32_t cause : 3;
	uint32_t pad : 20;
	uint32_t eor : 1;
};

struct flm_v17_sta_data_s {
	uint64_t id0; /* id0 and id1 results in a 72-bit int */
	uint32_t id1 : 8;
	uint32_t lds : 1;
	uint32_t lfs : 1;
	uint32_t lis : 1;
	uint32_t uds : 1;
	uint32_t uis : 1;
	uint32_t rds : 1;
	uint32_t ris : 1;
	uint32_t pds : 1;
	uint32_t pis : 1;
	uint32_t pad : 14;
	uint32_t eor : 1;
};

#pragma pack()
struct flm_v17_stat_lrn_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_lrn_ignore_s {
	uint32_t cnt;
};

struct flm_v17_stat_lrn_fail_s {
	uint32_t cnt;
};

struct flm_v17_stat_unl_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_unl_ignore_s {
	uint32_t cnt;
};

struct flm_v17_stat_rel_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_rel_ignore_s {
	uint32_t cnt;
};

struct flm_v17_stat_aul_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_aul_ignore_s {
	uint32_t cnt;
};

struct flm_v17_stat_aul_fail_s {
	uint32_t cnt;
};

struct flm_v17_stat_tul_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_flows_s {
	uint32_t cnt;
};

struct flm_v17_stat_prb_done_s {
	uint32_t cnt;
};

struct flm_v17_stat_prb_ignore_s {
	uint32_t cnt;
};

struct hw_mod_flm_v17_s {
	struct flm_v17_control_s *control;
	struct flm_v17_status_s *status;
	struct flm_v17_timeout_s *timeout;
	struct flm_v17_scrub_s *scrub;
	struct flm_v17_load_bin_s *load_bin;
	struct flm_v17_load_pps_s *load_pps;
	struct flm_v17_load_lps_s *load_lps;
	struct flm_v17_load_aps_s *load_aps;
	struct flm_v17_prio_s *prio;
	struct flm_v17_pst_s *pst;
	struct flm_v17_rcp_s *rcp;
	struct flm_v17_buf_ctrl_s *buf_ctrl;
	/* lrn_data is not handled by struct */
	/* inf_data is not handled by struct */
	/* sta_data is not handled by struct */
	struct flm_v17_stat_lrn_done_s *lrn_done;
	struct flm_v17_stat_lrn_ignore_s *lrn_ignore;
	struct flm_v17_stat_lrn_fail_s *lrn_fail;
	struct flm_v17_stat_unl_done_s *unl_done;
	struct flm_v17_stat_unl_ignore_s *unl_ignore;
	struct flm_v17_stat_rel_done_s *rel_done;
	struct flm_v17_stat_rel_ignore_s *rel_ignore;
	struct flm_v17_stat_aul_done_s *aul_done;
	struct flm_v17_stat_aul_ignore_s *aul_ignore;
	struct flm_v17_stat_aul_fail_s *aul_fail;
	struct flm_v17_stat_tul_done_s *tul_done;
	struct flm_v17_stat_flows_s *flows;
	struct flm_v17_stat_prb_done_s *prb_done;
	struct flm_v17_stat_prb_ignore_s *prb_ignore;
};

#endif /* _HW_MOD_FLM_V17_H_ */
