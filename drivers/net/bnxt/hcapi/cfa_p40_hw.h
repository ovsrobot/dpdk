/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2020 Broadcom
 * All rights reserved.
 */
/*
 * Name:  cfa_p40_hw.h
 *
 * Description: header for SWE based on Truflow
 *
 * Date:  taken from 12/16/19 17:18:12
 *
 * Note:  This file was first generated using  tflib_decode.py.
 *
 *        Changes have been made due to lack of availability of xml for
 *        addtional tables at this time (EEM Record and union table fields)
 *        Changes not autogenerated are noted in comments.
 */

#ifndef _CFA_P40_HW_H_
#define _CFA_P40_HW_H_

/**
 * Valid TCAM entry. (for idx 5 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_VALID_BITPOS   166
#define CFA_P40_PROF_L2_CTXT_TCAM_VALID_NUM_BITS 1
/**
 * Key type (pass). (for idx 5 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_KEY_TYPE_BITPOS 164
#define CFA_P40_PROF_L2_CTXT_TCAM_KEY_TYPE_NUM_BITS 2
/**
 * Tunnel HDR type. (for idx 5 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_TUN_HDR_TYPE_BITPOS 160
#define CFA_P40_PROF_L2_CTXT_TCAM_TUN_HDR_TYPE_NUM_BITS 4
/**
 * Number of VLAN tags in tunnel l2 header. (for idx 4 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_T_L2_NUMTAGS_BITPOS 158
#define CFA_P40_PROF_L2_CTXT_TCAM_T_L2_NUMTAGS_NUM_BITS 2
/**
 * Number of VLAN tags in l2 header. (for idx 4 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_L2_NUMTAGS_BITPOS 156
#define CFA_P40_PROF_L2_CTXT_TCAM_L2_NUMTAGS_NUM_BITS 2
/**
 * Tunnel/Inner Source/Dest. MAC Address.
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_MAC1_BITPOS    108
#define CFA_P40_PROF_L2_CTXT_TCAM_MAC1_NUM_BITS  48
/**
 * Tunnel Outer VLAN Tag ID. (for idx 3 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_T_OVID_BITPOS  96
#define CFA_P40_PROF_L2_CTXT_TCAM_T_OVID_NUM_BITS 12
/**
 * Tunnel Inner VLAN Tag ID. (for idx 2 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_T_IVID_BITPOS  84
#define CFA_P40_PROF_L2_CTXT_TCAM_T_IVID_NUM_BITS 12
/**
 * Source Partition. (for idx 2 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_SPARIF_BITPOS  80
#define CFA_P40_PROF_L2_CTXT_TCAM_SPARIF_NUM_BITS 4
/**
 * Source Virtual I/F. (for idx 2 ...)
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_SVIF_BITPOS    72
#define CFA_P40_PROF_L2_CTXT_TCAM_SVIF_NUM_BITS  8
/**
 * Tunnel/Inner Source/Dest. MAC Address.
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_MAC0_BITPOS    24
#define CFA_P40_PROF_L2_CTXT_TCAM_MAC0_NUM_BITS  48
/**
 * Outer VLAN Tag ID.
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_OVID_BITPOS    12
#define CFA_P40_PROF_L2_CTXT_TCAM_OVID_NUM_BITS  12
/**
 * Inner VLAN Tag ID.
 */
#define CFA_P40_PROF_L2_CTXT_TCAM_IVID_BITPOS    0
#define CFA_P40_PROF_L2_CTXT_TCAM_IVID_NUM_BITS  12

enum cfa_p40_prof_l2_ctxt_tcam_flds {
	CFA_P40_PROF_L2_CTXT_TCAM_VALID_FLD = 0,
	CFA_P40_PROF_L2_CTXT_TCAM_KEY_TYPE_FLD = 1,
	CFA_P40_PROF_L2_CTXT_TCAM_TUN_HDR_TYPE_FLD = 2,
	CFA_P40_PROF_L2_CTXT_TCAM_T_L2_NUMTAGS_FLD = 3,
	CFA_P40_PROF_L2_CTXT_TCAM_L2_NUMTAGS_FLD = 4,
	CFA_P40_PROF_L2_CTXT_TCAM_MAC1_FLD = 5,
	CFA_P40_PROF_L2_CTXT_TCAM_T_OVID_FLD = 6,
	CFA_P40_PROF_L2_CTXT_TCAM_T_IVID_FLD = 7,
	CFA_P40_PROF_L2_CTXT_TCAM_SPARIF_FLD = 8,
	CFA_P40_PROF_L2_CTXT_TCAM_SVIF_FLD = 9,
	CFA_P40_PROF_L2_CTXT_TCAM_MAC0_FLD = 10,
	CFA_P40_PROF_L2_CTXT_TCAM_OVID_FLD = 11,
	CFA_P40_PROF_L2_CTXT_TCAM_IVID_FLD = 12,
	CFA_P40_PROF_L2_CTXT_TCAM_MAX_FLD
};

#define CFA_P40_PROF_L2_CTXT_TCAM_TOTAL_NUM_BITS 167

/**
 * Valid entry. (for idx 2 ...)
 */
#define CFA_P40_ACT_VEB_TCAM_VALID_BITPOS        79
#define CFA_P40_ACT_VEB_TCAM_VALID_NUM_BITS      1
/**
 * reserved program to 0. (for idx 2 ...)
 */
#define CFA_P40_ACT_VEB_TCAM_RESERVED_BITPOS     78
#define CFA_P40_ACT_VEB_TCAM_RESERVED_NUM_BITS   1
/**
 * PF Parif Number. (for idx 2 ...)
 */
#define CFA_P40_ACT_VEB_TCAM_PARIF_IN_BITPOS     74
#define CFA_P40_ACT_VEB_TCAM_PARIF_IN_NUM_BITS   4
/**
 * Number of VLAN Tags. (for idx 2 ...)
 */
#define CFA_P40_ACT_VEB_TCAM_NUM_VTAGS_BITPOS    72
#define CFA_P40_ACT_VEB_TCAM_NUM_VTAGS_NUM_BITS  2
/**
 * Dest. MAC Address.
 */
#define CFA_P40_ACT_VEB_TCAM_MAC_BITPOS          24
#define CFA_P40_ACT_VEB_TCAM_MAC_NUM_BITS        48
/**
 * Outer VLAN Tag ID.
 */
#define CFA_P40_ACT_VEB_TCAM_OVID_BITPOS         12
#define CFA_P40_ACT_VEB_TCAM_OVID_NUM_BITS       12
/**
 * Inner VLAN Tag ID.
 */
#define CFA_P40_ACT_VEB_TCAM_IVID_BITPOS         0
#define CFA_P40_ACT_VEB_TCAM_IVID_NUM_BITS       12

enum cfa_p40_act_veb_tcam_flds {
	CFA_P40_ACT_VEB_TCAM_VALID_FLD = 0,
	CFA_P40_ACT_VEB_TCAM_RESERVED_FLD = 1,
	CFA_P40_ACT_VEB_TCAM_PARIF_IN_FLD = 2,
	CFA_P40_ACT_VEB_TCAM_NUM_VTAGS_FLD = 3,
	CFA_P40_ACT_VEB_TCAM_MAC_FLD = 4,
	CFA_P40_ACT_VEB_TCAM_OVID_FLD = 5,
	CFA_P40_ACT_VEB_TCAM_IVID_FLD = 6,
	CFA_P40_ACT_VEB_TCAM_MAX_FLD
};

#define CFA_P40_ACT_VEB_TCAM_TOTAL_NUM_BITS 80

/**
 * Entry is valid.
 */
#define CFA_P40_LKUP_TCAM_RECORD_MEM_VALID_BITPOS 18
#define CFA_P40_LKUP_TCAM_RECORD_MEM_VALID_NUM_BITS 1
/**
 * Action Record Pointer
 */
#define CFA_P40_LKUP_TCAM_RECORD_MEM_ACT_REC_PTR_BITPOS 2
#define CFA_P40_LKUP_TCAM_RECORD_MEM_ACT_REC_PTR_NUM_BITS 16
/**
 * for resolving TCAM/EM conflicts
 */
#define CFA_P40_LKUP_TCAM_RECORD_MEM_STRENGTH_BITPOS 0
#define CFA_P40_LKUP_TCAM_RECORD_MEM_STRENGTH_NUM_BITS 2

enum cfa_p40_lkup_tcam_record_mem_flds {
	CFA_P40_LKUP_TCAM_RECORD_MEM_VALID_FLD = 0,
	CFA_P40_LKUP_TCAM_RECORD_MEM_ACT_REC_PTR_FLD = 1,
	CFA_P40_LKUP_TCAM_RECORD_MEM_STRENGTH_FLD = 2,
	CFA_P40_LKUP_TCAM_RECORD_MEM_MAX_FLD
};

#define CFA_P40_LKUP_TCAM_RECORD_MEM_TOTAL_NUM_BITS 19

/**
 * (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_TPID_ANTI_SPOOF_CTL_BITPOS 62
#define CFA_P40_PROF_CTXT_REMAP_MEM_TPID_ANTI_SPOOF_CTL_NUM_BITS 2
enum cfa_p40_prof_ctxt_remap_mem_tpid_anti_spoof_ctl {
	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_IGNORE = 0x0UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_DROP = 0x1UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_DEFAULT = 0x2UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_SPIF = 0x3UL,
	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_MAX = 0x3UL
};
/**
 * (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_PRI_ANTI_SPOOF_CTL_BITPOS 60
#define CFA_P40_PROF_CTXT_REMAP_MEM_PRI_ANTI_SPOOF_CTL_NUM_BITS 2
enum cfa_p40_prof_ctxt_remap_mem_pri_anti_spoof_ctl {
	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_IGNORE = 0x0UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_DROP = 0x1UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_DEFAULT = 0x2UL,

	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_SPIF = 0x3UL,
	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_MAX = 0x3UL
};
/**
 * Bypass Source Properties Lookup. (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_BYP_SP_LKUP_BITPOS 59
#define CFA_P40_PROF_CTXT_REMAP_MEM_BYP_SP_LKUP_NUM_BITS 1
/**
 * SP Record Pointer. (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_SP_REC_PTR_BITPOS 43
#define CFA_P40_PROF_CTXT_REMAP_MEM_SP_REC_PTR_NUM_BITS 16
/**
 * BD Action pointer passing enable. (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_BD_ACT_EN_BITPOS 42
#define CFA_P40_PROF_CTXT_REMAP_MEM_BD_ACT_EN_NUM_BITS 1
/**
 * Default VLAN TPID. (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_TPID_BITPOS 39
#define CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_TPID_NUM_BITS 3
/**
 * Allowed VLAN TPIDs. (for idx 1 ...)
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_TPID_BITPOS 33
#define CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_TPID_NUM_BITS 6
/**
 * Default VLAN PRI.
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_PRI_BITPOS 30
#define CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_PRI_NUM_BITS 3
/**
 * Allowed VLAN PRIs.
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_PRI_BITPOS 22
#define CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_PRI_NUM_BITS 8
/**
 * Partition.
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_PARIF_BITPOS 18
#define CFA_P40_PROF_CTXT_REMAP_MEM_PARIF_NUM_BITS 4
/**
 * Bypass Lookup.
 */
#define CFA_P40_PROF_CTXT_REMAP_MEM_BYP_LKUP_EN_BITPOS 17
#define CFA_P40_PROF_CTXT_REMAP_MEM_BYP_LKUP_EN_NUM_BITS 1

/**
 * L2 Context Remap Data. Action bypass mode (1) {7'd0,prof_vnic[9:0]} Note:
 * should also set byp_lkup_en. Action bypass mode (0) byp_lkup_en(0) -
 * {prof_func[6:0],l2_context[9:0]} byp_lkup_en(1) - {1'b0,act_rec_ptr[15:0]}
 */

#define CFA_P40_PROF_CTXT_REMAP_MEM_PROF_VNIC_BITPOS 0
#define CFA_P40_PROF_CTXT_REMAP_MEM_PROF_VNIC_NUM_BITS 12

#define CFA_P40_PROF_CTXT_REMAP_MEM_PROF_FUNC_BITPOS 10
#define CFA_P40_PROF_CTXT_REMAP_MEM_PROF_FUNC_NUM_BITS 7

#define CFA_P40_PROF_CTXT_REMAP_MEM_L2_CTXT_BITPOS 0
#define CFA_P40_PROF_CTXT_REMAP_MEM_L2_CTXT_NUM_BITS 10

#define CFA_P40_PROF_CTXT_REMAP_MEM_ARP_BITPOS 0
#define CFA_P40_PROF_CTXT_REMAP_MEM_ARP_NUM_BITS 16

enum cfa_p40_prof_ctxt_remap_mem_flds {
	CFA_P40_PROF_CTXT_REMAP_MEM_TPID_ANTI_SPOOF_CTL_FLD = 0,
	CFA_P40_PROF_CTXT_REMAP_MEM_PRI_ANTI_SPOOF_CTL_FLD = 1,
	CFA_P40_PROF_CTXT_REMAP_MEM_BYP_SP_LKUP_FLD = 2,
	CFA_P40_PROF_CTXT_REMAP_MEM_SP_REC_PTR_FLD = 3,
	CFA_P40_PROF_CTXT_REMAP_MEM_BD_ACT_EN_FLD = 4,
	CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_TPID_FLD = 5,
	CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_TPID_FLD = 6,
	CFA_P40_PROF_CTXT_REMAP_MEM_DEFAULT_PRI_FLD = 7,
	CFA_P40_PROF_CTXT_REMAP_MEM_ALLOWED_PRI_FLD = 8,
	CFA_P40_PROF_CTXT_REMAP_MEM_PARIF_FLD = 9,
	CFA_P40_PROF_CTXT_REMAP_MEM_BYP_LKUP_EN_FLD = 10,
	CFA_P40_PROF_CTXT_REMAP_MEM_PROF_VNIC_FLD = 11,
	CFA_P40_PROF_CTXT_REMAP_MEM_PROF_FUNC_FLD = 12,
	CFA_P40_PROF_CTXT_REMAP_MEM_L2_CTXT_FLD = 13,
	CFA_P40_PROF_CTXT_REMAP_MEM_ARP_FLD = 14,
	CFA_P40_PROF_CTXT_REMAP_MEM_MAX_FLD
};

#define CFA_P40_PROF_CTXT_REMAP_MEM_TOTAL_NUM_BITS 64

/**
 * Bypass action pointer look up (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_PL_BYP_LKUP_EN_BITPOS 37
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_PL_BYP_LKUP_EN_NUM_BITS 1
/**
 * Exact match search enable (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_SEARCH_ENB_BITPOS 36
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_SEARCH_ENB_NUM_BITS 1
/**
 * Exact match profile
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_PROFILE_ID_BITPOS 28
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_PROFILE_ID_NUM_BITS 8
/**
 * Exact match key format
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_ID_BITPOS 23
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_ID_NUM_BITS 5
/**
 * Exact match key mask
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_MASK_BITPOS 13
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_MASK_NUM_BITS 10
/**
 * TCAM search enable
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_SEARCH_ENB_BITPOS 12
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_SEARCH_ENB_NUM_BITS 1
/**
 * TCAM profile
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_PROFILE_ID_BITPOS 4
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_PROFILE_ID_NUM_BITS 8
/**
 * TCAM key format
 */
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_KEY_ID_BITPOS 0
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_KEY_ID_NUM_BITS 4

#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_BYPASS_OPT_BITPOS 16
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_BYPASS_OPT_NUM_BITS 2

#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_ACT_REC_PTR_BITPOS 0
#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_ACT_REC_PTR_NUM_BITS 16

enum cfa_p40_prof_profile_tcam_remap_mem_flds {
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_PL_BYP_LKUP_EN_FLD = 0,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_SEARCH_ENB_FLD = 1,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_PROFILE_ID_FLD = 2,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_ID_FLD = 3,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_EM_KEY_MASK_FLD = 4,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_SEARCH_ENB_FLD = 5,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_PROFILE_ID_FLD = 6,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TCAM_KEY_ID_FLD = 7,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_BYPASS_OPT_FLD = 8,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_ACT_REC_PTR_FLD = 9,
	CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_MAX_FLD
};

#define CFA_P40_PROF_PROFILE_TCAM_REMAP_MEM_TOTAL_NUM_BITS 38

/**
 * Valid TCAM entry (for idx 2 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_VALID_BITPOS   80
#define CFA_P40_PROF_PROFILE_TCAM_VALID_NUM_BITS 1
/**
 * Packet type (for idx 2 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_PKT_TYPE_BITPOS 76
#define CFA_P40_PROF_PROFILE_TCAM_PKT_TYPE_NUM_BITS 4
/**
 * Pass through CFA (for idx 2 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_RECYCLE_CNT_BITPOS 74
#define CFA_P40_PROF_PROFILE_TCAM_RECYCLE_CNT_NUM_BITS 2
/**
 * Aggregate error (for idx 2 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_AGG_ERROR_BITPOS 73
#define CFA_P40_PROF_PROFILE_TCAM_AGG_ERROR_NUM_BITS 1
/**
 * Profile function (for idx 2 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_PROF_FUNC_BITPOS 66
#define CFA_P40_PROF_PROFILE_TCAM_PROF_FUNC_NUM_BITS 7
/**
 * Reserved for future use. Set to 0.
 */
#define CFA_P40_PROF_PROFILE_TCAM_RESERVED_BITPOS 57
#define CFA_P40_PROF_PROFILE_TCAM_RESERVED_NUM_BITS 9
/**
 * non-tunnel(0)/tunneled(1) packet (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_HREC_NEXT_BITPOS 56
#define CFA_P40_PROF_PROFILE_TCAM_HREC_NEXT_NUM_BITS 1
/**
 * Tunnel L2 tunnel valid (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_VALID_BITPOS 55
#define CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_VALID_NUM_BITS 1
/**
 * Tunnel L2 header type (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_TYPE_BITPOS 53
#define CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_TYPE_NUM_BITS 2
/**
 * Remapped tunnel L2 dest_type UC(0)/MC(2)/BC(3) (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL2_UC_MC_BC_BITPOS 51
#define CFA_P40_PROF_PROFILE_TCAM_TL2_UC_MC_BC_NUM_BITS 2
/**
 * Tunnel L2 1+ VLAN tags present (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL2_VTAG_PRESENT_BITPOS 50
#define CFA_P40_PROF_PROFILE_TCAM_TL2_VTAG_PRESENT_NUM_BITS 1
/**
 * Tunnel L2 2 VLAN tags present (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL2_TWO_VTAGS_BITPOS 49
#define CFA_P40_PROF_PROFILE_TCAM_TL2_TWO_VTAGS_NUM_BITS 1
/**
 * Tunnel L3 valid (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_VALID_BITPOS 48
#define CFA_P40_PROF_PROFILE_TCAM_TL3_VALID_NUM_BITS 1
/**
 * Tunnel L3 error (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_ERROR_BITPOS 47
#define CFA_P40_PROF_PROFILE_TCAM_TL3_ERROR_NUM_BITS 1
/**
 * Tunnel L3 header type (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_TYPE_BITPOS 43
#define CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_TYPE_NUM_BITS 4
/**
 * Tunnel L3 header is IPV4 or IPV6. (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_ISIP_BITPOS 42
#define CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_ISIP_NUM_BITS 1
/**
 * Tunnel L3 IPV6 src address is compressed (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_SRC_BITPOS 41
#define CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_SRC_NUM_BITS 1
/**
 * Tunnel L3 IPV6 dest address is compressed (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_DEST_BITPOS 40
#define CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_DEST_NUM_BITS 1
/**
 * Tunnel L4 valid (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_VALID_BITPOS 39
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_VALID_NUM_BITS 1
/**
 * Tunnel L4 error (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_ERROR_BITPOS 38
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_ERROR_NUM_BITS 1
/**
 * Tunnel L4 header type (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_TYPE_BITPOS 34
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_TYPE_NUM_BITS 4
/**
 * Tunnel L4 header is UDP or TCP (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_IS_UDP_TCP_BITPOS 33
#define CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_IS_UDP_TCP_NUM_BITS 1
/**
 * Tunnel valid (for idx 1 ...)
 */
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_VALID_BITPOS 32
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_VALID_NUM_BITS 1
/**
 * Tunnel error
 */
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_ERR_BITPOS 31
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_ERR_NUM_BITS 1
/**
 * Tunnel header type
 */
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_TYPE_BITPOS 27
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_TYPE_NUM_BITS 4
/**
 * Tunnel header flags
 */
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_FLAGS_BITPOS 24
#define CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_FLAGS_NUM_BITS 3
/**
 * L2 header valid
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_VALID_BITPOS 23
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_VALID_NUM_BITS 1
/**
 * L2 header error
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_ERROR_BITPOS 22
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_ERROR_NUM_BITS 1
/**
 * L2 header type
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_TYPE_BITPOS 20
#define CFA_P40_PROF_PROFILE_TCAM_L2_HDR_TYPE_NUM_BITS 2
/**
 * Remapped L2 dest_type UC(0)/MC(2)/BC(3)
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_UC_MC_BC_BITPOS 18
#define CFA_P40_PROF_PROFILE_TCAM_L2_UC_MC_BC_NUM_BITS 2
/**
 * L2 header 1+ VLAN tags present
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_VTAG_PRESENT_BITPOS 17
#define CFA_P40_PROF_PROFILE_TCAM_L2_VTAG_PRESENT_NUM_BITS 1
/**
 * L2 header 2 VLAN tags present
 */
#define CFA_P40_PROF_PROFILE_TCAM_L2_TWO_VTAGS_BITPOS 16
#define CFA_P40_PROF_PROFILE_TCAM_L2_TWO_VTAGS_NUM_BITS 1
/**
 * L3 header valid
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_VALID_BITPOS 15
#define CFA_P40_PROF_PROFILE_TCAM_L3_VALID_NUM_BITS 1
/**
 * L3 header error
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_ERROR_BITPOS 14
#define CFA_P40_PROF_PROFILE_TCAM_L3_ERROR_NUM_BITS 1
/**
 * L3 header type
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_HDR_TYPE_BITPOS 10
#define CFA_P40_PROF_PROFILE_TCAM_L3_HDR_TYPE_NUM_BITS 4
/**
 * L3 header is IPV4 or IPV6.
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_HDR_ISIP_BITPOS 9
#define CFA_P40_PROF_PROFILE_TCAM_L3_HDR_ISIP_NUM_BITS 1
/**
 * L3 header IPV6 src address is compressed
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_SRC_BITPOS 8
#define CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_SRC_NUM_BITS 1
/**
 * L3 header IPV6 dest address is compressed
 */
#define CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_DEST_BITPOS 7
#define CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_DEST_NUM_BITS 1
/**
 * L4 header valid
 */
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_VALID_BITPOS 6
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_VALID_NUM_BITS 1
/**
 * L4 header error
 */
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_ERROR_BITPOS 5
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_ERROR_NUM_BITS 1
/**
 * L4 header type
 */
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_TYPE_BITPOS 1
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_TYPE_NUM_BITS 4
/**
 * L4 header is UDP or TCP
 */
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_IS_UDP_TCP_BITPOS 0
#define CFA_P40_PROF_PROFILE_TCAM_L4_HDR_IS_UDP_TCP_NUM_BITS 1

enum cfa_p40_prof_profile_tcam_flds {
	CFA_P40_PROF_PROFILE_TCAM_VALID_FLD = 0,
	CFA_P40_PROF_PROFILE_TCAM_PKT_TYPE_FLD = 1,
	CFA_P40_PROF_PROFILE_TCAM_RECYCLE_CNT_FLD = 2,
	CFA_P40_PROF_PROFILE_TCAM_AGG_ERROR_FLD = 3,
	CFA_P40_PROF_PROFILE_TCAM_PROF_FUNC_FLD = 4,
	CFA_P40_PROF_PROFILE_TCAM_RESERVED_FLD = 5,
	CFA_P40_PROF_PROFILE_TCAM_HREC_NEXT_FLD = 6,
	CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_VALID_FLD = 7,
	CFA_P40_PROF_PROFILE_TCAM_TL2_HDR_TYPE_FLD = 8,
	CFA_P40_PROF_PROFILE_TCAM_TL2_UC_MC_BC_FLD = 9,
	CFA_P40_PROF_PROFILE_TCAM_TL2_VTAG_PRESENT_FLD = 10,
	CFA_P40_PROF_PROFILE_TCAM_TL2_TWO_VTAGS_FLD = 11,
	CFA_P40_PROF_PROFILE_TCAM_TL3_VALID_FLD = 12,
	CFA_P40_PROF_PROFILE_TCAM_TL3_ERROR_FLD = 13,
	CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_TYPE_FLD = 14,
	CFA_P40_PROF_PROFILE_TCAM_TL3_HDR_ISIP_FLD = 15,
	CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_SRC_FLD = 16,
	CFA_P40_PROF_PROFILE_TCAM_TL3_IPV6_CMP_DEST_FLD = 17,
	CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_VALID_FLD = 18,
	CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_ERROR_FLD = 19,
	CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_TYPE_FLD = 20,
	CFA_P40_PROF_PROFILE_TCAM_TL4_HDR_IS_UDP_TCP_FLD = 21,
	CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_VALID_FLD = 22,
	CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_ERR_FLD = 23,
	CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_TYPE_FLD = 24,
	CFA_P40_PROF_PROFILE_TCAM_TUN_HDR_FLAGS_FLD = 25,
	CFA_P40_PROF_PROFILE_TCAM_L2_HDR_VALID_FLD = 26,
	CFA_P40_PROF_PROFILE_TCAM_L2_HDR_ERROR_FLD = 27,
	CFA_P40_PROF_PROFILE_TCAM_L2_HDR_TYPE_FLD = 28,
	CFA_P40_PROF_PROFILE_TCAM_L2_UC_MC_BC_FLD = 29,
	CFA_P40_PROF_PROFILE_TCAM_L2_VTAG_PRESENT_FLD = 30,
	CFA_P40_PROF_PROFILE_TCAM_L2_TWO_VTAGS_FLD = 31,
	CFA_P40_PROF_PROFILE_TCAM_L3_VALID_FLD = 32,
	CFA_P40_PROF_PROFILE_TCAM_L3_ERROR_FLD = 33,
	CFA_P40_PROF_PROFILE_TCAM_L3_HDR_TYPE_FLD = 34,
	CFA_P40_PROF_PROFILE_TCAM_L3_HDR_ISIP_FLD = 35,
	CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_SRC_FLD = 36,
	CFA_P40_PROF_PROFILE_TCAM_L3_IPV6_CMP_DEST_FLD = 37,
	CFA_P40_PROF_PROFILE_TCAM_L4_HDR_VALID_FLD = 38,
	CFA_P40_PROF_PROFILE_TCAM_L4_HDR_ERROR_FLD = 39,
	CFA_P40_PROF_PROFILE_TCAM_L4_HDR_TYPE_FLD = 40,
	CFA_P40_PROF_PROFILE_TCAM_L4_HDR_IS_UDP_TCP_FLD = 41,
	CFA_P40_PROF_PROFILE_TCAM_MAX_FLD
};

#define CFA_P40_PROF_PROFILE_TCAM_TOTAL_NUM_BITS 81

/**
 * CFA flexible key layout definition
 */
enum cfa_p40_key_fld_id {
	CFA_P40_KEY_FLD_ID_MAX
};

/**************************************************************************/
/**
 * Non-autogenerated fields
 */

/**
 * Valid
 */
#define CFA_P40_EEM_KEY_TBL_VALID_BITPOS 0
#define CFA_P40_EEM_KEY_TBL_VALID_NUM_BITS 1

/**
 * L1 Cacheable
 */
#define CFA_P40_EEM_KEY_TBL_L1_CACHEABLE_BITPOS 1
#define CFA_P40_EEM_KEY_TBL_L1_CACHEABLE_NUM_BITS 1

/**
 * Strength
 */
#define CFA_P40_EEM_KEY_TBL_STRENGTH_BITPOS 2
#define CFA_P40_EEM_KEY_TBL_STRENGTH_NUM_BITS 2

/**
 * Key Size
 */
#define CFA_P40_EEM_KEY_TBL_KEY_SZ_BITPOS 15
#define CFA_P40_EEM_KEY_TBL_KEY_SZ_NUM_BITS 9

/**
 * Record Size
 */
#define CFA_P40_EEM_KEY_TBL_REC_SZ_BITPOS 24
#define CFA_P40_EEM_KEY_TBL_REC_SZ_NUM_BITS 5

/**
 * Action Record Internal
 */
#define CFA_P40_EEM_KEY_TBL_ACT_REC_INT_BITPOS 29
#define CFA_P40_EEM_KEY_TBL_ACT_REC_INT_NUM_BITS 1

/**
 * External Flow Counter
 */
#define CFA_P40_EEM_KEY_TBL_EXT_FLOW_CTR_BITPOS 30
#define CFA_P40_EEM_KEY_TBL_EXT_FLOW_CTR_NUM_BITS 1

/**
 * Action Record Pointer
 */
#define CFA_P40_EEM_KEY_TBL_AR_PTR_BITPOS 31
#define CFA_P40_EEM_KEY_TBL_AR_PTR_NUM_BITS 33

/**
 * EEM Key omitted - create using keybuilder
 * Fields here cannot be larger than a uint64_t
 */

#define CFA_P40_EEM_KEY_TBL_TOTAL_NUM_BITS 64

enum cfa_p40_eem_key_tbl_flds {
	CFA_P40_EEM_KEY_TBL_VALID_FLD = 0,
	CFA_P40_EEM_KEY_TBL_L1_CACHEABLE_FLD = 1,
	CFA_P40_EEM_KEY_TBL_STRENGTH_FLD = 2,
	CFA_P40_EEM_KEY_TBL_KEY_SZ_FLD = 3,
	CFA_P40_EEM_KEY_TBL_REC_SZ_FLD = 4,
	CFA_P40_EEM_KEY_TBL_ACT_REC_INT_FLD = 5,
	CFA_P40_EEM_KEY_TBL_EXT_FLOW_CTR_FLD = 6,
	CFA_P40_EEM_KEY_TBL_AR_PTR_FLD = 7,
	CFA_P40_EEM_KEY_TBL_MAX_FLD
};

/**
 * Mirror Destination 0 Source Property Record Pointer
 */
#define CFA_P40_MIRROR_TBL_SP_PTR_BITPOS 0
#define CFA_P40_MIRROR_TBL_SP_PTR_NUM_BITS 11

/**
 * igonore or honor drop
 */
#define CFA_P40_MIRROR_TBL_IGN_DROP_BITPOS 13
#define CFA_P40_MIRROR_TBL_IGN_DROP_NUM_BITS 1

/**
 * ingress or egress copy
 */
#define CFA_P40_MIRROR_TBL_COPY_BITPOS 14
#define CFA_P40_MIRROR_TBL_COPY_NUM_BITS 1

/**
 * Mirror Destination enable.
 */
#define CFA_P40_MIRROR_TBL_EN_BITPOS 15
#define CFA_P40_MIRROR_TBL_EN_NUM_BITS 1

/**
 * Action Record Pointer
 */
#define CFA_P40_MIRROR_TBL_AR_PTR_BITPOS 16
#define CFA_P40_MIRROR_TBL_AR_PTR_NUM_BITS 16

#define CFA_P40_MIRROR_TBL_TOTAL_NUM_BITS 32

enum cfa_p40_mirror_tbl_flds {
	CFA_P40_MIRROR_TBL_SP_PTR_FLD = 0,
	CFA_P40_MIRROR_TBL_IGN_DROP_FLD = 1,
	CFA_P40_MIRROR_TBL_COPY_FLD = 2,
	CFA_P40_MIRROR_TBL_EN_FLD = 3,
	CFA_P40_MIRROR_TBL_AR_PTR_FLD = 4,
	CFA_P40_MIRROR_TBL_MAX_FLD
};

/**
 * P45 Specific Updates (SR) - Non-autogenerated
 */
/**
 * Valid TCAM entry.
 */
#define CFA_P45_PROF_L2_CTXT_TCAM_VALID_BITPOS   166
#define CFA_P45_PROF_L2_CTXT_TCAM_VALID_NUM_BITS 1
/**
 * Source Partition.
 */
#define CFA_P45_PROF_L2_CTXT_TCAM_SPARIF_BITPOS  166
#define CFA_P45_PROF_L2_CTXT_TCAM_SPARIF_NUM_BITS 4

/**
 * Source Virtual I/F.
 */
#define CFA_P45_PROF_L2_CTXT_TCAM_SVIF_BITPOS    72
#define CFA_P45_PROF_L2_CTXT_TCAM_SVIF_NUM_BITS  12


/* The SR layout of the l2 ctxt key is different from the Wh+.  Switch to
 * cfa_p45_hw.h definition when available.
 */
enum cfa_p45_prof_l2_ctxt_tcam_flds {
	CFA_P45_PROF_L2_CTXT_TCAM_VALID_FLD = 0,
	CFA_P45_PROF_L2_CTXT_TCAM_SPARIF_FLD = 1,
	CFA_P45_PROF_L2_CTXT_TCAM_KEY_TYPE_FLD = 2,
	CFA_P45_PROF_L2_CTXT_TCAM_TUN_HDR_TYPE_FLD = 3,
	CFA_P45_PROF_L2_CTXT_TCAM_T_L2_NUMTAGS_FLD = 4,
	CFA_P45_PROF_L2_CTXT_TCAM_L2_NUMTAGS_FLD = 5,
	CFA_P45_PROF_L2_CTXT_TCAM_MAC1_FLD = 6,
	CFA_P45_PROF_L2_CTXT_TCAM_T_OVID_FLD = 7,
	CFA_P45_PROF_L2_CTXT_TCAM_T_IVID_FLD = 8,
	CFA_P45_PROF_L2_CTXT_TCAM_SVIF_FLD = 9,
	CFA_P45_PROF_L2_CTXT_TCAM_MAC0_FLD = 10,
	CFA_P45_PROF_L2_CTXT_TCAM_OVID_FLD = 11,
	CFA_P45_PROF_L2_CTXT_TCAM_IVID_FLD = 12,
	CFA_P45_PROF_L2_CTXT_TCAM_MAX_FLD
};

#define CFA_P45_PROF_L2_CTXT_TCAM_TOTAL_NUM_BITS 171

#endif /* _CFA_P40_HW_H_ */
