/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2020 Broadcom
 * All rights reserved.
 */


#ifndef ULP_TEMPLATE_DB_H_
#define ULP_TEMPLATE_DB_H_

#define BNXT_ULP_REGFILE_MAX_SZ 16
#define BNXT_ULP_MAX_NUM_DEVICES 4
#define BNXT_ULP_LOG2_MAX_NUM_DEV 2
#define BNXT_ULP_CACHE_TBL_MAX_SZ 4
#define BNXT_ULP_CLASS_SIG_TBL_MAX_SZ 256
#define BNXT_ULP_CLASS_MATCH_LIST_MAX_SZ 2
#define BNXT_ULP_CLASS_HID_LOW_PRIME 7919
#define BNXT_ULP_CLASS_HID_HIGH_PRIME 7919
#define BNXT_ULP_CLASS_HID_SHFTR 0
#define BNXT_ULP_CLASS_HID_SHFTL 23
#define BNXT_ULP_CLASS_HID_MASK 255
#define BNXT_ULP_ACT_SIG_TBL_MAX_SZ 256
#define BNXT_ULP_ACT_MATCH_LIST_MAX_SZ 2
#define BNXT_ULP_ACT_HID_LOW_PRIME 7919
#define BNXT_ULP_ACT_HID_HIGH_PRIME 7919
#define BNXT_ULP_ACT_HID_SHFTR 0
#define BNXT_ULP_ACT_HID_SHFTL 23
#define BNXT_ULP_ACT_HID_MASK 255
#define BNXT_ULP_CACHE_TBL_IDENT_MAX_NUM 2
#define BNXT_ULP_GLB_RESOURCE_INFO_TBL_MAX_SZ 2

enum bnxt_ulp_action_bit {
	BNXT_ULP_ACTION_BIT_MARK             = 0x0000000000000001,
	BNXT_ULP_ACTION_BIT_DROP             = 0x0000000000000002,
	BNXT_ULP_ACTION_BIT_COUNT            = 0x0000000000000004,
	BNXT_ULP_ACTION_BIT_RSS              = 0x0000000000000008,
	BNXT_ULP_ACTION_BIT_METER            = 0x0000000000000010,
	BNXT_ULP_ACTION_BIT_VNIC             = 0x0000000000000020,
	BNXT_ULP_ACTION_BIT_VPORT            = 0x0000000000000040,
	BNXT_ULP_ACTION_BIT_VXLAN_DECAP      = 0x0000000000000080,
	BNXT_ULP_ACTION_BIT_NVGRE_DECAP      = 0x0000000000000100,
	BNXT_ULP_ACTION_BIT_POP_MPLS         = 0x0000000000000200,
	BNXT_ULP_ACTION_BIT_PUSH_MPLS        = 0x0000000000000400,
	BNXT_ULP_ACTION_BIT_MAC_SWAP         = 0x0000000000000800,
	BNXT_ULP_ACTION_BIT_SET_MAC_SRC      = 0x0000000000001000,
	BNXT_ULP_ACTION_BIT_SET_MAC_DST      = 0x0000000000002000,
	BNXT_ULP_ACTION_BIT_POP_VLAN         = 0x0000000000004000,
	BNXT_ULP_ACTION_BIT_PUSH_VLAN        = 0x0000000000008000,
	BNXT_ULP_ACTION_BIT_SET_VLAN_PCP     = 0x0000000000010000,
	BNXT_ULP_ACTION_BIT_SET_VLAN_VID     = 0x0000000000020000,
	BNXT_ULP_ACTION_BIT_SET_IPV4_SRC     = 0x0000000000040000,
	BNXT_ULP_ACTION_BIT_SET_IPV4_DST     = 0x0000000000080000,
	BNXT_ULP_ACTION_BIT_SET_IPV6_SRC     = 0x0000000000100000,
	BNXT_ULP_ACTION_BIT_SET_IPV6_DST     = 0x0000000000200000,
	BNXT_ULP_ACTION_BIT_DEC_TTL          = 0x0000000000400000,
	BNXT_ULP_ACTION_BIT_SET_TP_SRC       = 0x0000000000800000,
	BNXT_ULP_ACTION_BIT_SET_TP_DST       = 0x0000000001000000,
	BNXT_ULP_ACTION_BIT_VXLAN_ENCAP      = 0x0000000002000000,
	BNXT_ULP_ACTION_BIT_NVGRE_ENCAP      = 0x0000000004000000,
	BNXT_ULP_ACTION_BIT_LAST             = 0x0000000008000000
};

enum bnxt_ulp_hdr_bit {
	BNXT_ULP_HDR_BIT_O_ETH               = 0x0000000000000001,
	BNXT_ULP_HDR_BIT_O_IPV4              = 0x0000000000000002,
	BNXT_ULP_HDR_BIT_O_IPV6              = 0x0000000000000004,
	BNXT_ULP_HDR_BIT_O_TCP               = 0x0000000000000008,
	BNXT_ULP_HDR_BIT_O_UDP               = 0x0000000000000010,
	BNXT_ULP_HDR_BIT_T_VXLAN             = 0x0000000000000020,
	BNXT_ULP_HDR_BIT_T_GRE               = 0x0000000000000040,
	BNXT_ULP_HDR_BIT_I_ETH               = 0x0000000000000080,
	BNXT_ULP_HDR_BIT_I_IPV4              = 0x0000000000000100,
	BNXT_ULP_HDR_BIT_I_IPV6              = 0x0000000000000200,
	BNXT_ULP_HDR_BIT_I_TCP               = 0x0000000000000400,
	BNXT_ULP_HDR_BIT_I_UDP               = 0x0000000000000800,
	BNXT_ULP_HDR_BIT_LAST                = 0x0000000000001000
};

enum bnxt_ulp_act_type {
	BNXT_ULP_ACT_TYPE_NOT_SUPPORTED = 0,
	BNXT_ULP_ACT_TYPE_SUPPORTED = 1,
	BNXT_ULP_ACT_TYPE_END = 2,
	BNXT_ULP_ACT_TYPE_LAST = 3
};

enum bnxt_ulp_byte_order {
	BNXT_ULP_BYTE_ORDER_BE = 0,
	BNXT_ULP_BYTE_ORDER_LE = 1,
	BNXT_ULP_BYTE_ORDER_LAST = 2
};

enum bnxt_ulp_cache_tbl_id {
	BNXT_ULP_CACHE_TBL_ID_L2_CNTXT_TCAM_INGRESS = 0,
	BNXT_ULP_CACHE_TBL_ID_L2_CNTXT_TCAM_EGRESS = 1,
	BNXT_ULP_CACHE_TBL_ID_PROFILE_TCAM_INGRESS = 2,
	BNXT_ULP_CACHE_TBL_ID_PROFILE_TCAM_EGRESS = 3,
	BNXT_ULP_CACHE_TBL_ID_LAST = 4
};

enum bnxt_ulp_cf_idx {
	BNXT_ULP_CF_IDX_MPLS_TAG_NUM = 0,
	BNXT_ULP_CF_IDX_O_VTAG_NUM = 1,
	BNXT_ULP_CF_IDX_O_VTAG_PRESENT = 2,
	BNXT_ULP_CF_IDX_O_TWO_VTAGS = 3,
	BNXT_ULP_CF_IDX_I_VTAG_NUM = 4,
	BNXT_ULP_CF_IDX_I_VTAG_PRESENT = 5,
	BNXT_ULP_CF_IDX_I_TWO_VTAGS = 6,
	BNXT_ULP_CF_IDX_INCOMING_IF = 7,
	BNXT_ULP_CF_IDX_DIRECTION = 8,
	BNXT_ULP_CF_IDX_SVIF_FLAG = 9,
	BNXT_ULP_CF_IDX_O_L3 = 10,
	BNXT_ULP_CF_IDX_I_L3 = 11,
	BNXT_ULP_CF_IDX_O_L4 = 12,
	BNXT_ULP_CF_IDX_I_L4 = 13,
	BNXT_ULP_CF_IDX_DEV_PORT_ID = 14,
	BNXT_ULP_CF_IDX_DRV_FUNC_SVIF = 15,
	BNXT_ULP_CF_IDX_DRV_FUNC_SPIF = 16,
	BNXT_ULP_CF_IDX_DRV_FUNC_PARIF = 17,
	BNXT_ULP_CF_IDX_DRV_FUNC_VNIC = 18,
	BNXT_ULP_CF_IDX_DRV_FUNC_PHY_PORT = 19,
	BNXT_ULP_CF_IDX_VF_FUNC_SVIF = 20,
	BNXT_ULP_CF_IDX_VF_FUNC_SPIF = 21,
	BNXT_ULP_CF_IDX_VF_FUNC_PARIF = 22,
	BNXT_ULP_CF_IDX_VF_FUNC_VNIC = 23,
	BNXT_ULP_CF_IDX_PHY_PORT_SVIF = 24,
	BNXT_ULP_CF_IDX_PHY_PORT_SPIF = 25,
	BNXT_ULP_CF_IDX_PHY_PORT_PARIF = 26,
	BNXT_ULP_CF_IDX_PHY_PORT_VPORT = 27,
	BNXT_ULP_CF_IDX_VFR_FLAG = 28,
	BNXT_ULP_CF_IDX_LAST = 29
};

enum bnxt_ulp_device_id {
	BNXT_ULP_DEVICE_ID_WH_PLUS = 0,
	BNXT_ULP_DEVICE_ID_THOR = 1,
	BNXT_ULP_DEVICE_ID_STINGRAY = 2,
	BNXT_ULP_DEVICE_ID_STINGRAY2 = 3,
	BNXT_ULP_DEVICE_ID_LAST = 4
};

enum bnxt_ulp_direction {
	BNXT_ULP_DIRECTION_INGRESS = 0,
	BNXT_ULP_DIRECTION_EGRESS = 1,
	BNXT_ULP_DIRECTION_LAST = 2
};

enum bnxt_ulp_glb_regfile_index {
	BNXT_ULP_GLB_REGFILE_INDEX_GLB_PROF_FUNC_ID = 0,
	BNXT_ULP_GLB_REGFILE_INDEX_LAST = 1
};

enum bnxt_ulp_hdr_type {
	BNXT_ULP_HDR_TYPE_NOT_SUPPORTED = 0,
	BNXT_ULP_HDR_TYPE_SUPPORTED = 1,
	BNXT_ULP_HDR_TYPE_END = 2,
	BNXT_ULP_HDR_TYPE_LAST = 3
};

enum bnxt_ulp_mark_enable {
	BNXT_ULP_MARK_ENABLE_NO = 0,
	BNXT_ULP_MARK_ENABLE_YES = 1,
	BNXT_ULP_MARK_ENABLE_LAST = 2
};

enum bnxt_ulp_mask_opc {
	BNXT_ULP_MASK_OPC_SET_TO_CONSTANT = 0,
	BNXT_ULP_MASK_OPC_SET_TO_HDR_FIELD = 1,
	BNXT_ULP_MASK_OPC_SET_TO_REGFILE = 2,
	BNXT_ULP_MASK_OPC_SET_TO_GLB_REGFILE = 3,
	BNXT_ULP_MASK_OPC_ADD_PAD = 4,
	BNXT_ULP_MASK_OPC_LAST = 5
};

enum bnxt_ulp_match_type {
	BNXT_ULP_MATCH_TYPE_EM = 0,
	BNXT_ULP_MATCH_TYPE_WC = 1,
	BNXT_ULP_MATCH_TYPE_LAST = 2
};

enum bnxt_ulp_priority {
	BNXT_ULP_PRIORITY_LEVEL_0 = 0,
	BNXT_ULP_PRIORITY_LEVEL_1 = 1,
	BNXT_ULP_PRIORITY_LEVEL_2 = 2,
	BNXT_ULP_PRIORITY_LEVEL_3 = 3,
	BNXT_ULP_PRIORITY_LEVEL_4 = 4,
	BNXT_ULP_PRIORITY_LEVEL_5 = 5,
	BNXT_ULP_PRIORITY_LEVEL_6 = 6,
	BNXT_ULP_PRIORITY_LEVEL_7 = 7,
	BNXT_ULP_PRIORITY_NOT_USED = 8,
	BNXT_ULP_PRIORITY_LAST = 9
};

enum bnxt_ulp_regfile_index {
	BNXT_ULP_REGFILE_INDEX_CLASS_TID = 0,
	BNXT_ULP_REGFILE_INDEX_L2_CNTXT_ID_0 = 1,
	BNXT_ULP_REGFILE_INDEX_L2_CNTXT_ID_1 = 2,
	BNXT_ULP_REGFILE_INDEX_PROF_FUNC_ID_0 = 3,
	BNXT_ULP_REGFILE_INDEX_PROF_FUNC_ID_1 = 4,
	BNXT_ULP_REGFILE_INDEX_EM_PROFILE_ID_0 = 5,
	BNXT_ULP_REGFILE_INDEX_EM_PROFILE_ID_1 = 6,
	BNXT_ULP_REGFILE_INDEX_WC_PROFILE_ID_0 = 7,
	BNXT_ULP_REGFILE_INDEX_WC_PROFILE_ID_1 = 8,
	BNXT_ULP_REGFILE_INDEX_ACTION_PTR_MAIN = 9,
	BNXT_ULP_REGFILE_INDEX_ACTION_PTR_0 = 10,
	BNXT_ULP_REGFILE_INDEX_ENCAP_PTR_0 = 11,
	BNXT_ULP_REGFILE_INDEX_ENCAP_PTR_1 = 12,
	BNXT_ULP_REGFILE_INDEX_CRITICAL_RESOURCE = 13,
	BNXT_ULP_REGFILE_INDEX_CACHE_ENTRY_PTR = 14,
	BNXT_ULP_REGFILE_INDEX_NOT_USED = 15,
	BNXT_ULP_REGFILE_INDEX_LAST = 16
};

enum bnxt_ulp_result_opc {
	BNXT_ULP_RESULT_OPC_SET_TO_CONSTANT = 0,
	BNXT_ULP_RESULT_OPC_SET_TO_ACT_PROP = 1,
	BNXT_ULP_RESULT_OPC_SET_TO_ACT_BIT = 2,
	BNXT_ULP_RESULT_OPC_SET_TO_ENCAP_ACT_PROP_SZ = 3,
	BNXT_ULP_RESULT_OPC_SET_TO_REGFILE = 4,
	BNXT_ULP_RESULT_OPC_SET_TO_GLB_REGFILE = 5,
	BNXT_ULP_RESULT_OPC_SET_TO_COMP_FIELD = 6,
	BNXT_ULP_RESULT_OPC_LAST = 7
};

enum bnxt_ulp_search_before_alloc {
	BNXT_ULP_SEARCH_BEFORE_ALLOC_NO = 0,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_YES = 1,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_LAST = 2
};

enum bnxt_ulp_spec_opc {
	BNXT_ULP_SPEC_OPC_SET_TO_CONSTANT = 0,
	BNXT_ULP_SPEC_OPC_SET_TO_HDR_FIELD = 1,
	BNXT_ULP_SPEC_OPC_SET_TO_COMP_FIELD = 2,
	BNXT_ULP_SPEC_OPC_SET_TO_REGFILE = 3,
	BNXT_ULP_SPEC_OPC_SET_TO_GLB_REGFILE = 4,
	BNXT_ULP_SPEC_OPC_ADD_PAD = 5,
	BNXT_ULP_SPEC_OPC_LAST = 6
};

enum bnxt_ulp_encap_vtag_encoding {
	BNXT_ULP_ENCAP_VTAG_ENCODING_DTAG_ECAP_PRI = 4,
	BNXT_ULP_ENCAP_VTAG_ENCODING_DTAG_REMAP_DIFFSERV = 5,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_ECAP_PRI = 6,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_DIFFSERV = 7,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_0 = 8,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_1 = 9,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_2 = 10,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_3 = 11,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_4 = 12,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_5 = 13,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_6 = 14,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NO_TAG_REMAP_PRI_7 = 15,
	BNXT_ULP_ENCAP_VTAG_ENCODING_NOP = 0,
	BNXT_ULP_ENCAP_VTAG_ENCODING_STAG_ECAP_PRI = 1,
	BNXT_ULP_ENCAP_VTAG_ENCODING_STAG_IVLAN_PRI = 2,
	BNXT_ULP_ENCAP_VTAG_ENCODING_STAG_REMAP_DIFFSERV = 3
};

enum bnxt_ulp_fdb_resource_flags {
	BNXT_ULP_FDB_RESOURCE_FLAGS_DIR_EGR = 0x01,
	BNXT_ULP_FDB_RESOURCE_FLAGS_DIR_INGR = 0x00
};

enum bnxt_ulp_fdb_type {
	BNXT_ULP_FDB_TYPE_DEFAULT = 1,
	BNXT_ULP_FDB_TYPE_REGULAR = 0
};

enum bnxt_ulp_flow_dir_bitmask {
	BNXT_ULP_FLOW_DIR_BITMASK_EGR = 0x8000000000000000,
	BNXT_ULP_FLOW_DIR_BITMASK_ING = 0x0000000000000000
};

enum bnxt_ulp_match_type_bitmask {
	BNXT_ULP_MATCH_TYPE_BITMASK_EM = 0x0000000000000000,
	BNXT_ULP_MATCH_TYPE_BITMASK_WM = 0x0000000000000001
};

enum bnxt_ulp_resource_func {
	BNXT_ULP_RESOURCE_FUNC_INVALID = 0x00,
	BNXT_ULP_RESOURCE_FUNC_EM_TABLE = 0x20,
	BNXT_ULP_RESOURCE_FUNC_RSVD1 = 0x40,
	BNXT_ULP_RESOURCE_FUNC_RSVD2 = 0x60,
	BNXT_ULP_RESOURCE_FUNC_TCAM_TABLE = 0x80,
	BNXT_ULP_RESOURCE_FUNC_INDEX_TABLE = 0x81,
	BNXT_ULP_RESOURCE_FUNC_CACHE_TABLE = 0x82,
	BNXT_ULP_RESOURCE_FUNC_IDENTIFIER = 0x83,
	BNXT_ULP_RESOURCE_FUNC_IF_TABLE = 0x84,
	BNXT_ULP_RESOURCE_FUNC_HW_FID = 0x85
};

enum bnxt_ulp_resource_sub_type {
	BNXT_ULP_RESOURCE_SUB_TYPE_NOT_USED = 0,
	BNXT_ULP_RESOURCE_SUB_TYPE_IT_NORMAL = 0,
	BNXT_ULP_RESOURCE_SUB_TYPE_IT_VFR_ACT_IDX = 1,
	BNXT_ULP_RESOURCE_SUB_TYPE_IT_INT_CNT_IDX = 2,
	BNXT_ULP_RESOURCE_SUB_TYPE_IT_EXT_CNT_IDX = 3,
	BNXT_ULP_RESOURCE_SUB_TYPE_TT_L2_CNTXT_TCAM_CACHE = 0,
	BNXT_ULP_RESOURCE_SUB_TYPE_TT_PROFILE_TCAM_CACHE = 1
};

enum bnxt_ulp_sym {
	BNXT_ULP_SYM_BIG_ENDIAN = 0,
	BNXT_ULP_SYM_DECAP_FUNC_NONE = 0,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L2 = 11,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L3 = 12,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L4 = 13,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL2 = 3,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL3 = 8,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL4 = 9,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TUN = 10,
	BNXT_ULP_SYM_ECV_CUSTOM_EN_NO = 0,
	BNXT_ULP_SYM_ECV_CUSTOM_EN_YES = 1,
	BNXT_ULP_SYM_ECV_L2_EN_NO = 0,
	BNXT_ULP_SYM_ECV_L2_EN_YES = 1,
	BNXT_ULP_SYM_ECV_L3_TYPE_IPV4 = 4,
	BNXT_ULP_SYM_ECV_L3_TYPE_IPV6 = 5,
	BNXT_ULP_SYM_ECV_L3_TYPE_MPLS_8847 = 6,
	BNXT_ULP_SYM_ECV_L3_TYPE_MPLS_8848 = 7,
	BNXT_ULP_SYM_ECV_L3_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_L4_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP = 4,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_CSUM = 5,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_ENTROPY = 6,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_ENTROPY_CSUM = 7,
	BNXT_ULP_SYM_ECV_TUN_TYPE_GENERIC = 1,
	BNXT_ULP_SYM_ECV_TUN_TYPE_GRE = 5,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NGE = 3,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NVGRE = 4,
	BNXT_ULP_SYM_ECV_TUN_TYPE_VXLAN = 2,
	BNXT_ULP_SYM_ECV_VALID_NO = 0,
	BNXT_ULP_SYM_ECV_VALID_YES = 1,
	BNXT_ULP_SYM_IP_PROTO_UDP = 17,
	BNXT_ULP_SYM_L2_HDR_TYPE_DIX = 0,
	BNXT_ULP_SYM_L2_HDR_TYPE_LLC = 2,
	BNXT_ULP_SYM_L2_HDR_TYPE_LLC_SNAP = 1,
	BNXT_ULP_SYM_L3_HDR_TYPE_ARP = 2,
	BNXT_ULP_SYM_L3_HDR_TYPE_EAPOL = 4,
	BNXT_ULP_SYM_L3_HDR_TYPE_FCOE = 6,
	BNXT_ULP_SYM_L3_HDR_TYPE_IPV4 = 0,
	BNXT_ULP_SYM_L3_HDR_TYPE_IPV6 = 1,
	BNXT_ULP_SYM_L3_HDR_TYPE_PTP = 3,
	BNXT_ULP_SYM_L3_HDR_TYPE_ROCE = 5,
	BNXT_ULP_SYM_L3_HDR_TYPE_UPAR1 = 7,
	BNXT_ULP_SYM_L3_HDR_TYPE_UPAR2 = 8,
	BNXT_ULP_SYM_L4_HDR_TYPE_BTH_V1 = 5,
	BNXT_ULP_SYM_L4_HDR_TYPE_ICMP = 2,
	BNXT_ULP_SYM_L4_HDR_TYPE_TCP = 0,
	BNXT_ULP_SYM_L4_HDR_TYPE_UDP = 1,
	BNXT_ULP_SYM_L4_HDR_TYPE_UPAR1 = 3,
	BNXT_ULP_SYM_L4_HDR_TYPE_UPAR2 = 4,
	BNXT_ULP_SYM_LITTLE_ENDIAN = 1,
	BNXT_ULP_SYM_MATCH_TYPE_EM = 0,
	BNXT_ULP_SYM_MATCH_TYPE_WM = 1,
	BNXT_ULP_SYM_NO = 0,
	BNXT_ULP_SYM_PKT_TYPE_L2 = 0,
	BNXT_ULP_SYM_POP_VLAN_NO = 0,
	BNXT_ULP_SYM_POP_VLAN_YES = 1,
	BNXT_ULP_SYM_STINGRAY2_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_STINGRAY_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_THOR_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_TL2_HDR_TYPE_DIX = 0,
	BNXT_ULP_SYM_TL3_HDR_TYPE_IPV4 = 0,
	BNXT_ULP_SYM_TL3_HDR_TYPE_IPV6 = 1,
	BNXT_ULP_SYM_TL4_HDR_TYPE_TCP = 0,
	BNXT_ULP_SYM_TL4_HDR_TYPE_UDP = 1,
	BNXT_ULP_SYM_TUN_HDR_TYPE_GENEVE = 1,
	BNXT_ULP_SYM_TUN_HDR_TYPE_GRE = 3,
	BNXT_ULP_SYM_TUN_HDR_TYPE_IPV4 = 4,
	BNXT_ULP_SYM_TUN_HDR_TYPE_IPV6 = 5,
	BNXT_ULP_SYM_TUN_HDR_TYPE_MPLS = 7,
	BNXT_ULP_SYM_TUN_HDR_TYPE_NONE = 15,
	BNXT_ULP_SYM_TUN_HDR_TYPE_NVGRE = 2,
	BNXT_ULP_SYM_TUN_HDR_TYPE_PPPOE = 6,
	BNXT_ULP_SYM_TUN_HDR_TYPE_UPAR1 = 8,
	BNXT_ULP_SYM_TUN_HDR_TYPE_UPAR2 = 9,
	BNXT_ULP_SYM_TUN_HDR_TYPE_VXLAN = 0,
	BNXT_ULP_SYM_WH_PLUS_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_YES = 1
};

enum bnxt_ulp_act_prop_sz {
	BNXT_ULP_ACT_PROP_SZ_ENCAP_TUN_SZ = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_IP_SZ = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_VTAG_SZ = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_VTAG_TYPE = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_VTAG_NUM = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_L3_TYPE = 4,
	BNXT_ULP_ACT_PROP_SZ_MPLS_POP_NUM = 4,
	BNXT_ULP_ACT_PROP_SZ_MPLS_PUSH_NUM = 4,
	BNXT_ULP_ACT_PROP_SZ_PORT_ID = 4,
	BNXT_ULP_ACT_PROP_SZ_VNIC = 4,
	BNXT_ULP_ACT_PROP_SZ_VPORT = 4,
	BNXT_ULP_ACT_PROP_SZ_MARK = 4,
	BNXT_ULP_ACT_PROP_SZ_COUNT = 4,
	BNXT_ULP_ACT_PROP_SZ_METER = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_MAC_SRC = 8,
	BNXT_ULP_ACT_PROP_SZ_SET_MAC_DST = 8,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_VLAN = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_SET_VLAN_PCP = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_SET_VLAN_VID = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV4_SRC = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV4_DST = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV6_SRC = 16,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV6_DST = 16,
	BNXT_ULP_ACT_PROP_SZ_SET_TP_SRC = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_TP_DST = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_0 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_1 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_2 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_3 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_4 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_5 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_6 = 4,
	BNXT_ULP_ACT_PROP_SZ_OF_PUSH_MPLS_7 = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_L2_DMAC = 6,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_L2_SMAC = 6,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_VTAG = 8,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_IP = 32,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_IP_SRC = 16,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_UDP = 4,
	BNXT_ULP_ACT_PROP_SZ_ENCAP_TUN = 32,
	BNXT_ULP_ACT_PROP_SZ_LAST = 4
};

enum bnxt_ulp_act_prop_idx {
	BNXT_ULP_ACT_PROP_IDX_ENCAP_TUN_SZ = 0,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_IP_SZ = 4,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_VTAG_SZ = 8,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_VTAG_TYPE = 12,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_VTAG_NUM = 16,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_L3_TYPE = 20,
	BNXT_ULP_ACT_PROP_IDX_MPLS_POP_NUM = 24,
	BNXT_ULP_ACT_PROP_IDX_MPLS_PUSH_NUM = 28,
	BNXT_ULP_ACT_PROP_IDX_PORT_ID = 32,
	BNXT_ULP_ACT_PROP_IDX_VNIC = 36,
	BNXT_ULP_ACT_PROP_IDX_VPORT = 40,
	BNXT_ULP_ACT_PROP_IDX_MARK = 44,
	BNXT_ULP_ACT_PROP_IDX_COUNT = 48,
	BNXT_ULP_ACT_PROP_IDX_METER = 52,
	BNXT_ULP_ACT_PROP_IDX_SET_MAC_SRC = 56,
	BNXT_ULP_ACT_PROP_IDX_SET_MAC_DST = 64,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_VLAN = 72,
	BNXT_ULP_ACT_PROP_IDX_OF_SET_VLAN_PCP = 76,
	BNXT_ULP_ACT_PROP_IDX_OF_SET_VLAN_VID = 80,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV4_SRC = 84,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV4_DST = 88,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV6_SRC = 92,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV6_DST = 108,
	BNXT_ULP_ACT_PROP_IDX_SET_TP_SRC = 124,
	BNXT_ULP_ACT_PROP_IDX_SET_TP_DST = 128,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_0 = 132,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_1 = 136,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_2 = 140,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_3 = 144,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_4 = 148,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_5 = 152,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_6 = 156,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_7 = 160,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_L2_DMAC = 164,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_L2_SMAC = 170,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_VTAG = 176,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_IP = 184,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_IP_SRC = 216,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_UDP = 232,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_TUN = 236,
	BNXT_ULP_ACT_PROP_IDX_LAST = 268
};

enum bnxt_ulp_class_hid {
	BNXT_ULP_CLASS_HID_0013 = 0x0013
};

enum bnxt_ulp_act_hid {
	BNXT_ULP_ACT_HID_0029 = 0x0029
};

#endif
