/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2020 Broadcom
 * All rights reserved.
 */

#ifndef ULP_TEMPLATE_DB_H_
#define ULP_TEMPLATE_DB_H_

#define BNXT_ULP_REGFILE_MAX_SZ 17
#define BNXT_ULP_MAX_NUM_DEVICES 4
#define BNXT_ULP_LOG2_MAX_NUM_DEV 2
#define BNXT_ULP_CACHE_TBL_MAX_SZ 4
#define BNXT_ULP_CLASS_SIG_TBL_MAX_SZ 256
#define BNXT_ULP_CLASS_MATCH_LIST_MAX_SZ 4
#define BNXT_ULP_CLASS_HID_LOW_PRIME 7919
#define BNXT_ULP_CLASS_HID_HIGH_PRIME 7907
#define BNXT_ULP_CLASS_HID_SHFTR 16
#define BNXT_ULP_CLASS_HID_SHFTL 23
#define BNXT_ULP_CLASS_HID_MASK 255
#define BNXT_ULP_ACT_SIG_TBL_MAX_SZ 256
#define BNXT_ULP_ACT_MATCH_LIST_MAX_SZ 24
#define BNXT_ULP_ACT_HID_LOW_PRIME 7919
#define BNXT_ULP_ACT_HID_HIGH_PRIME 7919
#define BNXT_ULP_ACT_HID_SHFTR 23
#define BNXT_ULP_ACT_HID_SHFTL 23
#define BNXT_ULP_ACT_HID_MASK 255
#define BNXT_ULP_CACHE_TBL_IDENT_MAX_NUM 2
#define BNXT_ULP_GLB_RESOURCE_TBL_MAX_SZ 5
#define BNXT_ULP_GLB_TEMPLATE_TBL_MAX_SZ 1

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

enum bnxt_ulp_cf_idx {
	BNXT_ULP_CF_IDX_NOT_USED = 0,
	BNXT_ULP_CF_IDX_MPLS_TAG_NUM = 1,
	BNXT_ULP_CF_IDX_O_VTAG_NUM = 2,
	BNXT_ULP_CF_IDX_O_VTAG_PRESENT = 3,
	BNXT_ULP_CF_IDX_O_TWO_VTAGS = 4,
	BNXT_ULP_CF_IDX_I_VTAG_NUM = 5,
	BNXT_ULP_CF_IDX_I_VTAG_PRESENT = 6,
	BNXT_ULP_CF_IDX_I_TWO_VTAGS = 7,
	BNXT_ULP_CF_IDX_INCOMING_IF = 8,
	BNXT_ULP_CF_IDX_DIRECTION = 9,
	BNXT_ULP_CF_IDX_SVIF_FLAG = 10,
	BNXT_ULP_CF_IDX_O_L3 = 11,
	BNXT_ULP_CF_IDX_I_L3 = 12,
	BNXT_ULP_CF_IDX_O_L4 = 13,
	BNXT_ULP_CF_IDX_I_L4 = 14,
	BNXT_ULP_CF_IDX_DEV_PORT_ID = 15,
	BNXT_ULP_CF_IDX_DRV_FUNC_SVIF = 16,
	BNXT_ULP_CF_IDX_DRV_FUNC_SPIF = 17,
	BNXT_ULP_CF_IDX_DRV_FUNC_PARIF = 18,
	BNXT_ULP_CF_IDX_DRV_FUNC_VNIC = 19,
	BNXT_ULP_CF_IDX_DRV_FUNC_PHY_PORT = 20,
	BNXT_ULP_CF_IDX_VF_FUNC_SVIF = 21,
	BNXT_ULP_CF_IDX_VF_FUNC_SPIF = 22,
	BNXT_ULP_CF_IDX_VF_FUNC_PARIF = 23,
	BNXT_ULP_CF_IDX_VF_FUNC_VNIC = 24,
	BNXT_ULP_CF_IDX_PHY_PORT_SVIF = 25,
	BNXT_ULP_CF_IDX_PHY_PORT_SPIF = 26,
	BNXT_ULP_CF_IDX_PHY_PORT_PARIF = 27,
	BNXT_ULP_CF_IDX_PHY_PORT_VPORT = 28,
	BNXT_ULP_CF_IDX_ACT_ENCAP_IPV4_FLAG = 29,
	BNXT_ULP_CF_IDX_ACT_ENCAP_IPV6_FLAG = 30,
	BNXT_ULP_CF_IDX_LAST = 31
};

enum bnxt_ulp_cond_opcode {
	BNXT_ULP_COND_OPCODE_NOP = 0,
	BNXT_ULP_COND_OPCODE_COMP_FIELD = 1,
	BNXT_ULP_COND_OPCODE_ACTION_BIT = 2,
	BNXT_ULP_COND_OPCODE_HDR_BIT = 3,
	BNXT_ULP_COND_OPCODE_LAST = 4
};

enum bnxt_ulp_critical_resource {
	BNXT_ULP_CRITICAL_RESOURCE_NO = 0,
	BNXT_ULP_CRITICAL_RESOURCE_YES = 1,
	BNXT_ULP_CRITICAL_RESOURCE_LAST = 2
};

enum bnxt_ulp_device_id {
	BNXT_ULP_DEVICE_ID_WH_PLUS = 0,
	BNXT_ULP_DEVICE_ID_THOR = 1,
	BNXT_ULP_DEVICE_ID_STINGRAY = 2,
	BNXT_ULP_DEVICE_ID_STINGRAY2 = 3,
	BNXT_ULP_DEVICE_ID_LAST = 4
};

enum bnxt_ulp_df_param_type {
	BNXT_ULP_DF_PARAM_TYPE_DEV_PORT_ID = 0,
	BNXT_ULP_DF_PARAM_TYPE_LAST = 1
};

enum bnxt_ulp_direction {
	BNXT_ULP_DIRECTION_INGRESS = 0,
	BNXT_ULP_DIRECTION_EGRESS = 1,
	BNXT_ULP_DIRECTION_LAST = 2
};

enum bnxt_ulp_flow_mem_type {
	BNXT_ULP_FLOW_MEM_TYPE_INT = 0,
	BNXT_ULP_FLOW_MEM_TYPE_EXT = 1,
	BNXT_ULP_FLOW_MEM_TYPE_BOTH = 2,
	BNXT_ULP_FLOW_MEM_TYPE_LAST = 3
};

enum bnxt_ulp_glb_regfile_index {
	BNXT_ULP_GLB_REGFILE_INDEX_NOT_USED = 0,
	BNXT_ULP_GLB_REGFILE_INDEX_GLB_PROF_FUNC_ID = 1,
	BNXT_ULP_GLB_REGFILE_INDEX_GLB_L2_CNTXT_ID = 2,
	BNXT_ULP_GLB_REGFILE_INDEX_GLB_LB_AREC_PTR = 3,
	BNXT_ULP_GLB_REGFILE_INDEX_LAST = 4
};

enum bnxt_ulp_hdr_type {
	BNXT_ULP_HDR_TYPE_NOT_SUPPORTED = 0,
	BNXT_ULP_HDR_TYPE_SUPPORTED = 1,
	BNXT_ULP_HDR_TYPE_END = 2,
	BNXT_ULP_HDR_TYPE_LAST = 3
};

enum bnxt_ulp_index_opcode {
	BNXT_ULP_INDEX_OPCODE_NOT_USED = 0,
	BNXT_ULP_INDEX_OPCODE_ALLOCATE = 1,
	BNXT_ULP_INDEX_OPCODE_GLOBAL = 2,
	BNXT_ULP_INDEX_OPCODE_COMP_FIELD = 3,
	BNXT_ULP_INDEX_OPCODE_LAST = 4
};

enum bnxt_ulp_mapper_opc {
	BNXT_ULP_MAPPER_OPC_SET_TO_CONSTANT = 0,
	BNXT_ULP_MAPPER_OPC_SET_TO_HDR_FIELD = 1,
	BNXT_ULP_MAPPER_OPC_SET_TO_COMP_FIELD = 2,
	BNXT_ULP_MAPPER_OPC_SET_TO_REGFILE = 3,
	BNXT_ULP_MAPPER_OPC_SET_TO_GLB_REGFILE = 4,
	BNXT_ULP_MAPPER_OPC_SET_TO_ZERO = 5,
	BNXT_ULP_MAPPER_OPC_SET_TO_ACT_BIT = 6,
	BNXT_ULP_MAPPER_OPC_SET_TO_ACT_PROP = 7,
	BNXT_ULP_MAPPER_OPC_SET_TO_ENCAP_ACT_PROP_SZ = 8,
	BNXT_ULP_MAPPER_OPC_LAST = 9
};

enum bnxt_ulp_mark_db_opcode {
	BNXT_ULP_MARK_DB_OPCODE_NOP = 0,
	BNXT_ULP_MARK_DB_OPCODE_SET_IF_MARK_ACTION = 1,
	BNXT_ULP_MARK_DB_OPCODE_SET_VFR_FLAG = 2,
	BNXT_ULP_MARK_DB_OPCODE_LAST = 3
};

enum bnxt_ulp_match_type {
	BNXT_ULP_MATCH_TYPE_EM = 0,
	BNXT_ULP_MATCH_TYPE_WM = 1,
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
	BNXT_ULP_REGFILE_INDEX_NOT_USED = 0,
	BNXT_ULP_REGFILE_INDEX_CLASS_TID = 1,
	BNXT_ULP_REGFILE_INDEX_L2_CNTXT_ID_0 = 2,
	BNXT_ULP_REGFILE_INDEX_L2_CNTXT_ID_1 = 3,
	BNXT_ULP_REGFILE_INDEX_PROF_FUNC_ID_0 = 4,
	BNXT_ULP_REGFILE_INDEX_PROF_FUNC_ID_1 = 5,
	BNXT_ULP_REGFILE_INDEX_EM_PROFILE_ID_0 = 6,
	BNXT_ULP_REGFILE_INDEX_EM_PROFILE_ID_1 = 7,
	BNXT_ULP_REGFILE_INDEX_WC_PROFILE_ID_0 = 8,
	BNXT_ULP_REGFILE_INDEX_WC_PROFILE_ID_1 = 9,
	BNXT_ULP_REGFILE_INDEX_MAIN_ACTION_PTR = 10,
	BNXT_ULP_REGFILE_INDEX_ACTION_PTR_0 = 11,
	BNXT_ULP_REGFILE_INDEX_ENCAP_PTR_0 = 12,
	BNXT_ULP_REGFILE_INDEX_ENCAP_PTR_1 = 13,
	BNXT_ULP_REGFILE_INDEX_CRITICAL_RESOURCE = 14,
	BNXT_ULP_REGFILE_INDEX_FLOW_CNTR_PTR_0 = 15,
	BNXT_ULP_REGFILE_INDEX_MAIN_SP_PTR = 16,
	BNXT_ULP_REGFILE_INDEX_LAST = 17
};

enum bnxt_ulp_search_before_alloc {
	BNXT_ULP_SEARCH_BEFORE_ALLOC_NO = 0,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_YES = 1,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_LAST = 2
};

enum bnxt_ulp_fdb_resource_flags {
	BNXT_ULP_FDB_RESOURCE_FLAGS_DIR_INGR = 0x00,
	BNXT_ULP_FDB_RESOURCE_FLAGS_DIR_EGR = 0x01
};

enum bnxt_ulp_fdb_type {
	BNXT_ULP_FDB_TYPE_REGULAR = 0,
	BNXT_ULP_FDB_TYPE_DEFAULT = 1
};

enum bnxt_ulp_flow_dir_bitmask {
	BNXT_ULP_FLOW_DIR_BITMASK_ING = 0x0000000000000000,
	BNXT_ULP_FLOW_DIR_BITMASK_EGR = 0x8000000000000000
};

enum bnxt_ulp_match_type_bitmask {
	BNXT_ULP_MATCH_TYPE_BITMASK_EM = 0x0000000000000000,
	BNXT_ULP_MATCH_TYPE_BITMASK_WM = 0x0000000000000001
};

enum bnxt_ulp_resource_func {
	BNXT_ULP_RESOURCE_FUNC_INVALID = 0x00,
	BNXT_ULP_RESOURCE_FUNC_EXT_EM_TABLE = 0x20,
	BNXT_ULP_RESOURCE_FUNC_INT_EM_TABLE = 0x40,
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
	BNXT_ULP_RESOURCE_SUB_TYPE_INDEX_TYPE_NORMAL = 0,
	BNXT_ULP_RESOURCE_SUB_TYPE_INDEX_TYPE_VFR_CFA_ACTION = 1,
	BNXT_ULP_RESOURCE_SUB_TYPE_INDEX_TYPE_INT_COUNT = 2,
	BNXT_ULP_RESOURCE_SUB_TYPE_INDEX_TYPE_EXT_COUNT = 3,
	BNXT_ULP_RESOURCE_SUB_TYPE_CACHE_TYPE_L2_CNTXT_TCAM = 0,
	BNXT_ULP_RESOURCE_SUB_TYPE_CACHE_TYPE_PROFILE_TCAM = 1
};

enum bnxt_ulp_sym {
	BNXT_ULP_SYM_PKT_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_PKT_TYPE_L2 = 0,
	BNXT_ULP_SYM_RECYCLE_CNT_IGNORE = 0,
	BNXT_ULP_SYM_RECYCLE_CNT_ZERO = 0,
	BNXT_ULP_SYM_RECYCLE_CNT_ONE = 1,
	BNXT_ULP_SYM_RECYCLE_CNT_TWO = 2,
	BNXT_ULP_SYM_RECYCLE_CNT_THREE = 3,
	BNXT_ULP_SYM_AGG_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_AGG_ERROR_NO = 0,
	BNXT_ULP_SYM_AGG_ERROR_YES = 1,
	BNXT_ULP_SYM_RESERVED_IGNORE = 0,
	BNXT_ULP_SYM_HREC_NEXT_IGNORE = 0,
	BNXT_ULP_SYM_HREC_NEXT_NO = 0,
	BNXT_ULP_SYM_HREC_NEXT_YES = 1,
	BNXT_ULP_SYM_TL2_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_TL2_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_TL2_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_TL2_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_TL2_HDR_TYPE_DIX = 0,
	BNXT_ULP_SYM_TL2_UC_MC_BC_IGNORE = 0,
	BNXT_ULP_SYM_TL2_UC_MC_BC_UC = 0,
	BNXT_ULP_SYM_TL2_UC_MC_BC_MC = 2,
	BNXT_ULP_SYM_TL2_UC_MC_BC_BC = 3,
	BNXT_ULP_SYM_TL2_VTAG_PRESENT_IGNORE = 0,
	BNXT_ULP_SYM_TL2_VTAG_PRESENT_NO = 0,
	BNXT_ULP_SYM_TL2_VTAG_PRESENT_YES = 1,
	BNXT_ULP_SYM_TL2_TWO_VTAGS_IGNORE = 0,
	BNXT_ULP_SYM_TL2_TWO_VTAGS_NO = 0,
	BNXT_ULP_SYM_TL2_TWO_VTAGS_YES = 1,
	BNXT_ULP_SYM_TL3_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_TL3_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_TL3_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_TL3_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_TL3_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_TL3_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_TL3_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_TL3_HDR_TYPE_IPV4 = 0,
	BNXT_ULP_SYM_TL3_HDR_TYPE_IPV6 = 1,
	BNXT_ULP_SYM_TL3_HDR_ISIP_IGNORE = 0,
	BNXT_ULP_SYM_TL3_HDR_ISIP_NO = 0,
	BNXT_ULP_SYM_TL3_HDR_ISIP_YES = 1,
	BNXT_ULP_SYM_TL3_IPV6_CMP_SRC_IGNORE = 0,
	BNXT_ULP_SYM_TL3_IPV6_CMP_SRC_NO = 0,
	BNXT_ULP_SYM_TL3_IPV6_CMP_SRC_YES = 1,
	BNXT_ULP_SYM_TL3_IPV6_CMP_DST_IGNORE = 0,
	BNXT_ULP_SYM_TL3_IPV6_CMP_DST_NO = 0,
	BNXT_ULP_SYM_TL3_IPV6_CMP_DST_YES = 1,
	BNXT_ULP_SYM_TL4_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_TL4_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_TL4_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_TL4_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_TL4_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_TL4_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_TL4_HDR_IS_UDP_TCP_IGNORE = 0,
	BNXT_ULP_SYM_TL4_HDR_IS_UDP_TCP_NO = 0,
	BNXT_ULP_SYM_TL4_HDR_IS_UDP_TCP_YES = 1,
	BNXT_ULP_SYM_TL4_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_TL4_HDR_TYPE_TCP = 0,
	BNXT_ULP_SYM_TL4_HDR_TYPE_UDP = 1,
	BNXT_ULP_SYM_TUN_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_TUN_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_TUN_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_TUN_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_TUN_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_TUN_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_TUN_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_TUN_HDR_TYPE_VXLAN = 0,
	BNXT_ULP_SYM_TUN_HDR_TYPE_GENEVE = 1,
	BNXT_ULP_SYM_TUN_HDR_TYPE_NVGRE = 2,
	BNXT_ULP_SYM_TUN_HDR_TYPE_GRE = 3,
	BNXT_ULP_SYM_TUN_HDR_TYPE_IPV4 = 4,
	BNXT_ULP_SYM_TUN_HDR_TYPE_IPV6 = 5,
	BNXT_ULP_SYM_TUN_HDR_TYPE_PPPOE = 6,
	BNXT_ULP_SYM_TUN_HDR_TYPE_MPLS = 7,
	BNXT_ULP_SYM_TUN_HDR_TYPE_UPAR1 = 8,
	BNXT_ULP_SYM_TUN_HDR_TYPE_UPAR2 = 9,
	BNXT_ULP_SYM_TUN_HDR_TYPE_NONE = 15,
	BNXT_ULP_SYM_TUN_HDR_FLAGS_IGNORE = 0,
	BNXT_ULP_SYM_L2_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_L2_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_L2_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_L2_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_L2_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_L2_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_L2_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_L2_HDR_TYPE_DIX = 0,
	BNXT_ULP_SYM_L2_HDR_TYPE_LLC_SNAP = 1,
	BNXT_ULP_SYM_L2_HDR_TYPE_LLC = 2,
	BNXT_ULP_SYM_L2_UC_MC_BC_IGNORE = 0,
	BNXT_ULP_SYM_L2_UC_MC_BC_UC = 0,
	BNXT_ULP_SYM_L2_UC_MC_BC_MC = 2,
	BNXT_ULP_SYM_L2_UC_MC_BC_BC = 3,
	BNXT_ULP_SYM_L2_VTAG_PRESENT_IGNORE = 0,
	BNXT_ULP_SYM_L2_VTAG_PRESENT_NO = 0,
	BNXT_ULP_SYM_L2_VTAG_PRESENT_YES = 1,
	BNXT_ULP_SYM_L2_TWO_VTAGS_IGNORE = 0,
	BNXT_ULP_SYM_L2_TWO_VTAGS_NO = 0,
	BNXT_ULP_SYM_L2_TWO_VTAGS_YES = 1,
	BNXT_ULP_SYM_L3_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_L3_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_L3_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_L3_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_L3_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_L3_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_L3_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_L3_HDR_TYPE_IPV4 = 0,
	BNXT_ULP_SYM_L3_HDR_TYPE_IPV6 = 1,
	BNXT_ULP_SYM_L3_HDR_TYPE_ARP = 2,
	BNXT_ULP_SYM_L3_HDR_TYPE_PTP = 3,
	BNXT_ULP_SYM_L3_HDR_TYPE_EAPOL = 4,
	BNXT_ULP_SYM_L3_HDR_TYPE_ROCE = 5,
	BNXT_ULP_SYM_L3_HDR_TYPE_FCOE = 6,
	BNXT_ULP_SYM_L3_HDR_TYPE_UPAR1 = 7,
	BNXT_ULP_SYM_L3_HDR_TYPE_UPAR2 = 8,
	BNXT_ULP_SYM_L3_HDR_ISIP_IGNORE = 0,
	BNXT_ULP_SYM_L3_HDR_ISIP_NO = 0,
	BNXT_ULP_SYM_L3_HDR_ISIP_YES = 1,
	BNXT_ULP_SYM_L3_IPV6_CMP_SRC_IGNORE = 0,
	BNXT_ULP_SYM_L3_IPV6_CMP_SRC_NO = 0,
	BNXT_ULP_SYM_L3_IPV6_CMP_SRC_YES = 1,
	BNXT_ULP_SYM_L3_IPV6_CMP_DST_IGNORE = 0,
	BNXT_ULP_SYM_L3_IPV6_CMP_DST_NO = 0,
	BNXT_ULP_SYM_L3_IPV6_CMP_DST_YES = 1,
	BNXT_ULP_SYM_L4_HDR_VALID_IGNORE = 0,
	BNXT_ULP_SYM_L4_HDR_VALID_NO = 0,
	BNXT_ULP_SYM_L4_HDR_VALID_YES = 1,
	BNXT_ULP_SYM_L4_HDR_ERROR_IGNORE = 0,
	BNXT_ULP_SYM_L4_HDR_ERROR_NO = 0,
	BNXT_ULP_SYM_L4_HDR_ERROR_YES = 1,
	BNXT_ULP_SYM_L4_HDR_TYPE_IGNORE = 0,
	BNXT_ULP_SYM_L4_HDR_TYPE_TCP = 0,
	BNXT_ULP_SYM_L4_HDR_TYPE_UDP = 1,
	BNXT_ULP_SYM_L4_HDR_TYPE_ICMP = 2,
	BNXT_ULP_SYM_L4_HDR_TYPE_UPAR1 = 3,
	BNXT_ULP_SYM_L4_HDR_TYPE_UPAR2 = 4,
	BNXT_ULP_SYM_L4_HDR_TYPE_BTH_V1 = 5,
	BNXT_ULP_SYM_L4_HDR_IS_UDP_TCP_IGNORE = 0,
	BNXT_ULP_SYM_L4_HDR_IS_UDP_TCP_NO = 0,
	BNXT_ULP_SYM_L4_HDR_IS_UDP_TCP_YES = 1,
	BNXT_ULP_SYM_POP_VLAN_NO = 0,
	BNXT_ULP_SYM_POP_VLAN_YES = 1,
	BNXT_ULP_SYM_DECAP_FUNC_NONE = 0,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL2 = 3,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL3 = 8,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TL4 = 9,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_TUN = 10,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L2 = 11,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L3 = 12,
	BNXT_ULP_SYM_DECAP_FUNC_THRU_L4 = 13,
	BNXT_ULP_SYM_ECV_VALID_NO = 0,
	BNXT_ULP_SYM_ECV_VALID_YES = 1,
	BNXT_ULP_SYM_ECV_CUSTOM_EN_NO = 0,
	BNXT_ULP_SYM_ECV_CUSTOM_EN_YES = 1,
	BNXT_ULP_SYM_ECV_L2_EN_NO = 0,
	BNXT_ULP_SYM_ECV_L2_EN_YES = 1,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_NOP = 0,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_1_ENCAP_PRI = 1,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_1_IVLAN_PRI = 2,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_1_REMAP_DIFFSERV = 3,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_2_ENCAP_PRI = 4,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_2_REMAP_DIFFSERV = 5,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_ENCAP_PRI = 6,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_REMAP_DIFFSERV = 7,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_0 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_1 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_2 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_3 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_4 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_5 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_6 = 8,
	BNXT_ULP_SYM_ECV_VTAG_TYPE_ADD_0_PRI_7 = 8,
	BNXT_ULP_SYM_ECV_L3_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_L3_TYPE_IPV4 = 4,
	BNXT_ULP_SYM_ECV_L3_TYPE_IPV6 = 5,
	BNXT_ULP_SYM_ECV_L3_TYPE_MPLS_8847 = 6,
	BNXT_ULP_SYM_ECV_L3_TYPE_MPLS_8848 = 7,
	BNXT_ULP_SYM_ECV_L4_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP = 4,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_CSUM = 5,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_ENTROPY = 6,
	BNXT_ULP_SYM_ECV_L4_TYPE_UDP_ENTROPY_CSUM = 7,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NONE = 0,
	BNXT_ULP_SYM_ECV_TUN_TYPE_GENERIC = 1,
	BNXT_ULP_SYM_ECV_TUN_TYPE_VXLAN = 2,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NGE = 3,
	BNXT_ULP_SYM_ECV_TUN_TYPE_NVGRE = 4,
	BNXT_ULP_SYM_ECV_TUN_TYPE_GRE = 5,
	BNXT_ULP_SYM_WH_PLUS_INT_ACT_REC = 1,
	BNXT_ULP_SYM_WH_PLUS_EXT_ACT_REC = 0,
	BNXT_ULP_SYM_WH_PLUS_UC_ACT_REC = 0,
	BNXT_ULP_SYM_WH_PLUS_MC_ACT_REC = 1,
	BNXT_ULP_SYM_ACT_REC_DROP_YES = 1,
	BNXT_ULP_SYM_ACT_REC_DROP_NO = 0,
	BNXT_ULP_SYM_ACT_REC_POP_VLAN_YES = 1,
	BNXT_ULP_SYM_ACT_REC_POP_VLAN_NO = 0,
	BNXT_ULP_SYM_ACT_REC_METER_EN_YES = 1,
	BNXT_ULP_SYM_ACT_REC_METER_EN_NO = 0,
	BNXT_ULP_SYM_WH_PLUS_LOOPBACK_PORT = 4,
	BNXT_ULP_SYM_WH_PLUS_EXT_EM_MAX_KEY_SIZE = 448,
	BNXT_ULP_SYM_STINGRAY_LOOPBACK_PORT = 16,
	BNXT_ULP_SYM_STINGRAY_EXT_EM_MAX_KEY_SIZE = 448,
	BNXT_ULP_SYM_STINGRAY2_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_THOR_LOOPBACK_PORT = 3,
	BNXT_ULP_SYM_MATCH_TYPE_EM = 0,
	BNXT_ULP_SYM_MATCH_TYPE_WM = 1,
	BNXT_ULP_SYM_IP_PROTO_ICMP = 1,
	BNXT_ULP_SYM_IP_PROTO_IGMP = 2,
	BNXT_ULP_SYM_IP_PROTO_IP_IN_IP = 4,
	BNXT_ULP_SYM_IP_PROTO_TCP = 6,
	BNXT_ULP_SYM_IP_PROTO_UDP = 17,
	BNXT_ULP_SYM_NO = 0,
	BNXT_ULP_SYM_YES = 1
};

enum bnxt_ulp_wh_plus {
	BNXT_ULP_WH_PLUS_LOOPBACK_PORT = 4,
	BNXT_ULP_WH_PLUS_EXT_EM_MAX_KEY_SIZE = 448
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
	BNXT_ULP_CLASS_HID_0080 = 0x0080,
	BNXT_ULP_CLASS_HID_0087 = 0x0087,
	BNXT_ULP_CLASS_HID_0000 = 0x0000
};

enum bnxt_ulp_act_hid {
	BNXT_ULP_ACT_HID_0002 = 0x0002,
	BNXT_ULP_ACT_HID_0022 = 0x0022,
	BNXT_ULP_ACT_HID_0026 = 0x0026,
	BNXT_ULP_ACT_HID_0006 = 0x0006,
	BNXT_ULP_ACT_HID_0009 = 0x0009,
	BNXT_ULP_ACT_HID_0029 = 0x0029,
	BNXT_ULP_ACT_HID_002d = 0x002d,
	BNXT_ULP_ACT_HID_004b = 0x004b,
	BNXT_ULP_ACT_HID_004a = 0x004a,
	BNXT_ULP_ACT_HID_004f = 0x004f,
	BNXT_ULP_ACT_HID_004e = 0x004e,
	BNXT_ULP_ACT_HID_006c = 0x006c,
	BNXT_ULP_ACT_HID_0070 = 0x0070,
	BNXT_ULP_ACT_HID_0021 = 0x0021,
	BNXT_ULP_ACT_HID_0025 = 0x0025,
	BNXT_ULP_ACT_HID_0043 = 0x0043,
	BNXT_ULP_ACT_HID_0042 = 0x0042,
	BNXT_ULP_ACT_HID_0047 = 0x0047,
	BNXT_ULP_ACT_HID_0046 = 0x0046,
	BNXT_ULP_ACT_HID_0064 = 0x0064,
	BNXT_ULP_ACT_HID_0068 = 0x0068,
	BNXT_ULP_ACT_HID_00a1 = 0x00a1,
	BNXT_ULP_ACT_HID_00df = 0x00df
};

enum bnxt_ulp_df_tpl {
	BNXT_ULP_DF_TPL_PORT_TO_VS = 1,
	BNXT_ULP_DF_TPL_VS_TO_PORT = 2,
	BNXT_ULP_DF_TPL_VFREP_TO_VF = 3,
	BNXT_ULP_DF_TPL_VF_TO_VFREP = 4,
	BNXT_ULP_DF_TPL_DRV_FUNC_SVIF_PUSH_VLAN = 5,
	BNXT_ULP_DF_TPL_PORT_SVIF_VID_VNIC_POP_VLAN = 6,
	BNXT_ULP_DF_TPL_LOOPBACK_ACTION_REC = 7
};

#endif
