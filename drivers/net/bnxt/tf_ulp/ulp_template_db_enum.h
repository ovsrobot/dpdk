/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2020 Broadcom
 * All rights reserved.
 */

#ifndef ULP_TEMPLATE_DB_H_
#define ULP_TEMPLATE_DB_H_

#define BNXT_ULP_REGFILE_MAX_SZ 19
#define BNXT_ULP_MAX_NUM_DEVICES 4
#define BNXT_ULP_LOG2_MAX_NUM_DEV 2
#define BNXT_ULP_CACHE_TBL_MAX_SZ 4
#define BNXT_ULP_CLASS_SIG_TBL_MAX_SZ 2048
#define BNXT_ULP_CLASS_MATCH_LIST_MAX_SZ 201
#define BNXT_ULP_CLASS_HID_LOW_PRIME 7919
#define BNXT_ULP_CLASS_HID_HIGH_PRIME 7907
#define BNXT_ULP_CLASS_HID_SHFTR 32
#define BNXT_ULP_CLASS_HID_SHFTL 31
#define BNXT_ULP_CLASS_HID_MASK 2047
#define BNXT_ULP_ACT_SIG_TBL_MAX_SZ 4096
#define BNXT_ULP_ACT_MATCH_LIST_MAX_SZ 83
#define BNXT_ULP_ACT_HID_LOW_PRIME 7919
#define BNXT_ULP_ACT_HID_HIGH_PRIME 4721
#define BNXT_ULP_ACT_HID_SHFTR 23
#define BNXT_ULP_ACT_HID_SHFTL 23
#define BNXT_ULP_ACT_HID_MASK 4095
#define BNXT_ULP_CACHE_TBL_IDENT_MAX_NUM 2
#define BNXT_ULP_GLB_RESOURCE_TBL_MAX_SZ 8
#define BNXT_ULP_GLB_TEMPLATE_TBL_MAX_SZ 1

enum bnxt_ulp_action_bit {
	BNXT_ULP_ACTION_BIT_MARK             = 0x0000000000000001,
	BNXT_ULP_ACTION_BIT_DROP             = 0x0000000000000002,
	BNXT_ULP_ACTION_BIT_COUNT            = 0x0000000000000004,
	BNXT_ULP_ACTION_BIT_RSS              = 0x0000000000000008,
	BNXT_ULP_ACTION_BIT_METER            = 0x0000000000000010,
	BNXT_ULP_ACTION_BIT_VXLAN_DECAP      = 0x0000000000000020,
	BNXT_ULP_ACTION_BIT_POP_MPLS         = 0x0000000000000040,
	BNXT_ULP_ACTION_BIT_PUSH_MPLS        = 0x0000000000000080,
	BNXT_ULP_ACTION_BIT_MAC_SWAP         = 0x0000000000000100,
	BNXT_ULP_ACTION_BIT_SET_MAC_SRC      = 0x0000000000000200,
	BNXT_ULP_ACTION_BIT_SET_MAC_DST      = 0x0000000000000400,
	BNXT_ULP_ACTION_BIT_POP_VLAN         = 0x0000000000000800,
	BNXT_ULP_ACTION_BIT_PUSH_VLAN        = 0x0000000000001000,
	BNXT_ULP_ACTION_BIT_SET_VLAN_PCP     = 0x0000000000002000,
	BNXT_ULP_ACTION_BIT_SET_VLAN_VID     = 0x0000000000004000,
	BNXT_ULP_ACTION_BIT_SET_IPV4_SRC     = 0x0000000000008000,
	BNXT_ULP_ACTION_BIT_SET_IPV4_DST     = 0x0000000000010000,
	BNXT_ULP_ACTION_BIT_SET_IPV6_SRC     = 0x0000000000020000,
	BNXT_ULP_ACTION_BIT_SET_IPV6_DST     = 0x0000000000040000,
	BNXT_ULP_ACTION_BIT_DEC_TTL          = 0x0000000000080000,
	BNXT_ULP_ACTION_BIT_SET_TP_SRC       = 0x0000000000100000,
	BNXT_ULP_ACTION_BIT_SET_TP_DST       = 0x0000000000200000,
	BNXT_ULP_ACTION_BIT_VXLAN_ENCAP      = 0x0000000000400000,
	BNXT_ULP_ACTION_BIT_LAST             = 0x0000000000800000
};

enum bnxt_ulp_hdr_bit {
	BNXT_ULP_HDR_BIT_O_ETH               = 0x0000000000000001,
	BNXT_ULP_HDR_BIT_OO_VLAN             = 0x0000000000000002,
	BNXT_ULP_HDR_BIT_OI_VLAN             = 0x0000000000000004,
	BNXT_ULP_HDR_BIT_O_IPV4              = 0x0000000000000008,
	BNXT_ULP_HDR_BIT_O_IPV6              = 0x0000000000000010,
	BNXT_ULP_HDR_BIT_O_TCP               = 0x0000000000000020,
	BNXT_ULP_HDR_BIT_O_UDP               = 0x0000000000000040,
	BNXT_ULP_HDR_BIT_T_VXLAN             = 0x0000000000000080,
	BNXT_ULP_HDR_BIT_T_GRE               = 0x0000000000000100,
	BNXT_ULP_HDR_BIT_I_ETH               = 0x0000000000000200,
	BNXT_ULP_HDR_BIT_IO_VLAN             = 0x0000000000000400,
	BNXT_ULP_HDR_BIT_II_VLAN             = 0x0000000000000800,
	BNXT_ULP_HDR_BIT_I_IPV4              = 0x0000000000001000,
	BNXT_ULP_HDR_BIT_I_IPV6              = 0x0000000000002000,
	BNXT_ULP_HDR_BIT_I_TCP               = 0x0000000000004000,
	BNXT_ULP_HDR_BIT_I_UDP               = 0x0000000000008000,
	BNXT_ULP_HDR_BIT_LAST                = 0x0000000000010000
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
	BNXT_ULP_CF_IDX_O_NO_VTAG = 3,
	BNXT_ULP_CF_IDX_O_ONE_VTAG = 4,
	BNXT_ULP_CF_IDX_O_TWO_VTAGS = 5,
	BNXT_ULP_CF_IDX_I_VTAG_NUM = 6,
	BNXT_ULP_CF_IDX_I_NO_VTAG = 7,
	BNXT_ULP_CF_IDX_I_ONE_VTAG = 8,
	BNXT_ULP_CF_IDX_I_TWO_VTAGS = 9,
	BNXT_ULP_CF_IDX_INCOMING_IF = 10,
	BNXT_ULP_CF_IDX_DIRECTION = 11,
	BNXT_ULP_CF_IDX_SVIF_FLAG = 12,
	BNXT_ULP_CF_IDX_O_L3 = 13,
	BNXT_ULP_CF_IDX_I_L3 = 14,
	BNXT_ULP_CF_IDX_O_L4 = 15,
	BNXT_ULP_CF_IDX_I_L4 = 16,
	BNXT_ULP_CF_IDX_DEV_PORT_ID = 17,
	BNXT_ULP_CF_IDX_DRV_FUNC_SVIF = 18,
	BNXT_ULP_CF_IDX_DRV_FUNC_SPIF = 19,
	BNXT_ULP_CF_IDX_DRV_FUNC_PARIF = 20,
	BNXT_ULP_CF_IDX_DRV_FUNC_VNIC = 21,
	BNXT_ULP_CF_IDX_DRV_FUNC_PHY_PORT = 22,
	BNXT_ULP_CF_IDX_VF_FUNC_SVIF = 23,
	BNXT_ULP_CF_IDX_VF_FUNC_SPIF = 24,
	BNXT_ULP_CF_IDX_VF_FUNC_PARIF = 25,
	BNXT_ULP_CF_IDX_VF_FUNC_VNIC = 26,
	BNXT_ULP_CF_IDX_PHY_PORT_SVIF = 27,
	BNXT_ULP_CF_IDX_PHY_PORT_SPIF = 28,
	BNXT_ULP_CF_IDX_PHY_PORT_PARIF = 29,
	BNXT_ULP_CF_IDX_PHY_PORT_VPORT = 30,
	BNXT_ULP_CF_IDX_ACT_ENCAP_IPV4_FLAG = 31,
	BNXT_ULP_CF_IDX_ACT_ENCAP_IPV6_FLAG = 32,
	BNXT_ULP_CF_IDX_ACT_DEC_TTL = 33,
	BNXT_ULP_CF_IDX_ACT_T_DEC_TTL = 34,
	BNXT_ULP_CF_IDX_ACT_PORT_IS_SET = 35,
	BNXT_ULP_CF_IDX_ACT_PORT_TYPE = 36,
	BNXT_ULP_CF_IDX_MATCH_PORT_TYPE = 37,
	BNXT_ULP_CF_IDX_MATCH_PORT_IS_VFREP = 38,
	BNXT_ULP_CF_IDX_VF_TO_VF = 39,
	BNXT_ULP_CF_IDX_L3_HDR_CNT = 40,
	BNXT_ULP_CF_IDX_L4_HDR_CNT = 41,
	BNXT_ULP_CF_IDX_VFR_MODE = 42,
	BNXT_ULP_CF_IDX_LOOPBACK_PARIF = 43,
	BNXT_ULP_CF_IDX_LAST = 44
};

enum bnxt_ulp_cond_opcode {
	BNXT_ULP_COND_OPCODE_NOP = 0,
	BNXT_ULP_COND_OPCODE_COMP_FIELD_IS_SET = 1,
	BNXT_ULP_COND_OPCODE_ACTION_BIT_IS_SET = 2,
	BNXT_ULP_COND_OPCODE_HDR_BIT_IS_SET = 3,
	BNXT_ULP_COND_OPCODE_COMP_FIELD_NOT_SET = 4,
	BNXT_ULP_COND_OPCODE_ACTION_BIT_NOT_SET = 5,
	BNXT_ULP_COND_OPCODE_HDR_BIT_NOT_SET = 6,
	BNXT_ULP_COND_OPCODE_LAST = 7
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
	BNXT_ULP_GLB_REGFILE_INDEX_GLB_LB_AREC_PTR = 2,
	BNXT_ULP_GLB_REGFILE_INDEX_L2_PROF_FUNC_ID = 3,
	BNXT_ULP_GLB_REGFILE_INDEX_VXLAN_PROF_FUNC_ID = 4,
	BNXT_ULP_GLB_REGFILE_INDEX_ENCAP_MAC_PTR = 5,
	BNXT_ULP_GLB_REGFILE_INDEX_LAST = 6
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
	BNXT_ULP_INDEX_OPCODE_CONSTANT = 4,
	BNXT_ULP_INDEX_OPCODE_LAST = 5
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
	BNXT_ULP_MAPPER_OPC_IF_ACT_BIT_THEN_ACT_PROP_ELSE_CONST = 9,
	BNXT_ULP_MAPPER_OPC_IF_ACT_BIT_THEN_CONST_ELSE_CONST = 10,
	BNXT_ULP_MAPPER_OPC_IF_COMP_FIELD_THEN_CF_ELSE_CF = 11,
	BNXT_ULP_MAPPER_OPC_IF_HDR_BIT_THEN_CONST_ELSE_CONST = 12,
	BNXT_ULP_MAPPER_OPC_LAST = 13
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

enum bnxt_ulp_mem_type_opcode {
	BNXT_ULP_MEM_TYPE_OPCODE_NOP = 0,
	BNXT_ULP_MEM_TYPE_OPCODE_EXECUTE_IF_INT = 1,
	BNXT_ULP_MEM_TYPE_OPCODE_EXECUTE_IF_EXT = 2,
	BNXT_ULP_MEM_TYPE_OPCODE_LAST = 3
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
	BNXT_ULP_REGFILE_INDEX_MODIFY_IPV4_SRC_PTR_0 = 17,
	BNXT_ULP_REGFILE_INDEX_MODIFY_IPV4_DST_PTR_0 = 18,
	BNXT_ULP_REGFILE_INDEX_LAST = 19
};

enum bnxt_ulp_search_before_alloc {
	BNXT_ULP_SEARCH_BEFORE_ALLOC_NO = 0,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_SEARCH_IF_HIT_SKIP = 1,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_SEARCH_IF_HIT_UPDATE = 2,
	BNXT_ULP_SEARCH_BEFORE_ALLOC_LAST = 3
};

enum bnxt_ulp_template_type {
	BNXT_ULP_TEMPLATE_TYPE_CLASS = 0,
	BNXT_ULP_TEMPLATE_TYPE_ACTION = 1,
	BNXT_ULP_TEMPLATE_TYPE_LAST = 2
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
	BNXT_ULP_SYM_VF_FUNC_PARIF = 15,
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
	BNXT_ULP_ACT_PROP_SZ_PUSH_VLAN = 2,
	BNXT_ULP_ACT_PROP_SZ_SET_VLAN_PCP = 1,
	BNXT_ULP_ACT_PROP_SZ_SET_VLAN_VID = 2,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV4_SRC = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV4_DST = 4,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV6_SRC = 16,
	BNXT_ULP_ACT_PROP_SZ_SET_IPV6_DST = 16,
	BNXT_ULP_ACT_PROP_SZ_SET_TP_SRC = 2,
	BNXT_ULP_ACT_PROP_SZ_SET_TP_DST = 2,
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
	BNXT_ULP_ACT_PROP_IDX_PUSH_VLAN = 72,
	BNXT_ULP_ACT_PROP_IDX_SET_VLAN_PCP = 74,
	BNXT_ULP_ACT_PROP_IDX_SET_VLAN_VID = 75,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV4_SRC = 77,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV4_DST = 81,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV6_SRC = 85,
	BNXT_ULP_ACT_PROP_IDX_SET_IPV6_DST = 101,
	BNXT_ULP_ACT_PROP_IDX_SET_TP_SRC = 117,
	BNXT_ULP_ACT_PROP_IDX_SET_TP_DST = 119,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_0 = 121,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_1 = 125,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_2 = 129,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_3 = 133,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_4 = 137,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_5 = 141,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_6 = 145,
	BNXT_ULP_ACT_PROP_IDX_OF_PUSH_MPLS_7 = 149,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_L2_DMAC = 153,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_L2_SMAC = 159,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_VTAG = 165,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_IP = 173,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_IP_SRC = 205,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_UDP = 221,
	BNXT_ULP_ACT_PROP_IDX_ENCAP_TUN = 225,
	BNXT_ULP_ACT_PROP_IDX_LAST = 257
};

enum bnxt_ulp_class_hid {
	BNXT_ULP_CLASS_HID_0138 = 0x0138,
	BNXT_ULP_CLASS_HID_03f0 = 0x03f0,
	BNXT_ULP_CLASS_HID_0139 = 0x0139,
	BNXT_ULP_CLASS_HID_03f1 = 0x03f1,
	BNXT_ULP_CLASS_HID_068b = 0x068b,
	BNXT_ULP_CLASS_HID_0143 = 0x0143,
	BNXT_ULP_CLASS_HID_0118 = 0x0118,
	BNXT_ULP_CLASS_HID_03d0 = 0x03d0,
	BNXT_ULP_CLASS_HID_0119 = 0x0119,
	BNXT_ULP_CLASS_HID_03d1 = 0x03d1,
	BNXT_ULP_CLASS_HID_06ab = 0x06ab,
	BNXT_ULP_CLASS_HID_0163 = 0x0163,
	BNXT_ULP_CLASS_HID_0128 = 0x0128,
	BNXT_ULP_CLASS_HID_03e0 = 0x03e0,
	BNXT_ULP_CLASS_HID_0129 = 0x0129,
	BNXT_ULP_CLASS_HID_03e1 = 0x03e1,
	BNXT_ULP_CLASS_HID_069b = 0x069b,
	BNXT_ULP_CLASS_HID_0153 = 0x0153,
	BNXT_ULP_CLASS_HID_0134 = 0x0134,
	BNXT_ULP_CLASS_HID_03fc = 0x03fc,
	BNXT_ULP_CLASS_HID_0135 = 0x0135,
	BNXT_ULP_CLASS_HID_03fd = 0x03fd,
	BNXT_ULP_CLASS_HID_0687 = 0x0687,
	BNXT_ULP_CLASS_HID_014f = 0x014f,
	BNXT_ULP_CLASS_HID_0114 = 0x0114,
	BNXT_ULP_CLASS_HID_03dc = 0x03dc,
	BNXT_ULP_CLASS_HID_0115 = 0x0115,
	BNXT_ULP_CLASS_HID_03dd = 0x03dd,
	BNXT_ULP_CLASS_HID_06a7 = 0x06a7,
	BNXT_ULP_CLASS_HID_016f = 0x016f,
	BNXT_ULP_CLASS_HID_0124 = 0x0124,
	BNXT_ULP_CLASS_HID_03ec = 0x03ec,
	BNXT_ULP_CLASS_HID_0125 = 0x0125,
	BNXT_ULP_CLASS_HID_03ed = 0x03ed,
	BNXT_ULP_CLASS_HID_0697 = 0x0697,
	BNXT_ULP_CLASS_HID_015f = 0x015f,
	BNXT_ULP_CLASS_HID_0452 = 0x0452,
	BNXT_ULP_CLASS_HID_0528 = 0x0528,
	BNXT_ULP_CLASS_HID_0790 = 0x0790,
	BNXT_ULP_CLASS_HID_046e = 0x046e,
	BNXT_ULP_CLASS_HID_0462 = 0x0462,
	BNXT_ULP_CLASS_HID_0518 = 0x0518,
	BNXT_ULP_CLASS_HID_07a0 = 0x07a0,
	BNXT_ULP_CLASS_HID_045e = 0x045e,
	BNXT_ULP_CLASS_HID_0228 = 0x0228,
	BNXT_ULP_CLASS_HID_06d0 = 0x06d0,
	BNXT_ULP_CLASS_HID_02be = 0x02be,
	BNXT_ULP_CLASS_HID_07a6 = 0x07a6,
	BNXT_ULP_CLASS_HID_0218 = 0x0218,
	BNXT_ULP_CLASS_HID_06e0 = 0x06e0,
	BNXT_ULP_CLASS_HID_028e = 0x028e,
	BNXT_ULP_CLASS_HID_0796 = 0x0796,
	BNXT_ULP_CLASS_HID_079c = 0x079c,
	BNXT_ULP_CLASS_HID_0654 = 0x0654,
	BNXT_ULP_CLASS_HID_06d2 = 0x06d2,
	BNXT_ULP_CLASS_HID_058a = 0x058a,
	BNXT_ULP_CLASS_HID_052f = 0x052f,
	BNXT_ULP_CLASS_HID_07e7 = 0x07e7,
	BNXT_ULP_CLASS_HID_079d = 0x079d,
	BNXT_ULP_CLASS_HID_0655 = 0x0655,
	BNXT_ULP_CLASS_HID_046d = 0x046d,
	BNXT_ULP_CLASS_HID_0725 = 0x0725,
	BNXT_ULP_CLASS_HID_06d3 = 0x06d3,
	BNXT_ULP_CLASS_HID_058b = 0x058b,
	BNXT_ULP_CLASS_HID_07ac = 0x07ac,
	BNXT_ULP_CLASS_HID_0664 = 0x0664,
	BNXT_ULP_CLASS_HID_06e2 = 0x06e2,
	BNXT_ULP_CLASS_HID_05ba = 0x05ba,
	BNXT_ULP_CLASS_HID_051f = 0x051f,
	BNXT_ULP_CLASS_HID_07d7 = 0x07d7,
	BNXT_ULP_CLASS_HID_07ad = 0x07ad,
	BNXT_ULP_CLASS_HID_0665 = 0x0665,
	BNXT_ULP_CLASS_HID_045d = 0x045d,
	BNXT_ULP_CLASS_HID_0715 = 0x0715,
	BNXT_ULP_CLASS_HID_06e3 = 0x06e3,
	BNXT_ULP_CLASS_HID_05bb = 0x05bb,
	BNXT_ULP_CLASS_HID_016a = 0x016a,
	BNXT_ULP_CLASS_HID_03d2 = 0x03d2,
	BNXT_ULP_CLASS_HID_0612 = 0x0612,
	BNXT_ULP_CLASS_HID_00da = 0x00da,
	BNXT_ULP_CLASS_HID_06bd = 0x06bd,
	BNXT_ULP_CLASS_HID_0165 = 0x0165,
	BNXT_ULP_CLASS_HID_016b = 0x016b,
	BNXT_ULP_CLASS_HID_03d3 = 0x03d3,
	BNXT_ULP_CLASS_HID_03a5 = 0x03a5,
	BNXT_ULP_CLASS_HID_066d = 0x066d,
	BNXT_ULP_CLASS_HID_0613 = 0x0613,
	BNXT_ULP_CLASS_HID_00db = 0x00db,
	BNXT_ULP_CLASS_HID_015a = 0x015a,
	BNXT_ULP_CLASS_HID_03e2 = 0x03e2,
	BNXT_ULP_CLASS_HID_0622 = 0x0622,
	BNXT_ULP_CLASS_HID_00ea = 0x00ea,
	BNXT_ULP_CLASS_HID_068d = 0x068d,
	BNXT_ULP_CLASS_HID_0155 = 0x0155,
	BNXT_ULP_CLASS_HID_015b = 0x015b,
	BNXT_ULP_CLASS_HID_03e3 = 0x03e3,
	BNXT_ULP_CLASS_HID_0395 = 0x0395,
	BNXT_ULP_CLASS_HID_065d = 0x065d,
	BNXT_ULP_CLASS_HID_0623 = 0x0623,
	BNXT_ULP_CLASS_HID_00eb = 0x00eb,
	BNXT_ULP_CLASS_HID_04bc = 0x04bc,
	BNXT_ULP_CLASS_HID_0442 = 0x0442,
	BNXT_ULP_CLASS_HID_050a = 0x050a,
	BNXT_ULP_CLASS_HID_06ba = 0x06ba,
	BNXT_ULP_CLASS_HID_0472 = 0x0472,
	BNXT_ULP_CLASS_HID_0700 = 0x0700,
	BNXT_ULP_CLASS_HID_04c8 = 0x04c8,
	BNXT_ULP_CLASS_HID_0678 = 0x0678,
	BNXT_ULP_CLASS_HID_061f = 0x061f,
	BNXT_ULP_CLASS_HID_05ad = 0x05ad,
	BNXT_ULP_CLASS_HID_06a5 = 0x06a5,
	BNXT_ULP_CLASS_HID_0455 = 0x0455,
	BNXT_ULP_CLASS_HID_05dd = 0x05dd,
	BNXT_ULP_CLASS_HID_0563 = 0x0563,
	BNXT_ULP_CLASS_HID_059b = 0x059b,
	BNXT_ULP_CLASS_HID_070b = 0x070b,
	BNXT_ULP_CLASS_HID_04bd = 0x04bd,
	BNXT_ULP_CLASS_HID_0443 = 0x0443,
	BNXT_ULP_CLASS_HID_050b = 0x050b,
	BNXT_ULP_CLASS_HID_06bb = 0x06bb,
	BNXT_ULP_CLASS_HID_0473 = 0x0473,
	BNXT_ULP_CLASS_HID_0701 = 0x0701,
	BNXT_ULP_CLASS_HID_04c9 = 0x04c9,
	BNXT_ULP_CLASS_HID_0679 = 0x0679,
	BNXT_ULP_CLASS_HID_05e2 = 0x05e2,
	BNXT_ULP_CLASS_HID_00b0 = 0x00b0,
	BNXT_ULP_CLASS_HID_0648 = 0x0648,
	BNXT_ULP_CLASS_HID_03f8 = 0x03f8,
	BNXT_ULP_CLASS_HID_02ea = 0x02ea,
	BNXT_ULP_CLASS_HID_05b8 = 0x05b8,
	BNXT_ULP_CLASS_HID_0370 = 0x0370,
	BNXT_ULP_CLASS_HID_00e0 = 0x00e0,
	BNXT_ULP_CLASS_HID_0745 = 0x0745,
	BNXT_ULP_CLASS_HID_0213 = 0x0213,
	BNXT_ULP_CLASS_HID_031b = 0x031b,
	BNXT_ULP_CLASS_HID_008b = 0x008b,
	BNXT_ULP_CLASS_HID_044d = 0x044d,
	BNXT_ULP_CLASS_HID_071b = 0x071b,
	BNXT_ULP_CLASS_HID_0003 = 0x0003,
	BNXT_ULP_CLASS_HID_05b3 = 0x05b3,
	BNXT_ULP_CLASS_HID_05e3 = 0x05e3,
	BNXT_ULP_CLASS_HID_00b1 = 0x00b1,
	BNXT_ULP_CLASS_HID_0649 = 0x0649,
	BNXT_ULP_CLASS_HID_03f9 = 0x03f9,
	BNXT_ULP_CLASS_HID_02eb = 0x02eb,
	BNXT_ULP_CLASS_HID_05b9 = 0x05b9,
	BNXT_ULP_CLASS_HID_0371 = 0x0371,
	BNXT_ULP_CLASS_HID_00e1 = 0x00e1,
	BNXT_ULP_CLASS_HID_048b = 0x048b,
	BNXT_ULP_CLASS_HID_0749 = 0x0749,
	BNXT_ULP_CLASS_HID_05f1 = 0x05f1,
	BNXT_ULP_CLASS_HID_04b7 = 0x04b7,
	BNXT_ULP_CLASS_HID_049b = 0x049b,
	BNXT_ULP_CLASS_HID_0759 = 0x0759,
	BNXT_ULP_CLASS_HID_05e1 = 0x05e1,
	BNXT_ULP_CLASS_HID_04a7 = 0x04a7,
	BNXT_ULP_CLASS_HID_0301 = 0x0301,
	BNXT_ULP_CLASS_HID_07f9 = 0x07f9,
	BNXT_ULP_CLASS_HID_0397 = 0x0397,
	BNXT_ULP_CLASS_HID_068f = 0x068f,
	BNXT_ULP_CLASS_HID_02f1 = 0x02f1,
	BNXT_ULP_CLASS_HID_0609 = 0x0609,
	BNXT_ULP_CLASS_HID_0267 = 0x0267,
	BNXT_ULP_CLASS_HID_077f = 0x077f,
	BNXT_ULP_CLASS_HID_01e1 = 0x01e1,
	BNXT_ULP_CLASS_HID_0329 = 0x0329,
	BNXT_ULP_CLASS_HID_01c1 = 0x01c1,
	BNXT_ULP_CLASS_HID_0309 = 0x0309,
	BNXT_ULP_CLASS_HID_01d1 = 0x01d1,
	BNXT_ULP_CLASS_HID_0319 = 0x0319,
	BNXT_ULP_CLASS_HID_01e2 = 0x01e2,
	BNXT_ULP_CLASS_HID_032a = 0x032a,
	BNXT_ULP_CLASS_HID_0650 = 0x0650,
	BNXT_ULP_CLASS_HID_0198 = 0x0198,
	BNXT_ULP_CLASS_HID_01c2 = 0x01c2,
	BNXT_ULP_CLASS_HID_030a = 0x030a,
	BNXT_ULP_CLASS_HID_0670 = 0x0670,
	BNXT_ULP_CLASS_HID_01b8 = 0x01b8,
	BNXT_ULP_CLASS_HID_01d2 = 0x01d2,
	BNXT_ULP_CLASS_HID_031a = 0x031a,
	BNXT_ULP_CLASS_HID_0660 = 0x0660,
	BNXT_ULP_CLASS_HID_01a8 = 0x01a8,
	BNXT_ULP_CLASS_HID_01dd = 0x01dd,
	BNXT_ULP_CLASS_HID_0315 = 0x0315,
	BNXT_ULP_CLASS_HID_003d = 0x003d,
	BNXT_ULP_CLASS_HID_02f5 = 0x02f5,
	BNXT_ULP_CLASS_HID_01cd = 0x01cd,
	BNXT_ULP_CLASS_HID_0305 = 0x0305,
	BNXT_ULP_CLASS_HID_01de = 0x01de,
	BNXT_ULP_CLASS_HID_0316 = 0x0316,
	BNXT_ULP_CLASS_HID_066c = 0x066c,
	BNXT_ULP_CLASS_HID_01a4 = 0x01a4,
	BNXT_ULP_CLASS_HID_003e = 0x003e,
	BNXT_ULP_CLASS_HID_02f6 = 0x02f6,
	BNXT_ULP_CLASS_HID_078c = 0x078c,
	BNXT_ULP_CLASS_HID_0044 = 0x0044,
	BNXT_ULP_CLASS_HID_01ce = 0x01ce,
	BNXT_ULP_CLASS_HID_0306 = 0x0306,
	BNXT_ULP_CLASS_HID_067c = 0x067c,
	BNXT_ULP_CLASS_HID_01b4 = 0x01b4
};

enum bnxt_ulp_act_hid {
	BNXT_ULP_ACT_HID_015a = 0x015a,
	BNXT_ULP_ACT_HID_00eb = 0x00eb,
	BNXT_ULP_ACT_HID_0043 = 0x0043,
	BNXT_ULP_ACT_HID_03d8 = 0x03d8,
	BNXT_ULP_ACT_HID_02c1 = 0x02c1,
	BNXT_ULP_ACT_HID_015e = 0x015e,
	BNXT_ULP_ACT_HID_00ef = 0x00ef,
	BNXT_ULP_ACT_HID_0047 = 0x0047,
	BNXT_ULP_ACT_HID_03dc = 0x03dc,
	BNXT_ULP_ACT_HID_02c5 = 0x02c5,
	BNXT_ULP_ACT_HID_025b = 0x025b,
	BNXT_ULP_ACT_HID_01ec = 0x01ec,
	BNXT_ULP_ACT_HID_0144 = 0x0144,
	BNXT_ULP_ACT_HID_04d9 = 0x04d9,
	BNXT_ULP_ACT_HID_03c2 = 0x03c2,
	BNXT_ULP_ACT_HID_025f = 0x025f,
	BNXT_ULP_ACT_HID_01f0 = 0x01f0,
	BNXT_ULP_ACT_HID_0148 = 0x0148,
	BNXT_ULP_ACT_HID_04dd = 0x04dd,
	BNXT_ULP_ACT_HID_03c6 = 0x03c6,
	BNXT_ULP_ACT_HID_0000 = 0x0000,
	BNXT_ULP_ACT_HID_0002 = 0x0002,
	BNXT_ULP_ACT_HID_0800 = 0x0800,
	BNXT_ULP_ACT_HID_0101 = 0x0101,
	BNXT_ULP_ACT_HID_0020 = 0x0020,
	BNXT_ULP_ACT_HID_0901 = 0x0901,
	BNXT_ULP_ACT_HID_0121 = 0x0121,
	BNXT_ULP_ACT_HID_0004 = 0x0004,
	BNXT_ULP_ACT_HID_0006 = 0x0006,
	BNXT_ULP_ACT_HID_0804 = 0x0804,
	BNXT_ULP_ACT_HID_0105 = 0x0105,
	BNXT_ULP_ACT_HID_0024 = 0x0024,
	BNXT_ULP_ACT_HID_0905 = 0x0905,
	BNXT_ULP_ACT_HID_0125 = 0x0125,
	BNXT_ULP_ACT_HID_0001 = 0x0001,
	BNXT_ULP_ACT_HID_0005 = 0x0005,
	BNXT_ULP_ACT_HID_0009 = 0x0009,
	BNXT_ULP_ACT_HID_000d = 0x000d,
	BNXT_ULP_ACT_HID_0021 = 0x0021,
	BNXT_ULP_ACT_HID_0029 = 0x0029,
	BNXT_ULP_ACT_HID_0025 = 0x0025,
	BNXT_ULP_ACT_HID_002d = 0x002d,
	BNXT_ULP_ACT_HID_0801 = 0x0801,
	BNXT_ULP_ACT_HID_0809 = 0x0809,
	BNXT_ULP_ACT_HID_0805 = 0x0805,
	BNXT_ULP_ACT_HID_080d = 0x080d,
	BNXT_ULP_ACT_HID_0c15 = 0x0c15,
	BNXT_ULP_ACT_HID_0c19 = 0x0c19,
	BNXT_ULP_ACT_HID_02f6 = 0x02f6,
	BNXT_ULP_ACT_HID_04f8 = 0x04f8,
	BNXT_ULP_ACT_HID_01df = 0x01df,
	BNXT_ULP_ACT_HID_07e5 = 0x07e5,
	BNXT_ULP_ACT_HID_06ce = 0x06ce,
	BNXT_ULP_ACT_HID_02fa = 0x02fa,
	BNXT_ULP_ACT_HID_04fc = 0x04fc,
	BNXT_ULP_ACT_HID_01e3 = 0x01e3,
	BNXT_ULP_ACT_HID_07e9 = 0x07e9,
	BNXT_ULP_ACT_HID_06d2 = 0x06d2,
	BNXT_ULP_ACT_HID_03f7 = 0x03f7,
	BNXT_ULP_ACT_HID_05f9 = 0x05f9,
	BNXT_ULP_ACT_HID_02e0 = 0x02e0,
	BNXT_ULP_ACT_HID_08e6 = 0x08e6,
	BNXT_ULP_ACT_HID_07cf = 0x07cf,
	BNXT_ULP_ACT_HID_03fb = 0x03fb,
	BNXT_ULP_ACT_HID_05fd = 0x05fd,
	BNXT_ULP_ACT_HID_02e4 = 0x02e4,
	BNXT_ULP_ACT_HID_08ea = 0x08ea,
	BNXT_ULP_ACT_HID_07d3 = 0x07d3,
	BNXT_ULP_ACT_HID_040d = 0x040d,
	BNXT_ULP_ACT_HID_040f = 0x040f,
	BNXT_ULP_ACT_HID_0413 = 0x0413,
	BNXT_ULP_ACT_HID_0567 = 0x0567,
	BNXT_ULP_ACT_HID_0a49 = 0x0a49,
	BNXT_ULP_ACT_HID_050e = 0x050e,
	BNXT_ULP_ACT_HID_0668 = 0x0668,
	BNXT_ULP_ACT_HID_0b4a = 0x0b4a,
	BNXT_ULP_ACT_HID_0411 = 0x0411,
	BNXT_ULP_ACT_HID_056b = 0x056b,
	BNXT_ULP_ACT_HID_0a4d = 0x0a4d,
	BNXT_ULP_ACT_HID_0512 = 0x0512,
	BNXT_ULP_ACT_HID_066c = 0x066c,
	BNXT_ULP_ACT_HID_0b4e = 0x0b4e
};

enum bnxt_ulp_df_tpl {
	BNXT_ULP_DF_TPL_PORT_TO_VS = 1,
	BNXT_ULP_DF_TPL_VS_TO_PORT = 2,
	BNXT_ULP_DF_TPL_VFREP_TO_VF = 3,
	BNXT_ULP_DF_TPL_VF_TO_VFREP = 4,
	BNXT_ULP_DF_TPL_LOOPBACK_ACTION_REC = 5
};

#endif
