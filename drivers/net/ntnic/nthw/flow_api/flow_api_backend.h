/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __FLOW_API_BACKEND_H__
#define __FLOW_API_BACKEND_H__

/*
 * Flow API
 * Direct access to NIC HW module memory and register fields in a
 * module version independent representation
 */

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "ntlog.h"

/* supported module versions */
#include "../flow_api/hw_mod/hw_mod_km_v7.h"
#include "flow_api/hw_mod/hw_mod_cat_v18.h"
#include "flow_api/hw_mod/hw_mod_cat_v21.h"
#include "flow_api/hw_mod/hw_mod_cat_v22.h"
#include "flow_api/hw_mod/hw_mod_flm_v17.h"
#include "flow_api/hw_mod/hw_mod_flm_v20.h"
#include "flow_api/hw_mod/hw_mod_hst_v2.h"
#include "flow_api/hw_mod/hw_mod_km_v7.h"
#include "flow_api/hw_mod/hw_mod_qsl_v7.h"
#include "flow_api/hw_mod/hw_mod_pdb_v9.h"
#include "flow_api/hw_mod/hw_mod_slc_v1.h"
#include "flow_api/hw_mod/hw_mod_slc_lr_v2.h"
#include "flow_api/hw_mod/hw_mod_roa_v6.h"
#include "flow_api/hw_mod/hw_mod_hsh_v5.h"
#include "flow_api/hw_mod/hw_mod_ioa_v4.h"
#include "flow_api/hw_mod/hw_mod_rmc_v1_3.h"
#include "flow_api/hw_mod/hw_mod_tpe_v1.h"
#include "flow_api/hw_mod/hw_mod_tpe_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_PHYS_ADAPTERS 8

#define VER_MAJOR(ver) (((ver) >> 16) & 0xffff)
#define VER_MINOR(ver) ((ver) & 0xffff)

struct flow_api_backend_s;
struct common_func_s;

#define CAST_COMMON(mod) ((struct common_func_s *)(mod))

void *callocate_mod(struct common_func_s *mod, int sets, ...);
void zero_module_cache(struct common_func_s *mod);

#define ZERO_MOD_CACHE(mod) (zero_module_cache(CAST_COMMON(mod)))

#define ALL_ENTRIES -1000
#define ALL_BANK_ENTRIES -1001

static inline int error_index_too_large(const char *func)
{
	NT_LOG(INF, FILTER, "ERROR:%s: Index too large\n", func);
	return -2;
}

static inline int error_word_off_too_large(const char *func)
{
	NT_LOG(INF, FILTER, "ERROR:%s: Word offset too large\n", func);
	return -3;
}

static inline int error_unsup_ver(const char *func, const char *mod, int ver)
{
	NT_LOG(INF, FILTER, "ERROR:%s: Unsupported NIC module: %s ver %i.%i\n",
	       func, mod, VER_MAJOR(ver), VER_MINOR(ver));
	return -4;
}

static inline int error_unsup_field(const char *func)
{
	NT_LOG(INF, FILTER, "ERROR:%s: Unsupported field in NIC module\n",
		func);
	return -5;
}

static inline int error_resource_count(const char *func, const char *resource,
	const char *mod, int ver)
{
	NT_LOG(INF, FILTER,
	       "ERROR:%s: Insufficient resource [ %s ] : NIC module:"
	       "%s ver %i.%i\n",
	       func, resource, mod, VER_MAJOR(ver), VER_MINOR(ver));
	return -4;
}

#define NOT_FOUND 0xffffffff

enum { EXTRA_INDEXES };
#define COPY_INDEX (EXTRA_INDEX_COPY - EXTRA_INDEXES)

static inline void get_set(uint32_t *cached_val, uint32_t *val, int get)
{
	if (get)
		*val = *cached_val;
	else
		*cached_val = *val;
}

static inline void get_set_signed(int32_t *cached_val, uint32_t *val, int get)
{
	if (get)
		*val = (uint32_t)*cached_val;
	else
		*cached_val = (int32_t)*val;
}

static inline int find_equal_index(void *be_module_reg,
	unsigned int type_size, unsigned int idx, unsigned int start,
	unsigned int nb_elements, uint32_t *value, int get, const char *func)
{
	unsigned int i;
	if (!get)
		return error_unsup_field(func);
	*value = NOT_FOUND;
	if (start >= nb_elements)
		return error_index_too_large(func);
	for (i = start; i < nb_elements; i++) {
		if (idx == i)
			continue;
		if (memcmp((uint8_t *)be_module_reg + idx * type_size,
			   (uint8_t *)be_module_reg + i * type_size,
			   type_size) == 0) {
			*value = i;
			break;
		}
	}
	return 0;
}

static inline int do_compare_indexes(void *be_module_reg,
	unsigned int type_size, unsigned int idx, unsigned int cmp_idx,
	unsigned int nb_elements, int get, const char *func)
{
	if (!get)
		return error_unsup_field(func);
	if (cmp_idx >= nb_elements)
		return error_index_too_large(func);
	if (idx != cmp_idx &&
	    (memcmp((uint8_t *)be_module_reg + idx * type_size,
		    (uint8_t *)be_module_reg + cmp_idx * type_size,
		    type_size) == 0))
		return 1;
	return 0;
}

static inline int is_non_zero(const void *addr, size_t n)
{
	size_t i = 0;
	const uint8_t *p = (const uint8_t *)addr;

	for (i = 0; i < n; i++) {
		if (p[i] != 0)
			return 1;
	}
	return 0;
}

static inline int is_all_bits_set(const void *addr, size_t n)
{
	size_t i = 0;
	const uint8_t *p = (const uint8_t *)addr;

	for (i = 0; i < n; i++) {
		if (p[i] != 0xff)
			return 0;
	}
	return 1;
}

enum cte_index_e {
	CT_COL = 0,
	CT_COR = 1,
	CT_HSH = 2,
	CT_QSL = 3,
	CT_IPF = 4,
	CT_SLC = 5,
	CT_PDB = 6,
	CT_MSK = 7,
	CT_HST = 8,
	CT_EPP = 9,
	CT_TPE = 10,
	CT_RRB = 11,
	CT_CNT
};

/* Sideband info bit indicator */
#define SWX_INFO (1 << 6)

enum frame_offs_e {
	DYN_SOF = 0,
	DYN_L2 = 1,
	DYN_FIRST_VLAN = 2,
	DYN_MPLS = 3,
	DYN_L3 = 4,
	DYN_ID_IPV4_6 = 5,
	DYN_FINAL_IP_DST = 6,
	DYN_L4 = 7,
	DYN_L4_PAYLOAD = 8,
	DYN_TUN_PAYLOAD = 9,
	DYN_TUN_L2 = 10,
	DYN_TUN_VLAN = 11,
	DYN_TUN_MPLS = 12,
	DYN_TUN_L3 = 13,
	DYN_TUN_ID_IPV4_6 = 14,
	DYN_TUN_FINAL_IP_DST = 15,
	DYN_TUN_L4 = 16,
	DYN_TUN_L4_PAYLOAD = 17,
	DYN_EOF = 18,
	DYN_L3_PAYLOAD_END = 19,
	DYN_TUN_L3_PAYLOAD_END = 20,
	SB_VNI = SWX_INFO | 1,
	SB_MAC_PORT = SWX_INFO | 2,
	SB_KCC_ID = SWX_INFO | 3
};

enum km_flm_if_select_e { KM_FLM_IF_FIRST = 0, KM_FLM_IF_SECOND = 1 };

enum {
	QW0_SEL_EXCLUDE = 0,
	QW0_SEL_FIRST32 = 1,
	QW0_SEL_SECOND32 = 2,
	QW0_SEL_FIRST64 = 3,
	QW0_SEL_ALL128 = 4,
};

enum {
	QW4_SEL_EXCLUDE = 0,
	QW4_SEL_FIRST32 = 1,
	QW4_SEL_FIRST64 = 2,
	QW4_SEL_ALL128 = 3,
};

enum {
	SW8_SEL_EXCLUDE = 0,
	SW8_SEL_FIRST16 = 1,
	SW8_SEL_SECOND16 = 2,
	SW8_SEL_ALL32 = 3,
};

enum {
	DW8_SEL_EXCLUDE = 0,
	DW8_SEL_FIRST16 = 1,
	DW8_SEL_SECOND16 = 2,
	DW8_SEL_FIRST32 = 3,
	DW8_SEL_FIRST32_SWAP16 = 4,
	DW8_SEL_ALL64 = 5,
};

enum {
	SW9_SEL_EXCLUDE = 0,
	SW9_SEL_FIRST16 = 1,
	SW9_SEL_ALL32 = 2,
};

enum {
	DW10_SEL_EXCLUDE = 0,
	DW10_SEL_FIRST16 = 1,
	DW10_SEL_FIRST32 = 2,
	DW10_SEL_ALL64 = 3,
};

enum {
	SWX_SEL_EXCLUDE = 0,
	SWX_SEL_ALL32 = 1,
};

enum {
	PROT_OTHER = 0,
	PROT_L2_ETH2 = 1,
	PROT_L2_SNAP = 2,
	PROT_L2_LLC = 3,
	PROT_L2_RAW = 4,
	PROT_L2_PPPOE_D = 5,
	PROT_L2_PPOE_S = 6
};

enum { PROT_L3_IPV4 = 1, PROT_L3_IPV6 = 2 };

enum { PROT_L4_TCP = 1, PROT_L4_UDP = 2, PROT_L4_SCTP = 3, PROT_L4_ICMP = 4 };

enum {
	PROT_TUN_IP_IN_IP = 1,
	PROT_TUN_ETHER_IP = 2,
	PROT_TUN_GREV0 = 3,
	PROT_TUN_GREV1 = 4,
	PROT_TUN_GTPV0U = 5,
	PROT_TUN_GTPV1U = 6,
	PROT_TUN_GTPV1C = 7,
	PROT_TUN_GTPV2C = 8,
	PROT_TUN_VXLAN = 9,
	PROT_TUN_PSEUDO_WIRE = 10
};

enum { PROT_TUN_L2_OTHER = 0, PROT_TUN_L2_ETH2 = 1 };

enum { PROT_TUN_L3_OTHER = 0, PROT_TUN_L3_IPV4 = 1, PROT_TUN_L3_IPV6 = 2 };

enum {
	PROT_TUN_L4_OTHER = 0,
	PROT_TUN_L4_TCP = 1,
	PROT_TUN_L4_UDP = 2,
	PROT_TUN_L4_SCTP = 3,
	PROT_TUN_L4_ICMP = 4
};

enum {
	IP_FRAG_NOT_A_FRAG = 0,
	IP_FRAG_FIRST = 1,
	IP_FRAG_MIDDLE = 2,
	IP_FRAG_LAST = 3
};

enum {
	HASH_HASH_NONE = 0,
	HASH_USER_DEFINED = 1,
	HASH_LAST_MPLS_LABEL = 2,
	HASH_ALL_MPLS_LABELS = 3,
	HASH_2TUPLE = 4,
	HASH_2TUPLESORTED = 5,
	HASH_LAST_VLAN_ID = 6,
	HASH_ALL_VLAN_IDS = 7,
	HASH_5TUPLE = 8,
	HASH_5TUPLESORTED = 9,
	HASH_3TUPLE_GRE_V0 = 10,
	HASH_3TUPLE_GRE_V0_SORTED = 11,
	HASH_5TUPLE_SCTP = 12,
	HASH_5TUPLE_SCTP_SORTED = 13,
	HASH_3TUPLE_GTP_V0 = 14,
	HASH_3TUPLE_GTP_V0_SORTED = 15,
	HASH_3TUPLE_GTP_V1V2 = 16,
	HASH_3TUPLE_GTP_V1V2_SORTED = 17,
	HASH_HASHINNER_2TUPLE = 18,
	HASH_HASHINNER_2TUPLESORTED = 19,
	HASH_HASHINNER_5TUPLE = 20,
	HASH_HASHINNER_5TUPLESORTED = 21,
	HASH_KM = 30,
	HASH_ROUND_ROBIN = 31,
	HASH_OUTER_DST_IP = 32,
	HASH_INNER_SRC_IP = 33,
};

enum {
	CPY_SELECT_DSCP_IPV4 = 0,
	CPY_SELECT_DSCP_IPV6 = 1,
	CPY_SELECT_RQI_QFI = 2,
	CPY_SELECT_IPV4 = 3,
	CPY_SELECT_PORT = 4,
	CPY_SELECT_TEID = 5,
};

#define RCK_CML(_comp_) (1 << ((_comp_) * 4))
#define RCK_CMU(_comp_) (1 << ((_comp_) * 4 + 1))
#define RCK_SEL(_comp_) (1 << ((_comp_) * 4 + 2))
#define RCK_SEU(_comp_) (1 << ((_comp_) * 4 + 3))

#define RCK_EXT(x) (((uint32_t)(x) << 6))

#define FIELD_START_INDEX 100

#define COMMON_FUNC_INFO_S         \
	int ver;                   \
	void *base;                \
	unsigned int allocated_size; \
	int debug

struct common_func_s {
	COMMON_FUNC_INFO_S;
};

struct cat_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_cat_funcs;
	uint32_t nb_flow_types;
	uint32_t nb_pm_ext;
	uint32_t nb_len;
	uint32_t kcc_size;
	uint32_t cts_num;
	uint32_t kcc_banks;
	uint32_t kcc_id_bit_size;
	uint32_t kcc_records;
	uint32_t km_if_count;
	int32_t km_if_m0;
	int32_t km_if_m1;

	union {
		struct hw_mod_cat_v18_s v18;
		struct hw_mod_cat_v21_s v21;
		struct hw_mod_cat_v22_s v22;
	};
};

enum hw_cat_e {
	/*
	 *  functions initial CAT v18
	 */
	/* 00 */ HW_CAT_CFN_SET_ALL_DEFAULTS = 0,
	/* 01 */ HW_CAT_CFN_PRESET_ALL,
	/* 02 */ HW_CAT_CFN_COMPARE,
	/* 03 */ HW_CAT_CFN_FIND,
	/* 04 */ HW_CAT_CFN_COPY_FROM,
	/* 05 */ HW_CAT_COT_PRESET_ALL,
	/* 06 */ HW_CAT_COT_COMPARE,
	/* 07 */ HW_CAT_COT_FIND,
	/* fields */
	/* 00 */ HW_CAT_CFN_ENABLE = FIELD_START_INDEX,
	/* 01 */ HW_CAT_CFN_INV,
	/* 02 */ HW_CAT_CFN_PTC_INV,
	/* 03 */ HW_CAT_CFN_PTC_ISL,
	/* 04 */ HW_CAT_CFN_PTC_CFP,
	/* 05 */ HW_CAT_CFN_PTC_MAC,
	/* 06 */ HW_CAT_CFN_PTC_L2,
	/* 07 */ HW_CAT_CFN_PTC_VNTAG,
	/* 08 */ HW_CAT_CFN_PTC_VLAN,
	/* 09 */ HW_CAT_CFN_PTC_MPLS,
	/* 10 */ HW_CAT_CFN_PTC_L3,
	/* 11 */ HW_CAT_CFN_PTC_FRAG,
	/* 12 */ HW_CAT_CFN_PTC_IP_PROT,
	/* 13 */ HW_CAT_CFN_PTC_L4,
	/* 14 */ HW_CAT_CFN_PTC_TUNNEL,
	/* 15 */ HW_CAT_CFN_PTC_TNL_L2,
	/* 16 */ HW_CAT_CFN_PTC_TNL_VLAN,
	/* 17 */ HW_CAT_CFN_PTC_TNL_MPLS,
	/* 18 */ HW_CAT_CFN_PTC_TNL_L3,
	/* 19 */ HW_CAT_CFN_PTC_TNL_FRAG,
	/* 20 */ HW_CAT_CFN_PTC_TNL_IP_PROT,
	/* 21 */ HW_CAT_CFN_PTC_TNL_L4,
	/* 22 */ HW_CAT_CFN_ERR_INV,
	/* 23 */ HW_CAT_CFN_ERR_CV,
	/* 24 */ HW_CAT_CFN_ERR_FCS,
	/* 25 */ HW_CAT_CFN_ERR_TRUNC,
	/* 26 */ HW_CAT_CFN_ERR_L3_CS,
	/* 27 */ HW_CAT_CFN_ERR_L4_CS,
	/* 28 */ HW_CAT_CFN_MAC_PORT,
	/* 29 */ HW_CAT_CFN_PM_CMP,
	/* 30 */ HW_CAT_CFN_PM_DCT,
	/* 31 */ HW_CAT_CFN_PM_EXT_INV,
	/* 32 */ HW_CAT_CFN_PM_CMB,
	/* 33 */ HW_CAT_CFN_PM_AND_INV,
	/* 34 */ HW_CAT_CFN_PM_OR_INV,
	/* 35 */ HW_CAT_CFN_PM_INV,
	/* 36 */ HW_CAT_CFN_LC,
	/* 37 */ HW_CAT_CFN_LC_INV,
	/* 38 */ HW_CAT_CFN_KM0_OR,
	/* 39 */ HW_CAT_CFN_KM1_OR,
	/* 40 */ HW_CAT_KCE_ENABLE_BM,
	/* 41 */ HW_CAT_KCS_CATEGORY,
	/* 42 */ HW_CAT_FTE_ENABLE_BM,
	/* 43 */ HW_CAT_CTE_ENABLE_BM,
	/* 44 */ HW_CAT_CTS_CAT_A,
	/* 45 */ HW_CAT_CTS_CAT_B,
	/* 46 */ HW_CAT_COT_COLOR,
	/* 47 */ HW_CAT_COT_KM,
	/* 48 */ HW_CAT_CCT_COLOR,
	/* 49 */ HW_CAT_CCT_KM,
	/* 50 */ HW_CAT_KCC_KEY,
	/* 51 */ HW_CAT_KCC_CATEGORY,
	/* 52 */ HW_CAT_KCC_ID,
	/* 53 */ HW_CAT_EXO_DYN,
	/* 54 */ HW_CAT_EXO_OFS,
	/* 55 */ HW_CAT_RCK_DATA,
	/* 56 */ HW_CAT_LEN_LOWER,
	/* 57 */ HW_CAT_LEN_UPPER,
	/* 58 */ HW_CAT_LEN_DYN1,
	/* 59 */ HW_CAT_LEN_DYN2,
	/* 60 */ HW_CAT_LEN_INV,
	/* 61 */ HW_CAT_CFN_ERR_TNL_L3_CS,
	/* 62 */ HW_CAT_CFN_ERR_TNL_L4_CS,
	/* 63 */ HW_CAT_CFN_ERR_TTL_EXP,
	/* 64 */ HW_CAT_CFN_ERR_TNL_TTL_EXP,

	/* 65 */ HW_CAT_CCE_IMM,
	/* 66 */ HW_CAT_CCE_IND,
	/* 67 */ HW_CAT_CCS_COR_EN,
	/* 68 */ HW_CAT_CCS_COR,
	/* 69 */ HW_CAT_CCS_HSH_EN,
	/* 70 */ HW_CAT_CCS_HSH,
	/* 71 */ HW_CAT_CCS_QSL_EN,
	/* 72 */ HW_CAT_CCS_QSL,
	/* 73 */ HW_CAT_CCS_IPF_EN,
	/* 74 */ HW_CAT_CCS_IPF,
	/* 75 */ HW_CAT_CCS_SLC_EN,
	/* 76 */ HW_CAT_CCS_SLC,
	/* 77 */ HW_CAT_CCS_PDB_EN,
	/* 78 */ HW_CAT_CCS_PDB,
	/* 79 */ HW_CAT_CCS_MSK_EN,
	/* 80 */ HW_CAT_CCS_MSK,
	/* 81 */ HW_CAT_CCS_HST_EN,
	/* 82 */ HW_CAT_CCS_HST,
	/* 83 */ HW_CAT_CCS_EPP_EN,
	/* 84 */ HW_CAT_CCS_EPP,
	/* 85 */ HW_CAT_CCS_TPE_EN,
	/* 86 */ HW_CAT_CCS_TPE,
	/* 87 */ HW_CAT_CCS_RRB_EN,
	/* 88 */ HW_CAT_CCS_RRB,
	/* 89 */ HW_CAT_CCS_SB0_TYPE,
	/* 90 */ HW_CAT_CCS_SB0_DATA,
	/* 91 */ HW_CAT_CCS_SB1_TYPE,
	/* 92 */ HW_CAT_CCS_SB1_DATA,
	/* 93 */ HW_CAT_CCS_SB2_TYPE,
	/* 94 */ HW_CAT_CCS_SB2_DATA,

};

bool hw_mod_cat_present(struct flow_api_backend_s *be);
int hw_mod_cat_alloc(struct flow_api_backend_s *be);
void hw_mod_cat_free(struct flow_api_backend_s *be);
int hw_mod_cat_reset(struct flow_api_backend_s *be);
int hw_mod_cat_cfn_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cfn_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t value);
int hw_mod_cat_cfn_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t *value);
/* KCE/KCS/FTE KM */
int hw_mod_cat_kce_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count);
int hw_mod_cat_kce_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value);
int hw_mod_cat_kce_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value);
int hw_mod_cat_kcs_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count);
int hw_mod_cat_kcs_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value);
int hw_mod_cat_kcs_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value);
int hw_mod_cat_fte_km_flush(struct flow_api_backend_s *be,
			    enum km_flm_if_select_e if_num, int start_idx,
			    int count);
int hw_mod_cat_fte_km_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t value);
int hw_mod_cat_fte_km_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			  enum km_flm_if_select_e if_num, int index,
			  uint32_t *value);
/* KCE/KCS/FTE FLM */
int hw_mod_cat_kce_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count);
int hw_mod_cat_kce_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value);
int hw_mod_cat_kce_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value);
int hw_mod_cat_kcs_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count);
int hw_mod_cat_kcs_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value);
int hw_mod_cat_kcs_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value);
int hw_mod_cat_fte_flm_flush(struct flow_api_backend_s *be,
			     enum km_flm_if_select_e if_num, int start_idx,
			     int count);
int hw_mod_cat_fte_flm_set(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t value);
int hw_mod_cat_fte_flm_get(struct flow_api_backend_s *be, enum hw_cat_e field,
			   enum km_flm_if_select_e if_num, int index,
			   uint32_t *value);

int hw_mod_cat_cte_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cte_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_cte_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_cts_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cts_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_cts_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_cot_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cot_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_cot_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_cct_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cct_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_cct_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_kcc_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_kcc_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t value);
int hw_mod_cat_kcc_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, int word_off, uint32_t *value);

int hw_mod_cat_exo_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_exo_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_exo_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_rck_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_rck_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_rck_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_len_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_len_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_len_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
/* added in v22 */
int hw_mod_cat_cce_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_cce_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_cce_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);
int hw_mod_cat_ccs_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_cat_ccs_set(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t value);
int hw_mod_cat_ccs_get(struct flow_api_backend_s *be, enum hw_cat_e field,
		       int index, uint32_t *value);

struct km_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_categories;
	uint32_t nb_cam_banks;
	uint32_t nb_cam_record_words;
	uint32_t nb_cam_records;
	uint32_t nb_tcam_banks;
	uint32_t nb_tcam_bank_width;
	/* not read from backend, but rather set using version */
	uint32_t nb_km_rcp_mask_a_word_size;
	uint32_t nb_km_rcp_mask_b_word_size;
	union {
		struct hw_mod_km_v7_s v7;
	};
};

enum hw_km_e {
	/* functions */
	HW_KM_RCP_PRESET_ALL = 0,
	HW_KM_CAM_PRESET_ALL,
	/* to sync and reset hw with cache - force write all entries in a bank */
	HW_KM_TCAM_BANK_RESET,
	/* fields */
	HW_KM_RCP_QW0_DYN = FIELD_START_INDEX,
	HW_KM_RCP_QW0_OFS,
	HW_KM_RCP_QW0_SEL_A,
	HW_KM_RCP_QW0_SEL_B,
	HW_KM_RCP_QW4_DYN,
	HW_KM_RCP_QW4_OFS,
	HW_KM_RCP_QW4_SEL_A,
	HW_KM_RCP_QW4_SEL_B,
	HW_KM_RCP_DW8_DYN,
	HW_KM_RCP_DW8_OFS,
	HW_KM_RCP_DW8_SEL_A,
	HW_KM_RCP_DW8_SEL_B,
	HW_KM_RCP_DW10_DYN,
	HW_KM_RCP_DW10_OFS,
	HW_KM_RCP_DW10_SEL_A,
	HW_KM_RCP_DW10_SEL_B,
	HW_KM_RCP_SWX_CCH,
	HW_KM_RCP_SWX_SEL_A,
	HW_KM_RCP_SWX_SEL_B,
	HW_KM_RCP_MASK_A,
	HW_KM_RCP_MASK_B,
	HW_KM_RCP_DUAL,
	HW_KM_RCP_PAIRED,
	HW_KM_RCP_EL_A,
	HW_KM_RCP_EL_B,
	HW_KM_RCP_INFO_A,
	HW_KM_RCP_INFO_B,
	HW_KM_RCP_FTM_A,
	HW_KM_RCP_FTM_B,
	HW_KM_RCP_BANK_A,
	HW_KM_RCP_BANK_B,
	HW_KM_RCP_KL_A,
	HW_KM_RCP_KL_B,
	HW_KM_RCP_KEYWAY_A,
	HW_KM_RCP_KEYWAY_B,
	HW_KM_RCP_SYNERGY_MODE,
	HW_KM_RCP_DW0_B_DYN,
	HW_KM_RCP_DW0_B_OFS,
	HW_KM_RCP_DW2_B_DYN,
	HW_KM_RCP_DW2_B_OFS,
	HW_KM_RCP_SW4_B_DYN,
	HW_KM_RCP_SW4_B_OFS,
	HW_KM_RCP_SW5_B_DYN,
	HW_KM_RCP_SW5_B_OFS,
	HW_KM_CAM_W0,
	HW_KM_CAM_W1,
	HW_KM_CAM_W2,
	HW_KM_CAM_W3,
	HW_KM_CAM_W4,
	HW_KM_CAM_W5,
	HW_KM_CAM_FT0,
	HW_KM_CAM_FT1,
	HW_KM_CAM_FT2,
	HW_KM_CAM_FT3,
	HW_KM_CAM_FT4,
	HW_KM_CAM_FT5,
	HW_KM_TCAM_T,
	HW_KM_TCI_COLOR,
	HW_KM_TCI_FT,
	HW_KM_TCQ_BANK_MASK,
	HW_KM_TCQ_QUAL
};

bool hw_mod_km_present(struct flow_api_backend_s *be);
int hw_mod_km_alloc(struct flow_api_backend_s *be);
void hw_mod_km_free(struct flow_api_backend_s *be);
int hw_mod_km_reset(struct flow_api_backend_s *be);
int hw_mod_km_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			int count);
int hw_mod_km_rcp_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int index, int word_off, uint32_t value);
int hw_mod_km_rcp_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int index, int word_off, uint32_t *value);
int hw_mod_km_cam_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count);
int hw_mod_km_cam_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t value);
int hw_mod_km_cam_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value);
int hw_mod_km_tcam_flush(struct flow_api_backend_s *be, int start_bank,
			 int count);
int hw_mod_km_tcam_set(struct flow_api_backend_s *be, enum hw_km_e field,
		       int bank, int byte, int byte_val, uint32_t *value_set);
int hw_mod_km_tcam_get(struct flow_api_backend_s *be, enum hw_km_e field,
		       int bank, int byte, int byte_val, uint32_t *value_set);
int hw_mod_km_tci_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count);
int hw_mod_km_tci_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t value);
int hw_mod_km_tci_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value);
int hw_mod_km_tcq_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count);
int hw_mod_km_tcq_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value);
int hw_mod_km_tcq_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value);

struct hst_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_hst_rcp_categories;
	union {
		struct hw_mod_hst_v2_s v2;
	};
};

enum hw_hst_e {
	/* functions */
	HW_HST_RCP_PRESET_ALL = 0,
	HW_HST_RCP_FIND,
	HW_HST_RCP_COMPARE,
	/* Control fields */
	HW_HST_RCP_STRIP_MODE = FIELD_START_INDEX,
	HW_HST_RCP_START_DYN,
	HW_HST_RCP_START_OFS,
	HW_HST_RCP_END_DYN,
	HW_HST_RCP_END_OFS,
	HW_HST_RCP_MODIF0_CMD,
	HW_HST_RCP_MODIF0_DYN,
	HW_HST_RCP_MODIF0_OFS,
	HW_HST_RCP_MODIF0_VALUE,
	HW_HST_RCP_MODIF1_CMD,
	HW_HST_RCP_MODIF1_DYN,
	HW_HST_RCP_MODIF1_OFS,
	HW_HST_RCP_MODIF1_VALUE,
	HW_HST_RCP_MODIF2_CMD,
	HW_HST_RCP_MODIF2_DYN,
	HW_HST_RCP_MODIF2_OFS,
	HW_HST_RCP_MODIF2_VALUE,

};

bool hw_mod_hst_present(struct flow_api_backend_s *be);
int hw_mod_hst_alloc(struct flow_api_backend_s *be);
void hw_mod_hst_free(struct flow_api_backend_s *be);
int hw_mod_hst_reset(struct flow_api_backend_s *be);

int hw_mod_hst_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_hst_rcp_set(struct flow_api_backend_s *be, enum hw_hst_e field,
		       int index, uint32_t value);
int hw_mod_hst_rcp_get(struct flow_api_backend_s *be, enum hw_hst_e field,
		       int index, uint32_t *value);

struct flm_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_categories;
	uint32_t nb_size_mb;
	uint32_t nb_entry_size;
	uint32_t nb_variant;
	uint32_t nb_prios;
	uint32_t nb_pst_profiles;
	union {
		struct hw_mod_flm_v17_s v17;
		struct hw_mod_flm_v20_s v20;
	};
};

enum hw_flm_e {
	/* functions */
	HW_FLM_CONTROL_PRESET_ALL = 0,
	HW_FLM_RCP_PRESET_ALL,
	HW_FLM_FLOW_LRN_DATA_V17,
	HW_FLM_FLOW_INF_DATA_V17,
	HW_FLM_FLOW_STA_DATA_V17,
	/* Control fields */
	HW_FLM_CONTROL_ENABLE = FIELD_START_INDEX,
	HW_FLM_CONTROL_INIT,
	HW_FLM_CONTROL_LDS,
	HW_FLM_CONTROL_LFS,
	HW_FLM_CONTROL_LIS,
	HW_FLM_CONTROL_UDS,
	HW_FLM_CONTROL_UIS,
	HW_FLM_CONTROL_RDS,
	HW_FLM_CONTROL_RIS,
	HW_FLM_CONTROL_PDS,
	HW_FLM_CONTROL_PIS,
	HW_FLM_CONTROL_CRCWR,
	HW_FLM_CONTROL_CRCRD,
	HW_FLM_CONTROL_RBL,
	HW_FLM_CONTROL_EAB,
	HW_FLM_CONTROL_SPLIT_SDRAM_USAGE,
	HW_FLM_STATUS_CALIBDONE,
	HW_FLM_STATUS_INITDONE,
	HW_FLM_STATUS_IDLE,
	HW_FLM_STATUS_CRITICAL,
	HW_FLM_STATUS_PANIC,
	HW_FLM_STATUS_CRCERR,
	HW_FLM_STATUS_EFT_BP,
	HW_FLM_TIMEOUT_T,
	HW_FLM_SCRUB_I,
	HW_FLM_LOAD_BIN,
	HW_FLM_LOAD_PPS,
	HW_FLM_LOAD_LPS,
	HW_FLM_LOAD_APS,
	HW_FLM_PRIO_LIMIT0,
	HW_FLM_PRIO_FT0,
	HW_FLM_PRIO_LIMIT1,
	HW_FLM_PRIO_FT1,
	HW_FLM_PRIO_LIMIT2,
	HW_FLM_PRIO_FT2,
	HW_FLM_PRIO_LIMIT3,
	HW_FLM_PRIO_FT3,
	HW_FLM_PST_PRESET_ALL,
	HW_FLM_PST_BP,
	HW_FLM_PST_PP,
	HW_FLM_PST_TP,
	HW_FLM_RCP_LOOKUP,
	HW_FLM_RCP_QW0_DYN,
	HW_FLM_RCP_QW0_OFS,
	HW_FLM_RCP_QW0_SEL,
	HW_FLM_RCP_QW4_DYN,
	HW_FLM_RCP_QW4_OFS,
	HW_FLM_RCP_SW8_DYN,
	HW_FLM_RCP_SW8_OFS,
	HW_FLM_RCP_SW8_SEL,
	HW_FLM_RCP_SW9_DYN,
	HW_FLM_RCP_SW9_OFS,
	HW_FLM_RCP_MASK,
	HW_FLM_RCP_KID,
	HW_FLM_RCP_OPN,
	HW_FLM_RCP_IPN,
	HW_FLM_RCP_BYT_DYN,
	HW_FLM_RCP_BYT_OFS,
	HW_FLM_RCP_TXPLM,
	HW_FLM_RCP_AUTO_IPV4_MASK,
	HW_FLM_BUF_CTRL_LRN_FREE,
	HW_FLM_BUF_CTRL_INF_AVAIL,
	HW_FLM_BUF_CTRL_STA_AVAIL,
	HW_FLM_STAT_LRN_DONE,
	HW_FLM_STAT_LRN_IGNORE,
	HW_FLM_STAT_LRN_FAIL,
	HW_FLM_STAT_UNL_DONE,
	HW_FLM_STAT_UNL_IGNORE,
	HW_FLM_STAT_REL_DONE,
	HW_FLM_STAT_REL_IGNORE,
	HW_FLM_STAT_PRB_DONE,
	HW_FLM_STAT_PRB_IGNORE,
	HW_FLM_STAT_AUL_DONE,
	HW_FLM_STAT_AUL_IGNORE,
	HW_FLM_STAT_AUL_FAIL,
	HW_FLM_STAT_TUL_DONE,
	HW_FLM_STAT_FLOWS,
	HW_FLM_STAT_STA_DONE, /* module ver 0.20 */
	HW_FLM_STAT_INF_DONE, /* module ver 0.20 */
	HW_FLM_STAT_INF_SKIP, /* module ver 0.20 */
	HW_FLM_STAT_PCK_HIT, /* module ver 0.20 */
	HW_FLM_STAT_PCK_MISS, /* module ver 0.20 */
	HW_FLM_STAT_PCK_UNH, /* module ver 0.20 */
	HW_FLM_STAT_PCK_DIS, /* module ver 0.20 */
	HW_FLM_STAT_CSH_HIT, /* module ver 0.20 */
	HW_FLM_STAT_CSH_MISS, /* module ver 0.20 */
	HW_FLM_STAT_CSH_UNH, /* module ver 0.20 */
	HW_FLM_STAT_CUC_START, /* module ver 0.20 */
	HW_FLM_STAT_CUC_MOVE, /* module ver 0.20 */
};

bool hw_mod_flm_present(struct flow_api_backend_s *be);
int hw_mod_flm_alloc(struct flow_api_backend_s *be);
void hw_mod_flm_free(struct flow_api_backend_s *be);
int hw_mod_flm_reset(struct flow_api_backend_s *be);

int hw_mod_flm_control_flush(struct flow_api_backend_s *be);
int hw_mod_flm_control_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t value);
int hw_mod_flm_control_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t *value);

int hw_mod_flm_status_flush(struct flow_api_backend_s *be);
int hw_mod_flm_status_update(struct flow_api_backend_s *be);
int hw_mod_flm_status_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			  uint32_t value);
int hw_mod_flm_status_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			  uint32_t *value);

int hw_mod_flm_timeout_flush(struct flow_api_backend_s *be);
int hw_mod_flm_timeout_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t value);
int hw_mod_flm_timeout_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t *value);

int hw_mod_flm_scrub_flush(struct flow_api_backend_s *be);
int hw_mod_flm_scrub_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			 uint32_t value);
int hw_mod_flm_scrub_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			 uint32_t *value);

int hw_mod_flm_load_bin_flush(struct flow_api_backend_s *be);
int hw_mod_flm_load_bin_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value);
int hw_mod_flm_load_bin_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value);

int hw_mod_flm_load_pps_flush(struct flow_api_backend_s *be);
int hw_mod_flm_load_pps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value);
int hw_mod_flm_load_pps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value);

int hw_mod_flm_load_lps_flush(struct flow_api_backend_s *be);
int hw_mod_flm_load_lps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value);
int hw_mod_flm_load_lps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value);

int hw_mod_flm_load_aps_flush(struct flow_api_backend_s *be);
int hw_mod_flm_load_aps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value);
int hw_mod_flm_load_aps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value);

int hw_mod_flm_prio_flush(struct flow_api_backend_s *be);
int hw_mod_flm_prio_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t value);
int hw_mod_flm_prio_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t *value);

int hw_mod_flm_pst_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_flm_pst_set(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t value);
int hw_mod_flm_pst_get(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t *value);

int hw_mod_flm_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_flm_rcp_set_mask(struct flow_api_backend_s *be, enum hw_flm_e field,
			    int index, uint32_t *value);
int hw_mod_flm_rcp_set(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t value);
int hw_mod_flm_rcp_get(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t *value);

int hw_mod_flm_buf_ctrl_update(struct flow_api_backend_s *be);
int hw_mod_flm_buf_ctrl_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value);

int hw_mod_flm_stat_update(struct flow_api_backend_s *be);
int hw_mod_flm_stat_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t *value);

int hw_mod_flm_lrn_data_set_flush(struct flow_api_backend_s *be,
				  enum hw_flm_e field, const uint32_t *value);
int hw_mod_flm_inf_data_update_get(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   uint32_t word_cnt);
int hw_mod_flm_sta_data_update_get(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value);

struct hsh_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp;
	union {
		struct hw_mod_hsh_v5_s v5;
	};
};

enum hw_hsh_e {
	/* functions */
	HW_HSH_RCP_PRESET_ALL = 0,
	HW_HSH_RCP_COMPARE,
	HW_HSH_RCP_FIND,
	/* fields */
	HW_HSH_RCP_LOAD_DIST_TYPE = FIELD_START_INDEX,
	HW_HSH_RCP_MAC_PORT_MASK,
	HW_HSH_RCP_SORT,
	HW_HSH_RCP_QW0_PE,
	HW_HSH_RCP_QW0_OFS,
	HW_HSH_RCP_QW4_PE,
	HW_HSH_RCP_QW4_OFS,
	HW_HSH_RCP_W8_PE,
	HW_HSH_RCP_W8_OFS,
	HW_HSH_RCP_W8_SORT,
	HW_HSH_RCP_W9_PE,
	HW_HSH_RCP_W9_OFS,
	HW_HSH_RCP_W9_SORT,
	HW_HSH_RCP_W9_P,
	HW_HSH_RCP_P_MASK,
	HW_HSH_RCP_WORD_MASK,
	HW_HSH_RCP_SEED,
	HW_HSH_RCP_TNL_P,
	HW_HSH_RCP_HSH_VALID,
	HW_HSH_RCP_HSH_TYPE,
	HW_HSH_RCP_AUTO_IPV4_MASK

};

bool hw_mod_hsh_present(struct flow_api_backend_s *be);
int hw_mod_hsh_alloc(struct flow_api_backend_s *be);
void hw_mod_hsh_free(struct flow_api_backend_s *be);
int hw_mod_hsh_reset(struct flow_api_backend_s *be);
int hw_mod_hsh_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_hsh_rcp_set(struct flow_api_backend_s *be, enum hw_hsh_e field,
		       uint32_t index, uint32_t word_off, uint32_t value);
int hw_mod_hsh_rcp_get(struct flow_api_backend_s *be, enum hw_hsh_e field,
		       uint32_t index, uint32_t word_off, uint32_t *value);

struct qsl_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_qst_entries;
	union {
		struct hw_mod_qsl_v7_s v7;
	};
};

enum hw_qsl_e {
	/* functions */
	HW_QSL_RCP_PRESET_ALL = 0,
	HW_QSL_RCP_COMPARE,
	HW_QSL_RCP_FIND,
	HW_QSL_QST_PRESET_ALL,
	/* fields */
	HW_QSL_RCP_DISCARD = FIELD_START_INDEX,
	HW_QSL_RCP_DROP,
	HW_QSL_RCP_TBL_LO,
	HW_QSL_RCP_TBL_HI,
	HW_QSL_RCP_TBL_IDX,
	HW_QSL_RCP_TBL_MSK,
	HW_QSL_RCP_LR,
	HW_QSL_RCP_TSA,
	HW_QSL_RCP_VLI,
	HW_QSL_QST_QUEUE,
	HW_QSL_QST_EN, /* Alias: HW_QSL_QST_QEN */
	HW_QSL_QST_TX_PORT,
	HW_QSL_QST_LRE,
	HW_QSL_QST_TCI,
	HW_QSL_QST_VEN,
	HW_QSL_QEN_EN,
	HW_QSL_UNMQ_DEST_QUEUE,
	HW_QSL_UNMQ_EN,

};

bool hw_mod_qsl_present(struct flow_api_backend_s *be);
int hw_mod_qsl_alloc(struct flow_api_backend_s *be);
void hw_mod_qsl_free(struct flow_api_backend_s *be);
int hw_mod_qsl_reset(struct flow_api_backend_s *be);
int hw_mod_qsl_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_qsl_rcp_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value);
int hw_mod_qsl_rcp_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value);
int hw_mod_qsl_qst_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_qsl_qst_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value);
int hw_mod_qsl_qst_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value);
int hw_mod_qsl_qen_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_qsl_qen_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value);
int hw_mod_qsl_qen_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value);
int hw_mod_qsl_unmq_flush(struct flow_api_backend_s *be, int start_idx,
			  int count);
int hw_mod_qsl_unmq_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
			uint32_t index, uint32_t value);
int hw_mod_qsl_unmq_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
			uint32_t index, uint32_t *value);

struct slc_func_s {
	COMMON_FUNC_INFO_S;
	union {
		struct hw_mod_slc_v1_s v1;
	};
};

enum hw_slc_e {
	/* functions */
	HW_SLC_RCP_PRESET_ALL = 0,
	HW_SLC_RCP_COMPARE,
	HW_SLC_RCP_FIND,
	/* fields */
	HW_SLC_RCP_SLC_EN = FIELD_START_INDEX,
	HW_SLC_RCP_DYN,
	HW_SLC_RCP_OFS,
	HW_SLC_RCP_PCAP
};

bool hw_mod_slc_present(struct flow_api_backend_s *be);
int hw_mod_slc_alloc(struct flow_api_backend_s *be);
void hw_mod_slc_free(struct flow_api_backend_s *be);
int hw_mod_slc_reset(struct flow_api_backend_s *be);
int hw_mod_slc_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_slc_rcp_set(struct flow_api_backend_s *be, enum hw_slc_e field,
		       uint32_t index, uint32_t value);
int hw_mod_slc_rcp_get(struct flow_api_backend_s *be, enum hw_slc_e field,
		       uint32_t index, uint32_t *value);

struct slc_lr_func_s {
	COMMON_FUNC_INFO_S;
	union {
		struct hw_mod_slc_lr_v2_s v2;
	};
};

enum hw_slc_lr_e {
	/* functions */
	HW_SLC_LR_RCP_PRESET_ALL = 0,
	HW_SLC_LR_RCP_COMPARE,
	HW_SLC_LR_RCP_FIND,
	/* fields */
	HW_SLC_LR_RCP_SLC_EN = FIELD_START_INDEX,
	HW_SLC_LR_RCP_DYN,
	HW_SLC_LR_RCP_OFS,
	HW_SLC_LR_RCP_PCAP
};

bool hw_mod_slc_lr_present(struct flow_api_backend_s *be);
int hw_mod_slc_lr_alloc(struct flow_api_backend_s *be);
void hw_mod_slc_lr_free(struct flow_api_backend_s *be);
int hw_mod_slc_lr_reset(struct flow_api_backend_s *be);
int hw_mod_slc_lr_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			    int count);
int hw_mod_slc_lr_rcp_set(struct flow_api_backend_s *be, enum hw_slc_lr_e field,
			  uint32_t index, uint32_t value);
int hw_mod_slc_lr_rcp_get(struct flow_api_backend_s *be, enum hw_slc_lr_e field,
			  uint32_t index, uint32_t *value);

struct pdb_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_pdb_rcp_categories;

	union {
		struct hw_mod_pdb_v9_s v9;
	};
};

enum hw_pdb_e {
	/* functions */
	HW_PDB_RCP_PRESET_ALL = 0,
	HW_PDB_RCP_COMPARE,
	HW_PDB_RCP_FIND,
	/* fields */
	HW_PDB_RCP_DESCRIPTOR = FIELD_START_INDEX,
	HW_PDB_RCP_DESC_LEN,
	HW_PDB_RCP_TX_PORT,
	HW_PDB_RCP_TX_IGNORE,
	HW_PDB_RCP_TX_NOW,
	HW_PDB_RCP_CRC_OVERWRITE,
	HW_PDB_RCP_ALIGN,
	HW_PDB_RCP_OFS0_DYN,
	HW_PDB_RCP_OFS0_REL,
	HW_PDB_RCP_OFS1_DYN,
	HW_PDB_RCP_OFS1_REL,
	HW_PDB_RCP_OFS2_DYN,
	HW_PDB_RCP_OFS2_REL,
	HW_PDB_RCP_IP_PROT_TNL,
	HW_PDB_RCP_PPC_HSH,
	HW_PDB_RCP_DUPLICATE_EN,
	HW_PDB_RCP_DUPLICATE_BIT,
	HW_PDB_RCP_PCAP_KEEP_FCS,
	HW_PDB_CONFIG_TS_FORMAT,
	HW_PDB_CONFIG_PORT_OFS,
};

bool hw_mod_pdb_present(struct flow_api_backend_s *be);
int hw_mod_pdb_alloc(struct flow_api_backend_s *be);
void hw_mod_pdb_free(struct flow_api_backend_s *be);
int hw_mod_pdb_reset(struct flow_api_backend_s *be);
int hw_mod_pdb_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_pdb_rcp_set(struct flow_api_backend_s *be, enum hw_pdb_e field,
		       uint32_t index, uint32_t value);
int hw_mod_pdb_rcp_get(struct flow_api_backend_s *be, enum hw_pdb_e field,
		       uint32_t index, uint32_t *value);
int hw_mod_pdb_config_flush(struct flow_api_backend_s *be);
int hw_mod_pdb_config_set(struct flow_api_backend_s *be, enum hw_pdb_e field,
			  uint32_t value);

struct ioa_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_roa_epp_entries;
	union {
		struct hw_mod_ioa_v4_s v4;
	};
};

enum hw_ioa_e {
	/* functions */
	HW_IOA_RCP_PRESET_ALL = 0,
	HW_IOA_RCP_COMPARE,
	HW_IOA_RCP_FIND,
	HW_IOA_ROA_EPP_PRESET_ALL,
	HW_IOA_ROA_EPP_COMPARE,
	HW_IOA_ROA_EPP_FIND,
	/* fields */
	HW_IOA_RCP_TUNNEL_POP = FIELD_START_INDEX,
	HW_IOA_RCP_VLAN_POP,
	HW_IOA_RCP_VLAN_PUSH,
	HW_IOA_RCP_VLAN_VID,
	HW_IOA_RCP_VLAN_DEI,
	HW_IOA_RCP_VLAN_PCP,
	HW_IOA_RCP_VLAN_TPID_SEL,
	HW_IOA_RCP_QUEUE_OVERRIDE_EN,
	HW_IOA_RCP_QUEUE_ID,
	HW_IOA_CONFIG_CUST_TPID_0,
	HW_IOA_CONFIG_CUST_TPID_1,
	HW_IOA_ROA_EPP_PUSH_TUNNEL,
	HW_IOA_ROA_EPP_TX_PORT,
};

bool hw_mod_ioa_present(struct flow_api_backend_s *be);
int hw_mod_ioa_alloc(struct flow_api_backend_s *be);
void hw_mod_ioa_free(struct flow_api_backend_s *be);
int hw_mod_ioa_reset(struct flow_api_backend_s *be);
int hw_mod_ioa_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count);
int hw_mod_ioa_rcp_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
		       uint32_t index, uint32_t value);
int hw_mod_ioa_rcp_get(struct flow_api_backend_s *be, enum hw_ioa_e field,
		       uint32_t index, uint32_t *value);
int hw_mod_ioa_config_flush(struct flow_api_backend_s *be);
int hw_mod_ioa_config_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
			  uint32_t value);

int hw_mod_ioa_roa_epp_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
			   uint32_t index, uint32_t value);
int hw_mod_ioa_roa_epp_get(struct flow_api_backend_s *be, enum hw_ioa_e field,
			   uint32_t index, uint32_t *value);
int hw_mod_ioa_roa_epp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);

struct roa_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_tun_categories;
	uint32_t nb_lag_entries;
	union {
		struct hw_mod_roa_v6_s v6;
	};
};

enum hw_roa_e {
	/* functions */
	HW_ROA_TUNHDR_COMPARE = 0,
	HW_ROA_TUNCFG_PRESET_ALL,
	HW_ROA_TUNCFG_COMPARE,
	HW_ROA_TUNCFG_FIND,
	/* fields */
	HW_ROA_TUNHDR = FIELD_START_INDEX,
	HW_ROA_TUNCFG_TUN_LEN,
	HW_ROA_TUNCFG_TUN_TYPE,
	HW_ROA_TUNCFG_TUN_VLAN,
	HW_ROA_TUNCFG_IP_TYPE,
	HW_ROA_TUNCFG_IPCS_UPD,
	HW_ROA_TUNCFG_IPCS_PRECALC,
	HW_ROA_TUNCFG_IPTL_UPD,
	HW_ROA_TUNCFG_IPTL_PRECALC,
	HW_ROA_TUNCFG_VXLAN_UDP_LEN_UPD,
	HW_ROA_TUNCFG_TX_LAG_IX,
	HW_ROA_TUNCFG_RECIRCULATE,
	HW_ROA_TUNCFG_PUSH_TUNNEL,
	HW_ROA_TUNCFG_RECIRC_PORT,
	HW_ROA_TUNCFG_RECIRC_BYPASS,
	HW_ROA_CONFIG_FWD_RECIRCULATE,
	HW_ROA_CONFIG_FWD_NORMAL_PCKS,
	HW_ROA_CONFIG_FWD_TXPORT0,
	HW_ROA_CONFIG_FWD_TXPORT1,
	HW_ROA_CONFIG_FWD_CELLBUILDER_PCKS,
	HW_ROA_CONFIG_FWD_NON_NORMAL_PCKS,
	HW_ROA_LAGCFG_TXPHY_PORT,
	HW_ROA_IGS_PKT_DROP,
	HW_ROA_IGS_BYTE_DROP,
	HW_ROA_RCC_PKT_DROP,
	HW_ROA_RCC_BYTE_DROP,
};

bool hw_mod_roa_present(struct flow_api_backend_s *be);
int hw_mod_roa_alloc(struct flow_api_backend_s *be);
void hw_mod_roa_free(struct flow_api_backend_s *be);
int hw_mod_roa_reset(struct flow_api_backend_s *be);
int hw_mod_roa_tunhdr_flush(struct flow_api_backend_s *be, int start_idx,
			    int count);
int hw_mod_roa_tunhdr_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t word_off, uint32_t value);
int hw_mod_roa_tunhdr_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t word_off, uint32_t *value);
int hw_mod_roa_tuncfg_flush(struct flow_api_backend_s *be, int start_idx,
			    int count);
int hw_mod_roa_tuncfg_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t value);
int hw_mod_roa_tuncfg_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t *value);
int hw_mod_roa_config_flush(struct flow_api_backend_s *be);
int hw_mod_roa_config_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t value);
int hw_mod_roa_config_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t *value);
int hw_mod_roa_lagcfg_flush(struct flow_api_backend_s *be, int start_idx,
			    int count);
int hw_mod_roa_lagcfg_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t value);
int hw_mod_roa_lagcfg_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t *value);
int hw_mod_roa_igs_pkt_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			   uint32_t value);
int hw_mod_roa_igs_pkt_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			   uint32_t *value);
int hw_mod_roa_igs_pkt_flush(struct flow_api_backend_s *be);
int hw_mod_roa_igs_byte_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			    uint32_t value);
int hw_mod_roa_igs_byte_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			    uint32_t *value);
int hw_mod_roa_igs_byte_flush(struct flow_api_backend_s *be);
int hw_mod_roa_rcc_pkt_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			   uint32_t value);
int hw_mod_roa_rcc_pkt_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			   uint32_t *value);
int hw_mod_roa_rcc_pkt_flush(struct flow_api_backend_s *be);
int hw_mod_roa_rcc_byte_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			    uint32_t value);
int hw_mod_roa_rcc_byte_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			    uint32_t *value);
int hw_mod_roa_rcc_byte_flush(struct flow_api_backend_s *be);

struct rmc_func_s {
	COMMON_FUNC_INFO_S;
	union {
		struct hw_mod_rmc_v1_3_s v1_3;
	};
};

enum hw_rmc_e {
	HW_RMC_BLOCK_STATT = FIELD_START_INDEX,
	HW_RMC_BLOCK_KEEPA,
	HW_RMC_BLOCK_RPP_SLICE,
	HW_RMC_BLOCK_MAC_PORT,
	HW_RMC_LAG_PHY_ODD_EVEN,
};

bool hw_mod_rmc_present(struct flow_api_backend_s *be);
int hw_mod_rmc_alloc(struct flow_api_backend_s *be);
void hw_mod_rmc_free(struct flow_api_backend_s *be);
int hw_mod_rmc_reset(struct flow_api_backend_s *be);
int hw_mod_rmc_ctrl_set(struct flow_api_backend_s *be, enum hw_rmc_e field,
			uint32_t value);
int hw_mod_rmc_ctrl_get(struct flow_api_backend_s *be, enum hw_rmc_e field,
			uint32_t *value);
int hw_mod_rmc_ctrl_flush(struct flow_api_backend_s *be);

struct tpe_func_s {
	COMMON_FUNC_INFO_S;
	uint32_t nb_rcp_categories;
	uint32_t nb_ifr_categories;
	uint32_t nb_cpy_writers;
	uint32_t nb_rpl_depth;
	uint32_t nb_rpl_ext_categories;
	union {
		struct hw_mod_tpe_v1_s v1;
		struct hw_mod_tpe_v2_s v2;
	};
};

enum hw_tpe_e {
	/* functions */
	HW_TPE_PRESET_ALL = 0,
	HW_TPE_FIND,
	HW_TPE_COMPARE,
	/* Control fields */
	HW_TPE_RPP_RCP_EXP = FIELD_START_INDEX,
	HW_TPE_IFR_RCP_EN,
	HW_TPE_IFR_RCP_MTU,
	HW_TPE_INS_RCP_DYN,
	HW_TPE_INS_RCP_OFS,
	HW_TPE_INS_RCP_LEN,
	HW_TPE_RPL_RCP_DYN,
	HW_TPE_RPL_RCP_OFS,
	HW_TPE_RPL_RCP_LEN,
	HW_TPE_RPL_RCP_RPL_PTR,
	HW_TPE_RPL_RCP_EXT_PRIO,
	HW_TPE_RPL_EXT_RPL_PTR,
	HW_TPE_RPL_EXT_META_RPL_LEN, /* SW only */
	HW_TPE_RPL_RPL_VALUE,
	HW_TPE_CPY_RCP_READER_SELECT,
	HW_TPE_CPY_RCP_DYN,
	HW_TPE_CPY_RCP_OFS,
	HW_TPE_CPY_RCP_LEN,
	HW_TPE_HFU_RCP_LEN_A_WR,
	HW_TPE_HFU_RCP_LEN_A_OUTER_L4_LEN,
	HW_TPE_HFU_RCP_LEN_A_POS_DYN,
	HW_TPE_HFU_RCP_LEN_A_POS_OFS,
	HW_TPE_HFU_RCP_LEN_A_ADD_DYN,
	HW_TPE_HFU_RCP_LEN_A_ADD_OFS,
	HW_TPE_HFU_RCP_LEN_A_SUB_DYN,
	HW_TPE_HFU_RCP_LEN_B_WR,
	HW_TPE_HFU_RCP_LEN_B_POS_DYN,
	HW_TPE_HFU_RCP_LEN_B_POS_OFS,
	HW_TPE_HFU_RCP_LEN_B_ADD_DYN,
	HW_TPE_HFU_RCP_LEN_B_ADD_OFS,
	HW_TPE_HFU_RCP_LEN_B_SUB_DYN,
	HW_TPE_HFU_RCP_LEN_C_WR,
	HW_TPE_HFU_RCP_LEN_C_POS_DYN,
	HW_TPE_HFU_RCP_LEN_C_POS_OFS,
	HW_TPE_HFU_RCP_LEN_C_ADD_DYN,
	HW_TPE_HFU_RCP_LEN_C_ADD_OFS,
	HW_TPE_HFU_RCP_LEN_C_SUB_DYN,
	HW_TPE_HFU_RCP_TTL_WR,
	HW_TPE_HFU_RCP_TTL_POS_DYN,
	HW_TPE_HFU_RCP_TTL_POS_OFS,
	HW_TPE_HFU_RCP_CS_INF,
	HW_TPE_HFU_RCP_L3_PRT,
	HW_TPE_HFU_RCP_L3_FRAG,
	HW_TPE_HFU_RCP_TUNNEL,
	HW_TPE_HFU_RCP_L4_PRT,
	HW_TPE_HFU_RCP_OUTER_L3_OFS,
	HW_TPE_HFU_RCP_OUTER_L4_OFS,
	HW_TPE_HFU_RCP_INNER_L3_OFS,
	HW_TPE_HFU_RCP_INNER_L4_OFS,
	HW_TPE_CSU_RCP_OUTER_L3_CMD,
	HW_TPE_CSU_RCP_OUTER_L4_CMD,
	HW_TPE_CSU_RCP_INNER_L3_CMD,
	HW_TPE_CSU_RCP_INNER_L4_CMD,
};

bool hw_mod_tpe_present(struct flow_api_backend_s *be);
int hw_mod_tpe_alloc(struct flow_api_backend_s *be);
void hw_mod_tpe_free(struct flow_api_backend_s *be);
int hw_mod_tpe_reset(struct flow_api_backend_s *be);

int hw_mod_tpe_rpp_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_rpp_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_rpp_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_rpp_ifr_rcp_flush(struct flow_api_backend_s *be, int start_idx,
				 int count);
int hw_mod_tpe_rpp_ifr_rcp_set(struct flow_api_backend_s *be,
			       enum hw_tpe_e field, int index, uint32_t value);
int hw_mod_tpe_rpp_ifr_rcp_get(struct flow_api_backend_s *be,
			       enum hw_tpe_e field, int index, uint32_t *value);

int hw_mod_tpe_ifr_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_ifr_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_ifr_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_ins_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_ins_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_ins_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_rpl_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_rpl_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_rpl_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_rpl_ext_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_rpl_ext_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_rpl_ext_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_rpl_rpl_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_rpl_rpl_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);
int hw_mod_tpe_rpl_rpl_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_cpy_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_cpy_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_cpy_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_hfu_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_hfu_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_hfu_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

int hw_mod_tpe_csu_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count);
int hw_mod_tpe_csu_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value);
int hw_mod_tpe_csu_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value);

enum debug_mode_e {
	FLOW_BACKEND_DEBUG_MODE_NONE = 0x0000,
	FLOW_BACKEND_DEBUG_MODE_WRITE = 0x0001
};

struct flow_api_backend_ops {
	int version;
	int (*set_debug_mode)(void *dev, enum debug_mode_e mode);
	int (*get_nb_phy_port)(void *dev);
	int (*get_nb_rx_port)(void *dev);
	int (*get_ltx_avail)(void *dev);
	int (*get_nb_cat_funcs)(void *dev);
	int (*get_nb_categories)(void *dev);
	int (*get_nb_cat_km_if_cnt)(void *dev);
	int (*get_nb_cat_km_if_m0)(void *dev);
	int (*get_nb_cat_km_if_m1)(void *dev);

	int (*get_nb_queues)(void *dev);
	int (*get_nb_km_flow_types)(void *dev);
	int (*get_nb_pm_ext)(void *dev);
	int (*get_nb_len)(void *dev);
	int (*get_kcc_size)(void *dev);
	int (*get_kcc_banks)(void *dev);
	int (*get_nb_km_categories)(void *dev);
	int (*get_nb_km_cam_banks)(void *dev);
	int (*get_nb_km_cam_record_words)(void *dev);
	int (*get_nb_km_cam_records)(void *dev);
	int (*get_nb_km_tcam_banks)(void *dev);
	int (*get_nb_km_tcam_bank_width)(void *dev);
	int (*get_nb_flm_categories)(void *dev);
	int (*get_nb_flm_size_mb)(void *dev);
	int (*get_nb_flm_entry_size)(void *dev);
	int (*get_nb_flm_variant)(void *dev);
	int (*get_nb_flm_prios)(void *dev);
	int (*get_nb_flm_pst_profiles)(void *dev);
	int (*get_nb_hst_categories)(void *dev);
	int (*get_nb_qsl_categories)(void *dev);
	int (*get_nb_qsl_qst_entries)(void *dev);
	int (*get_nb_pdb_categories)(void *dev);
	int (*get_nb_ioa_categories)(void *dev);
	int (*get_nb_roa_categories)(void *dev);
	int (*get_nb_tpe_categories)(void *dev);
	int (*get_nb_tx_cpy_writers)(void *dev);
	int (*get_nb_tx_cpy_mask_mem)(void *dev);
	int (*get_nb_tx_rpl_depth)(void *dev);
	int (*get_nb_tx_rpl_ext_categories)(void *dev);
	int (*get_nb_tpe_ifr_categories)(void *dev);

	int (*alloc_rx_queue)(void *dev, int queue_id);
	int (*free_rx_queue)(void *dev, int hw_queue);

	/* CAT */
	bool (*get_cat_present)(void *dev);
	uint32_t (*get_cat_version)(void *dev);
	int (*cat_cfn_flush)(void *dev, const struct cat_func_s *cat,
			     int cat_func, int cnt);
	int (*cat_kce_flush)(void *dev, const struct cat_func_s *cat,
			     int km_if_idx, int index, int cnt);
	int (*cat_kcs_flush)(void *dev, const struct cat_func_s *cat,
			     int km_if_idx, int cat_func, int cnt);
	int (*cat_fte_flush)(void *dev, const struct cat_func_s *cat,
			     int km_if_idx, int index, int cnt);
	int (*cat_cte_flush)(void *dev, const struct cat_func_s *cat,
			     int cat_func, int cnt);
	int (*cat_cts_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_cot_flush)(void *dev, const struct cat_func_s *cat,
			     int cat_func, int cnt);
	int (*cat_cct_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_exo_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_rck_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_len_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_kcc_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_cce_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);
	int (*cat_ccs_flush)(void *dev, const struct cat_func_s *cat, int index,
			     int cnt);

	/* KM */
	bool (*get_km_present)(void *dev);
	uint32_t (*get_km_version)(void *dev);
	int (*km_rcp_flush)(void *dev, const struct km_func_s *km, int category,
			    int cnt);
	int (*km_cam_flush)(void *dev, const struct km_func_s *km, int bank,
			    int record, int cnt);
	int (*km_tcam_flush)(void *dev, const struct km_func_s *km, int bank,
			     int byte, int value, int cnt);
	int (*km_tci_flush)(void *dev, const struct km_func_s *km, int bank,
			    int record, int cnt);
	int (*km_tcq_flush)(void *dev, const struct km_func_s *km, int bank,
			    int record, int cnt);

	/* FLM */
	bool (*get_flm_present)(void *dev);
	uint32_t (*get_flm_version)(void *dev);
	int (*flm_control_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_status_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_status_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_timeout_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_scrub_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_load_bin_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_load_pps_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_load_lps_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_load_aps_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_prio_flush)(void *dev, const struct flm_func_s *flm);
	int (*flm_pst_flush)(void *dev, const struct flm_func_s *flm, int index,
			     int cnt);
	int (*flm_rcp_flush)(void *dev, const struct flm_func_s *flm, int index,
			     int cnt);
	int (*flm_buf_ctrl_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_stat_update)(void *dev, const struct flm_func_s *flm);
	int (*flm_lrn_data_flush)(void *be_dev, const struct flm_func_s *flm,
				  const uint32_t *lrn_data, uint32_t size);
	int (*flm_inf_data_update)(void *be_dev, const struct flm_func_s *flm,
				   uint32_t *lrn_data, uint32_t size);
	int (*flm_sta_data_update)(void *be_dev, const struct flm_func_s *flm,
				   uint32_t *lrn_data, uint32_t size);

	/* HSH */
	bool (*get_hsh_present)(void *dev);
	uint32_t (*get_hsh_version)(void *dev);
	int (*hsh_rcp_flush)(void *dev, const struct hsh_func_s *hsh,
			     int category, int cnt);

	/* HST */
	bool (*get_hst_present)(void *dev);
	uint32_t (*get_hst_version)(void *dev);
	int (*hst_rcp_flush)(void *dev, const struct hst_func_s *hst,
			     int category, int cnt);

	/* QSL */
	bool (*get_qsl_present)(void *dev);
	uint32_t (*get_qsl_version)(void *dev);
	int (*qsl_rcp_flush)(void *dev, const struct qsl_func_s *qsl,
			     int category, int cnt);
	int (*qsl_qst_flush)(void *dev, const struct qsl_func_s *qsl, int entry,
			     int cnt);
	int (*qsl_qen_flush)(void *dev, const struct qsl_func_s *qsl, int entry,
			     int cnt);
	int (*qsl_unmq_flush)(void *dev, const struct qsl_func_s *qsl,
			      int entry, int cnt);

	/* SLC */
	bool (*get_slc_present)(void *dev);
	uint32_t (*get_slc_version)(void *dev);
	int (*slc_rcp_flush)(void *dev, const struct slc_func_s *slc,
			     int category, int cnt);

	/* SLC LR */
	bool (*get_slc_lr_present)(void *dev);
	uint32_t (*get_slc_lr_version)(void *dev);
	int (*slc_lr_rcp_flush)(void *dev, const struct slc_lr_func_s *slc_lr,
				int category, int cnt);

	/* PDB */
	bool (*get_pdb_present)(void *dev);
	uint32_t (*get_pdb_version)(void *dev);
	int (*pdb_rcp_flush)(void *dev, const struct pdb_func_s *pdb,
			     int category, int cnt);
	int (*pdb_config_flush)(void *dev, const struct pdb_func_s *pdb);

	/* IOA */
	bool (*get_ioa_present)(void *dev);
	uint32_t (*get_ioa_version)(void *dev);
	int (*ioa_rcp_flush)(void *dev, const struct ioa_func_s *ioa, int index,
			     int cnt);
	int (*ioa_special_tpid_flush)(void *dev, const struct ioa_func_s *ioa);
	int (*ioa_roa_epp_flush)(void *dev, const struct ioa_func_s *ioa,
				 int index, int cnt);

	/* ROA */
	bool (*get_roa_present)(void *dev);
	uint32_t (*get_roa_version)(void *dev);
	int (*roa_tunhdr_flush)(void *dev, const struct roa_func_s *roa,
				int index, int cnt);
	int (*roa_tuncfg_flush)(void *dev, const struct roa_func_s *roa,
				int index, int cnt);
	int (*roa_config_flush)(void *dev, const struct roa_func_s *roa);
	int (*roa_lagcfg_flush)(void *dev, const struct roa_func_s *roa,
				int index, int cnt);

	/* RMC */
	bool (*get_rmc_present)(void *dev);
	uint32_t (*get_rmc_version)(void *dev);
	int (*rmc_ctrl_flush)(void *dev, const struct rmc_func_s *rmc);

	/* TPE */
	bool (*get_tpe_present)(void *dev);
	uint32_t (*get_tpe_version)(void *dev);
	int (*tpe_rpp_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_rpp_ifr_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				     int index, int cnt);
	int (*tpe_ifr_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_ins_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_rpl_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_rpl_ext_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_rpl_rpl_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_cpy_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_hfu_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
	int (*tpe_csu_rcp_flush)(void *dev, const struct tpe_func_s *tpe,
				 int index, int cnt);
};

struct flow_api_backend_s {
	void *be_dev;
	const struct flow_api_backend_ops *iface;

	/* flow filter FPGA modules */
	struct cat_func_s cat;
	struct km_func_s km;
	struct flm_func_s flm;
	struct hsh_func_s hsh;
	struct hst_func_s hst;
	struct qsl_func_s qsl;
	struct slc_func_s slc;
	struct slc_lr_func_s slc_lr;
	struct pdb_func_s pdb;
	struct ioa_func_s ioa;
	struct roa_func_s roa;
	struct rmc_func_s rmc;
	struct tpe_func_s tpe;

	/* NIC attributes */
	unsigned int num_phy_ports;
	unsigned int num_rx_ports;

	/* flow filter resource capacities */
	unsigned int max_categories;
	unsigned int max_queues;
};

int flow_api_backend_init(struct flow_api_backend_s *dev,
			  const struct flow_api_backend_ops *iface,
			  void *be_dev);
int flow_api_backend_reset(struct flow_api_backend_s *dev);
int flow_api_backend_done(struct flow_api_backend_s *dev);

#ifdef __cplusplus
}
#endif

#endif /* __FLOW_API_BACKEND_H__ */
