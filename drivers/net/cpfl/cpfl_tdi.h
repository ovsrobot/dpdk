/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#ifndef _CPFL_TDI_H_
#define _CPFL_TDI_H_

#include "cpfl_ethdev.h"
#include "cpfl_fxp_rule.h"
#include "cpfl_tdi_parser.h"

#define CPFL_TDI_KEY_FIELD_NUM_MAX 256	/* Max number of key field in a table. */
#define CPFL_TDI_ACTION_SPEC_NUM_MAX 64 /* Max number of action spec in a table. */
#define CPFL_TDI_ACTION_PARAMETER_NUM_MAX 16
#define CPFL_TDI_ACTION_BUF_SIZE_MAX 256
#define CPFL_TDI_TABLE_KEY_FIELD_MAX 32
#define CPFL_TDI_MAX_TABLE_KEY_SIZE 128

/**
 *
 * Table entry operation type.
 */

enum cpfl_tdi_table_entry_op {
	CPFL_TDI_TABLE_ENTRY_OP_ADD, /* Add an entry */
	CPFL_TDI_TABLE_ENTRY_OP_DEL, /* Delete an entry */
	CPFL_TDI_TABLE_ENTRY_OP_QRY, /* Query an entry */
};

/**
 * Table key match type.
 *
 * To specify the key match type of a table.
 */
enum cpfl_tdi_table_key_match_type {
	CPFL_TDI_TABLE_KEY_MATCH_TYPE_EXACT,	/**< Exact match. */
	CPFL_TDI_TABLE_KEY_MATCH_TYPE_WILDCARD, /**< Wildcard match. */
	CPFL_TDI_TABLE_KEY_MATCH_TYPE_RANGE,	/**< Range match. */
	CPFL_TDI_TABLE_KEY_MATCH_TYPE_LPM,	/**< longest prefix match. */
};

struct cpfl_tdi_param_info {
	uint32_t id;
	uint16_t offset;
	uint16_t size;
};

struct cpfl_tdi_action_spec_field_info {
	struct cpfl_tdi_immediate_field *field;
	struct cpfl_tdi_param_info param;
	struct cpfl_tdi_mod_field *mod_field;
	struct cpfl_tdi_hw_action *hw_action;
};

struct cpfl_tdi_table_key_field_info {
	struct cpfl_tdi_match_key_field *field;
	struct cpfl_tdi_match_key_format *format;
	struct cpfl_tdi_param_info param;
};

struct cpfl_tdi_action_node {
	TAILQ_ENTRY(cpfl_tdi_action_node) next;
	enum cpfl_tdi_hw_block hw_block_type;
	const struct cpfl_tdi_action *action;
	const struct cpfl_tdi_action_format *format;
	uint32_t buf_len;
	struct cpfl_tdi_param_info params[CPFL_TDI_ACTION_PARAMETER_NUM_MAX];
	uint8_t init_buf[CPFL_TDI_ACTION_BUF_SIZE_MAX];
	uint8_t query_msk[CPFL_TDI_ACTION_BUF_SIZE_MAX];
};

struct cpfl_tdi_table_node {
	TAILQ_ENTRY(cpfl_tdi_table_node) next;
	const struct cpfl_tdi_table *table;
	struct cpfl_tdi_action_node **actions;
	uint16_t buf_len;
	struct cpfl_tdi_param_info params[CPFL_TDI_TABLE_KEY_FIELD_MAX];
};

struct cpfl_tdi_table_key_obj {
	uint16_t buf_len;
	uint8_t buf[CPFL_TDI_MAX_TABLE_KEY_SIZE];
	const struct cpfl_tdi_table_node *tnode;
	union {
		struct {
			uint16_t prof_id;
			uint8_t sub_prof_id;
			uint8_t pin_to_cache;
			uint8_t fixed_fetch;
		} sem;
		struct {
			uint32_t mod_index;
			uint8_t pin_mod_content;
			uint8_t mod_obj_size;
		} mod;
	};
};

struct cpfl_tdi_action_obj {
	const struct cpfl_tdi_table *table;
	struct cpfl_tdi_action_node *node;
	uint16_t buf_len;
	uint8_t buf[CPFL_TDI_ACTION_BUF_SIZE_MAX];
};

TAILQ_HEAD(tdi_table_key_obj_list, tdi_table_key_obj);
TAILQ_HEAD(tdi_action_obj_list, tdi_action_obj);

struct cpfl_tdi_rule_info {
	enum cpfl_rule_type type;
	struct cpfl_tdi_table_key_obj kobj;
	struct cpfl_tdi_action_obj aobj;
	uint64_t cookie;
	uint8_t host_id;
	uint8_t port_num;
	uint8_t resp_req;
	/* vsi is used for lem and lpm rules */
	uint16_t vsi;
	uint8_t clear_mirror_1st_state;
};

void cpfl_tdi_free_table_list(struct cpfl_flow_parser *flow_parser);
int cpfl_tdi_build(struct cpfl_flow_parser *flow_parser);
#endif
