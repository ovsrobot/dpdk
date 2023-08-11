/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <json-c/json.h>
#include <rte_flow.h>

#ifndef _CPFL_FLOW_PARSER_H_
#define _CPFL_FLOW_PARSER_H_

#define CPFL_FLOW_JSON_STR_SIZE_MAX 100

/* Pattern Rules Storage Begin*/
enum cpfl_flow_pr_action_type {
	CPFL_JS_PR_ACTION_TYPE_SEM,
	CPFL_JS_PR_ACTION_TYPE_UNKNOWN = -1,
};

struct cpfl_flow_js_pr_key_attr {
	uint16_t ingress;
	uint16_t egress;
};

struct cpfl_flow_js_pr_key_proto_field {
	char name[CPFL_FLOW_JSON_STR_SIZE_MAX];
	union {
		char mask[CPFL_FLOW_JSON_STR_SIZE_MAX];
		uint32_t mask_32b;
	};
};

struct cpfl_flow_js_pr_key_proto {
	enum rte_flow_item_type type;
	struct cpfl_flow_js_pr_key_proto_field *fields;
	int fields_size;
};

enum cpfl_flow_js_fv_type {
	CPFL_FV_TYPE_PROTOCOL,
	CPFL_FV_TYPE_IMMEDIATE,
	CPFL_FV_TYPE_UNKNOWN = -1,

};

struct cpfl_flow_js_fv {
	uint16_t offset;
	enum cpfl_flow_js_fv_type type;
	union {
		uint16_t immediate;
		struct {
			uint16_t layer;
			enum rte_flow_item_type header;
			uint16_t offset;
			uint16_t mask;
		} proto;
	};
};

#define CPFL_MAX_SEM_FV_KEY_SIZE 64
struct cpfl_flow_js_pr_action_sem {
	uint16_t prof;
	uint16_t subprof;
	uint16_t keysize;
	struct cpfl_flow_js_fv *fv;
	int fv_size;
};

struct cpfl_flow_js_pr_action {
	enum cpfl_flow_pr_action_type type;
	union {
		struct cpfl_flow_js_pr_action_sem sem;
	};
};

struct cpfl_flow_js_pr {
	struct {
		struct cpfl_flow_js_pr_key_proto *protocols;
		uint16_t proto_size;
		struct cpfl_flow_js_pr_key_attr *attributes;
		uint16_t attr_size;
	} key;
	struct cpfl_flow_js_pr_action *actions;
	uint16_t actions_size;
};

/* Pattern Rules Storage End */

/* Modification Rules Storage Begin */
#define CPFL_FLOW_JS_PROTO_SIZE 16
struct cpfl_flow_js_mr_key_action_vxlan_encap {
	enum rte_flow_item_type protocols[CPFL_FLOW_JS_PROTO_SIZE];
	int proto_size;
};

struct cpfl_flow_js_mr_key_action {
	enum rte_flow_action_type type;
	union {
		struct cpfl_flow_js_mr_key_action_vxlan_encap encap;
	};
};

struct cpfl_flow_js_mr_key {
	struct cpfl_flow_js_mr_key_action *actions;
	int actions_size;
};

struct cpfl_flow_js_mr_layout {
	int index;
	char hint[CPFL_FLOW_JSON_STR_SIZE_MAX];
	uint16_t offset;
	uint16_t size;
};

struct cpfl_flow_js_mr_action_mod {
	uint16_t prof;
	uint16_t byte_len;
	struct cpfl_flow_js_mr_layout *layout;
	int layout_size;
};

enum cpfl_flow_mr_action_type {
	CPFL_JS_MR_ACTION_TYPE_MOD,
};

struct cpfl_flow_js_mr_action {
	enum cpfl_flow_mr_action_type type;
	union {
		struct cpfl_flow_js_mr_action_mod mod;
	};
};

struct cpfl_flow_js_mr {
	struct cpfl_flow_js_mr_key key;
	struct cpfl_flow_js_mr_action action;
};

/* Modification Rules Storage End */

struct cpfl_flow_js_parser {
	struct cpfl_flow_js_pr *patterns;
	int pr_size;
	struct cpfl_flow_js_mr *modifications;
	int mr_size;
};

/* Pattern Rules Begin */
struct cpfl_flow_pr_action_sem {
	uint16_t prof;
	uint16_t subprof;
	uint16_t keysize;
	uint8_t cpfl_flow_pr_fv[CPFL_MAX_SEM_FV_KEY_SIZE];
};

struct cpfl_flow_pr_action {
	enum cpfl_flow_pr_action_type type;
	union {
		struct cpfl_flow_pr_action_sem sem;
	};
};

/* Pattern Rules End */

/* Modification Rules Begin */
struct cpfl_flow_mr_key_action_vxlan_encap {
	enum rte_flow_item_type protocols[CPFL_FLOW_JS_PROTO_SIZE];
	uint16_t proto_size;
	const struct rte_flow_action *action;
};

struct cpfl_flow_mr_key_action {
	enum rte_flow_action_type type;
	union {
		struct cpfl_flow_mr_key_action_vxlan_encap encap;
	};
};

struct cpfl_flow_mr_action_mod {
	uint16_t prof;
	uint16_t byte_len;
	uint8_t data[256];
};

struct cpfl_flow_mr_action {
	enum cpfl_flow_mr_action_type type;
	union {
		struct cpfl_flow_mr_action_mod mod;
	};
};

/* Modification Rules End */

struct cpfl_pipeline_stage {
	int stage;
	int recircle;
};

int cpfl_parser_create(struct cpfl_flow_js_parser **parser, const char *filename);
int cpfl_parser_destroy(struct cpfl_flow_js_parser *parser);
int cpfl_flow_parse_items(struct cpfl_flow_js_parser *parser,
			  const struct rte_flow_item *items,
			  const struct rte_flow_attr *attr,
			  struct cpfl_flow_pr_action *pr_action);
int cpfl_flow_parse_actions(struct cpfl_flow_js_parser *parser,
			    const struct rte_flow_action *actions,
			    struct cpfl_flow_mr_action *mr_action);
#endif
