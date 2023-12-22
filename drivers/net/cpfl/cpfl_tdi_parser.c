/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <errno.h>
#include <rte_malloc.h>

#include "cpfl_tdi_parser.h"

static int
cpfl_tdi_get_integer_obj(json_t *jobj, const char *key, int *output)
{
	json_t *int_obj = json_object_get(jobj, key);

	if (int_obj == NULL) {
		PMD_DRV_LOG(ERR, "Missing %s", key);
		return -EINVAL;
	}

	if (!json_is_integer(int_obj)) {
		PMD_DRV_LOG(ERR, "%s is not a integer object.", key);
		return -EINVAL;
	}

	*output = json_integer_value(int_obj);

	return 0;
}

static int
cpfl_tdi_get_string_obj(json_t *jobj, const char *key, char *output)
{
	json_t *str_obj = json_object_get(jobj, key);

	if (str_obj == NULL) {
		PMD_DRV_LOG(ERR, "Missing %s", key);
		return -EINVAL;
	}

	if (!json_is_string(str_obj)) {
		PMD_DRV_LOG(ERR, "%s is not a string object.", key);
		return -EINVAL;
	}

	strncpy(output, json_string_value(str_obj), CPFL_TDI_JSON_STR_SIZE_MAX - 1);

	return 0;
}

static int
cpfl_tdi_get_boolean_obj(json_t *jobj, const char *key, bool *output)
{
	json_t *bool_obj = json_object_get(jobj, key);

	if (bool_obj == NULL) {
		PMD_DRV_LOG(ERR, "Missing %s", key);
		return -EINVAL;
	}

	if (!json_is_boolean(bool_obj)) {
		PMD_DRV_LOG(ERR, "%s is not a boolean object.", key);
		return -EINVAL;
	}

	*output = (bool)json_integer_value(bool_obj);

	return 0;
}

static int
cpfl_tdi_get_array_obj(json_t *jobj, const char *key, json_t **output)
{
	json_t *array_obj = json_object_get(jobj, key);

	if (array_obj == NULL) {
		PMD_DRV_LOG(ERR, "Missing %s", key);
		return -EINVAL;
	}

	if (!json_is_array(array_obj)) {
		PMD_DRV_LOG(ERR, "%s is not a array object.", key);
		return -EINVAL;
	}

	*output = array_obj;

	return 0;
}

static int
cpfl_tdi_get_object_obj(json_t *jobj, const char *key, json_t **output)
{
	json_t *obj_obj = json_object_get(jobj, key);

	if (obj_obj == NULL) {
		PMD_DRV_LOG(ERR, "Missing %s", key);
		return -EINVAL;
	}

	if (!json_is_object(obj_obj)) {
		PMD_DRV_LOG(ERR, "%s is not a array object.", key);
		return -EINVAL;
	}

	*output = obj_obj;

	return 0;
}

static int
cpfl_tdi_parse_table_type(json_t *root, struct cpfl_tdi_table *table)
{
	char tt[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "table_type", tt);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(tt, "match")) {
		table->table_type = CPFL_TDI_TABLE_TYPE_MATCH;
	} else if (!strcmp(tt, "match_value_lookup_table")) {
		table->table_type = CPFL_TDI_TABLE_TYPE_MATCH_VALUE_LOOKUP_TABLE;
	} else if (!strcmp(tt, "policer_meter")) {
		table->table_type = CPFL_TDI_TABLE_TYPE_POLICER_METER;
	} else {
		PMD_DRV_LOG(ERR, "Unknown table type %s", tt);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_table_dir(json_t *root, struct cpfl_tdi_table *table)
{
	char dir[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "direction", dir);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(dir, "RX")) {
		table->direction = CPFL_TDI_TABLE_DIR_RX;
	} else if (!strcmp(dir, "TX")) {
		table->direction = CPFL_TDI_TABLE_DIR_TX;
	} else if (!strcmp(dir, "BIDIRECTIONAL")) {
		table->direction = CPFL_TDI_TABLE_DIR_BI;
	} else {
		PMD_DRV_LOG(ERR, "Unknown direction type %s", dir);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_match_type(json_t *root, struct cpfl_tdi_match_key_field *mkf)
{
	char mt[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "match_type", mt);
	if (ret != 0)
		return ret;

	if (!strcmp(mt, "exact")) {
		mkf->match_type = CPFL_TDI_MATCH_TYPE_EXACT;
	} else if (!strcmp(mt, "selector")) {
		mkf->match_type = CPFL_TDI_MATCH_TYPE_SELECTOR;
	} else if (!strcmp(mt, "ternary")) {
		mkf->match_type = CPFL_TDI_MATCH_TYPE_TERNARY;
	} else if (!strcmp(mt, "lpm")) {
		mkf->match_type = CPFL_TDI_MATCH_TYPE_LPM;
	} else {
		PMD_DRV_LOG(ERR, "Unsupported match type %s.", mt);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_match_key_field_obj(json_t *root, struct cpfl_tdi_match_key_field *mkf)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_string_obj(root, "name", mkf->name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_string_obj(root, "instance_name", mkf->instance_name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_string_obj(root, "field_name", mkf->field_name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_match_type(root, mkf);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "bit_width", &val);
	if (ret != 0)
		return ret;

	mkf->bit_width = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "index", &val);
	if (ret != 0)
		return ret;

	mkf->index = (uint32_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "position", &val);
	if (ret != 0)
		return ret;

	mkf->position = (uint32_t)val;

	return 0;
}

static int
cpfl_tdi_parse_match_key_fields(json_t *root, struct cpfl_tdi_table *table)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	table->match_key_field_num = (uint16_t)array_len;
	table->match_key_fields =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_match_key_field) * array_len, 0);
	if (table->match_key_fields == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create match key field array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *mkf_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_match_key_field_obj(mkf_object, &table->match_key_fields[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_byte_order(json_t *root, struct cpfl_tdi_match_key_format *mkf)
{
	char bo[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "byte_order", bo);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(bo, "HOST")) {
		mkf->byte_order = CPFL_TDI_BYTE_ORDER_HOST;
	} else if (!strcmp(bo, "NETWORK")) {
		mkf->byte_order = CPFL_TDI_BYTE_ORDER_NETWORK;
	} else {
		PMD_DRV_LOG(ERR, "Unknown byte order type %s", bo);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_match_key_format_obj(json_t *root, struct cpfl_tdi_match_key_format *mkf)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_integer_obj(root, "match_key_handle", &val);
	if (ret != 0)
		return ret;

	mkf->match_key_handle = (uint32_t)val;

	ret = cpfl_tdi_parse_byte_order(root, mkf);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "byte_array_index", &val);
	if (ret != 0)
		return ret;

	mkf->byte_array_index = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "start_bit_offset", &val);
	if (ret != 0)
		return ret;

	mkf->start_bit_offset = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "bit_width", &val);
	if (ret != 0)
		return ret;

	mkf->bit_width = (uint16_t)val;

	return 0;
}

static int
cpfl_tdi_parse_match_key_format_array(json_t *root, struct cpfl_tdi_table *table)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	table->match_key_format_num = (uint16_t)array_len;
	table->match_key_format =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_match_key_format) * array_len, 0);
	if (table->match_key_format == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create match key format array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *mkf_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_match_key_format_obj(mkf_object, &table->match_key_format[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_p4_parameter_obj(json_t *root, struct cpfl_tdi_p4_parameter *param)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_string_obj(root, "name", param->name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "bit_width", &val);
	if (ret != 0)
		return ret;

	param->bit_width = (uint16_t)val;

	return 0;
}

static int
cpfl_tdi_parse_p4_parameters(json_t *root, struct cpfl_tdi_action *act)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	act->p4_parameter_num = (uint16_t)array_len;
	act->p4_parameters = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_p4_parameter) * array_len, 0);
	if (act->p4_parameters == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create p4 parameter array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *pp_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_p4_parameter_obj(pp_object, &act->p4_parameters[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_action_obj(json_t *root, struct cpfl_tdi_action *act)
{
	int ret, val = 0;
	json_t *jobj = NULL;

	ret = cpfl_tdi_get_string_obj(root, "name", act->name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "handle", &val);
	if (ret != 0)
		return ret;

	act->handle = (uint32_t)val;

	ret = cpfl_tdi_get_boolean_obj(root, "constant_default_action",
				       &act->constant_default_action);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_boolean_obj(root, "is_compiler_added_action",
				       &act->is_compiler_added_action);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_boolean_obj(root, "allowed_as_hit_action", &act->allowed_as_hit_action);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_boolean_obj(root, "allowed_as_default_action",
				       &act->allowed_as_default_action);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_array_obj(root, "p4_parameters", &jobj);
	if (ret != 0)
		return ret;

	return cpfl_tdi_parse_p4_parameters(jobj, act);
}

static int
cpfl_tdi_parse_actions(json_t *root, struct cpfl_tdi_table *table)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	table->action_num = (uint16_t)array_len;
	table->actions = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_action) * array_len, 0);
	if (table->actions == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create action array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *act_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_action_obj(act_object, &table->actions[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_ma_hw_block(json_t *root, struct cpfl_tdi_ma_hardware_block *hb)
{
	char name[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "name", name);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(name, "SEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_SEM;
	} else if (!strcmp(name, "LEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_LEM;
	} else if (!strcmp(name, "WCM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_WCM;
	} else if (!strcmp(name, "LPM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_LPM;
	} else if (!strcmp(name, "MOD")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_MOD;
	} else if (!strcmp(name, "HASH")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_HASH;
	} else if (!strcmp(name, "RC")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_RC;
	} else if (!strcmp(name, "CXP_LEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_CXP_LEM;
	} else if (!strcmp(name, "METER")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_METER;
	} else {
		PMD_DRV_LOG(ERR, "Unknown hardware block type %s", name);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_profiles(json_t *root, struct cpfl_tdi_ma_hardware_block *hb)
{
	int array_len = json_array_size(root);

	if (array_len > 16) {
		PMD_DRV_LOG(ERR, "Profile array out of bound: %d.", array_len);
		return -EINVAL;
	}

	if (array_len == 0)
		return 0;

	hb->profile_num = (uint16_t)array_len;
	for (int i = 0; i < array_len; i++) {
		int val;
		json_t *int_obj = json_array_get(root, i);

		if (!json_is_integer(int_obj)) {
			PMD_DRV_LOG(ERR, "Invalid profile id, not an integer.");
			return -EINVAL;
		}
		val = json_integer_value(int_obj);
		hb->profile[i] = (uint8_t)val;
	}

	return 0;
}

static int
cpfl_tdi_parse_immediate_field_obj(json_t *root, struct cpfl_tdi_immediate_field *imf)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_string_obj(root, "param_name", imf->param_name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "param_handle", &val);
	if (ret != 0)
		return ret;

	imf->param_handle = (uint32_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "dest_start", &val);
	if (ret != 0)
		return ret;

	imf->dest_start = (uint16_t)val;
	if (json_object_get(root, "start_bit_offset")) {
		ret = cpfl_tdi_get_integer_obj(root, "start_bit_offset", &val);
		if (ret != 0)
			return ret;

		imf->start_bit_offset = (uint16_t)val;
	}

	ret = cpfl_tdi_get_integer_obj(root, "dest_width", &val);
	if (ret != 0)
		return ret;

	imf->dest_width = (uint16_t)val;

	return 0;
}

static int
cpfl_tdi_parse_af_immediate_fields(json_t *root, struct cpfl_tdi_action_format *af)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	af->immediate_field_num = (uint16_t)array_len;
	af->immediate_fields =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_immediate_field) * array_len, 0);
	if (af->immediate_fields == NULL) {
		PMD_DRV_LOG(ERR, "Failed to immediate field array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *if_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_immediate_field_obj(if_object, &af->immediate_fields[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_mod_field_type(json_t *root, struct cpfl_tdi_mod_field *mf)
{
	char t[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;
	int val = 0;

	ret = cpfl_tdi_get_string_obj(root, "type", t);
	if (ret != 0)
		return ret;

	if (!strcmp("parameter", t)) {
		mf->type = CPFL_TDI_MOD_FIELD_TYPE_PARAMETER;
		ret = cpfl_tdi_get_integer_obj(root, "param_handle", &val);
		if (ret != 0)
			return ret;
		mf->param_handle = (uint32_t)val;
	} else if (!strcmp("constant", t)) {
		mf->type = CPFL_TDI_MOD_FIELD_TYPE_CONSTANT;
	} else {
		PMD_DRV_LOG(ERR, "Unknown mod field type %s.", t);
	}

	return 0;
}

static int
cpfl_tdi_parse_mod_field_byte_order(json_t *root, struct cpfl_tdi_mod_field *mf)
{
	char bo[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "byte_order", bo);
	if (ret != 0)
		return ret;

	if (!strcmp("HOST", bo))
		mf->byte_order = CPFL_TDI_BYTE_ORDER_HOST;
	else if (!strcmp("NETWORK", bo))
		mf->byte_order = CPFL_TDI_BYTE_ORDER_NETWORK;
	else
		PMD_DRV_LOG(ERR, "Unknown byte order type %s.", bo);

	return 0;
}

static int
cpfl_tdi_parse_mod_field_value(json_t *root, struct cpfl_tdi_mod_field *mf)
{
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	if (array_len > CPFL_TDI_VALUE_SIZE_MAX) {
		PMD_DRV_LOG(ERR, "Value array out of bound.");
		return -EINVAL;
	}

	mf->value_size = (uint16_t)array_len;
	for (int i = 0; i < array_len; i++) {
		int val;
		json_t *val_obj = json_array_get(root, i);

		if (!json_is_integer(val_obj)) {
			PMD_DRV_LOG(ERR, "Invalid value item, not an integer.");
			return -EINVAL;
		}
		val = json_integer_value(val_obj);
		mf->value[i] = (uint8_t)val;
	}

	return 0;
}

static int
cpfl_tdi_parse_mod_field_obj(json_t *root, struct cpfl_tdi_mod_field *mf)
{
	json_t *jobj = NULL;
	int ret, val = 0;

	ret = cpfl_tdi_get_string_obj(root, "name", mf->name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "handle", &val);
	if (ret != 0)
		return ret;

	mf->handle = (uint32_t)val;

	ret = cpfl_tdi_parse_mod_field_type(root, mf);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_mod_field_byte_order(root, mf);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "byte_array_index", &val);
	if (ret != 0)
		return ret;

	mf->byte_array_index = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "start_bit_offset", &val);
	if (ret != 0)
		return ret;

	mf->start_bit_offset = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "bit_width", &val);
	if (ret != 0)
		return ret;

	mf->bit_width = (uint16_t)val;

	ret = cpfl_tdi_get_array_obj(root, "value", &jobj);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_mod_field_value(jobj, mf);
	if (ret != 0)
		return ret;

	return 0;
}

static int
cpfl_tdi_parse_mod_fields(json_t *root, struct cpfl_tdi_mod_content_format *mcf)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	mcf->mod_field_num = (uint16_t)array_len;
	mcf->mod_fields = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_mod_field) * array_len, 0);
	if (mcf->mod_fields == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create mod field array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *mf_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_mod_field_obj(mf_object, &mcf->mod_fields[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_mod_content_format(json_t *root, struct cpfl_tdi_mod_content_format *mcf)
{
	json_t *jobj = NULL;
	int ret, val = 0;

	if (json_object_get(root, "mod_profile")) {
		ret = cpfl_tdi_get_integer_obj(root, "mod_profile", &val);
		if (ret != 0)
			return ret;
		mcf->mod_profile = (uint16_t)val;
	} else if (json_object_get(root, "mod_lut_num")) {
		ret = cpfl_tdi_get_integer_obj(root, "mod_lut_num", &val);
		if (ret != 0)
			return ret;
		mcf->mod_lut_num = (uint16_t)val;
	} else {
		PMD_DRV_LOG(ERR, "Failed to parse mod_content_format.");
		return -EINVAL;
	}

	ret = cpfl_tdi_get_integer_obj(root, "mod_obj_size", &val);
	if (ret != 0)
		return ret;

	mcf->mod_obj_size = (uint16_t)val;

	if (json_object_get(root, "mod_fields") != NULL) {
		ret = cpfl_tdi_get_array_obj(root, "mod_fields", &jobj);
		if (ret != 0)
			return ret;

		return cpfl_tdi_parse_mod_fields(jobj, mcf);
	}

	return 0;
}

static int
cpfl_tdi_pparse_action_code(json_t *root, struct cpfl_tdi_hw_action *ha)
{
	char ac[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "action_code", ac);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(ac, "SET10_1b")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_SET10_1b;
	} else if (!strcmp(ac, "SET1_16b")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_SET1_16b;
	} else if (!strcmp(ac, "SET1A_24b")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_SET1A_24b;
	} else if (!strcmp(ac, "SET1B_24b")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_SET1B_24b;
	} else if (!strcmp(ac, "SET2_8b")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_SET2_8b;
	} else if (!strcmp(ac, "NOP")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_NOP;
	} else if (!strcmp(ac, "AUX_DATA")) {
		ha->action_code = CPFL_TDI_ACTION_CODE_AUX_DATA;
	} else {
		PMD_DRV_LOG(ERR, "Unknown action code type %s", ac);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_setmd_action_code(json_t *root, struct cpfl_tdi_hw_action *ha)
{
	char ac[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	/* allow no value */
	if (json_object_get(root, "setmd_action_code") == NULL) {
		ha->setmd_action_code = CPFL_TDI_SETMD_ACTION_CODE_NONE;
		return 0;
	}

	ret = cpfl_tdi_get_string_obj(root, "setmd_action_code", ac);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(ac, "SET_8b")) {
		ha->setmd_action_code = CPFL_TDI_SETMD_ACTION_CODE_SET_8b;
	} else if (!strcmp(ac, "SET_16b")) {
		ha->setmd_action_code = CPFL_TDI_SETMD_ACTION_CODE_SET_16b;
	} else if (!strcmp(ac, "SET_32b_AUX")) {
		ha->setmd_action_code = CPFL_TDI_SETMD_ACTION_CODE_SET_32b_AUX;
	} else {
		PMD_DRV_LOG(ERR, "Unknown setmd action code type %s", ac);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_hw_action_parameter_obj(json_t *root, struct cpfl_tdi_hw_action_parameter *param)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_string_obj(root, "param_name", param->param_name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "param_handle", &val);
	if (ret != 0)
		return ret;

	param->param_handle = (uint32_t)val;

	return 0;
}

static int
cpfl_tdi_parse_hw_action_parameters(json_t *root, struct cpfl_tdi_hw_action *ha)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	ha->parameter_num = (uint16_t)array_len;
	ha->parameters =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_hw_action_parameter) * array_len, 0);
	if (ha->parameters == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create hw action parameter array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *p_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_hw_action_parameter_obj(p_object, &ha->parameters[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_hw_action_obj(json_t *root, struct cpfl_tdi_hw_action *ha)
{
	int ret, val = 0;
	json_t *jobj = NULL;

	ret = cpfl_tdi_get_integer_obj(root, "prec", &val);
	if (ret != 0)
		return ret;

	ha->prec = (uint16_t)val;

	ret = cpfl_tdi_pparse_action_code(root, ha);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_setmd_action_code(root, ha);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "index", &val);
	if (ret != 0)
		return ret;

	ha->index = (uint32_t)val;

	if (json_object_get(root, "mod_profile") != NULL) {
		ret = cpfl_tdi_get_integer_obj(root, "mod_profile", &val);
		if (ret != 0)
			return ret;
		ha->mod_profile = (uint16_t)val;
	}

	if (json_object_get(root, "prefetch") != NULL) {
		ret = cpfl_tdi_get_integer_obj(root, "prefetch", &val);
		if (ret != 0)
			return ret;
		ha->prefetch = (uint16_t)val;
	}

	if (json_object_get(root, "parameters") != NULL) {
		ret = cpfl_tdi_get_array_obj(root, "parameters", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_hw_action_parameters(jobj, ha);
		if (ret != 0)
			return ret;
	}

	if (json_object_get(root, "p4_ref_action_handle")) {
		ret = cpfl_tdi_get_integer_obj(root, "p4_ref_action_handle", &val);
		if (ret != 0)
			return ret;
		ha->p4_ref_action_handle = (uint32_t)val;
	}

	if (json_object_get(root, "p4_ref_table_handle")) {
		ret = cpfl_tdi_get_integer_obj(root, "p4_ref_table_handle", &val);
		if (ret != 0)
			return ret;
		ha->p4_ref_table_handle = (uint32_t)val;
	}

	if (json_object_get(root, "value")) {
		ret = cpfl_tdi_get_integer_obj(root, "value", &val);
		if (ret != 0)
			return ret;
		ha->value = (uint16_t)val;
	}

	if (json_object_get(root, "mask")) {
		ret = cpfl_tdi_get_integer_obj(root, "mask", &val);
		if (ret != 0)
			return ret;
		ha->mask = (uint16_t)val;
	}

	if (json_object_get(root, "type_id")) {
		ret = cpfl_tdi_get_integer_obj(root, "type_id", &val);
		if (ret != 0)
			return ret;
		ha->type_id = (uint16_t)val;
	}

	if (json_object_get(root, "offset")) {
		ret = cpfl_tdi_get_integer_obj(root, "offset", &val);
		if (ret != 0)
			return ret;
		ha->offset = (uint16_t)val;
	}

	return 0;
}

static int
cpfl_tdi_parse_hw_actions_list(json_t *root, struct cpfl_tdi_action_format *af)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	af->hw_action_num = (uint16_t)array_len;
	af->hw_actions_list = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_hw_action) * array_len, 0);
	if (af->hw_actions_list == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create hw action array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *ha_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_hw_action_obj(ha_object, &af->hw_actions_list[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_action_format_obj(json_t *root, struct cpfl_tdi_action_format *af)
{
	int ret, val = 0;
	json_t *jobj = NULL;

	ret = cpfl_tdi_get_string_obj(root, "action_name", af->action_name);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "action_handle", &val);
	if (ret != 0)
		return ret;

	af->action_handle = (uint32_t)val;

	ret = cpfl_tdi_get_array_obj(root, "immediate_fields", &jobj);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_af_immediate_fields(jobj, af);
	if (ret != 0)
		return ret;

	jobj = json_object_get(root, "mod_content_format");
	if (jobj != NULL) {
		ret = cpfl_tdi_parse_mod_content_format(jobj, &af->mod_content_format);
		if (ret != 0)
			return ret;
	}

	ret = cpfl_tdi_get_array_obj(root, "hw_actions_list", &jobj);
	if (ret != 0)
		return ret;

	return cpfl_tdi_parse_hw_actions_list(jobj, af);
}

static int
cpfl_tdi_parse_action_format_array(json_t *root, struct cpfl_tdi_ma_hardware_block *hb)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	hb->action_format_num = (uint16_t)array_len;
	hb->action_format = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_action_format) * array_len, 0);
	if (hb->action_format == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create action format array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *af_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_action_format_obj(af_object, &hb->action_format[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_act_rams(json_t *root, struct cpfl_tdi_wcm_params *wm)
{
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	if (array_len > 16) {
		PMD_DRV_LOG(ERR, "Action ram array out of bound.");
		return -EINVAL;
	}

	for (int i = 0; i < array_len; i++) {
		int val;
		json_t *am_obj = json_array_get(root, i);

		if (!json_is_integer(am_obj)) {
			PMD_DRV_LOG(ERR, "Invalid action ram index, not an integer.");
			return -EINVAL;
		}
		val = json_integer_value(am_obj);
		wm->act_rams[i] = (uint8_t)val;
	}

	return 0;
}

static int
cpfl_tdi_parse_wcm_params(json_t *root, struct cpfl_tdi_wcm_params *wm)
{
	int ret, val = 0;
	json_t *jobj = NULL;

	ret = cpfl_tdi_get_integer_obj(root, "wcm_group", &val);
	if (ret != 0)
		return ret;

	wm->wcm_group = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "slice_start_idx", &val);
	if (ret != 0)
		return ret;

	wm->slice_start_idx = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "table_width", &val);
	if (ret != 0)
		return ret;

	wm->table_width = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "entry_cnt", &val);
	if (ret != 0)
		return ret;

	wm->entry_cnt = (uint16_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "entry_idx", &val);
	if (ret != 0)
		return ret;

	wm->entry_idx = (uint16_t)val;

	ret = cpfl_tdi_get_array_obj(root, "act_rams", &jobj);
	if (ret != 0)
		return ret;

	return cpfl_tdi_parse_act_rams(jobj, wm);
}

static int
cpfl_tdi_parse_hb_immediate_fields(json_t *root, struct cpfl_tdi_ma_hardware_block *hb)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	hb->meter.immediate_field_num = (uint16_t)array_len;
	hb->meter.immediate_fields =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_immediate_field) * array_len, 0);
	if (hb->meter.immediate_fields == NULL) {
		PMD_DRV_LOG(ERR, "Failed to immediate field array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *if_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_immediate_field_obj(if_object, &hb->meter.immediate_fields[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_ma_hardware_block_obj(json_t *root,
				     enum cpfl_tdi_table_type table_type,
				     struct cpfl_tdi_ma_hardware_block *hb)
{
	int ret, val = 0;
	json_t *jobj = NULL;

	ret = cpfl_tdi_parse_ma_hw_block(root, hb);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "id", &val);
	if (ret != 0)
		return ret;

	hb->id = (uint32_t)val;

	ret = cpfl_tdi_get_string_obj(root, "hw_interface", hb->hw_interface);
	if (ret != 0)
		return ret;
	if (table_type == CPFL_TDI_TABLE_TYPE_MATCH) {
		ret = cpfl_tdi_get_array_obj(root, "profile", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_profiles(jobj, hb);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_get_array_obj(root, "action_format", &jobj);
		if (ret != 0)
			return ret;
		ret = cpfl_tdi_parse_action_format_array(jobj, hb);
		if (ret != 0)
			return ret;
	}

	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		ret = cpfl_tdi_get_integer_obj(root, "sub_profile", &val);
		if (ret != 0)
			return ret;

		hb->sem.sub_profile = (uint16_t)val;

		ret = cpfl_tdi_get_integer_obj(root, "obj_id", &val);
		if (ret != 0)
			return ret;

		hb->sem.obj_id = (uint32_t)val;
		break;
	case CPFL_TDI_HW_BLOCK_WCM:
		ret = cpfl_tdi_get_object_obj(root, "wcm_params", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_wcm_params(jobj, &hb->wcm.wcm_params);
		if (ret != 0)
			return ret;
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		ret = cpfl_tdi_get_string_obj(root, "hw_resource", hb->mod.hw_resource);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_get_integer_obj(root, "hw_resource_id", &val);
		if (ret != 0)
			return ret;
		hb->mod.hw_resource_id = (uint32_t)val;
		break;
	case CPFL_TDI_HW_BLOCK_METER:
		ret = cpfl_tdi_get_string_obj(root, "hw_resource", hb->mod.hw_resource);
		if (ret != 0)
			return ret;
		ret = cpfl_tdi_get_integer_obj(root, "hw_resource_id", &val);
		if (ret != 0)
			return ret;
		hb->mod.hw_resource_id = (uint32_t)val;
		ret = cpfl_tdi_get_array_obj(root, "immediate_fields", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_hb_immediate_fields(jobj, hb);
		if (ret != 0)
			return ret;
		break;
	case CPFL_TDI_HW_BLOCK_LEM:
	case CPFL_TDI_HW_BLOCK_CXP_LEM:
		ret = cpfl_tdi_get_integer_obj(root, "hash_size", &val);
		if (ret != 0)
			return ret;
		hb->lem.hash_size = (uint16_t)val;
		break;
	case CPFL_TDI_HW_BLOCK_LPM:
		ret = cpfl_tdi_get_integer_obj(root, "max_prefix_len", &val);
		if (ret != 0)
			return ret;
		hb->lpm.max_prefix_len = (uint16_t)val;
		break;
	case CPFL_TDI_HW_BLOCK_HASH:
		break;
	default:
		printf("not support this hardware_block type: %d\n", hb->hw_block);
		break;
	}

	return 0;
}

static int
cpfl_tdi_parse_ma_hardware_blocks(json_t *root,
				  enum cpfl_tdi_table_type table_type,
				  struct cpfl_tdi_match_attributes *ma)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	ma->hardware_block_num = (uint16_t)array_len;
	ma->hardware_blocks =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_ma_hardware_block) * array_len, 0);
	if (ma->hardware_blocks == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create match attribute's hardware block array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *hb_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_ma_hardware_block_obj(hb_object, table_type,
							   &ma->hardware_blocks[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_match_attributes(json_t *root,
				enum cpfl_tdi_table_type table_type,
				struct cpfl_tdi_match_attributes *ma)
{
	json_t *jobj = NULL;
	int ret;

	ret = cpfl_tdi_get_array_obj(root, "hardware_blocks", &jobj);
	if (ret != 0)
		return ret;

	return cpfl_tdi_parse_ma_hardware_blocks(jobj, table_type, ma);
}

static int
cpfl_tdi_parse_table_obj(json_t *root, struct cpfl_tdi_table *table)
{
	int ret, val = 0;
	struct json_t *jobj = NULL;

	ret = cpfl_tdi_parse_table_type(root, table);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_get_integer_obj(root, "handle", &val);
	if (ret != 0)
		return ret;
	table->handle = (uint32_t)val;

	ret = cpfl_tdi_get_string_obj(root, "name", table->name);
	if (ret != 0)
		return ret;

	if (table->table_type == CPFL_TDI_TABLE_TYPE_POLICER_METER) {
		/* TODO */
		return 0;
	}

	if (table->table_type == CPFL_TDI_TABLE_TYPE_MATCH) {
		ret = cpfl_tdi_parse_table_dir(root, table);
		if (ret != 0)
			return ret;
		ret = cpfl_tdi_get_boolean_obj(root, "add_on_miss", &table->add_on_miss);
		if (ret != 0)
			return ret;
		ret = cpfl_tdi_get_boolean_obj(root, "idle_timeout_with_auto_delete",
					       &table->idle_timeout_with_auto_delete);
		if (ret != 0)
			return ret;
		ret = cpfl_tdi_get_integer_obj(root, "default_action_handle", &val);
		if (ret != 0)
			return ret;
		table->default_action_handle = (uint32_t)val;
		ret = cpfl_tdi_get_array_obj(root, "actions", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_actions(jobj, table);
		if (ret != 0)
			return ret;
	} else if (table->table_type == CPFL_TDI_TABLE_TYPE_MATCH_VALUE_LOOKUP_TABLE) {
		ret = cpfl_tdi_get_integer_obj(root, "size", &val);
		if (ret != 0)
			return ret;
		table->size = (uint16_t)val;
		ret = cpfl_tdi_get_boolean_obj(root, "p4_hidden", &table->p4_hidden);
		if (ret != 0)
			return ret;
	}

	ret = cpfl_tdi_get_array_obj(root, "match_key_fields", &jobj);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_match_key_fields(jobj, table);
	if (ret != 0)
		return ret;

	if (json_object_get(root, "match_key_format") != NULL) {
		ret = cpfl_tdi_get_array_obj(root, "match_key_format", &jobj);
		if (ret != 0)
			return ret;

		ret = cpfl_tdi_parse_match_key_format_array(jobj, table);
		if (ret != 0)
			return ret;
	}

	ret = cpfl_tdi_get_object_obj(root, "match_attributes", &jobj);
	if (ret != 0)
		return ret;

	ret = cpfl_tdi_parse_match_attributes(jobj, table->table_type, &table->match_attributes);
	if (ret != 0)
		return ret;

	return 0;
}

static int
cpfl_tdi_parse_tables(json_t *root, struct cpfl_tdi_program *prog)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	prog->table_num = (uint16_t)array_len;
	prog->tables = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_table) * array_len, 0);
	if (prog->tables == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create table array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *table_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_table_obj(table_object, &prog->tables[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_hash_space_cfg(json_t *root, struct cpfl_tdi_hash_space_cfg *cfg)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_integer_obj(root, "base_128_entries", &val);
	if (ret != 0)
		return ret;

	cfg->base_128_entries = (uint32_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "base_256_entries", &val);
	if (ret != 0)
		return ret;

	cfg->base_256_entries = (uint32_t)val;

	return 0;
}

static int
cpfl_tdi_parse_rc_entry_space_cfg(json_t *root, struct cpfl_tdi_rc_entry_space_cfg *cfg)
{
	int ret, val = 0;

	ret = cpfl_tdi_get_integer_obj(root, "rc_num_banks", &val);
	if (ret != 0)
		return ret;

	cfg->rc_num_banks = (uint32_t)val;

	ret = cpfl_tdi_get_integer_obj(root, "rc_num_entries", &val);
	if (ret != 0)
		return ret;

	cfg->rc_num_entries = (uint32_t)val;

	return 0;
}

static int
cpfl_tdi_parse_gc_hw_block(json_t *root, struct cpfl_tdi_gc_hardware_block *hb)
{
	char name[CPFL_TDI_JSON_STR_SIZE_MAX];
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "name", name);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(name, "SEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_SEM;
	} else if (!strcmp(name, "LEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_LEM;
	} else if (!strcmp(name, "WCM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_WCM;
	} else if (!strcmp(name, "MOD")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_MOD;
	} else if (!strcmp(name, "HASH")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_HASH;
	} else if (!strcmp(name, "RC")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_RC;
	} else if (!strcmp(name, "CXP_LEM")) {
		hb->hw_block = CPFL_TDI_HW_BLOCK_CXP_LEM;
	} else {
		PMD_DRV_LOG(ERR, "Unknown hardware block type %s", name);
		return -EINVAL;
	}

	return 0;
}

static int
cpfl_tdi_parse_gc_hardware_block(json_t *root, struct cpfl_tdi_gc_hardware_block *hb)
{
	json_t *jobj = NULL;
	int ret;

	ret = cpfl_tdi_parse_gc_hw_block(root, hb);
	if (ret != 0)
		return ret;

	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_MOD:
		ret = cpfl_tdi_get_object_obj(root, "hash_space_cfg", &jobj);
		if (ret != 0)
			return ret;

		return cpfl_tdi_parse_hash_space_cfg(jobj, &hb->hash_space_cfg);
	case CPFL_TDI_HW_BLOCK_RC:
		ret = cpfl_tdi_get_object_obj(root, "rc_entry_space_cfg", &jobj);
		if (ret != 0)
			return ret;
		return cpfl_tdi_parse_rc_entry_space_cfg(jobj, &hb->rc_entry_space_cfg);
	default:
		break;
	}

	return 0;
}

static int
cpfl_tdi_parse_gc_hardware_blocks(json_t *root, struct cpfl_tdi_global_configs *gc)
{
	int ret;
	int array_len = json_array_size(root);

	if (array_len == 0)
		return 0;

	gc->hardware_block_num = (uint16_t)array_len;
	gc->hardware_blocks =
	    rte_zmalloc(NULL, sizeof(struct cpfl_tdi_gc_hardware_block) * array_len, 0);
	if (gc->hardware_blocks == NULL) {
		PMD_DRV_LOG(ERR, "Failed to create hardware block array.");
		return -ENOMEM;
	}

	for (int i = 0; i < array_len; i++) {
		json_t *hb_object = json_array_get(root, i);

		ret = cpfl_tdi_parse_gc_hardware_block(hb_object, &gc->hardware_blocks[i]);
		if (ret != 0)
			return ret;
	}

	return 0;
}

static int
cpfl_tdi_parse_global_configs(json_t *root, struct cpfl_tdi_global_configs *gc)
{
	json_t *jobj = NULL;
	int ret;

	ret = cpfl_tdi_get_array_obj(root, "hardware_blocks", &jobj);
	if (ret != 0)
		return ret;

	return cpfl_tdi_parse_gc_hardware_blocks(jobj, gc);
}

int
cpfl_tdi_program_create(json_t *root, struct cpfl_tdi_program *prog)
{
	json_t *jobj = NULL;
	int ret;

	ret = cpfl_tdi_get_string_obj(root, "program_name", prog->program_name);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_string_obj(root, "build_date", prog->build_date);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_string_obj(root, "compile_command", prog->compile_command);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_string_obj(root, "compiler_version", prog->compiler_version);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_string_obj(root, "schema_version", prog->schema_version);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_string_obj(root, "target", prog->target);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_object_obj(root, "global_configs", &jobj);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_parse_global_configs(jobj, &prog->global_configs);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_get_array_obj(root, "tables", &jobj);
	if (ret != 0)
		goto err;

	ret = cpfl_tdi_parse_tables(jobj, prog);
	if (ret != 0)
		goto err;

	json_decref(root);

	return 0;

err:
	cpfl_tdi_program_destroy(prog);
	return ret;
}

static void
cpfl_tdi_destroy_hw_action(struct cpfl_tdi_hw_action *action)
{
	if (action->parameter_num > 0)
		rte_free(action->parameters);
}

static void
cpfl_tdi_cpfl_tdi_destroy_action_format(struct cpfl_tdi_action_format *format)
{
	uint16_t i;

	if (format->immediate_field_num > 0)
		rte_free(format->immediate_fields);

	if (format->mod_content_format.mod_field_num > 0)
		rte_free(format->mod_content_format.mod_fields);

	for (i = 0; i < format->hw_action_num; i++)
		cpfl_tdi_destroy_hw_action(&format->hw_actions_list[i]);

	if (format->hw_action_num > 0)
		rte_free(format->hw_actions_list);
}

static void
cpfl_tdi_destroy_hardware_block(struct cpfl_tdi_ma_hardware_block *hb)
{
	uint16_t i;

	for (i = 0; i < hb->action_format_num; i++)
		cpfl_tdi_cpfl_tdi_destroy_action_format(&hb->action_format[i]);

	if (hb->action_format_num > 0)
		rte_free(hb->action_format);
}

static void
cpfl_tdi_destroy_action(struct cpfl_tdi_action *action)
{
	if (action->p4_parameter_num > 0)
		rte_free(action->p4_parameters);
}

static void
cpfl_tdi_destroy_table(struct cpfl_tdi_table *table)
{
	uint16_t i;

	if (table->match_key_field_num > 0)
		rte_free(table->match_key_fields);

	if (table->match_key_format_num > 0)
		rte_free(table->match_key_format);

	for (i = 0; i < table->action_num; i++)
		cpfl_tdi_destroy_action(&table->actions[i]);

	if (table->action_num > 0)
		rte_free(table->actions);

	for (i = 0; i < table->match_attributes.hardware_block_num; i++)
		cpfl_tdi_destroy_hardware_block(&table->match_attributes.hardware_blocks[i]);

	if (table->match_attributes.hardware_block_num > 0)
		rte_free(table->match_attributes.hardware_blocks);
}

void
cpfl_tdi_program_destroy(struct cpfl_tdi_program *program)
{
	uint16_t i;

	for (i = 0; i < program->table_num; i++)
		cpfl_tdi_destroy_table(&program->tables[i]);

	if (program->table_num > 0)
		rte_free(program->tables);

	rte_free(program);
}
