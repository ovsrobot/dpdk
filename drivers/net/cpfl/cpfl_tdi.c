/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */
#include <asm-generic/errno-base.h>
#include <rte_hash_crc.h>
#include <rte_tailq.h>
#include <stdint.h>
#include <string.h>

#include "cpfl_actions.h"
#include "cpfl_flow.h"
#include "cpfl_fxp_rule.h"
#include "cpfl_tdi.h"
#include "cpfl_tdi_parser.h"
#include "rte_common.h"
#include "rte_flow.h"

uint64_t cpfl_tdi_rule_cookie = CPFL_COOKIE_DEF;

/*help function to do left shift on a byte array */
static void
cpfl_tdi_shift_left(uint8_t *buf, int length, uint32_t shift_amount)
{
	uint32_t i;
	int j;
	uint32_t carry = 0;

	if (shift_amount == 0)
		return;

	for (i = 0; i < shift_amount; i += 8) {
		for (j = 0; j < length; j++) {
			uint32_t temp = (buf[j] << (shift_amount - i)) | carry;

			carry = (temp >> 8) & 0xff;
			buf[j] = temp & 0xff;
		}
	}
}

/* help function to init a mask array with bit_width */
static void
cpfl_tdi_init_msk_buf(uint8_t *buf, int length, uint32_t bit_width)
{
	uint32_t i;

	memset(buf, 0, length);
	for (i = 0; i < bit_width; i++) {
		cpfl_tdi_shift_left(buf, length, 1);
		buf[0] += 1;
	}
}

/* help function to OR a byte array with value and mask */
static void
cpfl_tdi_or_buf(uint8_t *buf, int length, uint8_t *values, uint8_t *mask)
{
	int i;

	for (i = 0; i < length; i++)
		buf[i] = (values[i] & mask[i]) | (buf[i] & ~mask[i]);
}

static uint32_t
cpfl_tdi_to_action_code(struct cpfl_tdi_hw_action *ha, uint8_t *val)
{
	switch (ha->action_code) {
	case CPFL_TDI_ACTION_CODE_SET1A_24b:
		switch (ha->index) {
		case 0: /* mod addr */
			return cpfl_act_mod_addr(ha->prec, (uint32_t)*val).data;
		case 8: /* todo */
			break;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1A_24b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1_16b:
		switch (ha->index) {
		case 2: /* set vsi */
			return cpfl_act_fwd_vsi(0, ha->prec, CPFL_PE_LAN, (uint16_t)*val).data;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1_16b index %d", ha->index);
			break;
		}
		break;
	case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
		switch (ha->setmd_action_code) {
		case CPFL_TDI_SETMD_ACTION_CODE_SET_16b:
			return cpfl_act_set_md16(ha->index, ha->prec, ha->type_id, ha->offset,
						 (uint16_t)*val)
			    .data;
		case CPFL_TDI_SETMD_ACTION_CODE_SET_32b_AUX: /* todo */
			return cpfl_act_fwd_vsi(0, ha->prec, CPFL_PE_LAN, (uint16_t)*val).data;
		default:
			PMD_DRV_LOG(WARNING, "Unsupported SET1b_24b setmd code %d",
				    ha->setmd_action_code);
			break;
		}
		break;
	default:
		PMD_DRV_LOG(WARNING, "Unsupported action code %d", ha->action_code);
		break;
	}

	return 0;
}

static void
cpfl_tdi_pack_sem_entry(struct cpfl_tdi_rule_info *rinfo,
			struct cpfl_tdi_ma_hardware_block *hb,
			enum cpfl_tdi_table_entry_op op,
			struct idpf_dma_mem *dma,
			struct idpf_ctlq_msg *msg)
{
	union cpfl_rule_cfg_pkt_record *blob;
	struct cpfl_rule_cfg_data cfg = {0};
	uint16_t cfg_ctrl;
	enum cpfl_ctlq_rule_cfg_opc opc = 0;
	const struct cpfl_tdi_table_key_obj *key = &rinfo->kobj;
	const struct cpfl_tdi_action_obj *action = &rinfo->aobj;

	blob = (void *)dma->va;
	memset(blob, 0, sizeof(*blob));

	cfg_ctrl = CPFL_GET_MEV_SEM_RULE_CFG_CTRL(hb->profile[0], hb->sem.sub_profile, 0, 0);

	switch (op) {
	case CPFL_TDI_TABLE_ENTRY_OP_ADD:
		cpfl_prep_sem_rule_blob(key->buf, key->buf_len, action->buf, action->buf_len,
					cfg_ctrl, blob);
		opc = cpfl_ctlq_sem_add_rule;
		break;
	case CPFL_TDI_TABLE_ENTRY_OP_DEL:
		cpfl_prep_sem_rule_blob(key->buf, key->buf_len, NULL, 0, cfg_ctrl, blob);
		opc = cpfl_ctlq_sem_del_rule;
		break;
	case CPFL_TDI_TABLE_ENTRY_OP_QRY:
		cpfl_prep_sem_rule_blob(key->buf, key->buf_len, NULL, 0, cfg_ctrl, blob);
		opc = cpfl_ctlq_sem_query_rule;
		break;
	default:
		PMD_DRV_LOG(ERR, "Unknown ops, this is a bug.");
		break;
	}

	cpfl_fill_rule_cfg_data_common(opc,
				       rinfo->cookie,
				       rinfo->vsi,
				       rinfo->port_num,
				       rinfo->host_id,
				       0, /* time_sel */
				       0, /* time_sel_val */
				       0, /* cache_wr_thru */
				       rinfo->resp_req,
				       sizeof(union cpfl_rule_cfg_pkt_record),
				       dma,
				       &cfg.common);

	cpfl_prep_rule_desc(&cfg, msg);
}

static void
cpfl_tdi_pack_mod_entry(struct cpfl_tdi_rule_info *rinfo,
			enum cpfl_tdi_table_entry_op op,
			struct idpf_dma_mem *dma,
			struct idpf_ctlq_msg *msg)
{
	union cpfl_rule_cfg_pkt_record *blob;
	struct cpfl_rule_cfg_data cfg = {0};
	uint32_t mod_index;
	enum cpfl_ctlq_rule_cfg_opc opc = 0;
	const struct cpfl_tdi_table_key_obj *key = &rinfo->kobj;
	const struct cpfl_tdi_action_obj *action = &rinfo->aobj;

	blob = (void *)dma->va;
	memset(blob, 0, sizeof(*blob));

	mod_index = *(const uint32_t *)&key->buf[0];

	switch (op) {
	case CPFL_TDI_TABLE_ENTRY_OP_ADD:
		cpfl_fill_rule_mod_content(CPFL_MOD_OBJ_SIZE_DEF, CPFL_PIN_MOD_CONTENT_DEF,
					   mod_index, &cfg.ext.mod_content);

		rte_memcpy(blob->mod_blob, action->buf, action->buf_len);
		opc = cpfl_ctlq_mod_add_update_rule;
		break;
	case CPFL_TDI_TABLE_ENTRY_OP_QRY:
		opc = cpfl_ctlq_mod_query_rule;
		break;
	default:
		break;
	}

	cpfl_fill_rule_cfg_data_common(opc,
				       CPFL_MOD_COOKIE_DEF,
				       0, /* vsi_id not used for mod */
				       CPFL_PORT_NUM_DEF,
				       0,
				       0,	    /* time_sel */
				       0,			    /* time_sel_val */
				       0,			    /* cache_wr_thru */
				       CPFL_RESP_REQ_DEF,
				       sizeof(union cpfl_rule_cfg_pkt_record),
				       dma,
				       &cfg.common);

	cpfl_prep_rule_desc(&cfg, msg);
}

static int
cpfl_tdi_rule_process(struct cpfl_itf *itf,
		      struct idpf_ctlq_info *tx_cq,
		      struct idpf_ctlq_info *rx_cq,
		      struct cpfl_tdi_rule_info *rinfo,
		      int rule_num,
		      enum cpfl_tdi_table_entry_op op)
{
	const struct cpfl_tdi_table_key_obj *kobj;
	struct idpf_hw *hw = &itf->adapter->base.hw;
	struct cpfl_tdi_ma_hardware_block *hb;
	const struct cpfl_tdi_table *table;
	int ret = 0;

	if (rule_num == 0)
		return 0;

	kobj = &rinfo->kobj;

	table = kobj->tnode->table;
	if (table->match_attributes.hardware_block_num == 0) {
		PMD_DRV_LOG(ERR, "No valid hardware block be specified");
		return -EINVAL;
	}
	hb = &table->match_attributes.hardware_blocks[0];
	switch (hb->hw_block) {
	case CPFL_TDI_HW_BLOCK_SEM:
		cpfl_tdi_pack_sem_entry(rinfo, hb, op, &itf->dma[0], &itf->msg[0]);
		break;
	case CPFL_TDI_HW_BLOCK_MOD:
		if (op == CPFL_TDI_TABLE_ENTRY_OP_DEL)
			/* do nothing */
			return 0;
		cpfl_tdi_pack_mod_entry(rinfo, op, &itf->dma[0], &itf->msg[0]);
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported hardware block %d", hb->hw_block);
		return -EINVAL;
	}

	ret = cpfl_send_ctlq_msg(hw, tx_cq, 1, itf->msg);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to send control message");
		return -EINVAL;
	}

	ret = cpfl_receive_ctlq_msg(hw, rx_cq, 1, itf->msg);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to update rule");
		return -EINVAL;
	}
	return 0;
}

static int
cpfl_tdi_fxp_rule_create(struct rte_eth_dev *dev,
			 struct rte_flow *flow,
			 void *meta,
			 struct rte_flow_error *error)
{
	struct cpfl_itf *itf = CPFL_DEV_TO_ITF(dev);
	struct cpfl_adapter_ext *ad = itf->adapter;
	int ret;
	uint32_t cpq_id = 0;
	struct cpfl_vport *vport;
	struct cpfl_repr *repr;
	struct cpfl_tdi_rule_info *rinfo = meta;

	if (!rinfo)
		goto err;

	if (itf->type == CPFL_ITF_TYPE_VPORT) {
		vport = (struct cpfl_vport *)itf;
		/* Every vport has one pair control queues configured to handle message.
		 * Even index is tx queue and odd index is rx queue.
		 */
		cpq_id = vport->base.devarg_id * 2;
	} else if (itf->type == CPFL_ITF_TYPE_REPRESENTOR) {
		repr = (struct cpfl_repr *)itf;
		cpq_id = ((repr->repr_id.pf_id + repr->repr_id.vf_id) & (CPFL_TX_CFGQ_NUM - 1)) * 2;
	} else {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "fail to find correct control queue");
		return -rte_errno;
	}

	ret = cpfl_tdi_rule_process(itf, ad->ctlqp[cpq_id], ad->ctlqp[cpq_id + 1], rinfo, 1,
				    CPFL_TDI_TABLE_ENTRY_OP_ADD);
	if (ret)
		goto err;

	flow->rule = rinfo;

	return 0;

err:
	return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				  "cpfl filter create flow fail");
}

static int
cpfl_tdi_fxp_rule_destroy(struct rte_eth_dev *dev,
			  struct rte_flow *flow,
			  struct rte_flow_error *error)
{
	struct cpfl_itf *itf = CPFL_DEV_TO_ITF(dev);
	struct cpfl_adapter_ext *ad = itf->adapter;
	struct cpfl_vport *vport;
	struct cpfl_repr *repr;
	struct cpfl_tdi_rule_info *rinfo = (struct cpfl_tdi_rule_info *)flow->rule;
	int ret = 0;
	uint32_t cpq_id = 0;

	if (itf->type == CPFL_ITF_TYPE_VPORT) {
		vport = (struct cpfl_vport *)itf;
		cpq_id = vport->base.devarg_id * 2;
	} else if (itf->type == CPFL_ITF_TYPE_REPRESENTOR) {
		repr = (struct cpfl_repr *)itf;
		cpq_id = ((repr->repr_id.pf_id + repr->repr_id.vf_id) & (CPFL_TX_CFGQ_NUM - 1)) * 2;
	} else {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "fail to find correct control queue");
		ret = -rte_errno;
		goto err;
	}

	ret = cpfl_tdi_rule_process(itf, ad->ctlqp[cpq_id], ad->ctlqp[cpq_id + 1], rinfo, 1,
				    CPFL_TDI_TABLE_ENTRY_OP_DEL);
	if (ret)
		goto err;

err:
	rte_free(rinfo);
	flow->rule = NULL;
	return ret;
}

void
cpfl_tdi_free_table_list(struct cpfl_flow_parser *flow_parser)
{
	struct cpfl_tdi_table_node *node;

	while ((node = TAILQ_FIRST(&flow_parser->tdi_table_list))) {
		TAILQ_REMOVE(&flow_parser->tdi_table_list, node, next);
		rte_free(node);
	}
}

static int
cpfl_tdi_build_table_list(struct cpfl_flow_parser *flow_parser)
{
	struct cpfl_tdi_program *prog = flow_parser->p4_parser;
	int i;

	TAILQ_INIT(&flow_parser->tdi_table_list);

	for (i = 0; i < prog->table_num; i++) {
		struct cpfl_tdi_table *table = &prog->tables[i];
		struct cpfl_tdi_table_node *node;

		node = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_table_node), 0);
		if (node == NULL)
			return -ENOMEM;

		node->table = table;
		TAILQ_INSERT_TAIL(&flow_parser->tdi_table_list, node, next);
	}

	return 0;
}

static void
cpfl_tdi_build_hw_action_buf(struct cpfl_tdi_action_node *node)
{
	int i, j;

	for (i = 0; i < node->format->hw_action_num; i++) {
		struct cpfl_tdi_hw_action *ha = &node->format->hw_actions_list[i];
		struct cpfl_tdi_hw_action_parameter *hap = &ha->parameters[0];
		uint32_t msk = UINT32_MAX;
		uint32_t action_code = 0;
		uint16_t offset;
		uint16_t size;

		switch (ha->action_code) {
		case CPFL_TDI_ACTION_CODE_SET10_1b:
		case CPFL_TDI_ACTION_CODE_SET1_16b:
		case CPFL_TDI_ACTION_CODE_SET1A_24b:
		case CPFL_TDI_ACTION_CODE_SET1B_24b:
			offset = node->buf_len;
			size = 4;
			node->buf_len += 4; /* 32 bit action encode */
			break;
		default:
			continue;
		}

		if (ha->parameter_num == 0) {
			switch (ha->action_code) {
			case CPFL_TDI_ACTION_CODE_SET10_1b:
				switch (ha->index) {
				case 0: /* drop */
					action_code = CPFL_ACT_MAKE_1B(ha->prec,
								       CPFL_ACT_1B_OP_DROP,
								       ha->value & ha->mask);
					break;
				default:
					continue;
				}
				break;
			case CPFL_TDI_ACTION_CODE_SET1A_24b:
				switch (ha->index) {
				case 9: /* mod profile */
					action_code =
					    cpfl_act_mod_profile(ha->prec, ha->mod_profile, 0, 0, 0,
								 CPFL_ACT_MOD_PROFILE_PREFETCH_256B)
						.data;
					break;
				case 8: /* queue */
					/* todo */
					break;
				default:
					break;
				}
				break;
			case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
				switch (ha->setmd_action_code) {
				case CPFL_TDI_SETMD_ACTION_CODE_SET_8b:
					action_code =
					    cpfl_act_set_md8(ha->index, ha->prec, ha->type_id,
							     ha->offset, ha->value, ha->mask)
						.data;
					break;
				default:
					break;
				}
				break;
			default:
				continue;
			}

			rte_memcpy(&node->init_buf[offset], &action_code, 4);
			rte_memcpy(&node->query_msk[offset], &msk, 4);
			continue;
		} else {
			uint32_t code_msk = 0;
			uint32_t dummy = 0;
			uint32_t action_code = cpfl_tdi_to_action_code(ha, (void *)&dummy);

			switch (ha->action_code) {
			case CPFL_TDI_ACTION_CODE_SET10_1b:
				code_msk = ~CPFL_ACT_1B_VAL_M;
				break;
			case CPFL_TDI_ACTION_CODE_SET1_16b:
				code_msk = ~CPFL_ACT_16B_VAL_M;
				break;
			case CPFL_TDI_ACTION_CODE_SET1A_24b:
				code_msk = ~CPFL_ACT_24B_A_VAL_M;
				break;
			case CPFL_TDI_ACTION_CODE_SET1B_24b: /* set metadata */
				code_msk = ~CPFL_ACT_24B_B_VAL_M;
				break;
			default:
				continue;
			}

			rte_memcpy(&node->init_buf[offset], &action_code, 4);
			rte_memcpy(&node->query_msk[offset], &code_msk, 4);
		}

		/* only check the first parameter */
		for (j = 0; j < node->format->immediate_field_num; j++) {
			struct cpfl_tdi_immediate_field *imf = &node->format->immediate_fields[j];

			if (imf->param_handle == hap->param_handle) {
				node->params[j].id = imf->param_handle;
				node->params[j].offset = offset;
				node->params[j].size = size;
			}
		}
	}
}

static void
cpfl_tdi_build_mod_content_format_buf(struct cpfl_tdi_action_node *node)
{
	int i, j;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX] = {0};
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX] = {0};

	for (i = 0; i < node->format->mod_content_format.mod_field_num; i++) {
		struct cpfl_tdi_mod_field *mf = &node->format->mod_content_format.mod_fields[i];
		uint16_t size = (uint16_t)((mf->start_bit_offset + mf->bit_width) >> 3);

		node->buf_len += size;

		if (mf->type == CPFL_TDI_MOD_FIELD_TYPE_CONSTANT) {
			rte_memcpy(val_buf, mf->value, size);
			cpfl_tdi_shift_left(val_buf, size, mf->start_bit_offset);
			cpfl_tdi_init_msk_buf(msk_buf, size, mf->bit_width);
			cpfl_tdi_shift_left(msk_buf, size, mf->start_bit_offset);
			cpfl_tdi_or_buf(&node->init_buf[mf->byte_array_index], size, val_buf,
					msk_buf);
			continue;
		}

		for (j = 0; j < node->format->immediate_field_num; j++) {
			struct cpfl_tdi_immediate_field *imf = &node->format->immediate_fields[j];

			if (imf->param_handle == mf->param_handle) {
				node->params[j].id = imf->param_handle;
				node->params[j].offset = mf->byte_array_index;
				node->params[j].size = size;
				break;
			}
		}
	}
}

static void
cpfl_tdi_build_action_params(struct cpfl_tdi_action_node *node)
{
	node->buf_len = 0;
	/* build mod content layout */
	if (node->format->mod_content_format.mod_field_num > 0) {
		cpfl_tdi_build_mod_content_format_buf(node);
		/* build action buffer layout */
	} else if (node->format->hw_action_num > 0) {
		cpfl_tdi_build_hw_action_buf(node);
	}
}

static void
cpfl_tdi_free_action_list(struct cpfl_flow_parser *flow_parser)
{
	struct cpfl_tdi_action_node *action;

	while ((action = TAILQ_FIRST(&flow_parser->tdi_action_list))) {
		TAILQ_REMOVE(&flow_parser->tdi_action_list, action, next);
		rte_free(action);
	}
}

static int
cpfl_tdi_build_action_list(struct cpfl_flow_parser *flow_parser)
{
#define _HASH_TABLE_NAME_SIZE 32
#define _HASH_TABLE_ENTRY_SIZE 1024
	struct cpfl_tdi_program *prog = flow_parser->p4_parser;
	char hname[_HASH_TABLE_NAME_SIZE];
	struct rte_hash *ht;
	int ret = 0;
	int i, j, k;

	snprintf(hname, _HASH_TABLE_NAME_SIZE, "cpfl_tdi_action_hash");

	struct rte_hash_parameters params = {
	    .name = hname,
	    .entries = _HASH_TABLE_ENTRY_SIZE,
	    .key_len = sizeof(uint32_t),
	    .hash_func = rte_hash_crc,
	    .hash_func_init_val = 0,
	    .socket_id = SOCKET_ID_ANY,
	    .extra_flag = 0,
	};

	ht = rte_hash_create(&params);

	if (ht == NULL) {
		PMD_INIT_LOG(ERR, "Failed to create hash table %s", hname);
		return -EINVAL;
	}

	TAILQ_INIT(&flow_parser->tdi_action_list);

	for (i = 0; i < prog->table_num; i++) {
		struct cpfl_tdi_table *table = &prog->tables[i];

		for (j = 0; j < table->action_num; j++) {
			struct cpfl_tdi_action *action = &table->actions[j];
			uint32_t handle = action->handle;
			struct cpfl_tdi_action_node *node;

			/* skip if already exist */
			if (rte_hash_lookup(ht, &handle) >= 0)
				continue;

			node = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_action_node), 0);
			if (node == NULL) {
				ret = -ENOMEM;
				goto err;
			}

			node->action = action;
			ret = rte_hash_add_key_data(ht, &handle, node);
			if (ret != 0)
				goto err;

			TAILQ_INSERT_TAIL(&flow_parser->tdi_action_list, node, next);
		}

		for (j = 0; j < table->match_attributes.hardware_block_num; j++) {
			struct cpfl_tdi_ma_hardware_block *hb =
			    &table->match_attributes.hardware_blocks[j];

			for (k = 0; k < hb->action_format_num; k++) {
				struct cpfl_tdi_action_format *format = &hb->action_format[k];
				uint32_t handle = format->action_handle;
				struct cpfl_tdi_action_node *node = NULL;

				if (rte_hash_lookup_data(ht, &handle, (void **)&node) >= 0) {
					node->hw_block_type = hb->hw_block;
					if (node->format == NULL) {
						node->format = format;
						cpfl_tdi_build_action_params(node);
					}
				}
			}
		}
	}

	rte_hash_free(ht);

	return 0;

err:

	rte_hash_free(ht);
	cpfl_tdi_free_action_list(flow_parser);
	return ret;
}

static int
cpfl_tdi_table_info_get(struct rte_eth_dev *dev,
			uint32_t table_id,
			struct cpfl_tdi_table_node **table_node)
{
	struct cpfl_itf *itf = CPFL_DEV_TO_ITF(dev);
	struct cpfl_adapter_ext *adapter = itf->adapter;
	struct cpfl_tdi_table_node *node;
	void *temp;
	int i;

	RTE_TAILQ_FOREACH_SAFE(node, &adapter->flow_parser.tdi_table_list, next, temp)
	{
		const struct cpfl_tdi_table *table = node->table;

		if (table->handle != table_id)
			continue;

		if (table->match_key_field_num > CPFL_TDI_KEY_FIELD_NUM_MAX) {
			PMD_DRV_LOG(ERR, "Too many fields (%d) in tdi table %s",
				    table->match_key_field_num, table->name);
			goto err;
		}

		if (table->action_num > CPFL_TDI_ACTION_SPEC_NUM_MAX) {
			PMD_DRV_LOG(ERR, "Too many action types (%d) in tdi table %s",
				    table->action_num, table->name);
			goto err;
		}

		/* match_key_field first */
		if (table->match_key_format_num == 0) {
			node->buf_len = 0;
			for (i = 0; i < table->match_key_field_num; i++) {
				struct cpfl_tdi_match_key_field *field =
				    &table->match_key_fields[i];
				uint32_t size = (uint16_t)(field->bit_width >> 3);

				node->params[i].id = field->index;
				node->params[i].offset =
				    node->buf_len; /* equal with field->position */
				node->params[i].size = size;
				node->buf_len += size;
			}
		} else {
			for (i = 0; i < table->match_key_format_num; i++) {
				struct cpfl_tdi_match_key_format *format =
				    &table->match_key_format[i];

				node->buf_len =
				    format->byte_array_index + (uint16_t)(format->bit_width >> 3);
				node->params[i].id = format->match_key_handle;
				node->params[i].offset = format->byte_array_index;
				node->params[i].size = (uint16_t)(format->bit_width >> 3);
			}
		}
		*table_node = node;

		return 0;
	}

err:
	return -EINVAL;
}

static int
cpfl_tdi_table_key_node_init(struct rte_eth_dev *dev __rte_unused,
			     struct cpfl_tdi_table_node *node,
			     struct cpfl_tdi_table_key_obj *kobj)
{
	kobj->tnode = node;
	kobj->buf_len = node->buf_len;
	kobj->sem.pin_to_cache = CPFL_PIN_TO_CACHE_DEF;
	kobj->sem.fixed_fetch = CPFL_FIXED_FETCH_DEF;
	return 0;
}

static int
cpfl_tdi_table_key_create(struct rte_eth_dev *dev,
			  uint32_t table_id,
			  struct cpfl_tdi_table_node **table_node,
			  struct cpfl_tdi_table_key_obj *kobj)
{
	int ret;

	if (!kobj)
		return -EINVAL;

	ret = cpfl_tdi_table_info_get(dev, table_id, table_node);
	if (ret != 0)
		return -EINVAL;

	ret = cpfl_tdi_table_key_node_init(dev, *table_node, kobj);
	if (ret != 0)
		return -EINVAL;

	return 0;
}

static int
cpfl_tdi_table_key_field_info_get(__rte_unused struct rte_eth_dev *dev,
				  struct cpfl_tdi_table_node *node,
				  uint32_t field_id,
				  struct cpfl_tdi_table_key_field_info **key_field_info)
{
	const struct cpfl_tdi_table *table = node->table;
	int i, j;

	for (i = 0; i < table->match_key_field_num; i++) {
		struct cpfl_tdi_match_key_field *field = &table->match_key_fields[i];
		struct cpfl_tdi_table_key_field_info *tkfinfo;

		if (field->index != field_id)
			continue;

		tkfinfo = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_table_key_field_info), 0);
		if (tkfinfo == NULL)
			return -ENOMEM;

		tkfinfo->field = field;
		tkfinfo->param = node->params[i];
		*key_field_info = tkfinfo;

		/* adjust byte width */
		for (j = 0; j < table->match_key_format_num; j++) {
			struct cpfl_tdi_match_key_format *format = &table->match_key_format[j];

			if (format->match_key_handle != field_id)
				continue;
			tkfinfo->format = format;
			return 0;
		}

		return 0;
	}

	return -EINVAL;
}

static int
_cpfl_tdi_table_key_field_set(struct rte_eth_dev *dev __rte_unused,
			      struct cpfl_tdi_table_key_obj *kobj,
			      struct cpfl_tdi_table_key_field_info *tkfinfo,
			      const uint8_t *value,
			      uint16_t size)
{
	struct cpfl_tdi_param_info *pi = &tkfinfo->param;
	uint8_t *target = &kobj->buf[pi->offset];

	rte_memcpy(target, value, size);

	/* Need to fix as this will overwrite. */
	if (tkfinfo->format != NULL)
		cpfl_tdi_shift_left(target, pi->size, tkfinfo->format->start_bit_offset);

	return 0;
}

static int
cpfl_tdi_table_key_field_set(struct rte_eth_dev *dev,
			     struct cpfl_tdi_table_node *table_node,
			     struct cpfl_tdi_table_key_obj *kobj,
			     uint32_t field_id,
			     const uint8_t *value,
			     uint16_t size)
{
	struct cpfl_tdi_table_key_field_info *key_field_info;
	int ret;

	if (!kobj || !value)
		return -EINVAL;

	ret = cpfl_tdi_table_key_field_info_get(dev, table_node, field_id, &key_field_info);
	if (ret != 0)
		return -EINVAL;

	if (key_field_info->field->match_type != CPFL_TDI_MATCH_TYPE_EXACT)
		return -EINVAL;

	ret = _cpfl_tdi_table_key_field_set(dev, kobj, key_field_info, value, size);
	if (ret != 0)
		return -EINVAL;

	return 0;
}

static int
cpfl_tdi_action_spec_info_get(struct rte_eth_dev *dev,
			      uint32_t spec_id,
			      struct cpfl_tdi_action_node **action_node)
{
	struct cpfl_itf *itf = CPFL_DEV_TO_ITF(dev);
	struct cpfl_adapter_ext *adapter = itf->adapter;
	struct cpfl_tdi_action_node *node;
	void *temp;

	RTE_TAILQ_FOREACH_SAFE(node, &adapter->flow_parser.tdi_action_list, next, temp)
	{
		if (node->action->handle != spec_id)
			continue;
		*action_node = node;

		return 0;
	}

	return -EINVAL;
}

static int
cpfl_tdi_action_obj_init(struct rte_eth_dev *dev __rte_unused,
			 struct cpfl_tdi_table_node *tnode,
			 struct cpfl_tdi_action_node *anode,
			 struct cpfl_tdi_action_obj *aobj)
{
	aobj->table = tnode->table;
	aobj->node = anode;
	aobj->buf_len = anode->buf_len;

	rte_memcpy(aobj->buf, anode->init_buf, anode->buf_len);

	return 0;
}

static inline bool __rte_unused
verify_action(struct cpfl_tdi_table_node *table_node, uint32_t spec_id)
{
	int i;
	const struct cpfl_tdi_table *table = table_node->table;

	for (i = 0; i < table->action_num; i++)
		if (spec_id == table->actions[i].handle)
			return true;

	return false;
}

static int
cpfl_tdi_action_node_get_by_spec_id(struct rte_eth_dev *dev,
				    uint32_t table_id __rte_unused,
				    uint32_t spec_id,
				    struct cpfl_tdi_action_node **action_node)
{
	return cpfl_tdi_action_spec_info_get(dev, spec_id, action_node);
}

static int
cpfl_tdi_action_spec_field_info_get(struct rte_eth_dev *dev __rte_unused,
				    struct cpfl_tdi_action_node *anode,
				    uint32_t field_id,
				    struct cpfl_tdi_action_spec_field_info **info)
{
	int ret = -EINVAL;
	int i, j;

	if (anode->format == NULL)
		goto err;

	for (i = 0; i < anode->format->immediate_field_num; i++) {
		struct cpfl_tdi_immediate_field *field = &anode->format->immediate_fields[i];
		struct cpfl_tdi_action_spec_field_info *asfinfo;

		if (field->param_handle != field_id)
			continue;

		asfinfo = rte_malloc(NULL, sizeof(struct cpfl_tdi_action_spec_field_info), 0);
		if (asfinfo == NULL) {
			ret = -ENOMEM;
			goto err;
		}

		asfinfo->field = field;
		asfinfo->param = anode->params[i];

		for (j = 0; j < anode->format->mod_content_format.mod_field_num; j++) {
			struct cpfl_tdi_mod_field *mod_field =
			    &anode->format->mod_content_format.mod_fields[j];

			if (mod_field->type != CPFL_TDI_MOD_FIELD_TYPE_PARAMETER)
				continue;

			if (mod_field->param_handle != field_id)
				continue;

			asfinfo->mod_field = mod_field;
		}

		for (i = 0; i < anode->format->hw_action_num; i++) {
			struct cpfl_tdi_hw_action *hw_action = &anode->format->hw_actions_list[i];

			if (hw_action->parameter_num == 0)
				continue;

			if (hw_action->parameters[0].param_handle != field_id)
				continue;

			asfinfo->hw_action = hw_action;
		}

		*info = asfinfo;

		return 0;
	}
	PMD_DRV_LOG(WARNING, "No immediate_field_num!!!");
err:
	return ret;
}

static int
_cpfl_tdi_action_field_set(struct rte_eth_dev *dev __rte_unused,
			   struct cpfl_tdi_action_obj *aobj,
			   struct cpfl_tdi_action_spec_field_info *asfinfo,
			   const uint8_t *value,
			   uint16_t size)
{
	struct cpfl_tdi_action_node *node = aobj->node;
	struct cpfl_tdi_param_info *pi = &asfinfo->param;
	uint8_t val_buf[CPFL_TDI_VALUE_SIZE_MAX] = {0};
	uint8_t msk_buf[CPFL_TDI_VALUE_SIZE_MAX] = {0};

	rte_memcpy(val_buf, value, size);

	if (node->format->mod_content_format.mod_field_num > 0) {
		struct cpfl_tdi_mod_field *mf = asfinfo->mod_field;

		cpfl_tdi_shift_left(val_buf, pi->size, mf->start_bit_offset);
		cpfl_tdi_init_msk_buf(msk_buf, pi->size, mf->bit_width);
		cpfl_tdi_shift_left(msk_buf, pi->size, mf->start_bit_offset);
		cpfl_tdi_or_buf(&aobj->buf[pi->offset], pi->size, val_buf, msk_buf);
	} else {
		struct cpfl_tdi_hw_action *ha = asfinfo->hw_action;
		uint32_t action_code = cpfl_tdi_to_action_code(ha, val_buf);

		rte_memcpy(&aobj->buf[pi->offset], &action_code, 4);
	}

	return 0;
}

static int
cpfl_tdi_action_field_set(struct rte_eth_dev *dev,
			  struct cpfl_tdi_action_obj *aobj,
			  struct cpfl_tdi_action_node *action_node,
			  uint32_t field_id,
			  const struct rte_flow_action_prog_argument *arg)
{
	struct cpfl_tdi_action_spec_field_info *asfinfo;
	enum rte_flow_action_type action_type;
	/* used when action is PORT_REPRESENTOR type */
	struct cpfl_itf *dst_itf;
	uint16_t dev_id; /* vsi id */
	uint8_t value;
	bool is_vsi;
	int ret;

	if (!aobj || !arg)
		return -EINVAL;

	ret = cpfl_tdi_action_spec_field_info_get(dev, action_node, field_id, &asfinfo);
	if (ret != 0)
		return -EINVAL;

	if (!strcmp(arg->name, "port_representor"))
		action_type = RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR;
	else if (!strcmp(arg->name, "represented_port"))
		action_type = RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT;
	else
		return _cpfl_tdi_action_field_set(dev, aobj, asfinfo, arg->value, arg->size);

	if (arg->size != 1)
		return -EINVAL;

	dst_itf = cpfl_get_itf_by_port_id(arg->value[0]);
	if (!dst_itf)
		goto err;

	is_vsi = (action_type == RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR ||
		  dst_itf->type == CPFL_ITF_TYPE_REPRESENTOR);
	if (is_vsi)
		dev_id = cpfl_get_vsi_id(dst_itf);
	else
		dev_id = cpfl_get_port_id(dst_itf);

	if (dev_id == CPFL_INVALID_HW_ID)
		goto err;

	value = (uint8_t)dev_id;

	return _cpfl_tdi_action_field_set(dev, aobj, asfinfo, &value, arg->size);
err:
	PMD_DRV_LOG(ERR, "Can not get dev id.");
	return -EINVAL;

	return 0;
}

int
cpfl_tdi_build(struct cpfl_flow_parser *flow_parser)
{
	int ret;

	ret = cpfl_tdi_build_table_list(flow_parser);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to build tdi table list");
		return ret;
	}

	ret = cpfl_tdi_build_action_list(flow_parser);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "Failed to build tdi action list");
		cpfl_tdi_free_table_list(flow_parser);
		return ret;
	}

	return 0;
}

static bool
cpfl_flow_items_all_is_flex(const struct rte_flow_item pattern[])
{
	int i;

	for (i = 0; pattern[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
		if (pattern[i].type != RTE_FLOW_ITEM_TYPE_FLEX)
			return false;
	}
	return true;
}

static void
cpfl_fill_rinfo_default_value(struct cpfl_tdi_rule_info *rinfo)
{
	if (cpfl_tdi_rule_cookie == ~0llu)
		cpfl_tdi_rule_cookie = CPFL_COOKIE_DEF;
	rinfo->cookie = cpfl_tdi_rule_cookie++;
	rinfo->host_id = CPFL_HOST_ID_DEF;
	rinfo->port_num = CPFL_PORT_NUM_DEF;
	rinfo->resp_req = CPFL_RESP_REQ_DEF;
	rinfo->vsi = CPFL_VSI_DEF;
	rinfo->clear_mirror_1st_state = CPFL_CLEAR_MIRROR_1ST_STATE_DEF;
}

static int
cpfl_tdi_parse_pattern(struct rte_eth_dev *dev,
		       const struct rte_flow_item pattern[],
		       uint32_t table_id,
		       struct cpfl_tdi_table_node **table_node,
		       struct cpfl_tdi_table_key_obj *kobj)
{
	const struct rte_flow_item_flex *flex;
	int i, ret;

	/* Create the key */
	ret = cpfl_tdi_table_key_create(dev, table_id, table_node, kobj);
	if (ret) {
		PMD_INIT_LOG(ERR, "Failed to create table key obj.");
		return -EINVAL;
	}

	for (i = 0; pattern[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
		if (pattern[i].type != RTE_FLOW_ITEM_TYPE_FLEX) {
			PMD_INIT_LOG(ERR, "All pattern type should be RTE_FLOW_ITEM_TYPE_FLEX.");
			return -EINVAL;
		}
		flex = pattern[i].spec;
		/* Set the key fields */
		ret = cpfl_tdi_table_key_field_set(dev, *table_node, kobj, i, flex->pattern,
						   flex->length);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to set table key field.");
			return -EINVAL;
		}
	}
	return 0;
}

static int
cpfl_tdi_parse_action(struct rte_eth_dev *dev,
		      const struct rte_flow_action actions[],
		      uint32_t table_id,
		      struct cpfl_tdi_table_node *table_node,
		      struct cpfl_tdi_action_node **action_node,
		      struct cpfl_tdi_action_obj *aobj)
{
	const struct rte_flow_action_prog *prog;
	const struct rte_flow_action_prog_argument *arg;
	uint32_t action_spec_id;
	int i, ret;
	uint32_t j;

	for (i = 0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
		if (actions[i].type != RTE_FLOW_ACTION_TYPE_PROG)
			continue;

		prog = actions[i].conf;
		action_spec_id = atoi(prog->name);
		/* Get action node */
		ret =
		    cpfl_tdi_action_node_get_by_spec_id(dev, table_id, action_spec_id, action_node);
		if (ret) {
			PMD_INIT_LOG(ERR, "Failed to get action node.");
			return -EINVAL;
		}

		ret = cpfl_tdi_action_obj_init(dev, table_node, *action_node, aobj);
		if (ret != 0) {
			PMD_INIT_LOG(ERR, "Failed to init action obj.");
			return -EINVAL;
		}

		for (j = 0; j < prog->args_num; j++) {
			arg = &prog->args[j];
			/* Set the action fields */
			ret = cpfl_tdi_action_field_set(dev, aobj, *action_node, j, arg);
			if (ret) {
				PMD_INIT_LOG(ERR, "Failed to set action field.");
				return -EINVAL;
			}
		}
	}
	return 0;
}

static int
cpfl_tdi_parse_pattern_action(struct rte_eth_dev *dev,
			      const struct rte_flow_attr *attr,
			      const struct rte_flow_item pattern[],
			      const struct rte_flow_action actions[],
			      void **meta)
{
	struct cpfl_itf *itf = CPFL_DEV_TO_ITF(dev);
	struct cpfl_adapter_ext *adapter = itf->adapter;
	int ret;
	struct cpfl_tdi_rule_info *rinfo;
	struct cpfl_tdi_table_node *table_node;
	struct cpfl_tdi_action_node *action_node;
	struct cpfl_tdi_table_key_obj *kobj;
	struct cpfl_tdi_action_obj *aobj;
	uint32_t table_id = attr->group;

	if (!adapter->flow_parser.is_p4_parser || !cpfl_flow_items_all_is_flex(pattern))
		return -EINVAL;

	rinfo = rte_zmalloc(NULL, sizeof(struct cpfl_tdi_rule_info), 0);
	if (!rinfo)
		return -ENOMEM;

	kobj = &rinfo->kobj;
	aobj = &rinfo->aobj;
	memset(kobj, 0, sizeof(struct cpfl_tdi_table_key_obj));
	memset(aobj, 0, sizeof(struct cpfl_tdi_action_obj));

	ret = cpfl_tdi_parse_pattern(dev, pattern, table_id, &table_node, kobj);
	if (ret) {
		PMD_DRV_LOG(ERR, "Invalid pattern");
		rte_free(rinfo);
		return -EINVAL;
	}

	ret = cpfl_tdi_parse_action(dev, actions, table_id, table_node, &action_node, aobj);
	if (ret) {
		PMD_DRV_LOG(ERR, "Invalid action");
		rte_free(rinfo);
		return -EINVAL;
	}

	cpfl_fill_rinfo_default_value(rinfo);
	if (!meta)
		rte_free(rinfo);
	else
		*meta = rinfo;

	return 0;
}

static int
cpfl_tdi_fxp_init(struct cpfl_adapter_ext *ad __rte_unused)
{
	return 0;
}

static void
cpfl_tdi_fxp_uninit(struct cpfl_adapter_ext *ad __rte_unused)
{
}

static struct cpfl_flow_engine cpfl_tdi_engine = {
	.type = CPFL_FLOW_ENGINE_TDI,
	.init = cpfl_tdi_fxp_init,
	.uninit = cpfl_tdi_fxp_uninit,
	.create = cpfl_tdi_fxp_rule_create,
	.destroy = cpfl_tdi_fxp_rule_destroy,
	.parse_pattern_action = cpfl_tdi_parse_pattern_action,
};

RTE_INIT(cpfl_sw_engine_init)
{
	struct cpfl_flow_engine *engine = &cpfl_tdi_engine;

	cpfl_flow_engine_register(engine);
}
