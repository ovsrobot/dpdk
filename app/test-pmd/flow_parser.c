/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 6WIND S.A.
 * Copyright 2016 Mellanox Technologies, Ltd
 * Copyright 2026 DynaNIC Semiconductors, Ltd.
 */

#include <string.h>

#include <rte_flow.h>
#include <rte_flow_parser_cmdline.h>

#include "testpmd.h"

static const struct tunnel_ops *
parser_tunnel_convert(const struct rte_flow_parser_tunnel_ops *src,
		      struct tunnel_ops *dst)
{
	if (src == NULL)
		return NULL;
	memset(dst, 0, sizeof(*dst));
	dst->id = src->id;
	strlcpy(dst->type, src->type, sizeof(dst->type));
	dst->enabled = src->enabled;
	dst->actions = src->actions;
	dst->items = src->items;
	return dst;
}

/** Dispatch a parsed flow command to testpmd port_flow_* functions. */
void
testpmd_flow_dispatch(const struct rte_flow_parser_output *in)
{
	struct tunnel_ops tops;

	switch (in->command) {
	case RTE_FLOW_PARSER_CMD_INFO:
		port_flow_get_info(in->port);
		break;
	case RTE_FLOW_PARSER_CMD_CONFIGURE:
		port_flow_configure(in->port,
				    &in->args.configure.port_attr,
				    in->args.configure.nb_queue,
				    &in->args.configure.queue_attr);
		break;
	case RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_CREATE:
		port_flow_pattern_template_create(in->port,
			in->args.vc.pat_templ_id,
			&((const struct rte_flow_pattern_template_attr) {
				.relaxed_matching = in->args.vc.attr.reserved,
				.ingress = in->args.vc.attr.ingress,
				.egress = in->args.vc.attr.egress,
				.transfer = in->args.vc.attr.transfer,
			}),
			in->args.vc.pattern);
		break;
	case RTE_FLOW_PARSER_CMD_PATTERN_TEMPLATE_DESTROY:
		port_flow_pattern_template_destroy(in->port,
			in->args.templ_destroy.template_id_n,
			in->args.templ_destroy.template_id);
		break;
	case RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_CREATE:
		port_flow_actions_template_create(in->port,
			in->args.vc.act_templ_id,
			&((const struct rte_flow_actions_template_attr) {
				.ingress = in->args.vc.attr.ingress,
				.egress = in->args.vc.attr.egress,
				.transfer = in->args.vc.attr.transfer,
			}),
			in->args.vc.actions,
			in->args.vc.masks);
		break;
	case RTE_FLOW_PARSER_CMD_ACTIONS_TEMPLATE_DESTROY:
		port_flow_actions_template_destroy(in->port,
			in->args.templ_destroy.template_id_n,
			in->args.templ_destroy.template_id);
		break;
	case RTE_FLOW_PARSER_CMD_TABLE_CREATE:
		port_flow_template_table_create(in->port,
			in->args.table.id, &in->args.table.attr,
			in->args.table.pat_templ_id_n,
			in->args.table.pat_templ_id,
			in->args.table.act_templ_id_n,
			in->args.table.act_templ_id);
		break;
	case RTE_FLOW_PARSER_CMD_TABLE_DESTROY:
		port_flow_template_table_destroy(in->port,
			in->args.table_destroy.table_id_n,
			in->args.table_destroy.table_id);
		break;
	case RTE_FLOW_PARSER_CMD_TABLE_RESIZE_COMPLETE:
		port_flow_template_table_resize_complete(in->port,
			in->args.table_destroy.table_id[0]);
		break;
	case RTE_FLOW_PARSER_CMD_GROUP_SET_MISS_ACTIONS:
		port_queue_group_set_miss_actions(in->port,
			&in->args.vc.attr, in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_TABLE_RESIZE:
		port_flow_template_table_resize(in->port,
			in->args.table.id,
			in->args.table.attr.nb_flows);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_CREATE:
		port_queue_flow_create(in->port, in->queue,
			in->postpone, in->args.vc.table_id,
			in->args.vc.rule_id, in->args.vc.pat_templ_id,
			in->args.vc.act_templ_id,
			in->args.vc.pattern, in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_DESTROY:
		port_queue_flow_destroy(in->port, in->queue,
			in->postpone, in->args.destroy.rule_n,
			in->args.destroy.rule);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_FLOW_UPDATE_RESIZED:
		port_queue_flow_update_resized(in->port, in->queue,
			in->postpone,
			(uint32_t)in->args.destroy.rule[0]);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_UPDATE:
		port_queue_flow_update(in->port, in->queue,
			in->postpone, in->args.vc.rule_id,
			in->args.vc.act_templ_id, in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_PUSH:
		port_queue_flow_push(in->port, in->queue);
		break;
	case RTE_FLOW_PARSER_CMD_PULL:
		port_queue_flow_pull(in->port, in->queue);
		break;
	case RTE_FLOW_PARSER_CMD_HASH:
		if (in->args.vc.encap_hash == 0)
			port_flow_hash_calc(in->port,
				in->args.vc.table_id,
				in->args.vc.pat_templ_id,
				in->args.vc.pattern);
		else
			port_flow_hash_calc_encap(in->port,
				in->args.vc.field,
				in->args.vc.pattern);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_AGED:
		port_queue_flow_aged(in->port, in->queue,
			in->args.aged.destroy);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_CREATE:
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE:
		port_queue_action_handle_create(in->port, in->queue,
			in->postpone, in->args.vc.attr.group,
			in->command == RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_LIST_CREATE,
			&((const struct rte_flow_indir_action_conf) {
				.ingress = in->args.vc.attr.ingress,
				.egress = in->args.vc.attr.egress,
				.transfer = in->args.vc.attr.transfer,
			}),
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_DESTROY:
		port_queue_action_handle_destroy(in->port, in->queue,
			in->postpone, in->args.ia_destroy.action_id_n,
			in->args.ia_destroy.action_id);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_UPDATE:
		port_queue_action_handle_update(in->port, in->queue,
			in->postpone, in->args.vc.attr.group,
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY:
		port_queue_action_handle_query(in->port, in->queue,
			in->postpone, in->args.ia.action_id);
		break;
	case RTE_FLOW_PARSER_CMD_QUEUE_INDIRECT_ACTION_QUERY_UPDATE:
		port_queue_action_handle_query_update(in->port,
			in->queue, in->postpone,
			in->args.ia.action_id, in->args.ia.qu_mode,
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_CREATE:
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE:
		port_action_handle_create(in->port,
			in->args.vc.attr.group,
			in->command == RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_LIST_CREATE,
			&((const struct rte_flow_indir_action_conf) {
				.ingress = in->args.vc.attr.ingress,
				.egress = in->args.vc.attr.egress,
				.transfer = in->args.vc.attr.transfer,
			}),
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_DESTROY:
		port_action_handle_destroy(in->port,
			in->args.ia_destroy.action_id_n,
			in->args.ia_destroy.action_id);
		break;
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_UPDATE:
		port_action_handle_update(in->port,
			in->args.vc.attr.group, in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY:
		port_action_handle_query(in->port,
			in->args.ia.action_id);
		break;
	case RTE_FLOW_PARSER_CMD_INDIRECT_ACTION_QUERY_UPDATE:
		port_action_handle_query_update(in->port,
			in->args.ia.action_id, in->args.ia.qu_mode,
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_VALIDATE:
		port_flow_validate(in->port, &in->args.vc.attr,
			in->args.vc.pattern, in->args.vc.actions,
			parser_tunnel_convert(
				(const struct rte_flow_parser_tunnel_ops *)
				&in->args.vc.tunnel_ops, &tops));
		break;
	case RTE_FLOW_PARSER_CMD_CREATE:
		port_flow_create(in->port, &in->args.vc.attr,
			in->args.vc.pattern, in->args.vc.actions,
			parser_tunnel_convert(
				(const struct rte_flow_parser_tunnel_ops *)
				&in->args.vc.tunnel_ops, &tops),
			in->args.vc.user_id);
		break;
	case RTE_FLOW_PARSER_CMD_DESTROY:
		port_flow_destroy(in->port,
			in->args.destroy.rule_n,
			in->args.destroy.rule,
			in->args.destroy.is_user_id);
		break;
	case RTE_FLOW_PARSER_CMD_UPDATE:
		port_flow_update(in->port, in->args.vc.rule_id,
			in->args.vc.actions, in->args.vc.is_user_id);
		break;
	case RTE_FLOW_PARSER_CMD_FLUSH:
		port_flow_flush(in->port);
		break;
	case RTE_FLOW_PARSER_CMD_DUMP_ONE:
	case RTE_FLOW_PARSER_CMD_DUMP_ALL:
		port_flow_dump(in->port, in->args.dump.mode,
			in->args.dump.rule, in->args.dump.file,
			in->args.dump.is_user_id);
		break;
	case RTE_FLOW_PARSER_CMD_QUERY:
		port_flow_query(in->port, in->args.query.rule,
			&in->args.query.action,
			in->args.query.is_user_id);
		break;
	case RTE_FLOW_PARSER_CMD_LIST:
		port_flow_list(in->port, in->args.list.group_n,
			in->args.list.group);
		break;
	case RTE_FLOW_PARSER_CMD_ISOLATE:
		port_flow_isolate(in->port, in->args.isolate.set);
		break;
	case RTE_FLOW_PARSER_CMD_AGED:
		port_flow_aged(in->port, (uint8_t)in->args.aged.destroy);
		break;
	case RTE_FLOW_PARSER_CMD_TUNNEL_CREATE:
		port_flow_tunnel_create(in->port,
			parser_tunnel_convert(
				(const struct rte_flow_parser_tunnel_ops *)
				&in->args.vc.tunnel_ops, &tops));
		break;
	case RTE_FLOW_PARSER_CMD_TUNNEL_DESTROY:
		port_flow_tunnel_destroy(in->port,
			in->args.vc.tunnel_ops.id);
		break;
	case RTE_FLOW_PARSER_CMD_TUNNEL_LIST:
		port_flow_tunnel_list(in->port);
		break;
	case RTE_FLOW_PARSER_CMD_ACTION_POL_G:
		port_meter_policy_add(in->port,
			in->args.policy.policy_id,
			in->args.vc.actions);
		break;
	case RTE_FLOW_PARSER_CMD_FLEX_ITEM_CREATE:
		flex_item_create(in->port,
			in->args.flex.token, in->args.flex.filename);
		break;
	case RTE_FLOW_PARSER_CMD_FLEX_ITEM_DESTROY:
		flex_item_destroy(in->port, in->args.flex.token);
		break;
	default:
		fprintf(stderr, "unhandled flow parser command %d\n",
			in->command);
		break;
	}
	fflush(stdout);
}
