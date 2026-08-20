/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include "i40e_ethdev.h"
#include "i40e_flow.h"

#include "../common/flow_engine.h"
#include "../common/flow_check.h"
#include "../common/flow_util.h"

struct i40e_tunnel_ctx {
	struct ci_flow_engine_ctx base;
	struct i40e_tunnel_filter_conf filter;
};

struct i40e_tunnel_flow {
	struct rte_flow base;
	struct i40e_tunnel_filter_conf filter;
};

/**
 * QinQ tunnel filter graph implementation
 * Pattern: START -> ETH -> OUTER_VLAN -> INNER_VLAN -> END
 */
enum i40e_tunnel_qinq_node_id {
	I40E_TUNNEL_QINQ_NODE_START = RTE_FLOW_NODE_FIRST,
	I40E_TUNNEL_QINQ_NODE_ETH,
	I40E_TUNNEL_QINQ_NODE_OUTER_VLAN,
	I40E_TUNNEL_QINQ_NODE_INNER_VLAN,
	I40E_TUNNEL_QINQ_NODE_END,
	I40E_TUNNEL_QINQ_NODE_MAX,
};

static int
i40e_tunnel_node_vlan_validate(const void *ctx __rte_unused, const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_vlan *vlan_mask = item->mask;

	/* matching eth proto not supported */
	if (vlan_mask->hdr.eth_proto) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid VLAN mask");
	}

	/* VLAN TCI must be fully masked */
	if (!CI_FIELD_IS_MASKED(&vlan_mask->hdr.vlan_tci)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid VLAN mask");
	}

	return 0;
}

/* common VLAN processing for both outer and inner VLAN nodes */
static int
i40e_tunnel_node_vlan_process(struct i40e_tunnel_ctx *tunnel_ctx,
		const struct rte_flow_item *item, bool is_inner)
{
	const struct rte_flow_item_vlan *vlan_spec = item->spec;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	/* Store the VLAN ID and set filter flag */
	if (is_inner) {
		tunnel_filter->inner_vlan = rte_be_to_cpu_16(vlan_spec->hdr.vlan_tci);
		tunnel_filter->filter_type |= RTE_ETH_TUNNEL_FILTER_IVLAN;
	} else {
		tunnel_filter->outer_vlan = rte_be_to_cpu_16(vlan_spec->hdr.vlan_tci);
		/* no special flag for outer VLAN matching */
	}

	return 0;
}

static int
i40e_tunnel_node_outer_vlan_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;

	return i40e_tunnel_node_vlan_process(tunnel_ctx, item, false);
}

static int
i40e_tunnel_node_inner_vlan_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;

	return i40e_tunnel_node_vlan_process(tunnel_ctx, item, true);
}

static int
i40e_tunnel_qinq_node_end_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tunnel_type = I40E_TUNNEL_TYPE_QINQ;

	/* QinQ filter is not meant to set this flag */
	tunnel_filter->filter_type &= ~RTE_ETH_TUNNEL_FILTER_IVLAN;

	return 0;
}

static const struct rte_flow_graph i40e_tunnel_qinq_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[I40E_TUNNEL_QINQ_NODE_START] = {
			.name = "START",
		},
		[I40E_TUNNEL_QINQ_NODE_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[I40E_TUNNEL_QINQ_NODE_OUTER_VLAN] = {
			.name = "OUTER_VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_vlan_validate,
			.process = i40e_tunnel_node_outer_vlan_process,
		},
		[I40E_TUNNEL_QINQ_NODE_INNER_VLAN] = {
			.name = "INNER_VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_vlan_validate,
			.process = i40e_tunnel_node_inner_vlan_process,
		},
		[I40E_TUNNEL_QINQ_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
			.process = i40e_tunnel_qinq_node_end_process,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[I40E_TUNNEL_QINQ_NODE_START] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_QINQ_NODE_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_QINQ_NODE_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_QINQ_NODE_OUTER_VLAN,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_QINQ_NODE_OUTER_VLAN] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_QINQ_NODE_INNER_VLAN,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_QINQ_NODE_INNER_VLAN] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_QINQ_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

static int
i40e_tunnel_action_check(const struct ci_flow_actions *actions,
		const struct ci_flow_actions_check_param *param,
		struct rte_flow_error *error)
{
	struct i40e_pf *pf = I40E_DEV_PRIVATE_TO_PF(param->driver_ctx);
	const struct rte_flow_action *first, *second;
	const struct rte_flow_action_queue *act_q;
	bool is_to_vf = false;

	first = actions->actions[0];
	/* can be NULL */
	second = actions->actions[1];

	/* first action must be PF or VF */
	if (first->type == RTE_FLOW_ACTION_TYPE_VF) {
		const struct rte_flow_action_vf *vf = first->conf;
		if (vf->id >= pf->vf_num) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION, first,
					"Invalid VF ID for tunnel filter");
		}
		is_to_vf = true;
	} else if (first->type != RTE_FLOW_ACTION_TYPE_PF) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, first,
				"Unsupported action");
	}

	/* check if second action is QUEUE */
	if (second == NULL)
		return 0;

	if (second->type != RTE_FLOW_ACTION_TYPE_QUEUE) {
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION, second,
					  "Unsupported action");
	}

	act_q = second->conf;
	/* check queue ID for PF flow */
	if (!is_to_vf && act_q->index >= pf->dev_data->nb_rx_queues) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF, act_q,
				"Invalid queue ID for tunnel filter");
	}
	/* check queue ID for VF flow */
	if (is_to_vf && act_q->index >= pf->vf_nb_qps) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF, act_q,
				"Invalid queue ID for tunnel filter");
	}

	return 0;
}

static int
i40e_tunnel_ctx_parse(const struct rte_flow_action actions[],
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct i40e_tunnel_ctx *tunnel_ctx = (struct i40e_tunnel_ctx *)ctx;
	struct ci_flow_actions parsed_actions = {0};
	struct ci_flow_actions_check_param ac_param = {
		.allowed_types = (enum rte_flow_action_type[]) {
			RTE_FLOW_ACTION_TYPE_QUEUE,
			RTE_FLOW_ACTION_TYPE_PF,
			RTE_FLOW_ACTION_TYPE_VF,
			RTE_FLOW_ACTION_TYPE_END
		},
		.max_actions = 2,
		.check = i40e_tunnel_action_check,
		.driver_ctx = ctx->dev_data->dev_private,
	};
	const struct rte_flow_action *first, *second;
	const struct rte_flow_action_queue *act_q;
	int ret;

	ret = ci_flow_check_attr(attr, NULL, error);
	if (ret)
		return ret;

	ret = ci_flow_check_actions(actions, &ac_param, &parsed_actions, error);
	if (ret)
		return ret;

	first = parsed_actions.actions[0];
	/* can be NULL */
	second = parsed_actions.actions[1];

	if (first->type == RTE_FLOW_ACTION_TYPE_VF) {
		const struct rte_flow_action_vf *vf = first->conf;
		tunnel_ctx->filter.vf_id = vf->id;
		tunnel_ctx->filter.is_to_vf = 1;
	} else if (first->type == RTE_FLOW_ACTION_TYPE_PF) {
		tunnel_ctx->filter.is_to_vf = 0;
	}

	/* check if second action is QUEUE */
	if (second == NULL)
		return 0;

	act_q = second->conf;
	tunnel_ctx->filter.queue_id = act_q->index;

	return 0;
}

static int
i40e_tunnel_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct i40e_tunnel_ctx *tunnel_ctx = (const struct i40e_tunnel_ctx *)ctx;
	struct i40e_tunnel_flow *tunnel_flow = (struct i40e_tunnel_flow *)flow;

	/* copy filter configuration from context to flow */
	tunnel_flow->filter = tunnel_ctx->filter;

	return 0;
}

static int
i40e_tunnel_flow_install(struct ci_flow *flow, struct rte_flow_error *error)
{
	struct i40e_pf *pf = I40E_DEV_PRIVATE_TO_PF(flow->dev_data->dev_private);
	struct i40e_tunnel_flow *tunnel_flow = (struct i40e_tunnel_flow *)flow;
	int ret;

	ret = i40e_dev_consistent_tunnel_filter_set(pf, &tunnel_flow->filter, 1);
	if (ret) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to install tunnel filter");
	}
	return 0;
}

static int
i40e_tunnel_flow_uninstall(struct ci_flow *flow, struct rte_flow_error *error)
{
	struct i40e_pf *pf = I40E_DEV_PRIVATE_TO_PF(flow->dev_data->dev_private);
	struct i40e_tunnel_flow *tunnel_flow = (struct i40e_tunnel_flow *)flow;
	int ret;

	ret = i40e_dev_consistent_tunnel_filter_set(pf, &tunnel_flow->filter, 0);
	if (ret) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to uninstall tunnel filter");
	}
	return 0;
}

static const struct ci_flow_engine_ops i40e_flow_engine_tunnel_ops = {
	.ctx_parse = i40e_tunnel_ctx_parse,
	.ctx_to_flow = i40e_tunnel_ctx_to_flow,
	.flow_install = i40e_tunnel_flow_install,
	.flow_uninstall = i40e_tunnel_flow_uninstall,
};

const struct ci_flow_engine i40e_flow_engine_tunnel_qinq = {
	.name = "tunnel_qinq",
	.ops = &i40e_flow_engine_tunnel_ops,
	.ctx_size = sizeof(struct i40e_tunnel_ctx),
	.flow_size = sizeof(struct i40e_tunnel_flow),
	.graph = &i40e_tunnel_qinq_graph,
};
