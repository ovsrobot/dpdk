/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include <rte_flow.h>
#include <rte_flow_graph.h>
#include <rte_ether.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_flow.h"
#include "../common/flow_check.h"
#include "../common/flow_util.h"
#include "../common/flow_engine.h"

struct ixgbe_ethertype_flow {
	struct rte_flow flow;
	struct rte_eth_ethertype_filter filter;
};

struct ixgbe_ethertype_ctx {
	struct ci_flow_engine_ctx base;
	struct rte_eth_ethertype_filter filter;
};

/**
 * Ethertype filter graph implementation
 * Pattern: START -> ETH -> END
 */

enum ixgbe_ethertype_node_id {
	IXGBE_ETHERTYPE_NODE_START = RTE_FLOW_NODE_FIRST,
	IXGBE_ETHERTYPE_NODE_ETH,
	IXGBE_ETHERTYPE_NODE_END,
	IXGBE_ETHERTYPE_NODE_MAX,
};

static int
ixgbe_ethertype_node_eth_validate(const void *ctx __rte_unused,
				  const struct rte_flow_item *item,
				  struct rte_flow_error *error)
{
	const struct rte_flow_item_eth *eth_spec;
	const struct rte_flow_item_eth *eth_mask;

	eth_spec = item->spec;
	eth_mask = item->mask;

	/* Source MAC mask must be all zeros */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.src_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Source MAC filtering not supported");
	}

	/* Dest MAC mask must be all zeros */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Destination MAC filtering not supported");
	}

	/* Ethertype mask must be exact match */
	if (!CI_FIELD_IS_MASKED(&eth_mask->hdr.ether_type)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Ethertype must be exactly matched");
	}

	/* IPv4/IPv6 ethertypes not supported by hardware */
	uint16_t ether_type = rte_be_to_cpu_16(eth_spec->hdr.ether_type);
	if (ether_type == RTE_ETHER_TYPE_IPV4 || ether_type == RTE_ETHER_TYPE_IPV6) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"IPv4/IPv6 not supported by ethertype filter");
	}

	return 0;
}

static int
ixgbe_ethertype_node_eth_process(void *ctx,
				 const struct rte_flow_item *item,
				 struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_ethertype_ctx *graph_ctx = ctx;
	const struct rte_flow_item_eth *eth_spec = item->spec;

	graph_ctx->filter.ether_type = rte_be_to_cpu_16(eth_spec->hdr.ether_type);

	return 0;
}

static const struct rte_flow_graph ixgbe_ethertype_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[IXGBE_ETHERTYPE_NODE_START] = {
			.name = "START",
		},
		[IXGBE_ETHERTYPE_NODE_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_ethertype_node_eth_validate,
			.process = ixgbe_ethertype_node_eth_process,
		},
		[IXGBE_ETHERTYPE_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[IXGBE_ETHERTYPE_NODE_START] = {
			.next = (const size_t[]) {
				IXGBE_ETHERTYPE_NODE_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_ETHERTYPE_NODE_ETH] = {
			.next = (const size_t[]) {
				IXGBE_ETHERTYPE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

static int
ixgbe_flow_ethertype_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ci_flow_actions parsed_actions;
	struct ci_flow_actions_check_param ap_param = {
		.allowed_types = (const enum rte_flow_action_type[]){
			/* only queue is allowed here */
			RTE_FLOW_ACTION_TYPE_QUEUE,
			RTE_FLOW_ACTION_TYPE_END
		},
		.max_actions = 1,
		.driver_ctx = ctx->dev_data,
		.check = ixgbe_flow_actions_check
	};
	struct ixgbe_ethertype_ctx *ethertype_ctx = (struct ixgbe_ethertype_ctx *)ctx;
	const struct rte_flow_action_queue *q_act;
	int ret;

	/* validate attributes */
	ret = ci_flow_check_attr(attr, NULL, error);
	if (ret)
		return ret;

	/* parse requested actions */
	ret = ci_flow_check_actions(actions, &ap_param, &parsed_actions, error);
	if (ret)
		return ret;

	q_act = (const struct rte_flow_action_queue *)parsed_actions.actions[0]->conf;

	/* set up filter action */
	ethertype_ctx->filter.queue = q_act->index;

	return 0;
}

static int
ixgbe_flow_ethertype_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct ixgbe_ethertype_ctx *ethertype_ctx = (const struct ixgbe_ethertype_ctx *)ctx;
	struct ixgbe_ethertype_flow *ethertype_flow = (struct ixgbe_ethertype_flow *)flow;

	/* copy filter configuration */
	ethertype_flow->filter = ethertype_ctx->filter;

	return 0;
}

static int
ixgbe_flow_ethertype_install(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_ethertype_flow *ethertype_flow = (struct ixgbe_ethertype_flow *)flow;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	int ret;

	ret = ixgbe_add_del_ethertype_filter(adapter, &ethertype_flow->filter, TRUE);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to add ethertype filter");
	}
	return ret;
}

static int
ixgbe_flow_ethertype_uninstall(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_ethertype_flow *ethertype_flow = (struct ixgbe_ethertype_flow *)flow;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	int ret;

	ret = ixgbe_add_del_ethertype_filter(adapter, &ethertype_flow->filter, FALSE);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to delete ethertype filter");
	}
	return ret;
}

static int
ixgbe_flow_ethertype_engine_init(const struct ci_flow_engine *engine __rte_unused,
		struct rte_eth_dev_data *dev_data,
		void *priv __rte_unused)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev_data->dev_private);

	if (hw->mac.type == ixgbe_mac_82599EB ||
			hw->mac.type == ixgbe_mac_X540 ||
			hw->mac.type == ixgbe_mac_X550 ||
			hw->mac.type == ixgbe_mac_X550EM_x ||
			hw->mac.type == ixgbe_mac_X550EM_a ||
			hw->mac.type == ixgbe_mac_E610)
		return 0;

	return -ENOTSUP;
}

static const struct ci_flow_engine_ops ixgbe_ethertype_ops = {
	.engine_init = ixgbe_flow_ethertype_engine_init,
	.ctx_parse = ixgbe_flow_ethertype_ctx_parse,
	.ctx_to_flow = ixgbe_flow_ethertype_ctx_to_flow,
	.flow_install = ixgbe_flow_ethertype_install,
	.flow_uninstall = ixgbe_flow_ethertype_uninstall,
};

const struct ci_flow_engine ixgbe_ethertype_flow_engine = {
	.name = "ethertype",
	.ctx_size = sizeof(struct ixgbe_ethertype_ctx),
	.flow_size = sizeof(struct ixgbe_ethertype_flow),
	.graph = &ixgbe_ethertype_graph,
	.ops = &ixgbe_ethertype_ops,
};
