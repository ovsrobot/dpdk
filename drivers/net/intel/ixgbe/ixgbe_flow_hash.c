/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include <rte_common.h>
#include <rte_flow.h>
#include <rte_flow_graph.h>
#include <rte_ether.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_flow.h"
#include "../common/flow_check.h"
#include "../common/flow_util.h"
#include "../common/flow_engine.h"

struct ixgbe_hash_flow {
	struct rte_flow flow;
	struct ixgbe_rte_flow_rss_conf rss_conf;
};

struct ixgbe_hash_ctx {
	struct ci_flow_engine_ctx base;
	struct ixgbe_rte_flow_rss_conf rss_conf;
};

/* Flow actions check specific to RSS filter */
static int
ixgbe_flow_actions_check_rss(const struct ci_flow_actions *parsed_actions,
		const struct ci_flow_actions_check_param *param,
		struct rte_flow_error *error)
{
	const struct rte_flow_action *action = parsed_actions->actions[0];
	const struct rte_flow_action_rss *rss_act = action->conf;
	const struct rte_eth_dev_data *dev_data = param->driver_ctx;
	const size_t rss_key_len = sizeof(((struct ixgbe_rte_flow_rss_conf *)0)->key);
	unsigned i;

	/* check if queue list is not empty */
	if (rss_act->queue_num == 0) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss_act,
			"RSS queue list is empty");
	}

	/* check if all queues are valid */
	for (i = 0; i < rss_act->queue_num; i++) {
		if (rss_act->queue[i] >= dev_data->nb_rx_queues) {
			return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss_act,
				"Invalid RSS queue specified");
		}
	}

	/* only support default hash function */
	if (rss_act->func != RTE_ETH_HASH_FUNCTION_DEFAULT) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss_act,
			"Non-default RSS hash functions are not supported");
	}
	/* levels aren't supported */
	if (rss_act->level) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss_act,
			"A nonzero RSS encapsulation level is not supported");
	}
	/* check key length */
	if (rss_act->key_len != 0 && rss_act->key_len != rss_key_len) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss_act,
			"RSS key must be exactly 40 bytes long");
	}
	return 0;
}

static int
ixgbe_flow_hash_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ci_flow_actions parsed_actions;
	struct ci_flow_actions_check_param ap_param = {
		.allowed_types = (const enum rte_flow_action_type[]){
			/* only rss allowed here */
			RTE_FLOW_ACTION_TYPE_RSS,
			RTE_FLOW_ACTION_TYPE_END
		},
		.driver_ctx = ctx->dev_data,
		.check = ixgbe_flow_actions_check_rss,
		.max_actions = 1,
	};
	struct ixgbe_hash_ctx *hash_ctx = (struct ixgbe_hash_ctx *)ctx;
	const struct rte_flow_action_rss *rss_conf;
	int ret;

	/* validate attributes */
	ret = ci_flow_check_attr(attr, NULL, error);
	if (ret)
		return ret;

	/* parse requested actions */
	ret = ci_flow_check_actions(actions, &ap_param, &parsed_actions, error);
	if (ret)
		return ret;

	rss_conf = parsed_actions.actions[0]->conf;

	ret = ixgbe_rss_conf_init(&hash_ctx->rss_conf, rss_conf);
	if (ret) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, rss_conf,
				"RSS context initialization failure");
	}

	return 0;
}

static int
ixgbe_flow_hash_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct ixgbe_hash_ctx *hash_ctx = (const struct ixgbe_hash_ctx *)ctx;
	struct ixgbe_hash_flow *hash_flow = (struct ixgbe_hash_flow *)flow;

	hash_flow->rss_conf = hash_ctx->rss_conf;

	return 0;
}

static int
ixgbe_flow_hash_flow_install(struct ci_flow *flow, struct rte_flow_error *error)
{
	struct ixgbe_hash_flow *hash_flow = (struct ixgbe_hash_flow *)flow;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	int ret;

	ret = ixgbe_config_rss_filter(adapter, &hash_flow->rss_conf, TRUE);
	if (ret != 0) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, flow,
				"Failed to install RSS filter");
	}
	return 0;
}

static int
ixgbe_flow_hash_flow_uninstall(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	struct ixgbe_filter_info *filter_info = IXGBE_DEV_PRIVATE_TO_FILTER_INFO(adapter);
	int ret;

	ret = ixgbe_config_rss_filter(adapter, &filter_info->rss_info, FALSE);
	if (ret != 0) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, flow,
				"Failed to uninstall RSS filter");
	}
	return 0;
}

static const struct ci_flow_engine_ops ixgbe_hash_ops = {
	/* RSS engine always available */
	.ctx_parse = ixgbe_flow_hash_ctx_parse,
	.ctx_to_flow = ixgbe_flow_hash_ctx_to_flow,
	.flow_install = ixgbe_flow_hash_flow_install,
	.flow_uninstall = ixgbe_flow_hash_flow_uninstall,
};

const struct ci_flow_engine ixgbe_hash_flow_engine = {
	.name = "hash",
	.ctx_size = sizeof(struct ixgbe_hash_ctx),
	.flow_size = sizeof(struct ixgbe_hash_flow),
	.ops = &ixgbe_hash_ops,
	/* RSS does not accept patterns */
};
