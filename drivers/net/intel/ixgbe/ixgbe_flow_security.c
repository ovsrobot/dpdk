/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#include <rte_common.h>
#include <rte_flow.h>
#include <rte_flow_graph.h>
#include <rte_ether.h>
#include <rte_security_driver.h>

#include "ixgbe_ethdev.h"
#include "ixgbe_flow.h"
#include "../common/flow_check.h"
#include "../common/flow_util.h"
#include "../common/flow_engine.h"

struct ixgbe_security_filter {
	struct ip_spec spec;
	struct rte_security_session *session;
	uint32_t sa_idx;
};

struct ixgbe_security_flow {
	struct rte_flow flow;
	struct ixgbe_security_filter security;
};

struct ixgbe_security_ctx {
	struct ci_flow_engine_ctx base;
	struct ixgbe_security_filter security;
};

/**
 * Ntuple security filter graph implementation
 * Pattern: START -> IPV4 | IPV6 -> END
 */

enum ixgbe_security_node_id {
	IXGBE_SECURITY_NODE_START = RTE_FLOW_NODE_FIRST,
	IXGBE_SECURITY_NODE_IPV4,
	IXGBE_SECURITY_NODE_IPV6,
	IXGBE_SECURITY_NODE_END,
	IXGBE_SECURITY_NODE_MAX,
};

static int
ixgbe_validate_security_ipv4(const void *ctx __rte_unused,
		const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

	/* only src/dst addresses are supported */
	if (ipv4_mask->hdr.version_ihl ||
	    ipv4_mask->hdr.type_of_service ||
	    ipv4_mask->hdr.total_length ||
	    ipv4_mask->hdr.packet_id ||
	    ipv4_mask->hdr.fragment_offset ||
	    ipv4_mask->hdr.next_proto_id ||
	    ipv4_mask->hdr.time_to_live ||
	    ipv4_mask->hdr.hdr_checksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPv4 mask");
	}

	/* both src/dst addresses must be fully masked */
	if (!CI_FIELD_IS_MASKED(&ipv4_mask->hdr.src_addr) ||
	    !CI_FIELD_IS_MASKED(&ipv4_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPv4 mask");
	}

	return 0;
}

static int
ixgbe_process_security_ipv4(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_security_ctx *sec_ctx = (struct ixgbe_security_ctx *)ctx;
	const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;

	/* copy entire spec */
	sec_ctx->security.spec.spec.ipv4 = *ipv4_spec;
	sec_ctx->security.spec.is_ipv6 = false;

	return 0;
}

static int
ixgbe_validate_security_ipv6(const void *ctx __rte_unused,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;

	/* only src/dst addresses are supported */
	if (ipv6_mask->hdr.vtc_flow ||
	    ipv6_mask->hdr.payload_len ||
	    ipv6_mask->hdr.proto ||
	    ipv6_mask->hdr.hop_limits) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPv6 mask");
	}
	/* both src/dst addresses must be fully masked */
	if (!CI_FIELD_IS_MASKED(&ipv6_mask->hdr.src_addr) ||
	    !CI_FIELD_IS_MASKED(&ipv6_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPv6 mask");
	}

	return 0;
}

static int
ixgbe_process_security_ipv6(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_security_ctx *sec_ctx = (struct ixgbe_security_ctx *)ctx;
	const struct rte_flow_item_ipv6 *ipv6_spec = item->spec;

	/* copy entire spec */
	sec_ctx->security.spec.spec.ipv6 = *ipv6_spec;
	sec_ctx->security.spec.is_ipv6 = true;

	return 0;
}

static const struct rte_flow_graph ixgbe_security_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[IXGBE_SECURITY_NODE_START] = {
			.name = "START",
		},
		[IXGBE_SECURITY_NODE_IPV4] = {
			.name = "IPV4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_security_ipv4,
			.process = ixgbe_process_security_ipv4,
		},
		[IXGBE_SECURITY_NODE_IPV6] = {
			.name = "IPV6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_security_ipv6,
			.process = ixgbe_process_security_ipv6,
		},
		[IXGBE_SECURITY_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[IXGBE_SECURITY_NODE_START] = {
			.next = (const size_t[]) {
				IXGBE_SECURITY_NODE_IPV4,
				IXGBE_SECURITY_NODE_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_SECURITY_NODE_IPV4] = {
			.next = (const size_t[]) {
				IXGBE_SECURITY_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_SECURITY_NODE_IPV6] = {
			.next = (const size_t[]) {
				IXGBE_SECURITY_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

static int
ixgbe_flow_security_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ixgbe_security_ctx *sec_ctx = (struct ixgbe_security_ctx *)ctx;
	struct ci_flow_actions parsed_actions;
	struct ci_flow_actions_check_param ap_param = {
		.allowed_types = (const enum rte_flow_action_type[]){
			/* only security is allowed here */
			RTE_FLOW_ACTION_TYPE_SECURITY,
			RTE_FLOW_ACTION_TYPE_END
		},
		.max_actions = 1,
	};
	const struct rte_flow_action_security *security;
	struct rte_security_session *session;
	const struct ixgbe_crypto_session *ic_session;
	int ret;

	/* validate attributes */
	ret = ci_flow_check_attr(attr, NULL, error);
	if (ret)
		return ret;

	/* parse requested actions */
	ret = ci_flow_check_actions(actions, &ap_param, &parsed_actions, error);
	if (ret)
		return ret;

	security = (const struct rte_flow_action_security *)parsed_actions.actions[0]->conf;

	if (security->security_session == NULL) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, &parsed_actions.actions[0],
				"NULL security session");
	}

	/* cast away constness since we need to store the session pointer in the context */
	session = RTE_CAST_PTR(struct rte_security_session *, security->security_session);

	/* verify that the session is of a correct type */
	ic_session = SECURITY_GET_SESS_PRIV(session);
	if (ic_session->dev_data != ctx->dev_data) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, &parsed_actions.actions[0],
				"Security session was created for a different device");
	}
	if (ic_session->op != IXGBE_OP_AUTHENTICATED_DECRYPTION) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, &parsed_actions.actions[0],
				"Only authenticated decryption is supported");
	}
	sec_ctx->security.session = session;

	return 0;
}

static int
ixgbe_flow_security_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct ixgbe_security_ctx *security_ctx = (const struct ixgbe_security_ctx *)ctx;
	struct ixgbe_security_flow *security_flow = (struct ixgbe_security_flow *)flow;

	security_flow->security = security_ctx->security;

	return 0;
}

static int
ixgbe_flow_security_flow_install(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_security_flow *security_flow = (struct ixgbe_security_flow *)flow;
	struct ixgbe_security_filter *filter = &security_flow->security;
	int ret;
	uint32_t sa_idx = 0;

	ret = ixgbe_crypto_add_ingress_sa_from_flow(filter->session, &filter->spec, &sa_idx);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to add ingress SA from flow");
	}
	filter->sa_idx = sa_idx;
	return 0;
}

static int
ixgbe_flow_security_flow_uninstall(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_security_flow *security_flow = (struct ixgbe_security_flow *)flow;
	struct ixgbe_security_filter *filter = &security_flow->security;
	int ret;

	ret = ixgbe_crypto_remove_ingress_sa_from_flow(filter->session, filter->sa_idx);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to remove ingress SA from flow");
	}
	return 0;
}

static int
ixgbe_flow_security_engine_init(const struct ci_flow_engine *engine __rte_unused,
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

static const struct ci_flow_engine_ops ixgbe_security_ops = {
	.engine_init = ixgbe_flow_security_engine_init,
	.ctx_parse = ixgbe_flow_security_ctx_parse,
	.ctx_to_flow = ixgbe_flow_security_ctx_to_flow,
	.flow_install = ixgbe_flow_security_flow_install,
	.flow_uninstall = ixgbe_flow_security_flow_uninstall,
};

const struct ci_flow_engine ixgbe_security_flow_engine = {
	.name = "security",
	.ctx_size = sizeof(struct ixgbe_security_ctx),
	.flow_size = sizeof(struct ixgbe_security_flow),
	.ops = &ixgbe_security_ops,
	.graph = &ixgbe_security_graph,
};
