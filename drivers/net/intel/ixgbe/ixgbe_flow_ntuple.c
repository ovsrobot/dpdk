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

#define IXGBE_MIN_N_TUPLE_PRIO 1
#define IXGBE_MAX_N_TUPLE_PRIO 7

struct ixgbe_ntuple_flow {
	struct rte_flow flow;
	struct rte_eth_ntuple_filter ntuple;
};

struct ixgbe_ntuple_ctx {
	struct ci_flow_engine_ctx base;
	struct rte_eth_ntuple_filter ntuple;
};

/**
 * Ntuple filter graph implementation
 * Pattern: START -> [ETH] -> [VLAN] -> IPV4 -> [TCP|UDP|SCTP] -> END
 */

enum ixgbe_ntuple_node_id {
	IXGBE_NTUPLE_NODE_START = RTE_FLOW_NODE_FIRST,
	IXGBE_NTUPLE_NODE_ETH,
	IXGBE_NTUPLE_NODE_VLAN,
	IXGBE_NTUPLE_NODE_IPV4,
	IXGBE_NTUPLE_NODE_TCP,
	IXGBE_NTUPLE_NODE_UDP,
	IXGBE_NTUPLE_NODE_SCTP,
	IXGBE_NTUPLE_NODE_END,
	IXGBE_NTUPLE_NODE_MAX,
};

static int
ixgbe_validate_ntuple_ipv4(const void *ctx __rte_unused,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv4 *ipv4_mask;

	ipv4_mask = item->mask;

	/* Only src/dst addresses and protocol supported */
	if (ipv4_mask->hdr.version_ihl ||
	    ipv4_mask->hdr.type_of_service ||
	    ipv4_mask->hdr.total_length ||
	    ipv4_mask->hdr.packet_id ||
	    ipv4_mask->hdr.fragment_offset ||
	    ipv4_mask->hdr.time_to_live ||
	    ipv4_mask->hdr.hdr_checksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst IP and protocol supported");
	}

	/* Masks must be 0 or all-ones */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&ipv4_mask->hdr.src_addr) ||
	    !CI_FIELD_IS_ZERO_OR_MASKED(&ipv4_mask->hdr.dst_addr) ||
	    !CI_FIELD_IS_ZERO_OR_MASKED(&ipv4_mask->hdr.next_proto_id)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial masks not supported");
	}

	return 0;
}

static int
ixgbe_process_ntuple_ipv4(void *ctx,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_ntuple_ctx *ntuple_ctx = ctx;
	const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
	const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;

	ntuple_ctx->ntuple.dst_ip = ipv4_spec->hdr.dst_addr;
	ntuple_ctx->ntuple.src_ip = ipv4_spec->hdr.src_addr;
	ntuple_ctx->ntuple.proto = ipv4_spec->hdr.next_proto_id;

	ntuple_ctx->ntuple.dst_ip_mask = ipv4_mask->hdr.dst_addr;
	ntuple_ctx->ntuple.src_ip_mask = ipv4_mask->hdr.src_addr;
	ntuple_ctx->ntuple.proto_mask = ipv4_mask->hdr.next_proto_id;

	return 0;
}

static int
ixgbe_validate_ntuple_tcp(const void *ctx __rte_unused,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error)
{
	const struct rte_flow_item_tcp *tcp_mask;

	tcp_mask = item->mask;

	/* Only src/dst ports and tcp_flags supported */
	if (tcp_mask->hdr.sent_seq ||
	    tcp_mask->hdr.recv_ack ||
	    tcp_mask->hdr.data_off ||
	    tcp_mask->hdr.rx_win ||
	    tcp_mask->hdr.cksum ||
	    tcp_mask->hdr.tcp_urp) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst ports and flags supported");
	}

	/* Port masks must be 0 or all-ones */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&tcp_mask->hdr.src_port) ||
	    !CI_FIELD_IS_ZERO_OR_MASKED(&tcp_mask->hdr.dst_port)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial port masks not supported");
	}

	/* TCP flags not supported by hardware */
	if (!CI_FIELD_IS_ZERO(&tcp_mask->hdr.tcp_flags)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"TCP flags filtering not supported");
	}

	return 0;
}

static int
ixgbe_process_ntuple_tcp(void *ctx,
			 const struct rte_flow_item *item,
			 struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_ntuple_ctx *ntuple_ctx = ctx;
	const struct rte_flow_item_tcp *tcp_spec = item->spec;
	const struct rte_flow_item_tcp *tcp_mask = item->mask;

	ntuple_ctx->ntuple.dst_port = tcp_spec->hdr.dst_port;
	ntuple_ctx->ntuple.src_port = tcp_spec->hdr.src_port;

	ntuple_ctx->ntuple.dst_port_mask = tcp_mask->hdr.dst_port;
	ntuple_ctx->ntuple.src_port_mask = tcp_mask->hdr.src_port;

	return 0;
}

static int
ixgbe_validate_ntuple_udp(const void *ctx __rte_unused,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error)
{
	const struct rte_flow_item_udp *udp_mask;

	udp_mask = item->mask;

	/* Only src/dst ports supported */
	if (udp_mask->hdr.dgram_len ||
	    udp_mask->hdr.dgram_cksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst ports supported");
	}

	/* Port masks must be 0 or all-ones */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&udp_mask->hdr.src_port) ||
	    !CI_FIELD_IS_ZERO_OR_MASKED(&udp_mask->hdr.dst_port)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial port masks not supported");
	}

	return 0;
}

static int
ixgbe_process_ntuple_udp(void *ctx,
			 const struct rte_flow_item *item,
			 struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_ntuple_ctx *ntuple_ctx = ctx;
	const struct rte_flow_item_udp *udp_spec = item->spec;
	const struct rte_flow_item_udp *udp_mask = item->mask;

	ntuple_ctx->ntuple.dst_port = udp_spec->hdr.dst_port;
	ntuple_ctx->ntuple.src_port = udp_spec->hdr.src_port;

	ntuple_ctx->ntuple.dst_port_mask = udp_mask->hdr.dst_port;
	ntuple_ctx->ntuple.src_port_mask = udp_mask->hdr.src_port;

	return 0;
}

static int
ixgbe_validate_ntuple_sctp(const void *ctx __rte_unused,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error)
{
	const struct rte_flow_item_sctp *sctp_mask;

	sctp_mask = item->mask;

	/* Only src/dst ports supported */
	if (sctp_mask->hdr.tag ||
	    sctp_mask->hdr.cksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst ports supported");
	}

	/* Port masks must be 0 or all-ones */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&sctp_mask->hdr.src_port) ||
	    !CI_FIELD_IS_ZERO_OR_MASKED(&sctp_mask->hdr.dst_port)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial port masks not supported");
	}

	return 0;
}

static int
ixgbe_process_ntuple_sctp(void *ctx,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_ntuple_ctx *ntuple_ctx = ctx;
	const struct rte_flow_item_sctp *sctp_spec = item->spec;
	const struct rte_flow_item_sctp *sctp_mask = item->mask;

	ntuple_ctx->ntuple.dst_port = sctp_spec->hdr.dst_port;
	ntuple_ctx->ntuple.src_port = sctp_spec->hdr.src_port;

	ntuple_ctx->ntuple.dst_port_mask = sctp_mask->hdr.dst_port;
	ntuple_ctx->ntuple.src_port_mask = sctp_mask->hdr.src_port;

	return 0;
}

static const struct rte_flow_graph ixgbe_ntuple_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[IXGBE_NTUPLE_NODE_START] = {
			.name = "START",
		},
		[IXGBE_NTUPLE_NODE_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_NTUPLE_NODE_VLAN] = {
			.name = "VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_NTUPLE_NODE_IPV4] = {
			.name = "IPV4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_ntuple_ipv4,
			.process = ixgbe_process_ntuple_ipv4,
		},
		[IXGBE_NTUPLE_NODE_TCP] = {
			.name = "TCP",
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_ntuple_tcp,
			.process = ixgbe_process_ntuple_tcp,
		},
		[IXGBE_NTUPLE_NODE_UDP] = {
			.name = "UDP",
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_ntuple_udp,
			.process = ixgbe_process_ntuple_udp,
		},
		[IXGBE_NTUPLE_NODE_SCTP] = {
			.name = "SCTP",
			.type = RTE_FLOW_ITEM_TYPE_SCTP,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_ntuple_sctp,
			.process = ixgbe_process_ntuple_sctp,
		},
		[IXGBE_NTUPLE_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[IXGBE_NTUPLE_NODE_START] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_ETH,
				IXGBE_NTUPLE_NODE_IPV4,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_ETH] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_VLAN,
				IXGBE_NTUPLE_NODE_IPV4,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_VLAN] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_IPV4,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_IPV4] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_TCP,
				IXGBE_NTUPLE_NODE_UDP,
				IXGBE_NTUPLE_NODE_SCTP,
				IXGBE_NTUPLE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_TCP] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_UDP] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_NTUPLE_NODE_SCTP] = {
			.next = (const size_t[]) {
				IXGBE_NTUPLE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

static int
ixgbe_flow_ntuple_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ixgbe_ntuple_ctx *ntuple_ctx = (struct ixgbe_ntuple_ctx *)ctx;
	struct ci_flow_attr_check_param attr_param = {
		.allow_priority = true,
	};
	struct ci_flow_actions parsed_actions;
	struct ci_flow_actions_check_param ap_param = {
		.allowed_types = (const enum rte_flow_action_type[]){
			/* only queue is allowed here */
			RTE_FLOW_ACTION_TYPE_QUEUE,
			RTE_FLOW_ACTION_TYPE_END
		},
		.driver_ctx = ctx->dev_data,
		.check = ixgbe_flow_actions_check,
		.max_actions = 1,
	};
	const struct rte_flow_action_queue *q_act;
	uint16_t priority;
	int ret;

	/* validate attributes */
	ret = ci_flow_check_attr(attr, &attr_param, error);
	if (ret)
		return ret;

	/* Priority must be 16-bit */
	if (attr->priority > UINT16_MAX) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, attr,
				"Priority must be 16-bit");
	}

	/* parse requested actions */
	ret = ci_flow_check_actions(actions, &ap_param, &parsed_actions, error);
	if (ret)
		return ret;

	q_act = (const struct rte_flow_action_queue *)parsed_actions.actions[0]->conf;

	ntuple_ctx->ntuple.queue = q_act->index;

	/*
	* rte_flow priority: 0 through UINT32_MAX, 0 is highest
	*
	 * ntuple priority: 001b through 111b, 111b is highest
	 *
	 * which means we need to transform priority from rte_flow to ntuple:
	 *
	 * 1) clamp max value
	 * 2) reverse
	 * 3) add min value
	 */
	priority = RTE_MIN(IXGBE_MAX_N_TUPLE_PRIO - 1, (uint16_t)attr->priority);
	priority = IXGBE_MAX_N_TUPLE_PRIO - 1 - priority;
	priority += IXGBE_MIN_N_TUPLE_PRIO;
	ntuple_ctx->ntuple.priority = priority;

	/* fixed value for ixgbe */
	ntuple_ctx->ntuple.flags = RTE_5TUPLE_FLAGS;

	return 0;
}

static int
ixgbe_flow_ntuple_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct ixgbe_ntuple_ctx *ntuple_ctx = (const struct ixgbe_ntuple_ctx *)ctx;
	struct ixgbe_ntuple_flow *ntuple_flow = (struct ixgbe_ntuple_flow *)flow;

	ntuple_flow->ntuple = ntuple_ctx->ntuple;

	return 0;
}

static int
ixgbe_flow_ntuple_flow_install(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_ntuple_flow *ntuple_flow = (struct ixgbe_ntuple_flow *)flow;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	int ret;

	ret = ixgbe_add_del_ntuple_filter(adapter, &ntuple_flow->ntuple, TRUE);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to add ntuple filter");
	}

	return 0;
}

static int
ixgbe_flow_ntuple_flow_uninstall(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_ntuple_flow *ntuple_flow = (struct ixgbe_ntuple_flow *)flow;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	int ret;

	ret = ixgbe_add_del_ntuple_filter(adapter, &ntuple_flow->ntuple, FALSE);
	if (ret) {
		return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to delete ntuple filter");
	}

	return 0;
}

static int
ixgbe_flow_ntuple_engine_init(const struct ci_flow_engine *engine __rte_unused,
		struct rte_eth_dev_data *dev_data,
		void *priv __rte_unused)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev_data->dev_private);

	/* only 82599 and X540 have L3/L4 5-tuple (ntuple) filters */
	if (hw->mac.type == ixgbe_mac_82599EB ||
			hw->mac.type == ixgbe_mac_X540)
		return 0;

	return -ENOTSUP;
}

static const struct ci_flow_engine_ops ixgbe_ntuple_ops = {
	.engine_init = ixgbe_flow_ntuple_engine_init,
	.ctx_parse = ixgbe_flow_ntuple_ctx_parse,
	.ctx_to_flow = ixgbe_flow_ntuple_ctx_to_flow,
	.flow_install = ixgbe_flow_ntuple_flow_install,
	.flow_uninstall = ixgbe_flow_ntuple_flow_uninstall,
};

const struct ci_flow_engine ixgbe_ntuple_flow_engine = {
	.name = "ntuple",
	.ctx_size = sizeof(struct ixgbe_ntuple_ctx),
	.flow_size = sizeof(struct ixgbe_ntuple_flow),
	.ops = &ixgbe_ntuple_ops,
	.graph = &ixgbe_ntuple_graph,
};
