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

/**
 * VXLAN tunnel filter graph implementation
 * Pattern: START -> ETH -> (IPv4 | IPv6) -> UDP -> VXLAN -> ETH -> [VLAN] -> END
 */
enum i40e_tunnel_vxlan_node_id {
	I40E_TUNNEL_VXLAN_NODE_START  = RTE_FLOW_NODE_FIRST,
	I40E_TUNNEL_VXLAN_NODE_OUTER_ETH,
	I40E_TUNNEL_VXLAN_NODE_IPV4,
	I40E_TUNNEL_VXLAN_NODE_IPV6,
	I40E_TUNNEL_VXLAN_NODE_UDP,
	I40E_TUNNEL_VXLAN_NODE_VXLAN,
	I40E_TUNNEL_VXLAN_NODE_INNER_ETH,
	I40E_TUNNEL_VXLAN_NODE_INNER_VLAN,
	I40E_TUNNEL_VXLAN_NODE_END,
	I40E_TUNNEL_VXLAN_NODE_MAX,
};

static int
i40e_tunnel_node_eth_validate(const void *ctx __rte_unused, const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_eth *eth_spec = item->spec;
	const struct rte_flow_item_eth *eth_mask = item->mask;

	/* spec/mask is optional */
	if (eth_spec == NULL && eth_mask == NULL)
		return 0;

	/* matching eth type not supported */
	if (eth_mask->hdr.ether_type) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid ETH mask");
	}

	/* source MAC must be fully unmasked */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.src_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid ETH mask");
	}
	/* destination MAC must be fully masked */
	if (!CI_FIELD_IS_MASKED(&eth_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid ETH mask");
	}

	return 0;
}

static int
i40e_tunnel_eth_process(struct i40e_tunnel_ctx *tunnel_ctx,
		const struct rte_flow_item *item, bool is_inner)
{
	const struct rte_flow_item_eth *eth_spec = item->spec;
	const struct rte_flow_item_eth *eth_mask = item->mask;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	/* eth spec/mask is optional */
	if (eth_spec == NULL && eth_mask == NULL)
		return 0;

	/* Store the MAC addresses and set filter flags */
	if (is_inner) {
		memcpy(&tunnel_filter->inner_mac, &eth_spec->hdr.dst_addr,
				sizeof(tunnel_filter->inner_mac));
		tunnel_filter->filter_type |= RTE_ETH_TUNNEL_FILTER_IMAC;
	} else {
		memcpy(&tunnel_filter->outer_mac, &eth_spec->hdr.dst_addr,
				sizeof(tunnel_filter->outer_mac));
		tunnel_filter->filter_type |= RTE_ETH_TUNNEL_FILTER_OMAC;
	}
	return 0;
}

static int
i40e_tunnel_node_outer_eth_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;

	return i40e_tunnel_eth_process(tunnel_ctx, item, false);
}

static int
i40e_tunnel_node_inner_eth_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;

	return i40e_tunnel_eth_process(tunnel_ctx, item, true);
}

static int
i40e_tunnel_node_ipv4_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->ip_type = I40E_TUNNEL_IPTYPE_IPV4;

	return 0;
}

static int
i40e_tunnel_node_ipv6_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->ip_type = I40E_TUNNEL_IPTYPE_IPV6;

	return 0;
}

static int
i40e_tunnel_node_vxlan_validate(const void *ctx __rte_unused,
		const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
	const struct rte_flow_item_vxlan *vxlan_mask = item->mask;

	/* spec/mask are optional */
	if (vxlan_spec == NULL && vxlan_mask == NULL)
		return 0;

	/* VNI must be fully masked */
	if (!CI_FIELD_IS_MASKED(&vxlan_mask->hdr.vni)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid VXLAN mask");
	}
	return 0;
}

static int
i40e_tunnel_node_vxlan_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
	const struct rte_flow_item_vxlan *vxlan_mask = item->mask;
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	/* spec/mask are optional */
	if (vxlan_spec == NULL && vxlan_mask == NULL)
		return 0;

	/* Store the VNI and set filter flag */
	tunnel_filter->tenant_id = ci_be24_to_cpu(vxlan_spec->hdr.vni);
	tunnel_filter->filter_type |= RTE_ETH_TUNNEL_FILTER_TENID;

	return 0;
}

static int
i40e_tunnel_node_end_validate(const void *ctx,
		const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	const struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	/* this shouldn't happen but check this just in case */
	if (i40e_check_tunnel_filter_type(tunnel_filter->filter_type) != 0) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid tunnel filter configuration");
	}
	return 0;
}

static int
i40e_tunnel_vxlan_node_end_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tunnel_type = I40E_TUNNEL_TYPE_VXLAN;

	return 0;
}

static const struct rte_flow_graph i40e_tunnel_vxlan_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[I40E_TUNNEL_VXLAN_NODE_START] = {
			.name = "START",
		},
		[I40E_TUNNEL_VXLAN_NODE_OUTER_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_eth_validate,
			.process = i40e_tunnel_node_outer_eth_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_IPV4] = {
			.name = "IPv4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv4_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_IPV6] = {
			.name = "IPv6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv6_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_UDP] = {
			.name = "UDP",
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[I40E_TUNNEL_VXLAN_NODE_VXLAN] = {
			.name = "VXLAN",
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_vxlan_validate,
			.process = i40e_tunnel_node_vxlan_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_INNER_ETH] = {
			.name = "INNER_ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_eth_validate,
			.process = i40e_tunnel_node_inner_eth_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_INNER_VLAN] = {
			.name = "INNER_VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_vlan_validate,
			.process = i40e_tunnel_node_inner_vlan_process,
		},
		[I40E_TUNNEL_VXLAN_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
			.validate = i40e_tunnel_node_end_validate,
			.process = i40e_tunnel_vxlan_node_end_process
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[I40E_TUNNEL_VXLAN_NODE_START] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_OUTER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_OUTER_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_IPV4,
				I40E_TUNNEL_VXLAN_NODE_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_IPV4] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_UDP,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_IPV6] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_UDP,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_UDP] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_VXLAN,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_VXLAN] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_INNER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_INNER_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_INNER_VLAN,
				I40E_TUNNEL_VXLAN_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_VXLAN_NODE_INNER_VLAN] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_VXLAN_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

/**
 * NVGRE tunnel filter graph implementation
 * Pattern: START -> ETH -> (IPv4 | IPv6) -> NVGRE -> ETH -> [VLAN] -> END
 */
enum i40e_tunnel_nvgre_node_id {
	I40E_TUNNEL_NVGRE_NODE_START  = RTE_FLOW_NODE_FIRST,
	I40E_TUNNEL_NVGRE_NODE_OUTER_ETH,
	I40E_TUNNEL_NVGRE_NODE_IPV4,
	I40E_TUNNEL_NVGRE_NODE_IPV6,
	I40E_TUNNEL_NVGRE_NODE_NVGRE,
	I40E_TUNNEL_NVGRE_NODE_INNER_ETH,
	I40E_TUNNEL_NVGRE_NODE_INNER_VLAN,
	I40E_TUNNEL_NVGRE_NODE_END,
	I40E_TUNNEL_NVGRE_NODE_MAX,
};

static int
i40e_tunnel_node_nvgre_validate(const void *ctx __rte_unused,
		const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_nvgre *nvgre_spec = item->spec;
	const struct rte_flow_item_nvgre *nvgre_mask = item->mask;

	/* spec/mask are optional */
	if (nvgre_spec == NULL && nvgre_mask == NULL)
		return 0;

	/* TNI must be fully masked */
	if (!CI_FIELD_IS_MASKED(&nvgre_mask->tni)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"Invalid NVGRE mask");
	}
	/* protocol must either be unmasked or fully masked */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&nvgre_mask->protocol)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"Invalid NVGRE mask");
	}
	/* reserved/version field must either be unmasked or fully masked */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&nvgre_mask->c_k_s_rsvd0_ver)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"Invalid NVGRE mask");
	}
	/* if reserved/version field is masked, it must be set to 0x2000 */
	if (nvgre_mask->c_k_s_rsvd0_ver &&
			nvgre_spec->c_k_s_rsvd0_ver != rte_cpu_to_be_16(0x2000)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"Invalid NVGRE spec");
	}
	/* if protocol field is masked, it must be set to 0x6558 */
	if (nvgre_mask->protocol &&
			nvgre_spec->protocol != rte_cpu_to_be_16(0x6558)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"Invalid NVGRE spec");
	}
	return 0;
}

static int
i40e_tunnel_node_nvgre_process(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	const struct rte_flow_item_nvgre *nvgre_spec = item->spec;
	const struct rte_flow_item_nvgre *nvgre_mask = item->mask;
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	/* spec/mask are optional */
	if (nvgre_spec == NULL && nvgre_mask == NULL)
		return 0;

	/* Store the VNI and set filter flag */
	tunnel_filter->tenant_id = ci_be24_to_cpu(nvgre_spec->tni);
	tunnel_filter->filter_type |= RTE_ETH_TUNNEL_FILTER_TENID;

	return 0;
}

static int
i40e_tunnel_node_nvgre_end_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tunnel_type = I40E_TUNNEL_TYPE_NVGRE;

	return 0;
}

static const struct rte_flow_graph i40e_tunnel_nvgre_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[I40E_TUNNEL_NVGRE_NODE_START] = {
			.name = "START",
		},
		[I40E_TUNNEL_NVGRE_NODE_OUTER_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_eth_validate,
			.process = i40e_tunnel_node_outer_eth_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_IPV4] = {
			.name = "IPv4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv4_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_IPV6] = {
			.name = "IPv6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv6_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_NVGRE] = {
			.name = "NVGRE",
			.type = RTE_FLOW_ITEM_TYPE_NVGRE,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_nvgre_validate,
			.process = i40e_tunnel_node_nvgre_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_INNER_ETH] = {
			.name = "INNER_ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_eth_validate,
			.process = i40e_tunnel_node_inner_eth_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_INNER_VLAN] = {
			.name = "INNER_VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_vlan_validate,
			.process = i40e_tunnel_node_inner_vlan_process,
		},
		[I40E_TUNNEL_NVGRE_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
			.validate = i40e_tunnel_node_end_validate,
			.process = i40e_tunnel_node_nvgre_end_process
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[I40E_TUNNEL_NVGRE_NODE_START] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_OUTER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_OUTER_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_IPV4,
				I40E_TUNNEL_NVGRE_NODE_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_IPV4] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_NVGRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_IPV6] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_NVGRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_NVGRE] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_INNER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_INNER_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_INNER_VLAN,
				I40E_TUNNEL_NVGRE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_NVGRE_NODE_INNER_VLAN] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_NVGRE_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

/**
 * MPLS tunnel filter graph implementation
 * Pattern: START -> ETH -> (IPv4 | IPv6) -> (UDP | GRE) -> MPLS -> END
 */
enum i40e_tunnel_mpls_node_id {
	I40E_TUNNEL_MPLS_NODE_START  = RTE_FLOW_NODE_FIRST,
	I40E_TUNNEL_MPLS_NODE_ETH,
	I40E_TUNNEL_MPLS_NODE_IPV4,
	I40E_TUNNEL_MPLS_NODE_IPV6,
	I40E_TUNNEL_MPLS_NODE_UDP,
	I40E_TUNNEL_MPLS_NODE_GRE,
	I40E_TUNNEL_MPLS_NODE_MPLS,
	I40E_TUNNEL_MPLS_NODE_END,
	I40E_TUNNEL_MPLS_NODE_MAX,
};

static int
i40e_tunnel_mpls_node_udp_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tunnel_type = I40E_TUNNEL_TYPE_MPLSoUDP;

	return 0;
}

static int
i40e_tunnel_mpls_node_gre_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tunnel_type = I40E_TUNNEL_TYPE_MPLSoGRE;

	return 0;
}

static int
i40e_tunnel_node_mpls_validate(const void *ctx __rte_unused,
		const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct rte_flow_item_mpls *mpls_mask = item->mask;
	const uint8_t label_mask[3] = {0xFF, 0xFF, 0xF0};

	/* MPLS label and TC must be fully masked */
	if (memcmp(mpls_mask->label_tc_s, label_mask, 3)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid MPLS mask");
	}
	return 0;
}

static int
i40e_tunnel_node_mpls_process(void *ctx, const struct rte_flow_item *item __rte_unused,
		struct rte_flow_error *error __rte_unused)
{
	const struct rte_flow_item_mpls *mpls_spec = item->spec;
	struct i40e_tunnel_ctx *tunnel_ctx = ctx;
	struct i40e_tunnel_filter_conf *tunnel_filter = &tunnel_ctx->filter;

	tunnel_filter->tenant_id = ci_be24_to_cpu(mpls_spec->label_tc_s) >> 4;

	return 0;
}

static const struct rte_flow_graph i40e_tunnel_mpls_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[I40E_TUNNEL_MPLS_NODE_START] = {
			.name = "START",
		},
		[I40E_TUNNEL_MPLS_NODE_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[I40E_TUNNEL_MPLS_NODE_IPV4] = {
			.name = "IPv4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv4_process,
		},
		[I40E_TUNNEL_MPLS_NODE_IPV6] = {
			.name = "IPv6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_node_ipv6_process,
		},
		[I40E_TUNNEL_MPLS_NODE_UDP] = {
			.name = "UDP",
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_mpls_node_udp_process,
		},
		[I40E_TUNNEL_MPLS_NODE_GRE] = {
			.name = "GRE",
			.type = RTE_FLOW_ITEM_TYPE_GRE,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
			.process = i40e_tunnel_mpls_node_gre_process,
		},
		[I40E_TUNNEL_MPLS_NODE_MPLS] = {
			.name = "MPLS",
			.type = RTE_FLOW_ITEM_TYPE_MPLS,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = i40e_tunnel_node_mpls_validate,
			.process = i40e_tunnel_node_mpls_process,
		},
		[I40E_TUNNEL_MPLS_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[I40E_TUNNEL_MPLS_NODE_START] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_ETH] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_IPV4,
				I40E_TUNNEL_MPLS_NODE_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_IPV4] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_UDP,
				I40E_TUNNEL_MPLS_NODE_GRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_IPV6] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_UDP,
				I40E_TUNNEL_MPLS_NODE_GRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_UDP] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_MPLS,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_GRE] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_MPLS,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[I40E_TUNNEL_MPLS_NODE_MPLS] = {
			.next = (const size_t[]) {
				I40E_TUNNEL_MPLS_NODE_END,
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

const struct ci_flow_engine i40e_flow_engine_tunnel_nvgre = {
	.name = "tunnel_nvgre",
	.ops = &i40e_flow_engine_tunnel_ops,
	.ctx_size = sizeof(struct i40e_tunnel_ctx),
	.flow_size = sizeof(struct i40e_tunnel_flow),
	.graph = &i40e_tunnel_nvgre_graph,
};

const struct ci_flow_engine i40e_flow_engine_tunnel_vxlan = {
	.name = "tunnel_vxlan",
	.ops = &i40e_flow_engine_tunnel_ops,
	.ctx_size = sizeof(struct i40e_tunnel_ctx),
	.flow_size = sizeof(struct i40e_tunnel_flow),
	.graph = &i40e_tunnel_vxlan_graph,
};

const struct ci_flow_engine i40e_flow_engine_tunnel_mpls = {
	.name = "tunnel_mpls",
	.ops = &i40e_flow_engine_tunnel_ops,
	.ctx_size = sizeof(struct i40e_tunnel_ctx),
	.flow_size = sizeof(struct i40e_tunnel_flow),
	.graph = &i40e_tunnel_mpls_graph,
};

const struct ci_flow_engine i40e_flow_engine_tunnel_qinq = {
	.name = "tunnel_qinq",
	.ops = &i40e_flow_engine_tunnel_ops,
	.ctx_size = sizeof(struct i40e_tunnel_ctx),
	.flow_size = sizeof(struct i40e_tunnel_flow),
	.graph = &i40e_tunnel_qinq_graph,
};
