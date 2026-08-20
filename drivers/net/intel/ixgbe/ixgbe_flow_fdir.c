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

struct ixgbe_fdir_flow {
	struct rte_flow flow;
	struct ixgbe_fdir_rule rule;
};

struct ixgbe_fdir_ctx {
	struct ci_flow_engine_ctx base;
	struct ixgbe_fdir_rule rule;
	bool supports_sctp_ports;
	const struct rte_flow_action *fwd_action;
	const struct rte_flow_action *aux_action;
};

#define IXGBE_FDIR_VLAN_TCI_MASK	rte_cpu_to_be_16(0xEFFF)
#define NVGRE_FLAGS 0x2000
#define NVGRE_PROTOCOL 0x6558

/**
 * FDIR normal graph implementation
 * Pattern: START -> [ETH] -> (IPv4|IPv6) -> [TCP|UDP|SCTP] -> [RAW] -> END
 * Pattern: START -> ETH -> VLAN -> END
 */

enum ixgbe_fdir_normal_node_id {
	IXGBE_FDIR_NORMAL_NODE_START = RTE_FLOW_NODE_FIRST,
	IXGBE_FDIR_NORMAL_NODE_ETH,
	IXGBE_FDIR_NORMAL_NODE_VLAN,
	IXGBE_FDIR_NORMAL_NODE_IPV4,
	IXGBE_FDIR_NORMAL_NODE_IPV6,
	IXGBE_FDIR_NORMAL_NODE_TCP,
	IXGBE_FDIR_NORMAL_NODE_UDP,
	IXGBE_FDIR_NORMAL_NODE_SCTP,
	IXGBE_FDIR_NORMAL_NODE_RAW,
	IXGBE_FDIR_NORMAL_NODE_END,
	IXGBE_FDIR_NORMAL_NODE_MAX,
};

static int
ixgbe_validate_fdir_normal_eth(const void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error)
{
	const struct ixgbe_fdir_ctx *fdir_ctx = (const struct ixgbe_fdir_ctx *)ctx;
	const struct rte_flow_item_eth *eth_mask = item->mask;

	if (item->spec == NULL && item->mask == NULL)
		return 0;

	/* we cannot have ETH item in signature mode */
	if (fdir_ctx->rule.mode == RTE_FDIR_MODE_SIGNATURE) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"ETH item not supported in signature mode");
	}
	/* ethertype isn't supported by FDIR */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.ether_type)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Ethertype filtering not supported");
	}
	/* source address mask must be all zeroes */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.src_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Source MAC filtering not supported");
	}
	/* destination address mask must be all ones */
	if (!CI_FIELD_IS_MASKED(&eth_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Destination MAC filtering must be exact match");
	}
	return 0;
}

static int
ixgbe_process_fdir_normal_eth(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;
	const struct rte_flow_item_eth *eth_spec = item->spec;
	const struct rte_flow_item_eth *eth_mask = item->mask;


	if (eth_spec == NULL && eth_mask == NULL)
		return 0;

	/* copy dst MAC */
	rule->b_spec = TRUE;
	memcpy(rule->ixgbe_fdir.formatted.inner_mac, eth_spec->hdr.dst_addr.addr_bytes,
			RTE_ETHER_ADDR_LEN);

	/* set tunnel type */
	rule->mode = RTE_FDIR_MODE_PERFECT_MAC_VLAN;
	/* when no VLAN specified, set full mask */
	rule->b_mask = TRUE;
	rule->mask.vlan_tci_mask = IXGBE_FDIR_VLAN_TCI_MASK;

	return 0;
}

static int
ixgbe_process_fdir_normal_vlan(void *ctx, const struct rte_flow_item *item,
		struct rte_flow_error *error __rte_unused)
{
	const struct rte_flow_item_vlan *vlan_spec = item->spec;
	const struct rte_flow_item_vlan *vlan_mask = item->mask;
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.vlan_id = vlan_spec->hdr.vlan_tci;

	rule->mask.vlan_tci_mask = vlan_mask->hdr.vlan_tci;
	rule->mask.vlan_tci_mask &= IXGBE_FDIR_VLAN_TCI_MASK;

	return 0;
}

static int
ixgbe_validate_fdir_normal_ipv4(const void *ctx,
			    const struct rte_flow_item *item,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;
	const struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	if (rule->mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"IPv4 not supported with ETH/VLAN items");
	}

	if (ipv4_mask->hdr.version_ihl ||
	    ipv4_mask->hdr.type_of_service ||
	    ipv4_mask->hdr.total_length ||
	    ipv4_mask->hdr.packet_id ||
	    ipv4_mask->hdr.fragment_offset ||
	    ipv4_mask->hdr.time_to_live ||
	    ipv4_mask->hdr.next_proto_id ||
	    ipv4_mask->hdr.hdr_checksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst addresses supported");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_ipv4(void *ctx,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_ipv4 *ipv4_spec = item->spec;
	const struct rte_flow_item_ipv4 *ipv4_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.flow_type = IXGBE_ATR_FLOW_TYPE_IPV4;

	/* spec may not be present */
	if (ipv4_spec) {
		rule->b_spec = TRUE;
		rule->ixgbe_fdir.formatted.dst_ip[0] = ipv4_spec->hdr.dst_addr;
		rule->ixgbe_fdir.formatted.src_ip[0] = ipv4_spec->hdr.src_addr;
	}

	rule->b_mask = TRUE;
	rule->mask.dst_ipv4_mask = ipv4_mask->hdr.dst_addr;
	rule->mask.src_ipv4_mask = ipv4_mask->hdr.src_addr;

	return 0;
}

static int
ixgbe_validate_fdir_normal_ipv6(const void *ctx,
			    const struct rte_flow_item *item,
			    struct rte_flow_error *error)
{
	const struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;
	const struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	if (rule->mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"IPv6 not supported with ETH/VLAN items");
	}

	if (rule->mode != RTE_FDIR_MODE_SIGNATURE) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"IPv6 only supported in signature mode");
	}

	ipv6_mask = item->mask;

	if (ipv6_mask->hdr.vtc_flow ||
	    ipv6_mask->hdr.payload_len ||
	    ipv6_mask->hdr.proto ||
	    ipv6_mask->hdr.hop_limits) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst addresses supported");
	}

	if (!CI_FIELD_IS_ZERO_OR_MASKED(&ipv6_mask->hdr.src_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial src address masks not supported");
	}
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&ipv6_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial dst address masks not supported");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_ipv6(void *ctx,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_ipv6 *ipv6_spec = item->spec;
	const struct rte_flow_item_ipv6 *ipv6_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;
	uint8_t j;

	rule->ixgbe_fdir.formatted.flow_type = IXGBE_ATR_FLOW_TYPE_IPV6;

	/* spec may not be present */
	if (ipv6_spec) {
		rule->b_spec = TRUE;
		memcpy(rule->ixgbe_fdir.formatted.src_ip, &ipv6_spec->hdr.src_addr,
				sizeof(struct rte_ipv6_addr));
		memcpy(rule->ixgbe_fdir.formatted.dst_ip, &ipv6_spec->hdr.dst_addr,
				sizeof(struct rte_ipv6_addr));
	}

	rule->b_mask = TRUE;
	for (j = 0; j < sizeof(struct rte_ipv6_addr); j++) {
		if (ipv6_mask->hdr.src_addr.a[j] == 0)
			rule->mask.src_ipv6_mask &= ~(1 << j);
		if (ipv6_mask->hdr.dst_addr.a[j] == 0)
			rule->mask.dst_ipv6_mask &= ~(1 << j);
	}

	return 0;
}

static int
ixgbe_validate_fdir_normal_tcp(const void *ctx,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error)
{
	const struct rte_flow_item_tcp *tcp_mask = item->mask;
	const struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	if (rule->mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"TCP not supported with ETH/VLAN items");
	}

	if (tcp_mask == NULL)
		return 0;

	if (tcp_mask->hdr.sent_seq ||
	    tcp_mask->hdr.recv_ack ||
	    tcp_mask->hdr.data_off ||
	    tcp_mask->hdr.tcp_flags ||
	    tcp_mask->hdr.rx_win ||
	    tcp_mask->hdr.cksum ||
	    tcp_mask->hdr.tcp_urp) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst ports supported");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_tcp(void *ctx,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_tcp *tcp_spec = item->spec;
	const struct rte_flow_item_tcp *tcp_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.flow_type |= IXGBE_ATR_L4TYPE_TCP;

	if (tcp_mask != NULL) {
		rule->b_mask = TRUE;
		rule->mask.src_port_mask = tcp_mask->hdr.src_port;
		rule->mask.dst_port_mask = tcp_mask->hdr.dst_port;
	}

	if (tcp_spec != NULL) {
		rule->b_spec = TRUE;
		rule->ixgbe_fdir.formatted.src_port = tcp_spec->hdr.src_port;
		rule->ixgbe_fdir.formatted.dst_port = tcp_spec->hdr.dst_port;
	}

	return 0;
}

static int
ixgbe_validate_fdir_normal_udp(const void *ctx,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error)
{
	const struct rte_flow_item_udp *udp_mask = item->mask;
	const struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	if (rule->mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"UDP not supported with ETH/VLAN items");
	}

	if (udp_mask == NULL)
		return 0;

	if (udp_mask->hdr.dgram_len ||
	    udp_mask->hdr.dgram_cksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only src/dst ports supported");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_udp(void *ctx,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_udp *udp_spec = item->spec;
	const struct rte_flow_item_udp *udp_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.flow_type |= IXGBE_ATR_L4TYPE_UDP;

	if (udp_mask != NULL) {
		rule->b_mask = TRUE;
		rule->mask.src_port_mask = udp_mask->hdr.src_port;
		rule->mask.dst_port_mask = udp_mask->hdr.dst_port;
	}

	if (udp_spec != NULL) {
		rule->b_spec = TRUE;
		rule->ixgbe_fdir.formatted.src_port = udp_spec->hdr.src_port;
		rule->ixgbe_fdir.formatted.dst_port = udp_spec->hdr.dst_port;
	}

	return 0;
}

static int
ixgbe_validate_fdir_normal_sctp(const void *ctx,
			    const struct rte_flow_item *item,
			    struct rte_flow_error *error)
{
	const struct rte_flow_item_sctp *sctp_mask = item->mask;
	const struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	if (rule->mode == RTE_FDIR_MODE_PERFECT_MAC_VLAN) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"SCTP not supported with ETH/VLAN items");
	}

	if (sctp_mask == NULL)
		return 0;


	/* Tag and checksum not supported */
	if (sctp_mask->hdr.tag ||
	    sctp_mask->hdr.cksum) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"SCTP tag/cksum not supported");
	}

	/*
	 * SCTP mask is not NULL, which means we are potentially looking at
	 * masking SCTP ports, so check hardware support.
	 */
	if (!fdir_ctx->supports_sctp_ports) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"SCTP port filtering not supported by hardware");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_sctp(void *ctx,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_sctp *sctp_spec = item->spec;
	const struct rte_flow_item_sctp *sctp_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.flow_type |= IXGBE_ATR_L4TYPE_SCTP;

	if (sctp_mask != NULL) {
		rule->b_mask = TRUE;
		rule->mask.src_port_mask = sctp_mask->hdr.src_port;
		rule->mask.dst_port_mask = sctp_mask->hdr.dst_port;
	}

	if (sctp_spec != NULL) {
		rule->b_spec = TRUE;
		rule->ixgbe_fdir.formatted.src_port = sctp_spec->hdr.src_port;
		rule->ixgbe_fdir.formatted.dst_port = sctp_spec->hdr.dst_port;
	}

	return 0;
}

static int
ixgbe_validate_fdir_normal_raw(const void *ctx __rte_unused,
			   const struct rte_flow_item *item,
			   struct rte_flow_error *error)
{
	const struct rte_flow_item_raw *raw_spec;
	const struct rte_flow_item_raw *raw_mask;

	raw_spec = item->spec;
	raw_mask = item->mask;

	if (raw_spec->pattern == NULL) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid RAW spec");
	}

	if (raw_mask->pattern == NULL) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid RAW mask");
	}

	if (raw_mask->length != raw_spec->length &&
			raw_mask->length != 0xffff) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid RAW mask");
	}

	if (raw_mask->relative != 0x1 ||
	    raw_mask->search != 0x1 ||
	    raw_mask->reserved != 0x0 ||
	    (uint32_t)raw_mask->offset != 0xffffffff ||
	    raw_mask->limit != 0xffff) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid RAW mask");
	}

	if (raw_spec->relative != 0 ||
	    raw_spec->search != 0 ||
	    raw_spec->reserved != 0 ||
	    raw_spec->offset > IXGBE_MAX_FLX_SOURCE_OFF ||
	    raw_spec->offset % 2 ||
	    raw_spec->limit != 0 ||
	    raw_spec->length != 2 ||
	    (raw_spec->pattern[0] == 0xff &&
	     raw_spec->pattern[1] == 0xff)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid RAW spec");
	}

	if (raw_mask->pattern[0] != 0xff ||
	    raw_mask->pattern[1] != 0xff) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"RAW pattern must be fully masked");
	}

	return 0;
}

static int
ixgbe_process_fdir_normal_raw(void *ctx,
			  const struct rte_flow_item *item,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_raw *raw_spec = item->spec;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->b_spec = TRUE;
	rule->ixgbe_fdir.formatted.flex_bytes =
		(((uint16_t)raw_spec->pattern[1]) << 8) | raw_spec->pattern[0];
	rule->flex_bytes_offset = raw_spec->offset;

	rule->b_mask = TRUE;
	rule->mask.flex_bytes_mask = 0xffff;

	return 0;
}

static int
ixgbe_process_fdir_normal_end(void *ctx, const struct rte_flow_item *item __rte_unused,
			  struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;

	/* check if we need L4 protocol */
	if (fdir_ctx->rule.ixgbe_fdir.formatted.flow_type & IXGBE_ATR_L4TYPE_MASK)
		fdir_ctx->rule.mask.l4_proto_match = 1;

	return 0;
}

static const struct rte_flow_graph ixgbe_fdir_normal_graph = {
	.ignore_nodes = (const enum rte_flow_item_type[]) {
		RTE_FLOW_ITEM_TYPE_FUZZY,
		RTE_FLOW_ITEM_TYPE_END,
	},
	.nodes = (struct rte_flow_graph_node[]) {
		[IXGBE_FDIR_NORMAL_NODE_START] = {
			.name = "START",
		},
		[IXGBE_FDIR_NORMAL_NODE_ETH] = {
			.name = "ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.validate = ixgbe_validate_fdir_normal_eth,
			.process = ixgbe_process_fdir_normal_eth,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_VLAN] = {
			.name = "VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.process = ixgbe_process_fdir_normal_vlan,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_IPV4] = {
			.name = "IPV4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.validate = ixgbe_validate_fdir_normal_ipv4,
			.process = ixgbe_process_fdir_normal_ipv4,
			.constraints = RTE_FLOW_NODE_EXPECT_MASK |
				       RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_IPV6] = {
			.name = "IPV6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.validate = ixgbe_validate_fdir_normal_ipv6,
			.process = ixgbe_process_fdir_normal_ipv6,
			.constraints = RTE_FLOW_NODE_EXPECT_MASK |
				       RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_TCP] = {
			.name = "TCP",
			.type = RTE_FLOW_ITEM_TYPE_TCP,
			.validate = ixgbe_validate_fdir_normal_tcp,
			.process = ixgbe_process_fdir_normal_tcp,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_MASK |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_UDP] = {
			.name = "UDP",
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.validate = ixgbe_validate_fdir_normal_udp,
			.process = ixgbe_process_fdir_normal_udp,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
			               RTE_FLOW_NODE_EXPECT_MASK |
			               RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_SCTP] = {
			.name = "SCTP",
			.type = RTE_FLOW_ITEM_TYPE_SCTP,
			.validate = ixgbe_validate_fdir_normal_sctp,
			.process = ixgbe_process_fdir_normal_sctp,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY |
				       RTE_FLOW_NODE_EXPECT_MASK |
				       RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_NORMAL_NODE_RAW] = {
			.name = "RAW",
			.type = RTE_FLOW_ITEM_TYPE_RAW,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
			.validate = ixgbe_validate_fdir_normal_raw,
			.process = ixgbe_process_fdir_normal_raw,
		},
		[IXGBE_FDIR_NORMAL_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
			.process = ixgbe_process_fdir_normal_end,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[IXGBE_FDIR_NORMAL_NODE_START] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_ETH,
				IXGBE_FDIR_NORMAL_NODE_IPV4,
				IXGBE_FDIR_NORMAL_NODE_IPV6,
				IXGBE_FDIR_NORMAL_NODE_TCP,
				IXGBE_FDIR_NORMAL_NODE_UDP,
				IXGBE_FDIR_NORMAL_NODE_SCTP,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_ETH] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_VLAN,
				IXGBE_FDIR_NORMAL_NODE_IPV4,
				IXGBE_FDIR_NORMAL_NODE_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_VLAN] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_IPV4] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_TCP,
				IXGBE_FDIR_NORMAL_NODE_UDP,
				IXGBE_FDIR_NORMAL_NODE_SCTP,
				IXGBE_FDIR_NORMAL_NODE_RAW,
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_IPV6] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_TCP,
				IXGBE_FDIR_NORMAL_NODE_UDP,
				IXGBE_FDIR_NORMAL_NODE_SCTP,
				IXGBE_FDIR_NORMAL_NODE_RAW,
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_TCP] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_RAW,
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_UDP] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_RAW,
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_SCTP] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_RAW,
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_NORMAL_NODE_RAW] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_NORMAL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

/**
 * FDIR tunnel graph implementation (VxLAN and NVGRE)
 * Pattern: START -> [OUTER_ETH] -> (OUTER_IPv4|OUTER_IPv6) -> [UDP] -> (VXLAN|NVGRE) -> INNER_ETH -> [VLAN] -> END
 * VxLAN:  START -> [OUTER_ETH] -> (OUTER_IPv4|OUTER_IPv6) -> UDP -> VXLAN -> INNER_ETH -> [VLAN] -> END
 * NVGRE:  START -> [OUTER_ETH] -> (OUTER_IPv4|OUTER_IPv6) -> NVGRE -> INNER_ETH -> [VLAN] -> END
 */

enum ixgbe_fdir_tunnel_node_id {
	IXGBE_FDIR_TUNNEL_NODE_START = RTE_FLOW_NODE_FIRST,
	IXGBE_FDIR_TUNNEL_NODE_OUTER_ETH,
	IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV4,
	IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV6,
	IXGBE_FDIR_TUNNEL_NODE_UDP,
	IXGBE_FDIR_TUNNEL_NODE_VXLAN,
	IXGBE_FDIR_TUNNEL_NODE_NVGRE,
	IXGBE_FDIR_TUNNEL_NODE_INNER_ETH,
	IXGBE_FDIR_TUNNEL_NODE_INNER_IPV4,
	IXGBE_FDIR_TUNNEL_NODE_VLAN,
	IXGBE_FDIR_TUNNEL_NODE_END,
	IXGBE_FDIR_TUNNEL_NODE_MAX,
};

static int
ixgbe_validate_fdir_tunnel_vxlan(const void *ctx __rte_unused,
				 const struct rte_flow_item *item,
				 struct rte_flow_error *error)
{
	const struct rte_flow_item_vxlan *vxlan_mask = item->mask;

	if (vxlan_mask->hdr.flags) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"VxLAN flags must be masked");
	}

	if (!CI_FIELD_IS_ZERO_OR_MASKED(&vxlan_mask->hdr.vni)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial VNI mask not supported");
	}

	return 0;
}

static int
ixgbe_process_fdir_tunnel_vxlan(void *ctx,
				const struct rte_flow_item *item,
				struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_vxlan *vxlan_spec = item->spec;
	const struct rte_flow_item_vxlan *vxlan_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.tunnel_type = IXGBE_FDIR_VXLAN_TUNNEL_TYPE;

	/* spec is optional */
	if (vxlan_spec != NULL) {
		rule->b_spec = TRUE;
		memcpy(((uint8_t *)&rule->ixgbe_fdir.formatted.tni_vni), vxlan_spec->hdr.vni,
				RTE_DIM(vxlan_spec->hdr.vni));
	}

	rule->b_mask = TRUE;
	rule->mask.tunnel_type_mask = 1;
	memcpy(&rule->mask.tunnel_id_mask, vxlan_mask->hdr.vni, RTE_DIM(vxlan_mask->hdr.vni));

	return 0;
}

static int
ixgbe_validate_fdir_tunnel_nvgre(const void *ctx __rte_unused,
				 const struct rte_flow_item *item,
				 struct rte_flow_error *error)
{
	const struct rte_flow_item_nvgre *nvgre_mask;

	nvgre_mask = item->mask;

	if (nvgre_mask->flow_id) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"NVGRE flow ID must not be masked");
	}

	if (!CI_FIELD_IS_ZERO_OR_MASKED(&nvgre_mask->protocol)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"NVGRE protocol must be fully masked or unmasked");
	}

	if (!CI_FIELD_IS_ZERO_OR_MASKED(&nvgre_mask->c_k_s_rsvd0_ver)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"NVGRE flags must be fully masked or unmasked");
	}

	if (!CI_FIELD_IS_ZERO_OR_MASKED(&nvgre_mask->tni)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial TNI mask not supported");
	}

	/* if spec is present, validate flags and protocol values */
	if (item->spec) {
		const struct rte_flow_item_nvgre *nvgre_spec = item->spec;

		if (nvgre_mask->c_k_s_rsvd0_ver &&
		    nvgre_spec->c_k_s_rsvd0_ver != rte_cpu_to_be_16(NVGRE_FLAGS)) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, item,
					"NVGRE flags must be 0x2000");
		}
		if (nvgre_mask->protocol &&
		    nvgre_spec->protocol != rte_cpu_to_be_16(NVGRE_PROTOCOL)) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, item,
					"NVGRE protocol must be 0x6558");
		}
	}

	return 0;
}

static int
ixgbe_process_fdir_tunnel_nvgre(void *ctx,
				const struct rte_flow_item *item,
				struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_nvgre *nvgre_spec = item->spec;
	const struct rte_flow_item_nvgre *nvgre_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.tunnel_type = IXGBE_FDIR_NVGRE_TUNNEL_TYPE;

	/* spec is optional */
	if (nvgre_spec != NULL) {
		rule->b_spec = TRUE;
		memcpy(&fdir_ctx->rule.ixgbe_fdir.formatted.tni_vni,
				nvgre_spec->tni, RTE_DIM(nvgre_spec->tni));
	}

	rule->b_mask = TRUE;
	rule->mask.tunnel_type_mask = 1;
	memcpy(&rule->mask.tunnel_id_mask, nvgre_mask->tni, RTE_DIM(nvgre_mask->tni));
	rule->mask.tunnel_id_mask <<= 8;
	return 0;
}

static int
ixgbe_validate_fdir_tunnel_inner_eth(const void *ctx __rte_unused,
				     const struct rte_flow_item *item,
				     struct rte_flow_error *error)
{
	const struct rte_flow_item_eth *eth_mask = item->mask;

	if (eth_mask->hdr.ether_type != 0) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Ether type mask not supported");
	}

	/* src addr must not be masked */
	if (!CI_FIELD_IS_ZERO(&eth_mask->hdr.src_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Masking not supported for src MAC address");
	}

	/* dst addr must be either fully masked or fully unmasked */
	if (!CI_FIELD_IS_ZERO_OR_MASKED(&eth_mask->hdr.dst_addr)) {
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Partial masks not supported for dst MAC address");
	}

	return 0;
}

static int
ixgbe_process_fdir_tunnel_inner_eth(void *ctx,
				    const struct rte_flow_item *item,
				    struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_eth *eth_spec = item->spec;
	const struct rte_flow_item_eth *eth_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;
	uint8_t j;

	/* spec is optional */
	if (eth_spec != NULL) {
		rule->b_spec = TRUE;
		memcpy(&rule->ixgbe_fdir.formatted.inner_mac,
				eth_spec->hdr.dst_addr.addr_bytes,
				RTE_ETHER_ADDR_LEN);
	}

	rule->b_mask = TRUE;
	rule->mask.mac_addr_byte_mask = 0;
	for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
		if (eth_mask->hdr.dst_addr.addr_bytes[j] == 0xFF) {
			rule->mask.mac_addr_byte_mask |= 0x1 << j;
		}
	}

	/* When no vlan, considered as full mask. */
	rule->mask.vlan_tci_mask = IXGBE_FDIR_VLAN_TCI_MASK;

	return 0;
}

static int
ixgbe_process_fdir_tunnel_vlan(void *ctx,
			       const struct rte_flow_item *item,
			       struct rte_flow_error *error __rte_unused)
{
	struct ixgbe_fdir_ctx *fdir_ctx = ctx;
	const struct rte_flow_item_vlan *vlan_spec = item->spec;
	const struct rte_flow_item_vlan *vlan_mask = item->mask;
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;

	rule->ixgbe_fdir.formatted.vlan_id = vlan_spec->hdr.vlan_tci;

	rule->mask.vlan_tci_mask = vlan_mask->hdr.vlan_tci;
	rule->mask.vlan_tci_mask &= IXGBE_FDIR_VLAN_TCI_MASK;

	return 0;
}

static const struct rte_flow_graph ixgbe_fdir_tunnel_graph = {
	.nodes = (struct rte_flow_graph_node[]) {
		[IXGBE_FDIR_TUNNEL_NODE_START] = {
			.name = "START",
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_ETH] = {
			.name = "OUTER_ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV4] = {
			.name = "OUTER_IPV4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV6] = {
			.name = "OUTER_IPV6",
			.type = RTE_FLOW_ITEM_TYPE_IPV6,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_FDIR_TUNNEL_NODE_UDP] = {
			.name = "UDP",
			.type = RTE_FLOW_ITEM_TYPE_UDP,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_FDIR_TUNNEL_NODE_VXLAN] = {
			.name = "VXLAN",
			.type = RTE_FLOW_ITEM_TYPE_VXLAN,
			.validate = ixgbe_validate_fdir_tunnel_vxlan,
			.process = ixgbe_process_fdir_tunnel_vxlan,
			.constraints = RTE_FLOW_NODE_EXPECT_MASK |
				RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_TUNNEL_NODE_NVGRE] = {
			.name = "NVGRE",
			.type = RTE_FLOW_ITEM_TYPE_NVGRE,
			.validate = ixgbe_validate_fdir_tunnel_nvgre,
			.process = ixgbe_process_fdir_tunnel_nvgre,
			.constraints = RTE_FLOW_NODE_EXPECT_MASK |
				RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_TUNNEL_NODE_INNER_ETH] = {
			.name = "INNER_ETH",
			.type = RTE_FLOW_ITEM_TYPE_ETH,
			.validate = ixgbe_validate_fdir_tunnel_inner_eth,
			.process = ixgbe_process_fdir_tunnel_inner_eth,
			.constraints = RTE_FLOW_NODE_EXPECT_MASK |
				RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_TUNNEL_NODE_INNER_IPV4] = {
			.name = "INNER_IPV4",
			.type = RTE_FLOW_ITEM_TYPE_IPV4,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[IXGBE_FDIR_TUNNEL_NODE_VLAN] = {
			.name = "VLAN",
			.type = RTE_FLOW_ITEM_TYPE_VLAN,
			.process = ixgbe_process_fdir_tunnel_vlan,
			.constraints = RTE_FLOW_NODE_EXPECT_SPEC_MASK,
		},
		[IXGBE_FDIR_TUNNEL_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge[]) {
		[IXGBE_FDIR_TUNNEL_NODE_START] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_OUTER_ETH,
				IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV4,
				IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV6,
				IXGBE_FDIR_TUNNEL_NODE_UDP,
				IXGBE_FDIR_TUNNEL_NODE_VXLAN,
				IXGBE_FDIR_TUNNEL_NODE_NVGRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_ETH] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV4,
				IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV6,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV4] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_UDP,
				IXGBE_FDIR_TUNNEL_NODE_NVGRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_OUTER_IPV6] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_UDP,
				IXGBE_FDIR_TUNNEL_NODE_NVGRE,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_UDP] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_VXLAN,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_VXLAN] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_INNER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_NVGRE] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_INNER_ETH,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_INNER_ETH] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_VLAN,
				IXGBE_FDIR_TUNNEL_NODE_INNER_IPV4,
				IXGBE_FDIR_TUNNEL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
		[IXGBE_FDIR_TUNNEL_NODE_VLAN] = {
			.next = (const size_t[]) {
				IXGBE_FDIR_TUNNEL_NODE_END,
				RTE_FLOW_NODE_EDGE_END
			}
		},
	},
};

static inline uint8_t
signature_match(const struct rte_flow_item *item)
{
	const struct rte_flow_item_fuzzy *spec, *last, *mask;
	uint32_t sh, lh, mh;

	spec = item->spec;
	last = item->last;
	mask = item->mask;

	if (spec == NULL || mask == NULL)
		return 0;

	sh = spec->thresh;

	if (last == NULL)
		lh = sh;
	else
		lh = last->thresh;

	mh = mask->thresh;
	sh = sh & mh;
	lh = lh & mh;

	/*
	 * A fuzzy item selects signature mode only when the masked threshold range
	 * is non-empty. Otherwise this stays a perfect-match rule.
	 */
	if (!sh || sh > lh)
		return 0;

	return 1;
}

/* pre-parse pattern to determine if this is a signature or perfect match rule */
static int
ixgbe_fdir_pattern_parse(struct ci_flow_engine_ctx *ctx,
		const struct rte_flow_item pattern[],
		struct rte_flow_error *error)
{
	struct ixgbe_fdir_ctx *fdir_ctx = (struct ixgbe_fdir_ctx *)ctx;
	const struct rte_flow_item *item;
	bool found = false;

	fdir_ctx->rule.mode = RTE_FDIR_MODE_PERFECT;

	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type != RTE_FLOW_ITEM_TYPE_FUZZY)
			continue;

		if (found) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, item,
					"Multiple FUZZY items not supported");
		}
		found = true;

		if (signature_match(item))
			fdir_ctx->rule.mode = RTE_FDIR_MODE_SIGNATURE;

		break;
	}

	return 0;
}

static int
ixgbe_fdir_actions_check(const struct ci_flow_actions *parsed_actions,
	const struct ci_flow_actions_check_param *param __rte_unused,
	struct rte_flow_error *error)
{
	const enum rte_flow_action_type fwd_actions[] = {
		RTE_FLOW_ACTION_TYPE_QUEUE,
		RTE_FLOW_ACTION_TYPE_DROP,
		RTE_FLOW_ACTION_TYPE_END
	};
	const struct rte_flow_action *action;

	/* do the generic checks first */
	int ret = ixgbe_flow_actions_check(parsed_actions, param, error);
	if (ret)
		return ret;

	/* first action must be a forwarding action */
	action = parsed_actions->actions[0];
	if (!ci_flow_action_type_in_list(action->type, fwd_actions)) {
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					  action, "First action must be QUEUE or DROP");
	}
	/* second action, if specified, must not be a forwarding action */
	action = parsed_actions->actions[1];
	if (action != NULL && ci_flow_action_type_in_list(action->type, fwd_actions)) {
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					  action, "Conflicting actions");
	}
	return 0;
}

static int
ixgbe_flow_fdir_ctx_validate(struct ci_flow_engine_ctx *ctx, struct rte_flow_error *error)
{
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(ctx->dev_data->dev_private);
	struct ixgbe_fdir_ctx *fdir_ctx = (struct ixgbe_fdir_ctx *)ctx;
	struct rte_eth_fdir_conf *global_fdir_conf = IXGBE_DEV_PRIVATE_TO_FDIR_CONF(adapter);

	/* DROP action should not be used with signature matches */
	if ((fdir_ctx->rule.mode == RTE_FDIR_MODE_SIGNATURE) &&
	    (fdir_ctx->fwd_action->type == RTE_FLOW_ACTION_TYPE_DROP)) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"DROP action not allowed with signature mode");
	}

	/* check for conflicting filter modes */
	if (global_fdir_conf->mode != RTE_FDIR_MODE_NONE &&
			global_fdir_conf->mode != fdir_ctx->rule.mode) {
		return rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Conflicting filter modes");
	}

	/* rules without spec aren't allowed */
	if (!fdir_ctx->rule.b_spec) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Rule spec cannot be empty");
	}

	return 0;
}

static int
ixgbe_flow_fdir_ctx_parse_common(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ixgbe_fdir_ctx *fdir_ctx = (struct ixgbe_fdir_ctx *)ctx;
	struct ci_flow_actions parsed_actions;
	struct ci_flow_actions_check_param ap_param = {
		.allowed_types = (const enum rte_flow_action_type[]){
			/* queue/mark/drop allowed here */
			RTE_FLOW_ACTION_TYPE_QUEUE,
			RTE_FLOW_ACTION_TYPE_DROP,
			RTE_FLOW_ACTION_TYPE_MARK,
			RTE_FLOW_ACTION_TYPE_END
		},
		.driver_ctx = ctx->dev_data,
		.check = ixgbe_fdir_actions_check
	};
	struct ixgbe_fdir_rule *rule = &fdir_ctx->rule;
	int ret;

	/* validate attributes */
	ret = ci_flow_check_attr(attr, NULL, error);
	if (ret)
		return ret;

	/* parse requested actions */
	ret = ci_flow_check_actions(actions, &ap_param, &parsed_actions, error);
	if (ret)
		return ret;

	fdir_ctx->fwd_action = parsed_actions.actions[0];
	/* can be NULL */
	fdir_ctx->aux_action = parsed_actions.actions[1];

	/* set up forward/drop action */
	if (fdir_ctx->fwd_action->type == RTE_FLOW_ACTION_TYPE_QUEUE) {
		const struct rte_flow_action_queue *q_act = fdir_ctx->fwd_action->conf;
		rule->queue = q_act->index;
	} else {
		rule->fdirflags = IXGBE_FDIRCMD_DROP;
	}

	/* set up mark action */
	if (fdir_ctx->aux_action != NULL && fdir_ctx->aux_action->type == RTE_FLOW_ACTION_TYPE_MARK) {
		const struct rte_flow_action_mark *m_act = fdir_ctx->aux_action->conf;
		rule->soft_id = m_act->id;
	}

	return ret;
}

static int
ixgbe_flow_fdir_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(ctx->dev_data->dev_private);
	struct ixgbe_fdir_ctx *fdir_ctx = (struct ixgbe_fdir_ctx *)ctx;
	int ret;

	/* call into common part first */
	ret = ixgbe_flow_fdir_ctx_parse_common(actions, attr, ctx, error);
	if (ret)
		return ret;

	/* some hardware does not support SCTP matching */
	if (hw->mac.type == ixgbe_mac_X550 ||
			hw->mac.type == ixgbe_mac_X550EM_x ||
			hw->mac.type == ixgbe_mac_X550EM_a ||
			hw->mac.type == ixgbe_mac_E610)
		fdir_ctx->supports_sctp_ports = true;

	/*
	 * Some fields may not be provided. Set spec to 0 and mask to default
	 * value. So, we need not do anything for the not provided fields later.
	 */
	memset(&fdir_ctx->rule.mask, 0xFF, sizeof(struct ixgbe_hw_fdir_mask));
	fdir_ctx->rule.mask.vlan_tci_mask = 0;
	fdir_ctx->rule.mask.flex_bytes_mask = 0;
	fdir_ctx->rule.mask.dst_port_mask = 0;
	fdir_ctx->rule.mask.src_port_mask = 0;
	fdir_ctx->rule.mask.l4_proto_match = 0;

	return 0;
}

static int
ixgbe_flow_fdir_tunnel_ctx_parse(const struct rte_flow_action *actions,
		const struct rte_flow_attr *attr,
		struct ci_flow_engine_ctx *ctx,
		struct rte_flow_error *error)
{
	struct ixgbe_fdir_ctx *fdir_ctx = (struct ixgbe_fdir_ctx *)ctx;
	int ret;

	/* call into common part first */
	ret = ixgbe_flow_fdir_ctx_parse_common(actions, attr, ctx, error);
	if (ret)
		return ret;

	/**
	 * Some fields may not be provided. Set spec to 0 and mask to default
	 * value. So, we need not do anything for the not provided fields later.
	 */
	memset(&fdir_ctx->rule.mask, 0xFF, sizeof(struct ixgbe_hw_fdir_mask));
	fdir_ctx->rule.mask.vlan_tci_mask = 0;

	fdir_ctx->rule.mode = RTE_FDIR_MODE_PERFECT_TUNNEL;

	return 0;
}

static int
ixgbe_flow_fdir_ctx_to_flow(const struct ci_flow_engine_ctx *ctx,
		struct ci_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	const struct ixgbe_fdir_ctx *fdir_ctx = (const struct ixgbe_fdir_ctx *)ctx;
	struct ixgbe_fdir_flow *fdir_flow = (struct ixgbe_fdir_flow *)flow;

	fdir_flow->rule = fdir_ctx->rule;

	return 0;
}

/* 1 if needs mask install, 0 if doesn't, -1 if incompatible */
static int
ixgbe_flow_fdir_needs_mask_install(struct ixgbe_fdir_flow *fdir_flow)
{
	struct rte_eth_dev_data *dev_data = fdir_flow->flow.flow.dev_data;
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(dev_data->dev_private);
	struct ixgbe_hw_fdir_info *global_fdir_info = IXGBE_DEV_PRIVATE_TO_FDIR_INFO(adapter);
	struct ixgbe_fdir_rule *rule = &fdir_flow->rule;
	int ret;

	/* if rule doesn't have a mask, don't do anything */
	if (rule->b_mask == 0)
		return 0;

	/* rule has a mask, check if global config doesn't */
	if (!global_fdir_info->mask_added)
		return 1;

	/* global config has a mask, check if it matches */
	ret = memcmp(&global_fdir_info->mask, &rule->mask, sizeof(rule->mask));
	if (ret)
		return -1;

	/* does rule specify flex bytes mask? */
	if (rule->mask.flex_bytes_mask == 0)
		/* compatible */
		return 0;

	/* if flex bytes mask is set, check if offset matches */
	if (global_fdir_info->flex_bytes_offset != rule->flex_bytes_offset)
		return -1;

	/* compatible */
	return 0;
}

static int
ixgbe_flow_fdir_install_mask(struct ixgbe_fdir_flow *fdir_flow, struct rte_flow_error *error)
{
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(fdir_flow->flow.flow.dev_data->dev_private);
	struct ixgbe_fdir_rule *rule = &fdir_flow->rule;
	int ret;

	/* do we need flex byte mask? */
	if (rule->mask.flex_bytes_mask != 0) {
		ret = ixgbe_fdir_set_flexbytes_offset(adapter, rule->flex_bytes_offset);
		if (ret != 0) {
			return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to set flex bytes offset");
		}
	}

	/* set mask */
	ret = ixgbe_fdir_set_input_mask(adapter, &rule->mask, rule->mode);
	if (ret != 0) {
		return rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Failed to set input mask");
	}

	return 0;
}

static int
ixgbe_flow_fdir_flow_install(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	struct rte_eth_fdir_conf *global_fdir_conf = IXGBE_DEV_PRIVATE_TO_FDIR_CONF(adapter);
	struct ixgbe_hw_fdir_info *global_fdir_info = IXGBE_DEV_PRIVATE_TO_FDIR_INFO(adapter);
	struct rte_eth_fdir_conf local_fdir_conf = *global_fdir_conf;
	struct ixgbe_fdir_flow *fdir_flow = (struct ixgbe_fdir_flow *)flow;
	struct ixgbe_fdir_rule *rule = &fdir_flow->rule;
	bool mask_installed = false;
	int ret;

	/* this is the mode we will be programming */
	local_fdir_conf.mode = rule->mode;

	/* if flow director isn't configured, configure it */
	if (global_fdir_conf->mode == RTE_FDIR_MODE_NONE) {
		ret = ixgbe_fdir_configure(adapter, &local_fdir_conf, &rule->mask);
		if (ret) {
			return rte_flow_error_set(error, -ret,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Failed to configure flow director");
		}
	}

	/* check if we need to install the mask first */
	ret = ixgbe_flow_fdir_needs_mask_install(fdir_flow);
	if (ret < 0) {
		return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Flow mask is incompatible with existing rules");
	} else if (ret > 0) {
		/* no mask yet, install it */
		ret = ixgbe_flow_fdir_install_mask(fdir_flow, error);
		if (ret != 0)
			return ret;
		mask_installed = true;
	}

	/* now install the rule */
	ret = ixgbe_fdir_filter_program(adapter, &local_fdir_conf, rule,
			FALSE, FALSE);
	if (ret) {
		return rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			NULL,
			"Failed to program flow director filter");
	}
	global_fdir_info->n_flows++;

	/* if we installed a mask, mark it as installed */
	if (mask_installed) {
		global_fdir_info->mask_added = TRUE;
		global_fdir_info->flex_bytes_offset = rule->flex_bytes_offset;
		global_fdir_info->mask = rule->mask;
	}
	global_fdir_conf->mode = rule->mode;

	return 0;
}

static int
ixgbe_flow_fdir_flow_uninstall(struct ci_flow *flow,
		struct rte_flow_error *error)
{
	struct ixgbe_adapter *adapter = IXGBE_DEV_PRIVATE_TO_ADAPTER(flow->dev_data->dev_private);
	struct rte_eth_fdir_conf *global_fdir_conf = IXGBE_DEV_PRIVATE_TO_FDIR_CONF(adapter);
	struct ixgbe_hw_fdir_info *global_fdir_info = IXGBE_DEV_PRIVATE_TO_FDIR_INFO(adapter);
	struct ixgbe_fdir_flow *fdir_flow = (struct ixgbe_fdir_flow *)flow;
	struct ixgbe_fdir_rule *rule = &fdir_flow->rule;
	int ret;

	/* uninstall the rule */
	ret = ixgbe_fdir_filter_program(adapter, global_fdir_conf, rule, TRUE, FALSE);
	if (ret != 0) {
		return rte_flow_error_set(error, -ret,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
			NULL,
			"Failed to remove flow director filter");
	}
	global_fdir_info->n_flows--;

	/* when last filter is removed, also remove the mask */
	if (global_fdir_info->n_flows > 0)
		return 0;

	global_fdir_info->mask_added = FALSE;
	global_fdir_info->mask = (struct ixgbe_hw_fdir_mask){0};
	global_fdir_info->flex_bytes_offset = 0;
	global_fdir_conf->mode = RTE_FDIR_MODE_NONE;

	return 0;
}

static int
ixgbe_flow_fdir_engine_init(const struct ci_flow_engine *engine __rte_unused,
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

static int
ixgbe_flow_fdir_tunnel_engine_init(const struct ci_flow_engine *engine __rte_unused,
		struct rte_eth_dev_data *dev_data,
		void *priv __rte_unused)
{
	struct ixgbe_hw *hw = IXGBE_DEV_PRIVATE_TO_HW(dev_data->dev_private);

	if (hw->mac.type == ixgbe_mac_X550 ||
			hw->mac.type == ixgbe_mac_X550EM_x ||
			hw->mac.type == ixgbe_mac_X550EM_a ||
			hw->mac.type == ixgbe_mac_E610)
		return 0;

	return -ENOTSUP;
}

static const struct ci_flow_engine_ops ixgbe_fdir_ops = {
	.engine_init = ixgbe_flow_fdir_engine_init,
	.ctx_parse = ixgbe_flow_fdir_ctx_parse,
	.pattern_parse = ixgbe_fdir_pattern_parse,
	.ctx_validate = ixgbe_flow_fdir_ctx_validate,
	.ctx_to_flow = ixgbe_flow_fdir_ctx_to_flow,
	.flow_install = ixgbe_flow_fdir_flow_install,
	.flow_uninstall = ixgbe_flow_fdir_flow_uninstall,
};

static const struct ci_flow_engine_ops ixgbe_fdir_tunnel_ops = {
	.engine_init = ixgbe_flow_fdir_tunnel_engine_init,
	.ctx_parse = ixgbe_flow_fdir_tunnel_ctx_parse,
	.ctx_validate = ixgbe_flow_fdir_ctx_validate,
	.ctx_to_flow = ixgbe_flow_fdir_ctx_to_flow,
	.flow_install = ixgbe_flow_fdir_flow_install,
	.flow_uninstall = ixgbe_flow_fdir_flow_uninstall,
};

const struct ci_flow_engine ixgbe_fdir_flow_engine = {
	.name = "fdir",
	.ctx_size = sizeof(struct ixgbe_fdir_ctx),
	.flow_size = sizeof(struct ixgbe_fdir_flow),
	.ops = &ixgbe_fdir_ops,
	.graph = &ixgbe_fdir_normal_graph,
};

const struct ci_flow_engine ixgbe_fdir_tunnel_flow_engine = {
	.name = "fdir_tunnel",
	.ctx_size = sizeof(struct ixgbe_fdir_ctx),
	.flow_size = sizeof(struct ixgbe_fdir_flow),
	.ops = &ixgbe_fdir_tunnel_ops,
	.graph = &ixgbe_fdir_tunnel_graph,
};
