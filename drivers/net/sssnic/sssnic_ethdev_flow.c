/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>
#include <rte_flow_driver.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_fdir.h"
#include "sssnic_ethdev_flow.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"

struct rte_flow {
	struct sssnic_ethdev_fdir_rule rule;
};

static enum rte_flow_item_type pattern_ethertype[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_any[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_ANY,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv4[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_any[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ANY,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv4_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv4_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv6[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv6_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv4_udp_vxlan_eth_ipv6_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV4,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_VXLAN,
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv6[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv6_udp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_UDP,
	RTE_FLOW_ITEM_TYPE_END,
};

static enum rte_flow_item_type pattern_eth_ipv6_tcp[] = {
	RTE_FLOW_ITEM_TYPE_ETH,
	RTE_FLOW_ITEM_TYPE_IPV6,
	RTE_FLOW_ITEM_TYPE_TCP,
	RTE_FLOW_ITEM_TYPE_END,
};

enum sssnic_ethdev_flow_type {
	SSSNIC_ETHDEV_FLOW_TYPE_UNKNOWN = -1,
	SSSNIC_ETHDEV_FLOW_TYPE_ETHERTYPE,
	SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
	SSSNIC_ETHDEV_FLOW_TYPE_COUNT,
};

struct sssnic_ethdev_flow_pattern {
	enum rte_flow_item_type *flow_items;
	enum sssnic_ethdev_flow_type type;
	bool is_tunnel;
};

static struct sssnic_ethdev_flow_pattern supported_flow_patterns[] = {
	{ pattern_ethertype, SSSNIC_ETHDEV_FLOW_TYPE_ETHERTYPE, false },
	{ pattern_eth_ipv4, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv4_udp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv4_tcp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv4_any, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv4_udp_vxlan, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, true },
	{ pattern_eth_ipv4_udp_vxlan_udp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, true },
	{ pattern_eth_ipv4_udp_vxlan_tcp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, true },
	{ pattern_eth_ipv4_udp_vxlan_any, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv4, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv4_tcp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv4_udp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv6, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv6_tcp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv4_udp_vxlan_eth_ipv6_udp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR,
		true },
	{ pattern_eth_ipv6, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv6_udp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
	{ pattern_eth_ipv6_tcp, SSSNIC_ETHDEV_FLOW_TYPE_FDIR, false },
};

static bool
sssnic_ethdev_flow_pattern_match(enum rte_flow_item_type *item_array,
	const struct rte_flow_item *pattern)
{
	const struct rte_flow_item *item = pattern;

	/* skip void items in the head of pattern */
	while (item->type == RTE_FLOW_ITEM_TYPE_VOID)
		item++;

	while ((*item_array == item->type) &&
		(*item_array != RTE_FLOW_ITEM_TYPE_END)) {
		item_array++;
		item++;
	}

	return (*item_array == RTE_FLOW_ITEM_TYPE_END &&
		item->type == RTE_FLOW_ITEM_TYPE_END);
}

static struct sssnic_ethdev_flow_pattern *
sssnic_ethdev_flow_pattern_lookup(const struct rte_flow_item *pattern)
{
	struct sssnic_ethdev_flow_pattern *flow_pattern;
	enum rte_flow_item_type *flow_items;
	size_t i;

	for (i = 0; i < RTE_DIM(supported_flow_patterns); i++) {
		flow_pattern = &supported_flow_patterns[i];
		flow_items = flow_pattern->flow_items;
		if (sssnic_ethdev_flow_pattern_match(flow_items, pattern))
			return flow_pattern;
	}

	return NULL;
}

static int
sssnic_ethdev_flow_action_parse(struct rte_eth_dev *ethdev,
	const struct rte_flow_action *actions, struct rte_flow_error *error,
	struct sssnic_ethdev_fdir_rule *fdir_rule)
{
	const struct rte_flow_action_queue *action_queue;
	const struct rte_flow_action *action = actions;

	if (action->type != RTE_FLOW_ACTION_TYPE_QUEUE) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
			NULL,
			"Unsupported action type, only support action queue");
		return -EINVAL;
	}

	action_queue = (const struct rte_flow_action_queue *)action->conf;
	if (action_queue->index >= ethdev->data->nb_rx_queues) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
			NULL, "Invalid queue index");
		return -EINVAL;
	}

	if (fdir_rule != NULL)
		fdir_rule->action.qid = action_queue->index;

	return 0;
}

static int
sssnic_ethdev_flow_ethertype_pattern_parse(const struct rte_flow_item *pattern,
	struct rte_flow_error *error, struct sssnic_ethdev_fdir_rule *fdir_rule)
{
	const struct rte_flow_item *item = pattern;
	const struct rte_flow_item_eth *spec, *mask;
	struct sssnic_ethdev_fdir_ethertype_match *fdir_match;

	while (item->type != RTE_FLOW_ITEM_TYPE_ETH)
		item++;

	spec = (const struct rte_flow_item_eth *)item->spec;
	mask = (const struct rte_flow_item_eth *)item->mask;

	if (item->last != NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_LAST,
			item, "Not support range");
		return -rte_errno;
	}

	if (spec == NULL || mask == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_LAST,
			item, "Ether mask or spec is NULL");
		return -rte_errno;
	}

	if (!rte_is_zero_ether_addr(&mask->src) ||
		!rte_is_zero_ether_addr(&mask->dst)) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item, "Invalid ether address mask");
		return -rte_errno;
	}

	if (mask->type != 0xffff) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM_MASK,
			item, "Invalid ether type mask");
		return -rte_errno;
	}

	if (fdir_rule != NULL) {
		fdir_rule->match.type = SSSNIC_ETHDEV_FDIR_MATCH_ETHERTYPE;
		fdir_match = &fdir_rule->match.ethertype;
		fdir_match->key.ether_type = rte_be_to_cpu_16(spec->type);
	}

	return 0;
}

static int
sssnic_ethdev_flow_eth_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error)
{
	if (item->spec != NULL || item->mask != NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item, "Not support eth match in fdir flow");
		return -rte_errno;
	}

	return 0;
}

static int
sssnic_ethdev_flow_ipv4_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error, bool outer,
	struct sssnic_ethdev_fdir_flow_match *fdir_match)
{
	const struct rte_flow_item_ipv4 *spec, *mask;
	uint32_t ip_addr;

	spec = (const struct rte_flow_item_ipv4 *)item->spec;
	mask = (const struct rte_flow_item_ipv4 *)item->mask;

	if (outer) {
		/* only tunnel flow has outer ipv4 */
		if (spec == NULL && mask == NULL)
			return 0;

		if (spec == NULL || mask == NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPV4 spec or mask");
			return -rte_errno;
		}

		if (mask->hdr.version_ihl || mask->hdr.type_of_service ||
			mask->hdr.total_length || mask->hdr.packet_id ||
			mask->hdr.fragment_offset || mask->hdr.time_to_live ||
			mask->hdr.next_proto_id || mask->hdr.hdr_checksum) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only support outer IPv4 src and dest address for tunnel flow");
			return -rte_errno;
		}

		if (fdir_match != NULL) {
			ip_addr = rte_be_to_cpu_32(spec->hdr.src_addr);
			fdir_match->key.ipv4.outer_sip_w0 = (uint16_t)ip_addr;
			fdir_match->key.ipv4.outer_sip_w1 =
				(uint16_t)(ip_addr >> 16);

			ip_addr = rte_be_to_cpu_32(mask->hdr.src_addr);
			fdir_match->mask.ipv4.outer_sip_w0 = (uint16_t)ip_addr;
			fdir_match->mask.ipv4.outer_sip_w1 =
				(uint16_t)(ip_addr >> 16);
		}
	} else {
		/* inner ip of tunnel flow or ip of non tunnel flow */
		if (spec == NULL && mask == NULL)
			return 0;

		if (spec == NULL || mask == NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPV4 spec or mask");
			return -rte_errno;
		}

		if (mask->hdr.version_ihl || mask->hdr.type_of_service ||
			mask->hdr.total_length || mask->hdr.packet_id ||
			mask->hdr.fragment_offset || mask->hdr.time_to_live ||
			mask->hdr.hdr_checksum) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only support IPv4 address and ipproto");
			return -rte_errno;
		}

		if (fdir_match != NULL) {
			ip_addr = rte_be_to_cpu_32(spec->hdr.src_addr);
			fdir_match->key.ipv4.sip_w0 = (uint16_t)ip_addr;
			fdir_match->key.ipv4.sip_w1 = (uint16_t)(ip_addr >> 16);

			ip_addr = rte_be_to_cpu_32(mask->hdr.src_addr);
			fdir_match->mask.ipv4.sip_w0 = (uint16_t)ip_addr;
			fdir_match->mask.ipv4.sip_w1 =
				(uint16_t)(ip_addr >> 16);

			fdir_match->key.ipv4.ip_proto = spec->hdr.next_proto_id;
			fdir_match->mask.ipv4.ip_proto =
				mask->hdr.next_proto_id;

			fdir_match->key.ipv4.ip_type =
				SSSNIC_ETHDEV_FDIR_FLOW_IPV4;
			fdir_match->mask.ipv4.ip_type = 0x1;
		}
	}

	return 0;
}

static int
sssnic_ethdev_flow_ipv6_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error, bool is_tunnel,
	struct sssnic_ethdev_fdir_flow_match *fdir_match)
{
	const struct rte_flow_item_ipv6 *spec, *mask;
	uint32_t ipv6_addr[4];
	int i;

	mask = (const struct rte_flow_item_ipv6 *)item->mask;
	spec = (const struct rte_flow_item_ipv6 *)item->spec;

	if (fdir_match != NULL) {
		/* ip_type of ipv6 flow_match can share with other flow_matches */
		fdir_match->key.ipv6.ip_type = SSSNIC_ETHDEV_FDIR_FLOW_IPV6;
		fdir_match->mask.ipv6.ip_type = 0x1;
	}

	if (is_tunnel) {
		if (mask == NULL && spec == NULL)
			return 0;

		if (spec == NULL || mask == NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPV6 spec or mask");
			return -rte_errno;
		}

		if (mask->hdr.vtc_flow || mask->hdr.payload_len ||
			mask->hdr.hop_limits || mask->hdr.src_addr) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only support IPv6 dest_addr and ipproto in tunnel flow");
			return -rte_errno;
		}

		if (fdir_match != NULL) {
			rte_memcpy(ipv6_addr, spec->hdr.dst_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->key.vxlan_ipv6.dip6_w0 =
				(uint16_t)ipv6_addr[0];
			fdir_match->key.vxlan_ipv6.dip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->key.vxlan_ipv6.dip6_w2 =
				(uint16_t)ipv6_addr[1];
			fdir_match->key.vxlan_ipv6.dip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->key.vxlan_ipv6.dip6_w4 =
				(uint16_t)ipv6_addr[2];
			fdir_match->key.vxlan_ipv6.dip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->key.vxlan_ipv6.dip6_w6 =
				(uint16_t)ipv6_addr[3];
			fdir_match->key.vxlan_ipv6.dip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			rte_memcpy(ipv6_addr, mask->hdr.dst_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->mask.vxlan_ipv6.dip6_w0 =
				(uint16_t)ipv6_addr[0];
			fdir_match->mask.vxlan_ipv6.dip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->mask.vxlan_ipv6.dip6_w2 =
				(uint16_t)ipv6_addr[1];
			fdir_match->mask.vxlan_ipv6.dip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->mask.vxlan_ipv6.dip6_w4 =
				(uint16_t)ipv6_addr[2];
			fdir_match->mask.vxlan_ipv6.dip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->mask.vxlan_ipv6.dip6_w6 =
				(uint16_t)ipv6_addr[3];
			fdir_match->mask.vxlan_ipv6.dip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			fdir_match->key.vxlan_ipv6.ip_proto = spec->hdr.proto;
			fdir_match->mask.vxlan_ipv6.ip_proto = mask->hdr.proto;
		}
	} else { /* non tunnel */
		if (spec == NULL || mask == NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Invalid IPV6 spec or mask");
			return -rte_errno;
		}

		if (mask->hdr.vtc_flow || mask->hdr.payload_len ||
			mask->hdr.hop_limits) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Only support IPv6 addr and ipproto");
			return -rte_errno;
		}

		if (fdir_match != NULL) {
			rte_memcpy(ipv6_addr, spec->hdr.dst_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->key.ipv6.dip6_w0 = (uint16_t)ipv6_addr[0];
			fdir_match->key.ipv6.dip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->key.ipv6.dip6_w2 = (uint16_t)ipv6_addr[1];
			fdir_match->key.ipv6.dip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->key.ipv6.dip6_w4 = (uint16_t)ipv6_addr[2];
			fdir_match->key.ipv6.dip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->key.ipv6.dip6_w6 = (uint16_t)ipv6_addr[3];
			fdir_match->key.ipv6.dip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			rte_memcpy(ipv6_addr, spec->hdr.src_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->key.ipv6.sip6_w0 = (uint16_t)ipv6_addr[0];
			fdir_match->key.ipv6.sip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->key.ipv6.sip6_w2 = (uint16_t)ipv6_addr[1];
			fdir_match->key.ipv6.sip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->key.ipv6.sip6_w4 = (uint16_t)ipv6_addr[2];
			fdir_match->key.ipv6.sip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->key.ipv6.sip6_w6 = (uint16_t)ipv6_addr[3];
			fdir_match->key.ipv6.sip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			rte_memcpy(ipv6_addr, mask->hdr.dst_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->mask.ipv6.dip6_w0 = (uint16_t)ipv6_addr[0];
			fdir_match->mask.ipv6.dip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->mask.ipv6.dip6_w2 = (uint16_t)ipv6_addr[1];
			fdir_match->mask.ipv6.dip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->mask.ipv6.dip6_w4 = (uint16_t)ipv6_addr[2];
			fdir_match->mask.ipv6.dip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->mask.ipv6.dip6_w6 = (uint16_t)ipv6_addr[3];
			fdir_match->mask.ipv6.dip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			rte_memcpy(ipv6_addr, mask->hdr.src_addr,
				sizeof(ipv6_addr));
			for (i = 0; i < 4; i++)
				ipv6_addr[i] = rte_be_to_cpu_32(ipv6_addr[i]);

			fdir_match->mask.ipv6.sip6_w0 = (uint16_t)ipv6_addr[0];
			fdir_match->mask.ipv6.sip6_w1 =
				(uint16_t)(ipv6_addr[0] >> 16);
			fdir_match->mask.ipv6.sip6_w2 = (uint16_t)ipv6_addr[1];
			fdir_match->mask.ipv6.sip6_w3 =
				(uint16_t)(ipv6_addr[1] >> 16);
			fdir_match->mask.ipv6.sip6_w4 = (uint16_t)ipv6_addr[2];
			fdir_match->mask.ipv6.sip6_w5 =
				(uint16_t)(ipv6_addr[2] >> 16);
			fdir_match->mask.ipv6.sip6_w6 = (uint16_t)ipv6_addr[3];
			fdir_match->mask.ipv6.sip6_w7 =
				(uint16_t)(ipv6_addr[3] >> 16);

			fdir_match->key.ipv6.ip_proto = spec->hdr.proto;
			fdir_match->mask.ipv6.ip_proto = mask->hdr.proto;
		}
	}

	return 0;
}

static int
sssnic_ethdev_flow_udp_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error, bool outer,
	struct sssnic_ethdev_fdir_flow_match *fdir_match)
{
	const struct rte_flow_item_udp *spec, *mask;

	spec = (const struct rte_flow_item_udp *)item->spec;
	mask = (const struct rte_flow_item_udp *)item->mask;

	if (outer) {
		if (spec != NULL || mask != NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Both of outer UDP spec and mask must be NULL in tunnel flow");
			return -rte_errno;
		}

		return 0;
	}

	if (fdir_match != NULL) {
		/* ipv6 match can share ip_proto with ipv4 match */
		fdir_match->key.ipv4.ip_proto = IPPROTO_UDP;
		fdir_match->mask.ipv4.ip_proto = 0xff;
	}

	if (spec == NULL && mask == NULL)
		return 0;

	if (spec == NULL || mask == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item, "Invalid UDP spec or mask");
		return -rte_errno;
	}

	if (fdir_match != NULL) {
		/* Other types of fdir match can share sport and dport with ipv4 match */
		fdir_match->key.ipv4.sport =
			rte_be_to_cpu_16(spec->hdr.src_port);
		fdir_match->mask.ipv4.sport =
			rte_be_to_cpu_16(mask->hdr.src_port);
		fdir_match->key.ipv4.dport =
			rte_be_to_cpu_16(spec->hdr.dst_port);
		fdir_match->mask.ipv4.dport =
			rte_be_to_cpu_16(mask->hdr.dst_port);
	}

	return 0;
}

static int
sssnic_ethdev_flow_tcp_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error, bool outer,
	struct sssnic_ethdev_fdir_flow_match *fdir_match)
{
	const struct rte_flow_item_tcp *spec, *mask;

	spec = (const struct rte_flow_item_tcp *)item->spec;
	mask = (const struct rte_flow_item_tcp *)item->mask;

	if (outer) {
		if (spec != NULL || mask != NULL) {
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Both of outer TCP spec and mask must be NULL in tunnel flow");
			return -rte_errno;
		}

		return 0;
	}

	if (fdir_match != NULL) {
		/* ipv6 match can share ip_proto with ipv4 match */
		fdir_match->key.ipv4.ip_proto = IPPROTO_TCP;
		fdir_match->mask.ipv6.ip_proto = 0xff;
	}

	if (spec == NULL && mask == NULL)
		return 0;

	if (spec == NULL || mask == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item, "Invalid TCP spec or mask.");
		return -rte_errno;
	}

	if (mask->hdr.sent_seq || mask->hdr.recv_ack || mask->hdr.data_off ||
		mask->hdr.rx_win || mask->hdr.tcp_flags || mask->hdr.cksum ||
		mask->hdr.tcp_urp) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item,
			"Invalid TCP item, support src_port and dst_port only");
		return -rte_errno;
	}

	if (fdir_match != NULL) {
		/* Other types of fdir match can share sport and dport with ipv4 match */
		fdir_match->key.ipv4.sport =
			rte_be_to_cpu_16(spec->hdr.src_port);
		fdir_match->mask.ipv4.sport =
			rte_be_to_cpu_16(mask->hdr.src_port);
		fdir_match->key.ipv4.dport =
			rte_be_to_cpu_16(spec->hdr.dst_port);
		fdir_match->mask.ipv4.dport =
			rte_be_to_cpu_16(mask->hdr.dst_port);
	}

	return 0;
}

static int
sssnic_ethdev_flow_vxlan_parse(const struct rte_flow_item *item,
	struct rte_flow_error *error,
	struct sssnic_ethdev_fdir_flow_match *fdir_match)
{
	const struct rte_flow_item_vxlan *spec, *mask;
	uint32_t vni;

	spec = (const struct rte_flow_item_vxlan *)item->spec;
	mask = (const struct rte_flow_item_vxlan *)item->mask;

	if (spec == NULL && mask == NULL)
		return 0;

	if (spec == NULL || mask == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			item, "Invalid VXLAN spec or mask");
		return -rte_errno;
	}

	/* vxlan-ipv6 match can share vni with vxlan-ipv4 match */
	if (fdir_match != NULL) {
		rte_memcpy(((uint8_t *)&vni) + 1, spec->vni, 3);
		vni = rte_be_to_cpu_32(vni);
		fdir_match->key.ipv4.vni_w0 = (uint16_t)vni;
		fdir_match->key.ipv4.vni_w1 = (uint16_t)(vni >> 16);
		rte_memcpy(((uint8_t *)&vni) + 1, mask->vni, 3);
		vni = rte_be_to_cpu_32(vni);
		fdir_match->mask.ipv4.vni_w0 = (uint16_t)vni;
		fdir_match->mask.ipv4.vni_w1 = (uint16_t)(vni >> 16);
	}

	return 0;
}

static int
sssnic_ethdev_flow_fdir_pattern_parse(const struct rte_flow_item *pattern,
	struct rte_flow_error *error, bool is_tunnel,
	struct sssnic_ethdev_fdir_rule *fdir_rule)
{
	struct sssnic_ethdev_fdir_flow_match *fdir_match = NULL;
	const struct rte_flow_item *flow_item;
	bool outer_ip;
	int ret = 0;

	fdir_rule->match.type = SSSNIC_ETHDEV_FDIR_MATCH_FLOW;
	if (fdir_rule != NULL)
		fdir_match = &fdir_rule->match.flow;

	if (is_tunnel)
		outer_ip = true;
	else
		outer_ip = false;

	flow_item = pattern;
	while (flow_item->type != RTE_FLOW_ITEM_TYPE_END) {
		switch (flow_item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			ret = sssnic_ethdev_flow_eth_parse(flow_item, error);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			ret = sssnic_ethdev_flow_ipv4_parse(flow_item, error,
				outer_ip, fdir_match);
			break;
		case RTE_FLOW_ITEM_TYPE_IPV6:
			ret = sssnic_ethdev_flow_ipv6_parse(flow_item, error,
				is_tunnel, fdir_match);
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			ret = sssnic_ethdev_flow_udp_parse(flow_item, error,
				outer_ip, fdir_match);
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			ret = sssnic_ethdev_flow_tcp_parse(flow_item, error,
				outer_ip, fdir_match);
			break;
		case RTE_FLOW_ITEM_TYPE_VXLAN:
			ret = sssnic_ethdev_flow_vxlan_parse(flow_item, error,
				fdir_match);
			outer_ip = false; /* next parsing is inner_ip */
			break;
		default:
			break;
		}

		if (ret != 0)
			return ret;

		flow_item++;
	}

	if (is_tunnel) {
		if (fdir_match != NULL) {
			/* tunnel_type of ipv4 flow_match can share with other flow_matches */
			fdir_match->key.ipv4.tunnel_type =
				SSSNIC_ETHDEV_FDIR_FLOW_TUNNEL_VXLAN;
			fdir_match->mask.ipv4.tunnel_type = 0x1;
		}
	}

	return 0;
}

static int
sssnic_ethdev_flow_attr_parse(const struct rte_flow_attr *attr,
	struct rte_flow_error *error)
{
	if (attr->egress != 0 || attr->priority != 0 || attr->group != 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ATTR,
			attr, "Invalid flow attr, support ingress only");
		return -rte_errno;
	}

	if (attr->ingress == 0) {
		rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, attr,
			"Ingress of flow attr is not set");
		return -rte_errno;
	}

	return 0;
}

static int
sssnic_ethdev_flow_parse(struct rte_eth_dev *ethdev,
	const struct rte_flow_attr *attr, const struct rte_flow_item *pattern,
	const struct rte_flow_action *actions, struct rte_flow_error *error,
	struct sssnic_ethdev_fdir_rule *fdir_rule)
{
	int ret;
	struct sssnic_ethdev_flow_pattern *flow_pattern;

	flow_pattern = sssnic_ethdev_flow_pattern_lookup(pattern);
	if (flow_pattern == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM,
			NULL, "Unsupported pattern");
		return -rte_errno;
	}

	if (flow_pattern->type == SSSNIC_ETHDEV_FLOW_TYPE_FDIR)
		ret = sssnic_ethdev_flow_fdir_pattern_parse(pattern, error,
			flow_pattern->is_tunnel, fdir_rule);
	else
		ret = sssnic_ethdev_flow_ethertype_pattern_parse(pattern, error,
			fdir_rule);
	if (ret != 0)
		return ret;

	ret = sssnic_ethdev_flow_action_parse(ethdev, actions, error,
		fdir_rule);
	if (ret != 0)
		return ret;

	ret = sssnic_ethdev_flow_attr_parse(attr, error);
	if (ret != 0)
		return ret;

	return 0;
}

static struct rte_flow *
sssnic_ethdev_flow_create(struct rte_eth_dev *ethdev,
	const struct rte_flow_attr *attr, const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[], struct rte_flow_error *error)
{
	struct sssnic_ethdev_fdir_rule *rule;
	int ret;

	rule = sssnic_ethdev_fdir_rule_alloc();
	if (rule == NULL) {
		rte_flow_error_set(error, ENOMEM, RTE_FLOW_ERROR_TYPE_HANDLE,
			NULL, "Failed to allocate fdir rule memory");
		return NULL;
	}

	ret = sssnic_ethdev_flow_parse(ethdev, attr, pattern, actions, error,
		rule);
	if (ret != 0) {
		sssnic_ethdev_fdir_rule_free(rule);
		return NULL;
	}

	ret = sssnic_ethdev_fdir_rule_add(ethdev, rule);
	if (ret != 0) {
		sssnic_ethdev_fdir_rule_free(rule);
		rte_flow_error_set(error, ret, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Failed to add fdir rule");
		return NULL;
	}

	return (struct rte_flow *)rule;
}

static int
sssnic_ethdev_flow_destroy(struct rte_eth_dev *ethdev, struct rte_flow *flow,
	struct rte_flow_error *error)
{
	int ret;

	if (flow == NULL) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_HANDLE,
			NULL, "Invalid parameter");
		return -rte_errno;
	}

	ret = sssnic_ethdev_fdir_rule_del(ethdev,
		(struct sssnic_ethdev_fdir_rule *)flow);

	if (ret != 0) {
		rte_flow_error_set(error, EIO, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Failed to delete fdir rule");
		return -rte_errno;
	}

	sssnic_ethdev_fdir_rule_free((struct sssnic_ethdev_fdir_rule *)flow);

	return 0;
}

static int
sssnic_ethdev_flow_validate(struct rte_eth_dev *ethdev,
	const struct rte_flow_attr *attr, const struct rte_flow_item pattern[],
	const struct rte_flow_action actions[], struct rte_flow_error *error)
{
	return sssnic_ethdev_flow_parse(ethdev, attr, pattern, actions, error,
		NULL);
}

static int
sssnic_ethdev_flow_flush(struct rte_eth_dev *ethdev,
	struct rte_flow_error *error)
{
	int ret;

	ret = sssnic_ethdev_fdir_rules_flush(ethdev);
	if (ret != 0) {
		rte_flow_error_set(error, EIO, RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Failed to flush fdir rules");
		return -rte_errno;
	}

	return 0;
}

static const struct rte_flow_ops sssnic_ethdev_flow_ops = {
	.validate = sssnic_ethdev_flow_validate,
	.create = sssnic_ethdev_flow_create,
	.destroy = sssnic_ethdev_flow_destroy,
	.flush = sssnic_ethdev_flow_flush,
};

int
sssnic_ethdev_flow_ops_get(struct rte_eth_dev *ethdev,
	const struct rte_flow_ops **ops)
{
	RTE_SET_USED(ethdev);

	*ops = &sssnic_ethdev_flow_ops;

	return 0;
}
