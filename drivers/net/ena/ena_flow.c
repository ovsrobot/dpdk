/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 Amazon.com, Inc. or its affiliates.
 */

#include <rte_flow.h>
#include <rte_flow_driver.h>
#include <rte_malloc.h>

#include "ena_ethdev.h"
#include "ena_logs.h"
#include "base/ena_com.h"
#include "ena_flow.h"

/* Flow handle encoding - no heap allocation needed */
static inline struct rte_flow *
ena_flow_handle_encode(uint16_t rule_idx)
{
	return (struct rte_flow *)(uintptr_t)(rule_idx + 1);
}

static inline int
ena_flow_handle_decode(const struct rte_flow *flow, uint16_t *rule_idx)
{
	uintptr_t v = (uintptr_t)flow;
	if (v == 0 || v > (uintptr_t)UINT16_MAX + 1)
		return -EINVAL;
	*rule_idx = (uint16_t)(v - 1);
	return 0;
}

/* Convert to ENA flow type - note: returns uint8_t for flow_type field */
static uint8_t
ena_flow_type_convert(bool ipv4, bool ipv6, bool tcp, bool udp)
{
	if (ipv4 && tcp)
		return ENA_ADMIN_FLOW_IPV4_TCP;
	if (ipv4 && udp)
		return ENA_ADMIN_FLOW_IPV4_UDP;
	if (ipv4)
		return ENA_ADMIN_FLOW_IPV4;
	if (ipv6 && tcp)
		return ENA_ADMIN_FLOW_IPV6_TCP;
	if (ipv6 && udp)
		return ENA_ADMIN_FLOW_IPV6_UDP;
	if (ipv6)
		return ENA_ADMIN_FLOW_IPV6;

	return ENA_ADMIN_FLOW_INVALID;
}

/* Parse rte_flow pattern and actions into ENA format */
static int
ena_flow_parse(struct rte_eth_dev *dev,
	       const struct rte_flow_item pattern[],
	       const struct rte_flow_action actions[],
	       struct ena_com_flow_steering_rule_params *cfg,
	       struct rte_flow_error *error)
{
	const struct rte_flow_item *item;
	const struct rte_flow_action *action;
	bool has_ipv4 = false, has_ipv6 = false;
	bool has_tcp = false, has_udp = false;
	bool has_queue = false;
	uint8_t flow_type;

	if (!pattern || !actions || !cfg)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "Null flow input");

	memset(cfg, 0, sizeof(*cfg));

	/* Parse pattern items - spec/mask semantics, ranges (last) are rejected */
	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type == RTE_FLOW_ITEM_TYPE_VOID)
			continue;

		switch (item->type) {
		case RTE_FLOW_ITEM_TYPE_ETH: {
			const struct rte_flow_item_eth *spec = item->spec;
			const struct rte_flow_item_eth *mask = item->mask;

			/* Reject mask/last without spec */
			if (!spec && (mask || item->last))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "mask/last without spec");

			if (!spec)
				break; /* wildcard ETH */

			/* Use default mask if not provided */
			if (!mask)
				mask = &rte_flow_item_eth_mask;

			/* Reject any ETH field matching (not supported) */
			if (mask->hdr.ether_type != 0)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "EtherType matching not supported");

			for (int i = 0; i < 6; i++) {
				if (mask->hdr.dst_addr.addr_bytes[i] ||
				    mask->hdr.src_addr.addr_bytes[i])
					return rte_flow_error_set(error, ENOTSUP,
								  RTE_FLOW_ERROR_TYPE_ITEM, item,
								  "MAC address matching not supported");
			}
			break;
		}

		case RTE_FLOW_ITEM_TYPE_IPV4: {
			const struct rte_flow_item_ipv4 *spec = item->spec;
			const struct rte_flow_item_ipv4 *mask = item->mask;

			/* Reject mask/last without spec */
			if (!spec && (mask || item->last))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "mask/last without spec");

			if (!spec)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "IPv4 item requires spec");

			if (item->last)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Range (last) not supported");

			has_ipv4 = true;
			if (has_ipv6)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Mixed IPv4/IPv6 not supported");

			/* Use default mask if not provided */
			if (!mask)
				mask = &rte_flow_item_ipv4_mask;

			/* Reject unsupported mask fields */
			if (mask->hdr.version_ihl || mask->hdr.total_length ||
			    mask->hdr.packet_id || mask->hdr.fragment_offset ||
			    mask->hdr.time_to_live || mask->hdr.next_proto_id ||
			    mask->hdr.hdr_checksum)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Unsupported IPv4 header mask fields");

			/* Copy supported fields: src/dst + tos */
			memcpy(cfg->flow_params.src_ip, &spec->hdr.src_addr, 4);
			memcpy(cfg->flow_params.src_ip_mask, &mask->hdr.src_addr, 4);
			memcpy(cfg->flow_params.dst_ip, &spec->hdr.dst_addr, 4);
			memcpy(cfg->flow_params.dst_ip_mask, &mask->hdr.dst_addr, 4);
			cfg->flow_params.tos = spec->hdr.type_of_service;
			cfg->flow_params.tos_mask = mask->hdr.type_of_service;
			break;
		}

		case RTE_FLOW_ITEM_TYPE_IPV6: {
			const struct rte_flow_item_ipv6 *spec = item->spec;
			const struct rte_flow_item_ipv6 *mask = item->mask;

			/* Reject mask/last without spec */
			if (!spec && (mask || item->last))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "mask/last without spec");

			if (!spec)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "IPv6 item requires spec");

			if (item->last)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Range (last) not supported");

			has_ipv6 = true;
			if (has_ipv4)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Mixed IPv4/IPv6 not supported");

			/* Use default mask if not provided */
			if (!mask)
				mask = &rte_flow_item_ipv6_mask;

			/* Reject unsupported IPv6 mask fields */
			if (mask->hdr.payload_len || mask->hdr.proto || mask->hdr.hop_limits)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Unsupported IPv6 header mask fields");

			/* Only allow traffic class bits in vtc_flow mask */
			uint32_t vtc_m = rte_be_to_cpu_32(mask->hdr.vtc_flow);
			if (vtc_m & 0xF0000000u) /* version bits */
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "IPv6 version matching not supported");
			if (vtc_m & 0x000FFFFFu) /* flowlabel bits */
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "IPv6 flowlabel matching not supported");

			memcpy(cfg->flow_params.src_ip, spec->hdr.src_addr.a, 16);
			memcpy(cfg->flow_params.src_ip_mask, mask->hdr.src_addr.a, 16);
			memcpy(cfg->flow_params.dst_ip, spec->hdr.dst_addr.a, 16);
			memcpy(cfg->flow_params.dst_ip_mask, mask->hdr.dst_addr.a, 16);

			uint32_t vtc = rte_be_to_cpu_32(spec->hdr.vtc_flow);
			cfg->flow_params.tos = (uint8_t)((vtc >> 20) & 0xFF);
			cfg->flow_params.tos_mask = (uint8_t)((vtc_m >> 20) & 0xFF);
			break;
		}

		case RTE_FLOW_ITEM_TYPE_TCP: {
			const struct rte_flow_item_tcp *spec = item->spec;
			const struct rte_flow_item_tcp *mask = item->mask;

			/* Reject mask/last without spec */
			if (!spec && (mask || item->last))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "mask/last without spec");

			if (!spec)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "TCP item requires spec");

			if (item->last)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Range (last) not supported");

			has_tcp = true;
			if (has_udp)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Mixed TCP/UDP not supported");

			/* Use default mask if not provided */
			if (!mask)
				mask = &rte_flow_item_tcp_mask;

			/* Reject unsupported TCP mask fields */
			if (mask->hdr.sent_seq || mask->hdr.recv_ack ||
			    mask->hdr.data_off || mask->hdr.tcp_flags ||
			    mask->hdr.rx_win || mask->hdr.cksum || mask->hdr.tcp_urp)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Unsupported TCP header mask fields");

			cfg->flow_params.src_port = rte_be_to_cpu_16(spec->hdr.src_port);
			cfg->flow_params.src_port_mask = rte_be_to_cpu_16(mask->hdr.src_port);
			cfg->flow_params.dst_port = rte_be_to_cpu_16(spec->hdr.dst_port);
			cfg->flow_params.dst_port_mask = rte_be_to_cpu_16(mask->hdr.dst_port);
			break;
		}

		case RTE_FLOW_ITEM_TYPE_UDP: {
			const struct rte_flow_item_udp *spec = item->spec;
			const struct rte_flow_item_udp *mask = item->mask;

			/* Reject mask/last without spec */
			if (!spec && (mask || item->last))
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "mask/last without spec");

			if (!spec)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "UDP item requires spec");

			if (item->last)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Range (last) not supported");

			has_udp = true;
			if (has_tcp)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Mixed TCP/UDP not supported");

			/* Use default mask if not provided */
			if (!mask)
				mask = &rte_flow_item_udp_mask;

			/* Reject unsupported UDP mask fields */
			if (mask->hdr.dgram_len || mask->hdr.dgram_cksum)
				return rte_flow_error_set(error, ENOTSUP,
							  RTE_FLOW_ERROR_TYPE_ITEM, item,
							  "Unsupported UDP header mask fields");

			cfg->flow_params.src_port = rte_be_to_cpu_16(spec->hdr.src_port);
			cfg->flow_params.src_port_mask = rte_be_to_cpu_16(mask->hdr.src_port);
			cfg->flow_params.dst_port = rte_be_to_cpu_16(spec->hdr.dst_port);
			cfg->flow_params.dst_port_mask = rte_be_to_cpu_16(mask->hdr.dst_port);
			break;
		}

		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ITEM,
						  item, "Unsupported pattern item");
		}
	}

	/* Determine flow type */
	flow_type = ena_flow_type_convert(has_ipv4, has_ipv6, has_tcp, has_udp);
	if (flow_type == ENA_ADMIN_FLOW_INVALID)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  NULL, "Invalid pattern: requires IPv4 or IPv6");

	cfg->flow_type = flow_type;

	/* Parse actions: exactly one QUEUE, no other non-VOID actions */
	for (action = actions; action->type != RTE_FLOW_ACTION_TYPE_END; action++) {
		switch (action->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;

		case RTE_FLOW_ACTION_TYPE_QUEUE: {
			const struct rte_flow_action_queue *queue = action->conf;

			if (!queue)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ACTION,
							  action, "Missing queue configuration");

			if (has_queue)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ACTION,
							  action, "Multiple QUEUE actions not supported");

			/*
			 * Validate queue index. It is checked only here: if the port is
			 * later reconfigured with fewer Rx queues, the device silently
			 * drops the packets matching this rule.
			 */
			if (queue->index >= dev->data->nb_rx_queues)
				return rte_flow_error_set(error, EINVAL,
							  RTE_FLOW_ERROR_TYPE_ACTION,
							  action, "Queue index out of range");

			cfg->qid = queue->index;
			has_queue = true;
			break;
		}

		default:
			return rte_flow_error_set(error, ENOTSUP,
						  RTE_FLOW_ERROR_TYPE_ACTION,
						  action, "Unsupported action type");
		}
	}

	/* QUEUE action is mandatory */
	if (!has_queue)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "QUEUE action required");

	return 0;
}

/* Validate flow rule */
static int
ena_flow_validate(struct rte_eth_dev *dev,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	struct ena_com_flow_steering_rule_params cfg;

	/* Check device is started - use STATE error type, not EAGAIN */
	if (!dev->data->dev_started)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_STATE, dev,
					  "Device not started; flow rules cannot be created in this state");

	/* Validate attributes */
	if (attr->group != 0)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_GROUP,
					  attr, "Only group 0 supported");

	if (attr->priority != 0)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY,
					  attr, "Priority not supported");

	if (!attr->ingress || attr->egress || attr->transfer)
		return rte_flow_error_set(error, ENOTSUP,
					  RTE_FLOW_ERROR_TYPE_ATTR,
					  attr, "Only ingress supported");

	/* Validate pattern and actions */
	return ena_flow_parse(dev, pattern, actions, &cfg, error);
}

/* Create flow rule */
static struct rte_flow *
ena_flow_create(struct rte_eth_dev *dev,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct ena_adapter *adapter = dev->data->dev_private;
	struct ena_com_dev *ena_dev = &adapter->ena_dev;
	struct ena_com_flow_steering_rule_params cfg;
	uint16_t rule_idx = ENA_ADMIN_FLOW_STEERING_DEVICE_CHOOSE_LOCATION;
	int ret;

	/* Validate attributes, parse pattern and actions into cfg */
	ret = ena_flow_validate(dev, attr, pattern, actions, error);
	if (ret)
		return NULL;

	/* Parse pattern and actions */
	ret = ena_flow_parse(dev, pattern, actions, &cfg, error);
	if (ret)
		return NULL;

	/* Add rule to hardware via base layer */
	ret = ena_com_flow_steering_add_rule(ena_dev, &cfg, &rule_idx);
	if (ret) {
		PMD_DRV_LOG_LINE(ERR, "Failed to add flow steering rule: %d", ret);
		rte_flow_error_set(error, (ret == -EAGAIN) ? EBUSY : -ret,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Failed to add flow steering rule");
		return NULL;
	}

	/* Increment flow counter for lifecycle tracking */
	adapter->flow_rule_count++;

	PMD_DRV_LOG_LINE(DEBUG, "Flow rule created at HW location %u (total: %u)",
		    rule_idx, adapter->flow_rule_count);

	/* Return encoded handle (no heap allocation) */
	return ena_flow_handle_encode(rule_idx);
}

/* Destroy flow rule */
static int
ena_flow_destroy(struct rte_eth_dev *dev,
		 struct rte_flow *rte_flow,
		 struct rte_flow_error *error)
{
	struct ena_adapter *adapter = dev->data->dev_private;
	struct ena_com_dev *ena_dev = &adapter->ena_dev;
	uint16_t rule_idx;
	int ret;

	/* Decode handle */
	ret = ena_flow_handle_decode(rte_flow, &rule_idx);
	if (ret)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					  "Invalid flow handle");

	/* Remove rule from hardware */
	ret = ena_com_flow_steering_remove_rule(ena_dev, rule_idx);
	if (ret) {
		PMD_DRV_LOG_LINE(ERR, "Failed to remove flow rule %u: %d",
			    rule_idx, ret);
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					  "Failed to remove rule from hardware");
	}

	/* Decrement flow counter */
	if (adapter->flow_rule_count > 0)
		adapter->flow_rule_count--;

	PMD_DRV_LOG_LINE(DEBUG, "Flow rule %u destroyed (remaining: %u)",
		    rule_idx, adapter->flow_rule_count);

	/* No free needed - handle is encoded, not allocated */
	return 0;
}

/* Flush all flow rules */
static int
ena_flow_flush(struct rte_eth_dev *dev, struct rte_flow_error *error)
{
	struct ena_adapter *adapter = dev->data->dev_private;
	struct ena_com_dev *ena_dev = &adapter->ena_dev;
	int ret;

	/* Remove all rules from hardware */
	ret = ena_com_flow_steering_remove_all_rules(ena_dev);
	if (ret) {
		PMD_DRV_LOG_LINE(ERR, "Failed to flush all flow rules: %d", ret);
		return rte_flow_error_set(error, -ret,
					  RTE_FLOW_ERROR_TYPE_UNSPECIFIED,
					  NULL, "Failed to flush rules from hardware");
	}

	PMD_DRV_LOG_LINE(DEBUG, "Flushed %u flow rules", adapter->flow_rule_count);

	/* Reset flow counter */
	adapter->flow_rule_count = 0;

	/* No handles to free - all were encoded, not allocated */
	return 0;
}

/* Query flow rule - not supported */
static int
ena_flow_query(struct rte_eth_dev *dev,
	       struct rte_flow *flow,
	       const struct rte_flow_action *action,
	       void *data,
	       struct rte_flow_error *error)
{
	(void)dev;
	(void)flow;
	(void)data;

	return rte_flow_error_set(error, ENOTSUP,
				  RTE_FLOW_ERROR_TYPE_ACTION,
				  action, "Query not supported");
}

/* Flow operations structure */
const struct rte_flow_ops ena_flow_ops = {
	.validate = ena_flow_validate,
	.create = ena_flow_create,
	.destroy = ena_flow_destroy,
	.flush = ena_flow_flush,
	.query = ena_flow_query,
};
