/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Maxime Peim <maxime.peim@gmail.com>
 *
 * This file contains the async flow API implementation
 * for the flow-perf application.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_flow.h>
#include <rte_vxlan.h>

#include "actions_gen.h"
#include "async_flow.h"
#include "flow_gen.h"
#include "items_gen.h"

/* Max iterations when draining pending async completions during cleanup */
#define DRAIN_MAX_ITERATIONS 100

/* Per-port async flow resources */
static struct async_flow_resources port_resources[MAX_PORTS];

/*
 * Initialize compound action types within a pre-allocated slot.
 * Called once per slot during pool init to set up internal pointers
 * for RSS, RAW_ENCAP, RAW_DECAP and VXLAN_ENCAP actions.
 */
static void
init_slot_compound_actions(struct rte_flow_action *actions, uint32_t n_actions,
			   const size_t *action_conf_sizes)
{
	uint32_t i;

	for (i = 0; i < n_actions; i++) {
		if (action_conf_sizes[i] == 0)
			continue;

		switch (actions[i].type) {
		case RTE_FLOW_ACTION_TYPE_RSS: {
			struct action_rss_data *rss = actions[i].conf;
			rss->conf.func = RTE_ETH_HASH_FUNCTION_DEFAULT;
			rss->conf.level = 0;
			rss->conf.types = GET_RSS_HF();
			rss->conf.key_len = sizeof(rss->key);
			rss->conf.key = rss->key;
			rss->conf.queue = rss->queue;
			rss->key[0] = 1;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP: {
			struct action_raw_encap_data *encap = actions[i].conf;
			encap->conf.data = encap->data;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP: {
			struct action_raw_decap_data *decap = actions[i].conf;
			decap->conf.data = decap->data;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP: {
			/*
			 * Layout within the conf area:
			 *   struct rte_flow_action_vxlan_encap
			 *   struct rte_flow_item[5]
			 *   struct rte_flow_item_eth
			 *   struct rte_flow_item_ipv4
			 *   struct rte_flow_item_udp
			 *   struct rte_flow_item_vxlan
			 */
			uint8_t *base = actions[i].conf;
			struct rte_flow_action_vxlan_encap *ve =
				(struct rte_flow_action_vxlan_encap *)base;
			struct rte_flow_item *items =
				(struct rte_flow_item
					 *)(base + sizeof(struct rte_flow_action_vxlan_encap));
			uint8_t *data = (uint8_t *)(items + 5);

			struct rte_flow_item_eth *item_eth = (struct rte_flow_item_eth *)data;
			data += sizeof(struct rte_flow_item_eth);
			struct rte_flow_item_ipv4 *item_ipv4 = (struct rte_flow_item_ipv4 *)data;
			data += sizeof(struct rte_flow_item_ipv4);
			struct rte_flow_item_udp *item_udp = (struct rte_flow_item_udp *)data;
			data += sizeof(struct rte_flow_item_udp);
			struct rte_flow_item_vxlan *item_vxlan = (struct rte_flow_item_vxlan *)data;

			memset(item_eth, 0, sizeof(*item_eth));
			memset(item_ipv4, 0, sizeof(*item_ipv4));
			memset(item_udp, 0, sizeof(*item_udp));
			memset(item_vxlan, 0, sizeof(*item_vxlan));

			item_ipv4->hdr.src_addr = RTE_IPV4(127, 0, 0, 1);
			item_ipv4->hdr.version_ihl = RTE_IPV4_VHL_DEF;
			item_udp->hdr.dst_port = RTE_BE16(RTE_VXLAN_DEFAULT_PORT);
			item_vxlan->hdr.vni[2] = 1;

			items[0].type = RTE_FLOW_ITEM_TYPE_ETH;
			items[0].spec = item_eth;
			items[0].mask = item_eth;
			items[1].type = RTE_FLOW_ITEM_TYPE_IPV4;
			items[1].spec = item_ipv4;
			items[1].mask = item_ipv4;
			items[2].type = RTE_FLOW_ITEM_TYPE_UDP;
			items[2].spec = item_udp;
			items[2].mask = item_udp;
			items[3].type = RTE_FLOW_ITEM_TYPE_VXLAN;
			items[3].spec = item_vxlan;
			items[3].mask = item_vxlan;
			items[4].type = RTE_FLOW_ITEM_TYPE_END;

			ve->definition = items;
			break;
		}
		default:
			break;
		}
	}
}

/*
 * Allocate and pre-initialize all per-slot flat buffers.
 * Returns 0 on success.
 */
static int
init_slot_pool(struct async_flow_resources *res, uint32_t nb_queues, uint32_t queue_size,
	       const struct rte_flow_item *pattern, uint32_t n_items, const size_t *item_spec_sizes,
	       const struct rte_flow_action *template_actions, uint32_t n_actions,
	       const size_t *action_conf_sizes)
{
	uint32_t items_array_bytes, actions_array_bytes;
	uint32_t spec_data_bytes, conf_data_bytes, mask_data_bytes;
	uint32_t slot_size, num_slots;
	uint32_t s, i;
	uint8_t *mptr;

	/* Compute shared mask size */
	mask_data_bytes = 0;
	for (i = 0; i < n_items; i++)
		mask_data_bytes += item_spec_sizes[i];

	/* specs and masks have the same size */
	spec_data_bytes = mask_data_bytes;

	conf_data_bytes = 0;
	for (i = 0; i < n_actions; i++)
		conf_data_bytes += action_conf_sizes[i];

	/* Compute per-slot layout sizes (+ 1 for END sentinel) */
	items_array_bytes = n_items * sizeof(struct rte_flow_item);
	actions_array_bytes = n_actions * sizeof(struct rte_flow_action);

	slot_size = RTE_ALIGN_CEIL(items_array_bytes + actions_array_bytes + spec_data_bytes +
					   conf_data_bytes,
				   RTE_CACHE_LINE_SIZE);

	num_slots = queue_size * nb_queues;

	/* Store layout info */
	res->slot_size = slot_size;
	res->slots_per_queue = queue_size;
	res->nb_queues = nb_queues;
	res->n_items = n_items;
	res->n_actions = n_actions;

	/* Allocate shared masks */
	if (mask_data_bytes > 0) {
		res->shared_masks = aligned_alloc(
			RTE_CACHE_LINE_SIZE, RTE_ALIGN_CEIL(mask_data_bytes, RTE_CACHE_LINE_SIZE));
		if (res->shared_masks == NULL) {
			fprintf(stderr, "Failed to allocate shared masks (%u bytes)\n",
				mask_data_bytes);
			return -ENOMEM;
		}
		memset(res->shared_masks, 0, mask_data_bytes);

		/* Copy mask data from template pattern */
		mptr = res->shared_masks;
		for (i = 0; i < n_items; i++) {
			if (item_spec_sizes[i] > 0 && pattern[i].mask != NULL)
				memcpy(mptr, pattern[i].mask, item_spec_sizes[i]);
			mptr += RTE_ALIGN_CEIL(item_spec_sizes[i], 8);
		}
	}

	/* Allocate per-slot pool */
	/* slot_size is already cache-line aligned, so total is a multiple */
	res->slot_pool = aligned_alloc(RTE_CACHE_LINE_SIZE, (size_t)num_slots * slot_size);
	if (res->slot_pool == NULL) {
		fprintf(stderr, "Failed to allocate slot pool (%u slots * %u bytes)\n", num_slots,
			slot_size);
		free(res->shared_masks);
		res->shared_masks = NULL;
		return -ENOMEM;
	}
	memset(res->slot_pool, 0, (size_t)num_slots * slot_size);

	/* Pre-initialize every slot */
	for (s = 0; s < num_slots; s++) {
		uint8_t *slot = res->slot_pool + (size_t)s * slot_size;
		struct rte_flow_item *items = (struct rte_flow_item *)slot;
		struct rte_flow_action *actions =
			(struct rte_flow_action *)(slot + items_array_bytes);
		uint8_t *data = slot + items_array_bytes + actions_array_bytes;

		/* Pre-set items: spec → per-slot data, mask → shared masks */
		mptr = res->shared_masks;
		for (i = 0; i < n_items; i++) {
			items[i].type = pattern[i].type;
			if (item_spec_sizes[i] > 0) {
				items[i].spec = data;
				items[i].mask = mptr;
				data += item_spec_sizes[i];
				mptr += item_spec_sizes[i];
			}
		}
		items[n_items].type = RTE_FLOW_ITEM_TYPE_END;

		/* Pre-set actions: conf → per-slot data */
		for (i = 0; i < n_actions; i++) {
			actions[i].type = template_actions[i].type;
			if (action_conf_sizes[i] > 0) {
				actions[i].conf = data;
				data += action_conf_sizes[i];
			}
		}
		actions[n_actions].type = RTE_FLOW_ACTION_TYPE_END;

		/* Initialize compound action types (RSS, RAW_ENCAP, etc.) */
		init_slot_compound_actions(actions, n_actions, action_conf_sizes);
	}

	/* Allocate and initialize per-queue slot tracking */
	res->queues =
		aligned_alloc(RTE_CACHE_LINE_SIZE, nb_queues * sizeof(struct async_flow_queue));
	if (res->queues == NULL) {
		fprintf(stderr, "Failed to allocate queue structs (%u queues)\n", nb_queues);
		free(res->slot_pool);
		res->slot_pool = NULL;
		free(res->shared_masks);
		res->shared_masks = NULL;
		return -ENOMEM;
	}
	memset(res->queues, 0, nb_queues * sizeof(struct async_flow_queue));
	for (s = 0; s < nb_queues; s++) {
		res->queues[s].slots = res->slot_pool + (size_t)s * queue_size * slot_size;
		res->queues[s].head = 0;
	}

	printf(":: Slot pool: %u slots * %u bytes = %u KB (shared masks: %u bytes)\n", num_slots,
	       slot_size, (num_slots * slot_size) / 1024, mask_data_bytes);

	return 0;
}

/*
 * Hot-path: update per-flow item values through pre-set pointers.
 * Only IPv4/IPv6 src_addr varies per flow (based on counter).
 */
static void
update_item_values(struct rte_flow_item *items, uint32_t counter)
{
	uint8_t i;

	for (i = 0; items[i].type != RTE_FLOW_ITEM_TYPE_END; i++) {
		switch (items[i].type) {
		case RTE_FLOW_ITEM_TYPE_IPV4: {
			struct rte_flow_item_ipv4 *spec = items[i].spec;
			spec->hdr.src_addr = RTE_BE32(counter);
			break;
		}
		case RTE_FLOW_ITEM_TYPE_IPV6: {
			struct rte_flow_item_ipv6 *spec = items[i].spec;
			uint8_t j;
			for (j = 0; j < 4; j++)
				spec->hdr.src_addr.a[15 - j] = counter >> (j * 8);
			break;
		}
		default:
			break;
		}
	}
}

/*
 * Hot-path: update per-flow action values through pre-set pointers.
 */
static void
update_action_values(struct rte_flow_action *actions, uint32_t counter, uint16_t hairpinq,
		     uint64_t encap_data, uint64_t decap_data, __rte_unused uint8_t core_idx,
		     bool unique_data, uint8_t rx_queues_count, uint16_t dst_port)
{
	uint8_t i;

	for (i = 0; actions[i].type != RTE_FLOW_ACTION_TYPE_END; i++) {
		switch (actions[i].type) {
		case RTE_FLOW_ACTION_TYPE_MARK: {
			struct rte_flow_action_mark *conf = actions[i].conf;
			conf->id = (counter % 255) + 1;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_QUEUE: {
			struct rte_flow_action_queue *conf = actions[i].conf;
			conf->index = hairpinq ? (counter % hairpinq) + rx_queues_count :
						 counter % rx_queues_count;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_METER: {
			struct rte_flow_action_meter *conf = actions[i].conf;
			conf->mtr_id = counter;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_RSS: {
			struct action_rss_data *conf = actions[i].conf;
			uint16_t q;
			if (hairpinq) {
				conf->conf.queue_num = hairpinq;
				for (q = 0; q < hairpinq; q++)
					conf->queue[q] = q + rx_queues_count;
			} else {
				conf->conf.queue_num = rx_queues_count;
				for (q = 0; q < rx_queues_count; q++)
					conf->queue[q] = q;
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_MAC_SRC:
		case RTE_FLOW_ACTION_TYPE_SET_MAC_DST: {
			struct rte_flow_action_set_mac *conf = actions[i].conf;
			uint32_t val = unique_data ? counter : 1;
			uint8_t j;
			for (j = 0; j < RTE_ETHER_ADDR_LEN; j++) {
				conf->mac_addr[j] = val & 0xff;
				val >>= 8;
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_SRC:
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DST: {
			struct rte_flow_action_set_ipv4 *conf = actions[i].conf;
			uint32_t ip = unique_data ? counter : 1;
			conf->ipv4_addr = RTE_BE32(ip + 1);
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_SRC:
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DST: {
			struct rte_flow_action_set_ipv6 *conf = actions[i].conf;
			uint32_t val = unique_data ? counter : 1;
			uint8_t j;
			for (j = 0; j < 16; j++) {
				conf->ipv6_addr.a[j] = val & 0xff;
				val >>= 8;
			}
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_TP_SRC: {
			struct rte_flow_action_set_tp *conf = actions[i].conf;
			uint32_t tp = unique_data ? counter : 100;
			tp = tp % 0xffff;
			conf->port = RTE_BE16(tp & 0xffff);
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_TP_DST: {
			struct rte_flow_action_set_tp *conf = actions[i].conf;
			uint32_t tp = unique_data ? counter : 100;
			if (tp > 0xffff)
				tp >>= 16;
			conf->port = RTE_BE16(tp & 0xffff);
			break;
		}
		case RTE_FLOW_ACTION_TYPE_INC_TCP_ACK:
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_ACK:
		case RTE_FLOW_ACTION_TYPE_INC_TCP_SEQ:
		case RTE_FLOW_ACTION_TYPE_DEC_TCP_SEQ: {
			rte_be32_t *conf = actions[i].conf;
			uint32_t val = unique_data ? counter : 1;
			*conf = RTE_BE32(val);
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_TTL: {
			struct rte_flow_action_set_ttl *conf = actions[i].conf;
			uint32_t val = unique_data ? counter : 1;
			conf->ttl_value = val % 0xff;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_SET_IPV4_DSCP:
		case RTE_FLOW_ACTION_TYPE_SET_IPV6_DSCP: {
			struct rte_flow_action_set_dscp *conf = actions[i].conf;
			uint32_t val = unique_data ? counter : 1;
			conf->dscp = val % 0xff;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_PORT_ID: {
			struct rte_flow_action_port_id *conf = actions[i].conf;
			conf->id = dst_port;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_RAW_ENCAP: {
			struct action_raw_encap_data *encap = actions[i].conf;
			uint8_t *header = encap->data;
			struct rte_ether_hdr eth_hdr;
			struct rte_ipv4_hdr ipv4_hdr;
			struct rte_udp_hdr udp_hdr;

			memset(&eth_hdr, 0, sizeof(eth_hdr));
			if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH)) {
				if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VLAN))
					eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_VLAN);
				else if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4))
					eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
				else if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6))
					eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
				memcpy(header, &eth_hdr, sizeof(eth_hdr));
				header += sizeof(eth_hdr);
			}
			if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4)) {
				uint32_t ip_dst = unique_data ? counter : 1;
				memset(&ipv4_hdr, 0, sizeof(ipv4_hdr));
				ipv4_hdr.src_addr = RTE_IPV4(127, 0, 0, 1);
				ipv4_hdr.dst_addr = RTE_BE32(ip_dst);
				ipv4_hdr.version_ihl = RTE_IPV4_VHL_DEF;
				if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP))
					ipv4_hdr.next_proto_id = 17; /* UDP */
				if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_GRE))
					ipv4_hdr.next_proto_id = 47; /* GRE */
				memcpy(header, &ipv4_hdr, sizeof(ipv4_hdr));
				header += sizeof(ipv4_hdr);
			}
			if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_UDP)) {
				memset(&udp_hdr, 0, sizeof(udp_hdr));
				if (encap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_VXLAN))
					udp_hdr.dst_port = RTE_BE16(RTE_VXLAN_DEFAULT_PORT);
				memcpy(header, &udp_hdr, sizeof(udp_hdr));
				header += sizeof(udp_hdr);
			}
			encap->conf.size = header - encap->data;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_RAW_DECAP: {
			struct action_raw_decap_data *decap_d = actions[i].conf;
			uint8_t *header = decap_d->data;
			struct rte_ether_hdr eth_hdr;

			memset(&eth_hdr, 0, sizeof(eth_hdr));
			if (decap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_ETH)) {
				if (decap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV4))
					eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV4);
				else if (decap_data & FLOW_ITEM_MASK(RTE_FLOW_ITEM_TYPE_IPV6))
					eth_hdr.ether_type = RTE_BE16(RTE_ETHER_TYPE_IPV6);
				memcpy(header, &eth_hdr, sizeof(eth_hdr));
				header += sizeof(eth_hdr);
			}
			decap_d->conf.size = header - decap_d->data;
			break;
		}
		case RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP: {
			uint8_t *base = actions[i].conf;
			struct rte_flow_item *vitems =
				(struct rte_flow_item
					 *)(base + sizeof(struct rte_flow_action_vxlan_encap));
			struct rte_flow_item_ipv4 *spec = vitems[1].spec;
			uint32_t ip_dst = unique_data ? counter : 1;
			/* vitems[1] is IPV4 */
			spec->hdr.dst_addr = RTE_BE32(ip_dst);
			break;
		}
		default:
			break;
		}
	}
}

int
async_flow_init_port(uint16_t port_id, uint32_t nb_queues, uint32_t queue_size,
		     uint64_t *flow_items, uint64_t *flow_actions, uint64_t *flow_attrs,
		     uint8_t flow_group, uint32_t rules_count)
{
	struct rte_flow_port_info port_info = {0};
	struct rte_flow_queue_info queue_info = {0};
	struct rte_flow_error error = {0};
	struct rte_flow_port_attr port_attr = {0};
	struct rte_flow_queue_attr queue_attr;
	const struct rte_flow_queue_attr **queue_attr_list;
	struct rte_flow_pattern_template_attr pt_attr = {0};
	struct rte_flow_actions_template_attr at_attr = {0};
	struct rte_flow_template_table_attr table_attr = {0};
	struct rte_flow_item pattern[MAX_ITEMS_NUM];
	struct rte_flow_action actions[MAX_ACTIONS_NUM];
	struct rte_flow_action action_masks[MAX_ACTIONS_NUM];
	size_t item_spec_sizes[MAX_ITEMS_NUM];
	size_t action_conf_sizes[MAX_ACTIONS_NUM];
	uint32_t n_items, n_actions;
	struct async_flow_resources *res;
	bool need_wire_orig_table = false;
	uint32_t i;
	int ret;

	if (port_id >= MAX_PORTS)
		return -1;

	res = &port_resources[port_id];
	memset(res, 0, sizeof(*res));

	/* Query port flow info */
	ret = rte_flow_info_get(port_id, &port_info, &queue_info, &error);
	if (ret != 0) {
		fprintf(stderr, "Port %u: rte_flow_info_get failed: %s\n", port_id,
			error.message ? error.message : "(no message)");
		return ret;
	}

	if (port_info.max_nb_queues == 0 || queue_info.max_size == 0) {
		fprintf(stderr, "Port %u: rte_flow_info_get reports that no queues are supported\n",
			port_id);
		return -1;
	}

	/* Limit to device capabilities if reported */
	if (port_info.max_nb_queues != 0 && port_info.max_nb_queues != UINT32_MAX &&
	    nb_queues > port_info.max_nb_queues)
		nb_queues = port_info.max_nb_queues;
	if (queue_info.max_size != 0 && queue_info.max_size != UINT32_MAX &&
	    queue_size > queue_info.max_size)
		queue_size = queue_info.max_size;

	/* Slot ring uses bitmask wrapping, so queue_size must be power of 2 */
	queue_size = rte_align32prevpow2(queue_size);
	if (queue_size == 0) {
		fprintf(stderr, "Port %u: queue_size is 0 after rounding\n", port_id);
		return -EINVAL;
	}

	for (i = 0; i < MAX_ATTRS_NUM; i++) {
		if (flow_attrs[i] == 0)
			break;
		if (flow_attrs[i] & INGRESS)
			pt_attr.ingress = 1;
		else if (flow_attrs[i] & EGRESS)
			pt_attr.egress = 1;
		else if (flow_attrs[i] & TRANSFER)
			pt_attr.transfer = 1;
	}
	/* Enable relaxed matching for better performance */
	pt_attr.relaxed_matching = 1;

	memset(pattern, 0, sizeof(pattern));
	memset(actions, 0, sizeof(actions));
	memset(action_masks, 0, sizeof(action_masks));

	/* Fill templates and gather per-item/action sizes */
	fill_items_template(pattern, flow_items, 0, 0, item_spec_sizes, &n_items);

	at_attr.ingress = pt_attr.ingress;
	at_attr.egress = pt_attr.egress;
	at_attr.transfer = pt_attr.transfer;

	fill_actions_template(actions, action_masks, flow_actions, &port_attr,
			      &need_wire_orig_table, action_conf_sizes, &n_actions);

	/*
	 * fill_actions_template count the number of actions that require each kind of object,
	 * so we multiply by the number of rules to have correct number
	 */
	port_attr.nb_counters *= rules_count;
	port_attr.nb_aging_objects *= rules_count;
	port_attr.nb_meters *= rules_count;
	port_attr.nb_conn_tracks *= rules_count;
	port_attr.nb_quotas *= rules_count;

	table_attr.flow_attr.group = flow_group;
	table_attr.flow_attr.priority = 0;
	table_attr.flow_attr.ingress = pt_attr.ingress;
	table_attr.flow_attr.egress = pt_attr.egress;
	table_attr.flow_attr.transfer = pt_attr.transfer;
	table_attr.nb_flows = rules_count;

	if (pt_attr.transfer && need_wire_orig_table)
		table_attr.specialize = RTE_FLOW_TABLE_SPECIALIZE_TRANSFER_WIRE_ORIG;

	queue_attr_list = malloc(sizeof(*queue_attr_list) * nb_queues);
	if (queue_attr_list == NULL) {
		fprintf(stderr, "Port %u: failed to allocate queue_attr_list\n", port_id);
		return -ENOMEM;
	}

	queue_attr.size = queue_size;
	for (i = 0; i < nb_queues; i++)
		queue_attr_list[i] = &queue_attr;

	ret = rte_flow_configure(port_id, &port_attr, nb_queues, queue_attr_list, &error);

	free(queue_attr_list);

	if (ret != 0) {
		fprintf(stderr, "Port %u: rte_flow_configure failed (ret=%d, type=%d): %s\n",
			port_id, ret, error.type, error.message ? error.message : "(no message)");
		return ret;
	}

	/* Create pattern template */
	res->pattern_template =
		rte_flow_pattern_template_create(port_id, &pt_attr, pattern, &error);
	if (res->pattern_template == NULL) {
		fprintf(stderr, "Port %u: pattern template create failed: %s\n", port_id,
			error.message ? error.message : "(no message)");
		return -1;
	}

	/* Create actions template */
	res->actions_template =
		rte_flow_actions_template_create(port_id, &at_attr, actions, action_masks, &error);
	if (res->actions_template == NULL) {
		fprintf(stderr, "Port %u: actions template create failed: %s\n", port_id,
			error.message ? error.message : "(no message)");
		rte_flow_pattern_template_destroy(port_id, res->pattern_template, &error);
		res->pattern_template = NULL;
		return -1;
	}

	/* Create template table */
	res->table = rte_flow_template_table_create(port_id, &table_attr, &res->pattern_template, 1,
						    &res->actions_template, 1, &error);
	if (res->table == NULL) {
		fprintf(stderr, "Port %u: template table create failed: %s\n", port_id,
			error.message ? error.message : "(no message)");
		rte_flow_actions_template_destroy(port_id, res->actions_template, &error);
		rte_flow_pattern_template_destroy(port_id, res->pattern_template, &error);
		res->pattern_template = NULL;
		res->actions_template = NULL;
		return -1;
	}

	/* Allocate and pre-initialize per-slot flat buffers */
	ret = init_slot_pool(res, nb_queues, queue_size, pattern, n_items, item_spec_sizes, actions,
			     n_actions, action_conf_sizes);
	if (ret != 0) {
		fprintf(stderr, "Port %u: slot pool init failed\n", port_id);
		rte_flow_template_table_destroy(port_id, res->table, &error);
		rte_flow_actions_template_destroy(port_id, res->actions_template, &error);
		rte_flow_pattern_template_destroy(port_id, res->pattern_template, &error);
		res->table = NULL;
		res->actions_template = NULL;
		res->pattern_template = NULL;
		return ret;
	}

	res->table_capacity = rules_count;
	res->initialized = true;

	printf(":: Port %u: Async flow engine initialized (queues=%u, queue_size=%u)\n", port_id,
	       nb_queues, queue_size);

	return 0;
}

struct rte_flow *
async_generate_flow(uint16_t port_id, uint32_t queue_id, uint32_t counter, uint16_t hairpinq,
		    uint64_t encap_data, uint64_t decap_data, uint16_t dst_port, uint8_t core_idx,
		    uint8_t rx_queues_count, bool unique_data, bool postpone,
		    struct rte_flow_error *error)
{
	struct async_flow_resources *res;
	struct async_flow_queue *q;
	uint8_t *slot;
	uint32_t idx, items_array_bytes;
	struct rte_flow_item *items;
	struct rte_flow_action *actions;
	struct rte_flow_op_attr op_attr = {
		.postpone = postpone,
	};

	if (port_id >= MAX_PORTS) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "Invalid port ID");
		return NULL;
	}

	res = &port_resources[port_id];
	if (!res->initialized) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "Async flow resources not initialized");
		return NULL;
	}

	if (queue_id >= res->nb_queues) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				   "Invalid queue ID");
		return NULL;
	}

	/* Pick the next slot from this queue's ring */
	q = &res->queues[queue_id];
	idx = q->head;
	q->head = (idx + 1) & (res->slots_per_queue - 1);
	slot = q->slots + (size_t)idx * res->slot_size;
	items_array_bytes = res->n_items * sizeof(struct rte_flow_item);
	items = (struct rte_flow_item *)slot;
	actions = (struct rte_flow_action *)(slot + items_array_bytes);

	/* Update only per-flow varying values */
	update_item_values(items, counter);
	update_action_values(actions, counter, hairpinq, encap_data, decap_data, core_idx,
			     unique_data, rx_queues_count, dst_port);

	return rte_flow_async_create(port_id, queue_id, &op_attr, res->table, items, 0, actions, 0,
				     NULL, error);
}

void
async_flow_cleanup_port(uint16_t port_id)
{
	struct async_flow_resources *res;
	struct rte_flow_error error;
	struct rte_flow_op_result results[64];
	int ret, i;

	if (port_id >= MAX_PORTS)
		return;

	res = &port_resources[port_id];
	if (!res->initialized)
		return;

	/* Drain any pending async completions from flow flush */
	for (i = 0; i < DRAIN_MAX_ITERATIONS; i++) {
		rte_flow_push(port_id, 0, &error);
		ret = rte_flow_pull(port_id, 0, results, 64, &error);
		if (ret <= 0)
			break;
	}

	if (res->table != NULL) {
		rte_flow_template_table_destroy(port_id, res->table, &error);
		res->table = NULL;
	}

	if (res->actions_template != NULL) {
		rte_flow_actions_template_destroy(port_id, res->actions_template, &error);
		res->actions_template = NULL;
	}

	if (res->pattern_template != NULL) {
		rte_flow_pattern_template_destroy(port_id, res->pattern_template, &error);
		res->pattern_template = NULL;
	}

	free(res->queues);
	res->queues = NULL;
	free(res->slot_pool);
	res->slot_pool = NULL;
	free(res->shared_masks);
	res->shared_masks = NULL;

	res->initialized = false;
}
