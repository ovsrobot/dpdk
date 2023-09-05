/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __CREATE_ELEMENTS_H__
#define __CREATE_ELEMENTS_H__

#include "stream_binary_flow_api.h"

#define MAX_ELEMENTS 64
#define MAX_ACTIONS 32

#define MAX_COLOR_FLOW_STATS 0x400

struct cnv_match_s {
	struct flow_elem flow_elem[MAX_ELEMENTS];
};

struct tun_def_s {
	struct flow_elem *tun_definition;
	struct cnv_match_s match;
};

struct cnv_attr_s {
	struct cnv_match_s match;
	struct flow_attr attr;
};

struct cnv_action_s {
	struct flow_action flow_actions[MAX_ACTIONS];
	struct tun_def_s tun_def;
	struct flow_action_rss flow_rss;
	struct rte_flow_action_mark mark;
	struct flow_action_raw_encap encap;
	struct flow_action_raw_decap decap;
	struct flow_action_queue queue;
};

/*
 * Only needed because it eases the use of statistics through NTAPI
 * for faster integration into NTAPI version of driver
 * Therefore, this is only a good idea when running on a temporary NTAPI
 * The query() functionality must go to flow engine, when moved to Open Source driver
 */

struct rte_flow {
	void *flw_hdl;
	int used;
	uint32_t flow_stat_id;

	uint64_t stat_pkts;
	uint64_t stat_bytes;
	uint8_t stat_tcp_flags;
};

enum nt_rte_flow_item_type {
	NT_RTE_FLOW_ITEM_TYPE_END = INT_MIN,
	NT_RTE_FLOW_ITEM_TYPE_TAG,
	NT_RTE_FLOW_ITEM_TYPE_TUNNEL,
};

enum nt_rte_flow_action_type {
	NT_RTE_FLOW_ACTION_TYPE_END = INT_MIN,
	NT_RTE_FLOW_ACTION_TYPE_TAG,
	NT_RTE_FLOW_ACTION_TYPE_TUNNEL_SET,
	NT_RTE_FLOW_ACTION_TYPE_JUMP,
};

static int convert_tables_initialized;

#define MAX_RTE_ENUM_INDEX 127

static int elem_list[MAX_RTE_ENUM_INDEX + 1];
static int action_list[MAX_RTE_ENUM_INDEX + 1];

#ifdef RTE_FLOW_DEBUG
static const char *elem_list_str[MAX_RTE_ENUM_INDEX + 1];
static const char *action_list_str[MAX_RTE_ENUM_INDEX + 1];
#endif

#define CNV_TO_ELEM(item) \
	({ \
		int _temp_item = (item); \
		((_temp_item >= 0 && _temp_item <= MAX_RTE_ENUM_INDEX) ? \
		elem_list[_temp_item] : -1); \
	})


#define CNV_TO_ACTION(action)                                   \
	({                                                          \
		int _temp_action = (action);                            \
		(_temp_action >= 0 && _temp_action <= MAX_RTE_ENUM_INDEX) ? \
		action_list[_temp_action] : -1; \
	})


static uint32_t flow_stat_id_map[MAX_COLOR_FLOW_STATS];
static rte_spinlock_t flow_lock = RTE_SPINLOCK_INITIALIZER;

static int convert_error(struct rte_flow_error *error,
			 struct flow_error *flow_error)
{
	if (error) {
		error->cause = NULL;
		error->message = flow_error->message;

		if (flow_error->type == FLOW_ERROR_NONE ||
				flow_error->type == FLOW_ERROR_SUCCESS)
			error->type = RTE_FLOW_ERROR_TYPE_NONE;

		else
			error->type = RTE_FLOW_ERROR_TYPE_UNSPECIFIED;
	}
	return 0;
}

/*
 * Map Flow MARK to flow stat id
 */
static uint32_t create_flow_stat_id_locked(uint32_t mark)
{
	uint32_t flow_stat_id = mark & (MAX_COLOR_FLOW_STATS - 1);

	while (flow_stat_id_map[flow_stat_id])
		flow_stat_id = (flow_stat_id + 1) & (MAX_COLOR_FLOW_STATS - 1);

	flow_stat_id_map[flow_stat_id] = mark + 1;
	return flow_stat_id;
}

static uint32_t create_flow_stat_id(uint32_t mark)
{
	rte_spinlock_lock(&flow_lock);
	uint32_t ret = create_flow_stat_id_locked(mark);

	rte_spinlock_unlock(&flow_lock);
	return ret;
}

static void delete_flow_stat_id_locked(uint32_t flow_stat_id)
{
	if (flow_stat_id < MAX_COLOR_FLOW_STATS)
		flow_stat_id_map[flow_stat_id] = 0;
}

static void initialize_global_cnv_tables(void)
{
	if (convert_tables_initialized)
		return;

	memset(elem_list, -1, sizeof(elem_list));
	elem_list[RTE_FLOW_ITEM_TYPE_END] = FLOW_ELEM_TYPE_END;
	elem_list[RTE_FLOW_ITEM_TYPE_ANY] = FLOW_ELEM_TYPE_ANY;
	elem_list[RTE_FLOW_ITEM_TYPE_ETH] = FLOW_ELEM_TYPE_ETH;
	elem_list[RTE_FLOW_ITEM_TYPE_VLAN] = FLOW_ELEM_TYPE_VLAN;
	elem_list[RTE_FLOW_ITEM_TYPE_IPV4] = FLOW_ELEM_TYPE_IPV4;
	elem_list[RTE_FLOW_ITEM_TYPE_IPV6] = FLOW_ELEM_TYPE_IPV6;
	elem_list[RTE_FLOW_ITEM_TYPE_UDP] = FLOW_ELEM_TYPE_UDP;
	elem_list[RTE_FLOW_ITEM_TYPE_SCTP] = FLOW_ELEM_TYPE_SCTP;
	elem_list[RTE_FLOW_ITEM_TYPE_TCP] = FLOW_ELEM_TYPE_TCP;
	elem_list[RTE_FLOW_ITEM_TYPE_ICMP] = FLOW_ELEM_TYPE_ICMP;
	elem_list[RTE_FLOW_ITEM_TYPE_VXLAN] = FLOW_ELEM_TYPE_VXLAN;
	elem_list[RTE_FLOW_ITEM_TYPE_GTP] = FLOW_ELEM_TYPE_GTP;
	elem_list[RTE_FLOW_ITEM_TYPE_PORT_ID] = FLOW_ELEM_TYPE_PORT_ID;
	elem_list[RTE_FLOW_ITEM_TYPE_TAG] = FLOW_ELEM_TYPE_TAG;
	elem_list[RTE_FLOW_ITEM_TYPE_VOID] = FLOW_ELEM_TYPE_VOID;

#ifdef RTE_FLOW_DEBUG
	elem_list_str[RTE_FLOW_ITEM_TYPE_END] = "FLOW_ELEM_TYPE_END";
	elem_list_str[RTE_FLOW_ITEM_TYPE_ANY] = "FLOW_ELEM_TYPE_ANY";
	elem_list_str[RTE_FLOW_ITEM_TYPE_ETH] = "FLOW_ELEM_TYPE_ETH";
	elem_list_str[RTE_FLOW_ITEM_TYPE_VLAN] = "FLOW_ELEM_TYPE_VLAN";
	elem_list_str[RTE_FLOW_ITEM_TYPE_IPV4] = "FLOW_ELEM_TYPE_IPV4";
	elem_list_str[RTE_FLOW_ITEM_TYPE_IPV6] = "FLOW_ELEM_TYPE_IPV6";
	elem_list_str[RTE_FLOW_ITEM_TYPE_UDP] = "FLOW_ELEM_TYPE_UDP";
	elem_list_str[RTE_FLOW_ITEM_TYPE_SCTP] = "FLOW_ELEM_TYPE_SCTP";
	elem_list_str[RTE_FLOW_ITEM_TYPE_TCP] = "FLOW_ELEM_TYPE_TCP";
	elem_list_str[RTE_FLOW_ITEM_TYPE_ICMP] = "FLOW_ELEM_TYPE_ICMP";
	elem_list_str[RTE_FLOW_ITEM_TYPE_VXLAN] = "FLOW_ELEM_TYPE_VXLAN";
	elem_list_str[RTE_FLOW_ITEM_TYPE_GTP] = "FLOW_ELEM_TYPE_GTP";
	elem_list_str[RTE_FLOW_ITEM_TYPE_PORT_ID] = "FLOW_ELEM_TYPE_PORT_ID";
	elem_list_str[RTE_FLOW_ITEM_TYPE_TAG] = "FLOW_ELEM_TYPE_TAG";
	elem_list_str[RTE_FLOW_ITEM_TYPE_VOID] = "FLOW_ELEM_TYPE_VOID";
#endif

	memset(action_list, -1, sizeof(action_list));
	action_list[RTE_FLOW_ACTION_TYPE_END] = FLOW_ACTION_TYPE_END;
	action_list[RTE_FLOW_ACTION_TYPE_MARK] = FLOW_ACTION_TYPE_MARK;
	action_list[RTE_FLOW_ACTION_TYPE_SET_TAG] = FLOW_ACTION_TYPE_SET_TAG;
	action_list[RTE_FLOW_ACTION_TYPE_DROP] = FLOW_ACTION_TYPE_DROP;
	action_list[RTE_FLOW_ACTION_TYPE_COUNT] = FLOW_ACTION_TYPE_COUNT;
	action_list[RTE_FLOW_ACTION_TYPE_RSS] = FLOW_ACTION_TYPE_RSS;
	action_list[RTE_FLOW_ACTION_TYPE_PORT_ID] = FLOW_ACTION_TYPE_PORT_ID;
	action_list[RTE_FLOW_ACTION_TYPE_QUEUE] = FLOW_ACTION_TYPE_QUEUE;
	action_list[RTE_FLOW_ACTION_TYPE_JUMP] = FLOW_ACTION_TYPE_JUMP;
	action_list[RTE_FLOW_ACTION_TYPE_METER] = FLOW_ACTION_TYPE_METER;
	action_list[RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP] =
		FLOW_ACTION_TYPE_VXLAN_ENCAP;
	action_list[RTE_FLOW_ACTION_TYPE_VXLAN_DECAP] =
		FLOW_ACTION_TYPE_VXLAN_DECAP;
	action_list[RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN] =
		FLOW_ACTION_TYPE_PUSH_VLAN;
	action_list[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID] =
		FLOW_ACTION_TYPE_SET_VLAN_VID;
	action_list[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP] =
		FLOW_ACTION_TYPE_SET_VLAN_PCP;
	action_list[RTE_FLOW_ACTION_TYPE_OF_POP_VLAN] =
		FLOW_ACTION_TYPE_POP_VLAN;
	action_list[RTE_FLOW_ACTION_TYPE_RAW_ENCAP] =
		FLOW_ACTION_TYPE_RAW_ENCAP;
	action_list[RTE_FLOW_ACTION_TYPE_RAW_DECAP] =
		FLOW_ACTION_TYPE_RAW_DECAP;
	action_list[RTE_FLOW_ACTION_TYPE_MODIFY_FIELD] =
		FLOW_ACTION_TYPE_MODIFY_FIELD;

#ifdef RTE_FLOW_DEBUG
	action_list_str[RTE_FLOW_ACTION_TYPE_END] = "FLOW_ACTION_TYPE_END";
	action_list_str[RTE_FLOW_ACTION_TYPE_MARK] = "FLOW_ACTION_TYPE_MARK";
	action_list_str[RTE_FLOW_ACTION_TYPE_SET_TAG] =
		"FLOW_ACTION_TYPE_SET_TAG";
	action_list_str[RTE_FLOW_ACTION_TYPE_DROP] = "FLOW_ACTION_TYPE_DROP";
	action_list_str[RTE_FLOW_ACTION_TYPE_COUNT] = "FLOW_ACTION_TYPE_COUNT";
	action_list_str[RTE_FLOW_ACTION_TYPE_RSS] = "FLOW_ACTION_TYPE_RSS";
	action_list_str[RTE_FLOW_ACTION_TYPE_PORT_ID] =
		"FLOW_ACTION_TYPE_PORT_ID";
	action_list_str[RTE_FLOW_ACTION_TYPE_QUEUE] = "FLOW_ACTION_TYPE_QUEUE";
	action_list_str[RTE_FLOW_ACTION_TYPE_JUMP] = "FLOW_ACTION_TYPE_JUMP";
	action_list_str[RTE_FLOW_ACTION_TYPE_METER] = "FLOW_ACTION_TYPE_METER";
	action_list_str[RTE_FLOW_ACTION_TYPE_VXLAN_ENCAP] =
		"FLOW_ACTION_TYPE_VXLAN_ENCAP";
	action_list_str[RTE_FLOW_ACTION_TYPE_VXLAN_DECAP] =
		"FLOW_ACTION_TYPE_VXLAN_DECAP";
	action_list_str[RTE_FLOW_ACTION_TYPE_OF_PUSH_VLAN] =
		"FLOW_ACTION_TYPE_PUSH_VLAN";
	action_list_str[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_VID] =
		"FLOW_ACTION_TYPE_SET_VLAN_VID";
	action_list_str[RTE_FLOW_ACTION_TYPE_OF_SET_VLAN_PCP] =
		"FLOW_ACTION_TYPE_SET_VLAN_PCP";
	action_list_str[RTE_FLOW_ACTION_TYPE_OF_POP_VLAN] =
		"FLOW_ACTION_TYPE_POP_VLAN";
	action_list_str[RTE_FLOW_ACTION_TYPE_RAW_ENCAP] =
		"FLOW_ACTION_TYPE_RAW_ENCAP";
	action_list_str[RTE_FLOW_ACTION_TYPE_RAW_DECAP] =
		"FLOW_ACTION_TYPE_RAW_DECAP";
	action_list_str[RTE_FLOW_ACTION_TYPE_MODIFY_FIELD] =
		"FLOW_ACTION_TYPE_MODIFY_FIELD";
#endif

	convert_tables_initialized = 1;
}

static int interpret_raw_data(uint8_t *data, uint8_t *preserve, int size,
			      struct flow_elem *out)
{
	int hdri = 0;
	int pkti = 0;

	/* Ethernet */
	if (size - pkti == 0)
		goto interpret_end;
	if (size - pkti < (int)sizeof(struct rte_ether_hdr))
		return -1;

	out[hdri].type = FLOW_ELEM_TYPE_ETH;
	out[hdri].spec = &data[pkti];
	out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

	rte_be16_t ether_type =
		((struct rte_ether_hdr *)&data[pkti])->ether_type;

	hdri += 1;
	pkti += sizeof(struct rte_ether_hdr);

	if (size - pkti == 0)
		goto interpret_end;

	/* VLAN */
	while (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
			ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ) ||
			ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ1)) {
		if (size - pkti == 0)
			goto interpret_end;
		if (size - pkti < (int)sizeof(struct rte_vlan_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_VLAN;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		ether_type = ((struct rte_vlan_hdr *)&data[pkti])->eth_proto;

		hdri += 1;
		pkti += sizeof(struct rte_vlan_hdr);
	}

	if (size - pkti == 0)
		goto interpret_end;

	/* Layer 3 */
	uint8_t next_header = 0;

	if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) &&
			(data[pkti] & 0xF0) == 0x40) {
		if (size - pkti < (int)sizeof(struct rte_ipv4_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_IPV4;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		next_header = data[pkti + 9];

		hdri += 1;
		pkti += sizeof(struct rte_ipv4_hdr);
	} else if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV6) &&
			(data[pkti] & 0xF0) == 0x60) {
		if (size - pkti < (int)sizeof(struct rte_ipv6_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_IPV6;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		next_header = data[pkti + 6];

		hdri += 1;
		pkti += sizeof(struct rte_ipv6_hdr);

	} else {
		return -1;
	}

	if (size - pkti == 0)
		goto interpret_end;

	/* Layer 4 */
	int gtpu_encap = 0;

	if (next_header == 1) { /* ICMP */
		if (size - pkti < (int)sizeof(struct rte_icmp_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_ICMP;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		hdri += 1;
		pkti += sizeof(struct rte_icmp_hdr);
	} else if (next_header == 6) { /* TCP */
		if (size - pkti < (int)sizeof(struct rte_tcp_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_TCP;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		hdri += 1;
		pkti += sizeof(struct rte_tcp_hdr);
	} else if (next_header == 17) { /* UDP */
		if (size - pkti < (int)sizeof(struct rte_udp_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_UDP;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		gtpu_encap = ((struct rte_udp_hdr *)&data[pkti])->dst_port ==
			     rte_cpu_to_be_16(RTE_GTPU_UDP_PORT);

		hdri += 1;
		pkti += sizeof(struct rte_udp_hdr);
	} else if (next_header == 132) { /* SCTP */
		if (size - pkti < (int)sizeof(struct rte_sctp_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_SCTP;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		hdri += 1;
		pkti += sizeof(struct rte_sctp_hdr);
	} else {
		return -1;
	}

	if (size - pkti == 0)
		goto interpret_end;

	/* GTPv1-U */
	if (gtpu_encap) {
		if (size - pkti < (int)sizeof(struct rte_gtp_hdr))
			return -1;

		out[hdri].type = FLOW_ELEM_TYPE_GTP;
		out[hdri].spec = &data[pkti];
		out[hdri].mask = (preserve != NULL) ? &preserve[pkti] : NULL;

		int extension_present_bit =
			((struct rte_gtp_hdr *)&data[pkti])->e;

		hdri += 1;
		pkti += sizeof(struct rte_gtp_hdr);

		if (extension_present_bit) {
			if (size - pkti <
					(int)sizeof(struct rte_gtp_hdr_ext_word))
				return -1;

			out[hdri].type = FLOW_ELEM_TYPE_GTP;
			out[hdri].spec = &data[pkti];
			out[hdri].mask = (preserve != NULL) ? &preserve[pkti] :
					 NULL;

			uint8_t next_ext =
				((struct rte_gtp_hdr_ext_word *)&data[pkti])
				->next_ext;

			hdri += 1;
			pkti += sizeof(struct rte_gtp_hdr_ext_word);

			while (next_ext) {
				size_t ext_len = data[pkti] * 4;

				if (size - pkti < (int)ext_len)
					return -1;

				out[hdri].type = FLOW_ELEM_TYPE_GTP;
				out[hdri].spec = &data[pkti];
				out[hdri].mask = (preserve != NULL) ?
						 &preserve[pkti] :
						 NULL;

				next_ext = data[pkti + ext_len - 1];

				hdri += 1;
				pkti += ext_len;
			}
		}
	}

	if (size - pkti != 0)
		return -1;

interpret_end:
	out[hdri].type = FLOW_ELEM_TYPE_END;
	out[hdri].spec = NULL;
	out[hdri].mask = NULL;

	return hdri + 1;
}

static int create_attr(struct cnv_attr_s *attribute,
		       const struct rte_flow_attr *attr)
{
	memset(&attribute->attr, 0x0, sizeof(struct flow_attr));
	if (attr) {
		attribute->attr.group = attr->group;
		attribute->attr.priority = attr->priority;
	}
	return 0;
}

static int create_match_elements(struct cnv_match_s *match,
				 const struct rte_flow_item items[],
				 int max_elem)
{
	int eidx = 0;
	int iter_idx = 0;
	int type = -1;

	if (!items) {
		NT_LOG(ERR, FILTER, "ERROR no items to iterate!\n");
		return -1;
	}

	if (!convert_tables_initialized)
		initialize_global_cnv_tables();

	do {
		type = CNV_TO_ELEM(items[iter_idx].type);
		if (type < 0) {
			if ((int)items[iter_idx].type ==
					NT_RTE_FLOW_ITEM_TYPE_TUNNEL) {
				type = FLOW_ELEM_TYPE_TUNNEL;
			} else {
				NT_LOG(ERR, FILTER,
				       "ERROR unknown item type received!\n");
				return -1;
			}
		}

		if (type >= 0) {
			if (items[iter_idx].last) {
				/* Ranges are not supported yet */
				NT_LOG(ERR, FILTER,
				       "ERROR ITEM-RANGE SETUP - NOT SUPPORTED!\n");
				return -1;
			}

			if (eidx == max_elem) {
				NT_LOG(ERR, FILTER,
				       "ERROR TOO MANY ELEMENTS ENCOUNTERED!\n");
				return -1;
			}

#ifdef RTE_FLOW_DEBUG
			NT_LOG(INF, FILTER,
			       "RTE ITEM -> FILTER FLOW ELEM - %i -> %i - %s\n",
			       items[iter_idx].type, type,
			       ((int)items[iter_idx].type >= 0) ?
			       elem_list_str[items[iter_idx].type] :
			       "FLOW_ELEM_TYPE_TUNNEL");

			switch (type) {
			case FLOW_ELEM_TYPE_ETH:
				if (items[iter_idx].spec) {
					const struct flow_elem_eth *eth =
							items[iter_idx].spec;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_ETH SPEC: dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
					       eth->d_addr.addr_b[0] & 0xFF,
					       eth->d_addr.addr_b[1] & 0xFF,
					       eth->d_addr.addr_b[2] & 0xFF,
					       eth->d_addr.addr_b[3] & 0xFF,
					       eth->d_addr.addr_b[4] & 0xFF,
					       eth->d_addr.addr_b[5] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                         src=%02X:%02X:%02X:%02X:%02X:%02X\n",
					       eth->s_addr.addr_b[0] & 0xFF,
					       eth->s_addr.addr_b[1] & 0xFF,
					       eth->s_addr.addr_b[2] & 0xFF,
					       eth->s_addr.addr_b[3] & 0xFF,
					       eth->s_addr.addr_b[4] & 0xFF,
					       eth->s_addr.addr_b[5] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                         type=%04x\n",
					       htons(eth->ether_type));
				}
				if (items[iter_idx].mask) {
					const struct flow_elem_eth *eth =
							items[iter_idx].mask;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_ETH MASK: dst=%02X:%02X:%02X:%02X:%02X:%02X\n",
					       eth->d_addr.addr_b[0] & 0xFF,
					       eth->d_addr.addr_b[1] & 0xFF,
					       eth->d_addr.addr_b[2] & 0xFF,
					       eth->d_addr.addr_b[3] & 0xFF,
					       eth->d_addr.addr_b[4] & 0xFF,
					       eth->d_addr.addr_b[5] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                         src=%02X:%02X:%02X:%02X:%02X:%02X\n",
					       eth->s_addr.addr_b[0] & 0xFF,
					       eth->s_addr.addr_b[1] & 0xFF,
					       eth->s_addr.addr_b[2] & 0xFF,
					       eth->s_addr.addr_b[3] & 0xFF,
					       eth->s_addr.addr_b[4] & 0xFF,
					       eth->s_addr.addr_b[5] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                         type=%04x\n",
					       htons(eth->ether_type));
				}
				break;
			case FLOW_ELEM_TYPE_VLAN:
				if (items[iter_idx].spec) {
					const struct flow_elem_vlan *vlan =
						(const struct flow_elem_vlan *)
						items[iter_idx]
						.spec;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_VLAN SPEC: tci=%04x\n",
					       htons(vlan->tci));
					NT_LOG(DBG, FILTER,
					       "                          inner type=%04x\n",
					       htons(vlan->inner_type));
				}
				if (items[iter_idx].mask) {
					const struct flow_elem_vlan *vlan =
						(const struct flow_elem_vlan *)
						items[iter_idx]
						.mask;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_VLAN MASK: tci=%04x\n",
					       htons(vlan->tci));
					NT_LOG(DBG, FILTER,
					       "                          inner type=%04x\n",
					       htons(vlan->inner_type));
				}
				break;
			case FLOW_ELEM_TYPE_IPV4:
				if (items[iter_idx].spec) {
					const struct flow_elem_ipv4 *ip =
							items[iter_idx].spec;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_IPV4 SPEC: dst=%d.%d.%d.%d\n",
					       ((const char *)&ip->hdr.dst_ip)[0] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[1] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[2] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[3] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                          src=%d.%d.%d.%d\n",
					       ((const char *)&ip->hdr.src_ip)[0] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[1] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[2] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[3] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                          fragment_offset=%u\n",
					       ip->hdr.frag_offset);
					NT_LOG(DBG, FILTER,
					       "                          next_proto_id=%u\n",
					       ip->hdr.next_proto_id);
					NT_LOG(DBG, FILTER,
					       "                          packet_id=%u\n",
					       ip->hdr.id);
					NT_LOG(DBG, FILTER,
					       "                          time_to_live=%u\n",
					       ip->hdr.ttl);
					NT_LOG(DBG, FILTER,
					       "                          type_of_service=%u\n",
					       ip->hdr.tos);
					NT_LOG(DBG, FILTER,
					       "                          version_ihl=%u\n",
					       ip->hdr.version_ihl);
					NT_LOG(DBG, FILTER,
					       "                          total_length=%u\n",
					       ip->hdr.length);
				}
				if (items[iter_idx].mask) {
					const struct flow_elem_ipv4 *ip =
							items[iter_idx].mask;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_IPV4 MASK: dst=%d.%d.%d.%d\n",
					       ((const char *)&ip->hdr.dst_ip)[0] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[1] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[2] & 0xFF,
					       ((const char *)&ip->hdr.dst_ip)[3] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                          src=%d.%d.%d.%d\n",
					       ((const char *)&ip->hdr.src_ip)[0] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[1] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[2] & 0xFF,
					       ((const char *)&ip->hdr.src_ip)[3] & 0xFF);
					NT_LOG(DBG, FILTER,
					       "                          fragment_offset=%x\n",
					       ip->hdr.frag_offset);
					NT_LOG(DBG, FILTER,
					       "                          next_proto_id=%x\n",
					       ip->hdr.next_proto_id);
					NT_LOG(DBG, FILTER,
					       "                          packet_id=%x\n",
					       ip->hdr.id);
					NT_LOG(DBG, FILTER,
					       "                          time_to_live=%x\n",
					       ip->hdr.ttl);
					NT_LOG(DBG, FILTER,
					       "                          type_of_service=%x\n",
					       ip->hdr.tos);
					NT_LOG(DBG, FILTER,
					       "                          version_ihl=%x\n",
					       ip->hdr.version_ihl);
					NT_LOG(DBG, FILTER,
					       "                          total_length=%x\n",
					       ip->hdr.length);
				}
				break;
			case FLOW_ELEM_TYPE_UDP:
				if (items[iter_idx].spec) {
					const struct flow_elem_udp *udp =
						(const struct flow_elem_udp *)
						items[iter_idx]
						.spec;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_UDP SPEC: src port=%04x\n",
					       htons(udp->hdr.src_port));
					NT_LOG(DBG, FILTER,
					       "                         dst port=%04x\n",
					       htons(udp->hdr.dst_port));
				}
				if (items[iter_idx].mask) {
					const struct flow_elem_udp *udp =
						(const struct flow_elem_udp *)
						items[iter_idx]
						.mask;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_UDP MASK: src port=%04x\n",
					       htons(udp->hdr.src_port));
					NT_LOG(DBG, FILTER,
					       "                         dst port=%04x\n",
					       htons(udp->hdr.dst_port));
				}
				break;
			case FLOW_ELEM_TYPE_TAG:
				if (items[iter_idx].spec) {
					const struct flow_elem_tag *tag =
						(const struct flow_elem_tag *)
						items[iter_idx]
						.spec;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_TAG SPEC: data=%u\n",
					       tag->data);
					NT_LOG(DBG, FILTER,
					       "                         index=%u\n",
					       tag->index);
				}
				if (items[iter_idx].mask) {
					const struct flow_elem_tag *tag =
						(const struct flow_elem_tag *)
						items[iter_idx]
						.mask;
					NT_LOG(DBG, FILTER,
					       "FLOW_ELEM_TYPE_TAG MASK: data=%u\n",
					       tag->data);
					NT_LOG(DBG, FILTER,
					       "                         index=%u\n",
					       tag->index);
				}
				break;
			case FLOW_ELEM_TYPE_VXLAN: {
				const struct flow_elem_vxlan *vxlan =
					(const struct flow_elem_vxlan *)
					items[iter_idx]
					.spec;
				const struct flow_elem_vxlan *mask =
					(const struct flow_elem_vxlan *)
					items[iter_idx]
					.mask;

				uint32_t vni =
					(uint32_t)(((uint32_t)vxlan->vni[0]
						    << 16) |
						   ((uint32_t)vxlan->vni[1]
						    << 8) |
						   ((uint32_t)vxlan->vni[2]));
				uint32_t vni_mask =
					(uint32_t)(((uint32_t)mask->vni[0]
						    << 16) |
						   ((uint32_t)mask->vni[1]
						    << 8) |
						   ((uint32_t)mask->vni[2]));

				NT_LOG(INF, FILTER, "VNI: %08x / %08x\n", vni,
				       vni_mask);
			}
			break;
			}
#endif

			match->flow_elem[eidx].type = type;
			match->flow_elem[eidx].spec = items[iter_idx].spec;
			match->flow_elem[eidx].mask = items[iter_idx].mask;

			eidx++;
			iter_idx++;
		}

	} while (type >= 0 && type != FLOW_ELEM_TYPE_END);

	return (type >= 0) ? 0 : -1;
}

static int
create_action_elements_vswitch(struct cnv_action_s *action,
			       const struct rte_flow_action actions[],
			       int max_elem, uint32_t *flow_stat_id)
{
	int aidx = 0;
	int iter_idx = 0;
	int type = -1;

	if (!actions)
		return -1;

	if (!convert_tables_initialized)
		initialize_global_cnv_tables();

	*flow_stat_id = MAX_COLOR_FLOW_STATS;
	do {
		type = CNV_TO_ACTION(actions[iter_idx].type);
		if (type < 0) {
			if ((int)actions[iter_idx].type ==
					NT_RTE_FLOW_ACTION_TYPE_TUNNEL_SET) {
				type = FLOW_ACTION_TYPE_TUNNEL_SET;
			} else {
				NT_LOG(ERR, FILTER,
				       "ERROR unknown action type received!\n");
				return -1;
			}
		}

#ifdef RTE_FLOW_DEBUG
		NT_LOG(INF, FILTER,
		       "RTE ACTION -> FILTER FLOW ACTION - %i -> %i - %s\n",
		       actions[iter_idx].type, type,
		       ((int)actions[iter_idx].type >= 0) ?
		       action_list_str[actions[iter_idx].type] :
		       "FLOW_ACTION_TYPE_TUNNEL_SET");
#endif

		if (type >= 0) {
			action->flow_actions[aidx].type = type;

			/*
			 * Non-compatible actions handled here
			 */
			switch (type) {
			case -1:
#ifdef RTE_FLOW_DEBUG
				NT_LOG(INF, FILTER,
				       "RTE ACTION UNSUPPORTED %i\n",
				       actions[iter_idx].type);
#endif
				return -1;

			case FLOW_ACTION_TYPE_RSS: {
				const struct rte_flow_action_rss *rss =
					(const struct rte_flow_action_rss *)
					actions[iter_idx]
					.conf;
				action->flow_rss.func =
					FLOW_HASH_FUNCTION_DEFAULT;

				if (rss->func !=
						RTE_ETH_HASH_FUNCTION_DEFAULT)
					return -1;
				action->flow_rss.level = rss->level;
				action->flow_rss.types = rss->types;
				action->flow_rss.key_len = rss->key_len;
				action->flow_rss.queue_num = rss->queue_num;
				action->flow_rss.key = rss->key;
				action->flow_rss.queue = rss->queue;
#ifdef RTE_FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RSS: rss->level = %u\n",
				       rss->level);
				NT_LOG(DBG, FILTER,
				       "                      rss->types = 0x%" PRIX64 "\n",
				       (unsigned long long)rss->types);
				NT_LOG(DBG, FILTER,
				       "                      rss->key_len = %u\n",
				       rss->key_len);
				NT_LOG(DBG, FILTER,
				       "                      rss->queue_num = %u\n",
				       rss->queue_num);
				NT_LOG(DBG, FILTER,
				       "                      rss->key = %p\n",
				       rss->key);
				unsigned int i;

				for (i = 0; i < rss->queue_num; i++) {
					NT_LOG(DBG, FILTER,
					       "                      rss->queue[%u] = %u\n",
					       i, rss->queue[i]);
				}
#endif
				action->flow_actions[aidx].conf =
					&action->flow_rss;
				break;
			}

			case FLOW_ACTION_TYPE_VXLAN_ENCAP: {
				const struct rte_flow_action_vxlan_encap *tun =
					(const struct rte_flow_action_vxlan_encap
					 *)actions[iter_idx]
					.conf;
				if (!tun || create_match_elements(&action->tun_def.match,
								  tun->definition,
								  MAX_ELEMENTS) != 0)
					return -1;
				action->tun_def.tun_definition =
					action->tun_def.match.flow_elem;
				action->flow_actions[aidx].conf =
					&action->tun_def;
			}
			break;

			case FLOW_ACTION_TYPE_MARK: {
				const struct rte_flow_action_mark *mark_id =
					(const struct rte_flow_action_mark *)
					actions[iter_idx]
					.conf;
				if (mark_id) {
#ifdef RTE_FLOW_DEBUG
					NT_LOG(DBG, FILTER, "Mark ID=%u\n",
					       mark_id->id);
#endif
					*flow_stat_id = create_flow_stat_id(mark_id->id);
					action->mark.id = *flow_stat_id;
					action->flow_actions[aidx].conf =
						&action->mark;

				} else {
					action->flow_actions[aidx].conf =
						actions[iter_idx].conf;
				}
			}
			break;

			default:
				/* Compatible */

				/*
				 * OVS Full offload does not add mark in RTE Flow
				 * We need one in FPGA to control flow(color) statistics
				 */
				if (type == FLOW_ACTION_TYPE_END &&
						*flow_stat_id == MAX_COLOR_FLOW_STATS) {
					/* We need to insert a mark for our FPGA */
					*flow_stat_id = create_flow_stat_id(0);
					action->mark.id = *flow_stat_id;

					action->flow_actions[aidx].type =
						FLOW_ACTION_TYPE_MARK;
					action->flow_actions[aidx].conf =
						&action->mark;
					aidx++;

					/* Move end type */
					action->flow_actions[aidx].type =
						FLOW_ACTION_TYPE_END;
				}

#ifdef RTE_FLOW_DEBUG
				switch (type) {
				case FLOW_ACTION_TYPE_PORT_ID:
					NT_LOG(DBG, FILTER,
					       "Port ID=%u, Original=%u\n",
					       ((const struct rte_flow_action_port_id
						 *)actions[iter_idx]
						.conf)
					       ->id,
					       ((const struct rte_flow_action_port_id
						 *)actions[iter_idx]
						.conf)
					       ->original);
					break;
				case FLOW_ACTION_TYPE_COUNT:
					NT_LOG(DBG, FILTER, "Count ID=%u\n",
					       ((const struct rte_flow_action_count
						 *)actions[iter_idx]
						.conf)
					       ->id);
					break;
				case FLOW_ACTION_TYPE_SET_TAG:
					NT_LOG(DBG, FILTER,
					       "FLOW_ACTION_TYPE_SET_TAG: data=%u\n",
					       ((const struct flow_action_tag *)
						actions[iter_idx]
						.conf)
					       ->data);
					NT_LOG(DBG, FILTER,
					       "                          mask=%u\n",
					       ((const struct flow_action_tag *)
						actions[iter_idx]
						.conf)
					       ->mask);
					NT_LOG(DBG, FILTER,
					       "                          index=%u\n",
					       ((const struct flow_action_tag *)
						actions[iter_idx]
						.conf)
					       ->index);
					break;
				}
#endif

				action->flow_actions[aidx].conf =
					actions[iter_idx].conf;
				break;
			}

			aidx++;
			if (aidx == max_elem)
				return -1;
			iter_idx++;
		}

	} while (type >= 0 && type != FLOW_ACTION_TYPE_END);

	return (type >= 0) ? 0 : -1;
}

static int create_action_elements_inline(struct cnv_action_s *action,
		const struct rte_flow_action actions[],
		int max_elem, uint32_t queue_offset)
{
	int aidx = 0;
	int type = -1;

	do {
		type = CNV_TO_ACTION(actions[aidx].type);

#ifdef RTE_FLOW_DEBUG
		NT_LOG(INF, FILTER,
		       "RTE ACTION -> FILTER FLOW ACTION - %i -> %i - %s\n",
		       actions[aidx].type, type,
		       ((int)actions[aidx].type >= 0) ?
		       action_list_str[actions[aidx].type] :
		       "FLOW_ACTION_TYPE_TUNNEL_SET");
#endif

		if (type >= 0) {
			action->flow_actions[aidx].type = type;

			/*
			 * Non-compatible actions handled here
			 */
			switch (type) {
			case FLOW_ACTION_TYPE_RSS: {
				const struct rte_flow_action_rss *rss =
					(const struct rte_flow_action_rss *)
					actions[aidx]
					.conf;
				action->flow_rss.func =
					FLOW_HASH_FUNCTION_DEFAULT;

				if (rss->func !=
						RTE_ETH_HASH_FUNCTION_DEFAULT)
					return -1;
				action->flow_rss.level = rss->level;
				action->flow_rss.types = rss->types;
				action->flow_rss.key_len = rss->key_len;
				action->flow_rss.queue_num = rss->queue_num;
				action->flow_rss.key = rss->key;
				action->flow_rss.queue = rss->queue;
				action->flow_actions[aidx].conf =
					&action->flow_rss;
#ifdef RTE_FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RSS: rss->level = %u\n",
				       rss->level);
				NT_LOG(DBG, FILTER,
				       "                      rss->types = 0x%" PRIX64 "\n",
				       (unsigned long long)rss->types);
				NT_LOG(DBG, FILTER,
				       "                      rss->key_len = %u\n",
				       rss->key_len);
				NT_LOG(DBG, FILTER,
				       "                      rss->queue_num = %u\n",
				       rss->queue_num);
				NT_LOG(DBG, FILTER,
				       "                      rss->key = %p\n",
				       rss->key);
				unsigned int i;

				for (i = 0; i < rss->queue_num; i++) {
					NT_LOG(DBG, FILTER,
					       "                      rss->queue[%u] = %u\n",
					       i, rss->queue[i]);
				}
#endif
			}
			break;

			case FLOW_ACTION_TYPE_RAW_DECAP: {
				const struct rte_flow_action_raw_decap *decap =
					(const struct rte_flow_action_raw_decap
					 *)actions[aidx]
					.conf;
				int item_count = interpret_raw_data(decap->data,
								    NULL, decap->size,
								    action->decap.items);
				if (item_count < 0)
					return item_count;
#ifdef RTE_FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RAW_DECAP: size = %u\n",
				       decap->size);
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RAW_DECAP: item_count = %u\n",
				       item_count);
				for (int i = 0; i < item_count; i++) {
					NT_LOG(DBG, FILTER,
					       "FLOW_ACTION_TYPE_RAW_DECAP: item = %u\n",
					       action->decap.items[i].type);
				}
#endif
				action->decap.data = decap->data;
				action->decap.size = decap->size;
				action->decap.item_count = item_count;
				action->flow_actions[aidx].conf =
					&action->decap;
			}
			break;

			case FLOW_ACTION_TYPE_RAW_ENCAP: {
				const struct rte_flow_action_raw_encap *encap =
					(const struct rte_flow_action_raw_encap
					 *)actions[aidx]
					.conf;
				int item_count = interpret_raw_data(encap->data,
								    encap->preserve,
								    encap->size,
								    action->encap.items);
				if (item_count < 0)
					return item_count;
#ifdef RTE_FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RAW_ENCAP: size = %u\n",
				       encap->size);
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_RAW_ENCAP: item_count = %u\n",
				       item_count);
#endif
				action->encap.data = encap->data;
				action->encap.preserve = encap->preserve;
				action->encap.size = encap->size;
				action->encap.item_count = item_count;
				action->flow_actions[aidx].conf =
					&action->encap;
			}
			break;

			case FLOW_ACTION_TYPE_QUEUE: {
				const struct rte_flow_action_queue *queue =
					(const struct rte_flow_action_queue *)
					actions[aidx]
					.conf;
				action->queue.index =
					queue->index + queue_offset;
				action->flow_actions[aidx].conf =
					&action->queue;
#ifdef RTE_FLOW_DEBUG
				NT_LOG(DBG, FILTER,
				       "FLOW_ACTION_TYPE_QUEUE: queue = %u\n",
				       action->queue.index);
#endif
			}
			break;

			default: {
				action->flow_actions[aidx].conf =
					actions[aidx].conf;

#ifdef RTE_FLOW_DEBUG
				switch (type) {
				case FLOW_ACTION_TYPE_PORT_ID:
					NT_LOG(DBG, FILTER,
					       "Port ID=%u, Original=%u\n",
					       ((const struct rte_flow_action_port_id
						 *)actions[aidx]
						.conf)
					       ->id,
					       ((const struct rte_flow_action_port_id
						 *)actions[aidx]
						.conf)
					       ->original);
					break;
				case FLOW_ACTION_TYPE_COUNT:
					NT_LOG(DBG, FILTER, "Count ID=%u\n",
					       ((const struct rte_flow_action_count
						 *)actions[aidx]
						.conf)
					       ->id);
					break;
				case FLOW_ACTION_TYPE_SET_TAG:
					NT_LOG(DBG, FILTER,
					       "FLOW_ACTION_TYPE_SET_TAG: data=%u\n",
					       ((const struct flow_action_tag *)
						actions[aidx]
						.conf)
					       ->data);
					NT_LOG(DBG, FILTER,
					       "                          mask=%u\n",
					       ((const struct flow_action_tag *)
						actions[aidx]
						.conf)
					       ->mask);
					NT_LOG(DBG, FILTER,
					       "                          index=%u\n",
					       ((const struct flow_action_tag *)
						actions[aidx]
						.conf)
					       ->index);
					break;
				}
#endif
			}
			break;
			}

			aidx++;
			if (aidx == max_elem)
				return -1;
		}

	} while (type >= 0 && type != FLOW_ACTION_TYPE_END);

	return (type >= 0) ? 0 : -1;
}

#endif /* __CREATE_ELEMENTS_H__ */
