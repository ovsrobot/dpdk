/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 Stephen Hemminger <stephen@networkplumber.org>
 */

/*
 * Tables that describe each flow item and flow action recognized by
 * the compiler.
 *
 * To add a new item type:
 *
 *   1. Add a static array of ``struct field_desc`` for each parsable
 *      field in the item's spec struct.
 *   2. Add an entry to ``flow_items[]``.
 *
 * The parser is entirely table-driven; no parser code needs to change.
 */

#include <stddef.h>
#include <string.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_flow.h>

#include "flow_compile_priv.h"

/*
 * Helper macros.
 *
 * FIELD:        a fixed-width field reachable by offsetof(spec, member).
 * FIELD_BYTES:  a byte array of declared length (for opaque/raw fields).
 * FIELD_CUSTOM: an alias whose semantics need a custom setter.
 */
#define FIELD(_n, _s, _m, _k)						\
	{ .name = (_n), .offset = offsetof(_s, _m),			\
	  .size = sizeof(((_s *)0)->_m), .kind = (_k), .set = NULL }

#define FIELD_BYTES(_n, _s, _m)						\
	{ .name = (_n), .offset = offsetof(_s, _m),			\
	  .size = sizeof(((_s *)0)->_m), .kind = FK_BYTES, .set = NULL }

/* ------------------------------------------------------------------ */
/* eth */

static const struct field_desc eth_fields[] = {
	FIELD("dst",	struct rte_flow_item_eth, hdr.dst_addr,    FK_MAC),
	FIELD("src",	struct rte_flow_item_eth, hdr.src_addr,    FK_MAC),
	FIELD("type",	struct rte_flow_item_eth, hdr.ether_type,  FK_BE16),
};

/* ------------------------------------------------------------------ */
/* vlan */

static const struct field_desc vlan_fields[] = {
	FIELD("tci",		struct rte_flow_item_vlan, hdr.vlan_tci,        FK_BE16),
	FIELD("inner_type",	struct rte_flow_item_vlan, hdr.eth_proto,       FK_BE16),
};

/* ------------------------------------------------------------------ */
/* ipv4 */

static const struct field_desc ipv4_fields[] = {
	FIELD("tos",		 struct rte_flow_item_ipv4, hdr.type_of_service, FK_U8),
	FIELD("ttl",		 struct rte_flow_item_ipv4, hdr.time_to_live,	 FK_U8),
	FIELD("proto",		 struct rte_flow_item_ipv4, hdr.next_proto_id,	 FK_U8),
	FIELD("src",		 struct rte_flow_item_ipv4, hdr.src_addr,	 FK_IPV4),
	FIELD("dst",		 struct rte_flow_item_ipv4, hdr.dst_addr,	 FK_IPV4),
	FIELD("fragment_offset", struct rte_flow_item_ipv4, hdr.fragment_offset, FK_BE16),
	FIELD("packet_id",	 struct rte_flow_item_ipv4, hdr.packet_id,	 FK_BE16),
	FIELD("total_length",	 struct rte_flow_item_ipv4, hdr.total_length,	 FK_BE16),
};

/* ------------------------------------------------------------------ */
/* ipv6 */

static const struct field_desc ipv6_fields[] = {
	FIELD("src",		struct rte_flow_item_ipv6, hdr.src_addr,	FK_IPV6),
	FIELD("dst",		struct rte_flow_item_ipv6, hdr.dst_addr,	FK_IPV6),
	FIELD("proto",		struct rte_flow_item_ipv6, hdr.proto,		FK_U8),
	FIELD("hop_limits",	struct rte_flow_item_ipv6, hdr.hop_limits,	FK_U8),
	FIELD("vtc_flow",	struct rte_flow_item_ipv6, hdr.vtc_flow,	FK_BE32),
	FIELD("payload_len",	struct rte_flow_item_ipv6, hdr.payload_len,	FK_BE16),
};

/* ------------------------------------------------------------------ */
/* tcp / udp */

static const struct field_desc tcp_fields[] = {
	FIELD("src",		struct rte_flow_item_tcp, hdr.src_port,	 FK_BE16),
	FIELD("dst",		struct rte_flow_item_tcp, hdr.dst_port,	 FK_BE16),
	FIELD("flags",		struct rte_flow_item_tcp, hdr.tcp_flags, FK_U8),
};

static const struct field_desc udp_fields[] = {
	FIELD("src",		struct rte_flow_item_udp, hdr.src_port,	FK_BE16),
	FIELD("dst",		struct rte_flow_item_udp, hdr.dst_port,	FK_BE16),
};

/* ------------------------------------------------------------------ */
/* vxlan -- the vni field is 24 bits stored as 3 raw bytes.  We expose
 * it as a 4-byte BE value where the low 24 bits are user supplied;
 * the table-driven setter handles the truncation.  A purist would add
 * a custom setter; the result here is identical and avoids the noise.
 */

static const struct field_desc vxlan_fields[] = {
	FIELD("flags",	struct rte_flow_item_vxlan, hdr.flags,	FK_U8),
	FIELD_BYTES("vni",	struct rte_flow_item_vxlan, hdr.vni),
};

/* ------------------------------------------------------------------ */
/* port_id / port_representor */

static const struct field_desc port_id_fields[] = {
	FIELD("id",		struct rte_flow_item_port_id, id,	FK_U32),
};

static const struct field_desc port_repr_fields[] = {
	FIELD("port_id",	struct rte_flow_item_ethdev, port_id,	FK_U16),
};

/* ------------------------------------------------------------------ */
/* The item table.  Order is irrelevant; lookup is by exact name match. */

#define ITEM(_n, _t, _s, _f) {						\
	.name = (_n), .type = (_t), .spec_size = sizeof(_s),		\
	.fields = (_f), .nfields = RTE_DIM(_f) }

#define ITEM_VOID(_n, _t) {						\
	.name = (_n), .type = (_t), .spec_size = 0,			\
	.fields = NULL, .nfields = 0 }

static const struct flow_item_desc flow_items[] = {
	ITEM_VOID("void",	RTE_FLOW_ITEM_TYPE_VOID),
	ITEM_VOID("any",	RTE_FLOW_ITEM_TYPE_ANY),
	ITEM("eth",		RTE_FLOW_ITEM_TYPE_ETH,		struct rte_flow_item_eth,	eth_fields),
	ITEM("vlan",		RTE_FLOW_ITEM_TYPE_VLAN,	struct rte_flow_item_vlan,	vlan_fields),
	ITEM("ipv4",		RTE_FLOW_ITEM_TYPE_IPV4,	struct rte_flow_item_ipv4,	ipv4_fields),
	ITEM("ipv6",		RTE_FLOW_ITEM_TYPE_IPV6,	struct rte_flow_item_ipv6,	ipv6_fields),
	ITEM("tcp",		RTE_FLOW_ITEM_TYPE_TCP,		struct rte_flow_item_tcp,	tcp_fields),
	ITEM("udp",		RTE_FLOW_ITEM_TYPE_UDP,		struct rte_flow_item_udp,	udp_fields),
	ITEM("vxlan",		RTE_FLOW_ITEM_TYPE_VXLAN,	struct rte_flow_item_vxlan,	vxlan_fields),
	ITEM("port_id",		RTE_FLOW_ITEM_TYPE_PORT_ID,	struct rte_flow_item_port_id,	port_id_fields),
	ITEM("port_representor", RTE_FLOW_ITEM_TYPE_PORT_REPRESENTOR,
				struct rte_flow_item_ethdev,	port_repr_fields),
	ITEM("represented_port", RTE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
				struct rte_flow_item_ethdev,	port_repr_fields),
};

/* ------------------------------------------------------------------ */
/* Action descriptor tables. */

static const struct field_desc act_queue_fields[] = {
	FIELD("index",	struct rte_flow_action_queue, index,	FK_U16),
};

static const struct field_desc act_mark_fields[] = {
	FIELD("id",	struct rte_flow_action_mark, id,	FK_U32),
};

static const struct field_desc act_jump_fields[] = {
	FIELD("group",	struct rte_flow_action_jump, group,	FK_U32),
};

static const struct field_desc act_count_fields[] = {
	FIELD("id",	struct rte_flow_action_count, id,	FK_U32),
};

static const struct field_desc act_port_id_fields[] = {
	FIELD("id",	struct rte_flow_action_port_id, id,	FK_U32),
};

static const struct field_desc act_port_repr_fields[] = {
	FIELD("port_id", struct rte_flow_action_ethdev, port_id, FK_U16),
};

#define ACTION(_n, _t, _s, _f) {					\
	.name = (_n), .type = (_t), .conf_size = sizeof(_s),		\
	.fields = (_f), .nfields = RTE_DIM(_f) }

#define ACTION_VOID(_n, _t) {						\
	.name = (_n), .type = (_t), .conf_size = 0,			\
	.fields = NULL, .nfields = 0 }

static const struct flow_action_desc flow_actions[] = {
	ACTION_VOID("void",		RTE_FLOW_ACTION_TYPE_VOID),
	ACTION_VOID("drop",		RTE_FLOW_ACTION_TYPE_DROP),
	ACTION_VOID("passthru",		RTE_FLOW_ACTION_TYPE_PASSTHRU),
	ACTION_VOID("of_pop_vlan",	RTE_FLOW_ACTION_TYPE_OF_POP_VLAN),
	ACTION_VOID("vxlan_decap",	RTE_FLOW_ACTION_TYPE_VXLAN_DECAP),

	ACTION("queue",		RTE_FLOW_ACTION_TYPE_QUEUE,
	       struct rte_flow_action_queue,		act_queue_fields),
	ACTION("mark",		RTE_FLOW_ACTION_TYPE_MARK,
	       struct rte_flow_action_mark,		act_mark_fields),
	ACTION("jump",		RTE_FLOW_ACTION_TYPE_JUMP,
	       struct rte_flow_action_jump,		act_jump_fields),
	ACTION("count",		RTE_FLOW_ACTION_TYPE_COUNT,
	       struct rte_flow_action_count,		act_count_fields),
	ACTION("port_id",	RTE_FLOW_ACTION_TYPE_PORT_ID,
	       struct rte_flow_action_port_id,		act_port_id_fields),
	ACTION("port_representor", RTE_FLOW_ACTION_TYPE_PORT_REPRESENTOR,
	       struct rte_flow_action_ethdev,		act_port_repr_fields),
	ACTION("represented_port", RTE_FLOW_ACTION_TYPE_REPRESENTED_PORT,
	       struct rte_flow_action_ethdev,		act_port_repr_fields),
};

/* ------------------------------------------------------------------ */
/* Public lookup helpers. */

static bool
name_eq(const char *a, const char *b, size_t bn)
{
	return strncmp(a, b, bn) == 0 && a[bn] == '\0';
}

const struct flow_item_desc *
flow_compile_item_lookup(const char *name, size_t len)
{
	for (size_t i = 0; i < RTE_DIM(flow_items); i++)
		if (name_eq(flow_items[i].name, name, len))
			return &flow_items[i];
	return NULL;
}

const struct flow_action_desc *
flow_compile_action_lookup(const char *name, size_t len)
{
	for (size_t i = 0; i < RTE_DIM(flow_actions); i++)
		if (name_eq(flow_actions[i].name, name, len))
			return &flow_actions[i];
	return NULL;
}

const struct field_desc *
flow_compile_field_lookup(const struct field_desc *tbl, uint16_t n,
			  const char *name, size_t len)
{
	for (uint16_t i = 0; i < n; i++)
		if (tbl[i].name != NULL && name_eq(tbl[i].name, name, len))
			return &tbl[i];
	return NULL;
}
