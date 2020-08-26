/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <rte_common.h>

#include "rte_swx_pipeline.h"
#include "rte_swx_table_em.h"

#define CHECK(condition)                                                       \
do {                                                                           \
	if (!(condition)) {                                                    \
		printf("Error in function %s at line %d\n",                    \
			__FUNCTION__, __LINE__);                               \
		return -1;                                                     \
	}                                                                      \
} while (0)

/*
 * Packet headers.
 */
static struct rte_swx_field_params ethernet_h[] = {
	{"dst_addr", 48},
	{"src_addr", 48},
	{"ether_type", 16},
};

static struct rte_swx_field_params ipv4_h[] = {
	{"ver_ihl", 8},
	{"diffserv", 8},
	{"total_len", 16},
	{"identification", 16},
	{"flags_offset", 16},
	{"ttl", 8},
	{"protocol", 8},
	{"hdr_checksum", 16},
	{"src_addr", 32},
	{"dst_addr", 32},
};

static struct rte_swx_field_params udp_h[] = {
	{"src_port", 16},
	{"dst_port", 16},
	{"length", 16},
	{"checksum", 16},
};

static struct rte_swx_field_params vxlan_h[] = {
	{"flags", 8},
	{"reserved", 24},
	{"vni", 24},
	{"reserved2", 8},
};

/*
 * Packet meta-data.
 */
static struct rte_swx_field_params metadata_t[] = {
	{"port_in", 32},
	{"port_out", 32},
};

/*
 * Actions.
 */
static const char *drop_instructions[] = {
	"mov m.port_out 4",
	"tx m.port_out",
};

static struct rte_swx_field_params vxlan_encap_args_t[] = {
	{"ethernet_dst_addr", 48},
	{"ethernet_src_addr", 48},
	{"ethernet_ether_type", 16},
	{"ipv4_ver_ihl", 8},
	{"ipv4_diffserv", 8},
	{"ipv4_total_len", 16},
	{"ipv4_identification", 16},
	{"ipv4_flags_offset", 16},
	{"ipv4_ttl", 8},
	{"ipv4_protocol", 8},
	{"ipv4_hdr_checksum", 16},
	{"ipv4_src_addr", 32},
	{"ipv4_dst_addr", 32},
	{"udp_src_port", 16},
	{"udp_dst_port", 16},
	{"udp_length", 16},
	{"udp_checksum", 16},
	{"vxlan_flags", 8},
	{"vxlan_reserved", 24},
	{"vxlan_vni", 24},
	{"vxlan_reserved2", 8},
	{"port_out", 32},
};

/* Input frame:
 *    Ethernet (14) | IPv4 (total_len)
 *
 * Output frame:
 *    Ethernet (14) | IPv4 (20) | UDP (8) | VXLAN (8) | Input frame | FCS (4)
 *
 * Note: The input frame has its FCS removed before encapsulation in the output
 * frame.
 *
 * Assumption: When read from the table, the outer IPv4 and UDP headers contain
 * the following fields:
 *    - t.ipv4_total_len: Set to 50, which covers the length of:
 *         - The outer IPv4 header (20 bytes);
 *         - The outer UDP header (8 bytes);
 *         - The outer VXLAN header (8 bytes);
 *         - The inner Ethernet header (14 bytes);
 *    - t.ipv4_hdr_checksum: Includes the above total length.
 *    - t.udp_length: Set to 30, which covers the length of:
 *         - The outer UDP header (8 bytes);
 *         - The outer VXLAN header (8 bytes);
 *         - The inner Ethernet header (14 bytes);
 *    - t.udp_checksum: Set to 0.
 *
 * Once the total length of the inner IPv4 packet (h.ipv4.total_len) is known,
 * the outer IPv4 and UDP headers are updated as follows:
 *    - h.outer_ipv4.total_len = t.ipv4_total_len + h.ipv4.total_len
 *    - h.outer_ipv4.hdr_checksum = t.ipv4_hdr_checksum + h.ipv4.total_len
 *    - h.outer_udp.length = t.udp_length + h.ipv4.total_len
 *    - h.outer_udp.checksum: No change.
 */
static const char *vxlan_encap_instructions[] = {
	/* Copy from table entry to haders and metadata. */
	"dma h.outer_ethernet t.ethernet_dst_addr",
	"dma h.outer_ipv4 t.ipv4_ver_ihl",
	"dma h.outer_udp t.udp_src_port",
	"dma h.outer_vxlan t.vxlan_flags",
	"mov m.port_out t.port_out",

	/* Update h.outer_ipv4.total_len field. */
	"add h.outer_ipv4.total_len h.ipv4.total_len",

	/* Update h.outer_ipv4.hdr_checksum field. */
	"ckadd h.outer_ipv4.hdr_checksum h.ipv4.total_len",

	/* Update h.outer_udp.length field. */
	"add h.outer_udp.length h.ipv4.total_len",

	"return"
};

/*
 * Tables.
 */
static struct rte_swx_match_field_params table_match_fields[] = {
	[0] = {
		.name = "h.ethernet.dst_addr",
		.match_type = RTE_SWX_TABLE_MATCH_EXACT,
	},
};

static const char *table_actions[] = {"drop", "vxlan_encap"};

static struct rte_swx_pipeline_table_params table_params = {
	/* Match. */
	.fields = table_match_fields,
	.n_fields = RTE_DIM(table_match_fields),

	/* Action. */
	.action_names = table_actions,
	.n_actions = RTE_DIM(table_actions),
	.default_action_name = "drop",
	.default_action_data = NULL,
	.default_action_is_const = 0,
};

/*
 * Pipeline.
 */
static const char *pipeline_instructions[] = {
	"rx m.port_in",
	"extract h.ethernet",
	"extract h.ipv4",
	"table vxlan",
	"emit h.outer_ethernet",
	"emit h.outer_ipv4",
	"emit h.outer_udp",
	"emit h.outer_vxlan",
	"emit h.ethernet",
	"emit h.ipv4",
	"tx m.port_out",
};

int
pipeline_setup_vxlan(struct rte_swx_pipeline *p);

int
pipeline_setup_vxlan(struct rte_swx_pipeline *p)
{
	int err;

	/*
	 * Packet headers.
	 */
	err = rte_swx_pipeline_struct_type_register(p,
		"ethernet_h",
		ethernet_h,
		RTE_DIM(ethernet_h));
	CHECK(!err);

	err = rte_swx_pipeline_struct_type_register(p,
		"ipv4_h",
		ipv4_h,
		RTE_DIM(ipv4_h));
	CHECK(!err);

	err = rte_swx_pipeline_struct_type_register(p,
		"udp_h",
		udp_h,
		RTE_DIM(udp_h));
	CHECK(!err);

	err = rte_swx_pipeline_struct_type_register(p,
		"vxlan_h",
		vxlan_h,
		RTE_DIM(vxlan_h));
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"outer_ethernet",
		"ethernet_h");
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"outer_ipv4",
		"ipv4_h");
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"outer_udp",
		"udp_h");
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"outer_vxlan",
		"vxlan_h");
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"ethernet",
		"ethernet_h");
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"ipv4",
		"ipv4_h");
	CHECK(!err);

	/*
	 * Packet meta-data.
	 */
	err = rte_swx_pipeline_struct_type_register(p,
		"metadata_t",
		metadata_t,
		RTE_DIM(metadata_t));
	CHECK(!err);

	err = rte_swx_pipeline_packet_metadata_register(p,
		"metadata_t");
	CHECK(!err);

	/*
	 * Actions.
	 */
	err = rte_swx_pipeline_action_config(p,
		"drop",
		NULL,
		drop_instructions,
		RTE_DIM(drop_instructions));
	CHECK(!err);

	err = rte_swx_pipeline_struct_type_register(p,
		"vxlan_encap_args_t",
		vxlan_encap_args_t,
		RTE_DIM(vxlan_encap_args_t));
	CHECK(!err);

	err = rte_swx_pipeline_action_config(p,
		"vxlan_encap",
		"vxlan_encap_args_t",
		vxlan_encap_instructions,
		RTE_DIM(vxlan_encap_instructions));
	CHECK(!err);

	/*
	 * Tables.
	 */
	err = rte_swx_pipeline_table_type_register(p,
		"exact",
		RTE_SWX_TABLE_MATCH_EXACT,
		&rte_swx_table_exact_match_ops);
	CHECK(!err);

	err = rte_swx_pipeline_table_config(p,
		"vxlan",
		&table_params,
		NULL,
		NULL,
		1 * 1024 * 1024);
	CHECK(!err);

	/*
	 * Pipeline.
	 */
	err = rte_swx_pipeline_instructions_config(p,
		pipeline_instructions,
		RTE_DIM(pipeline_instructions));
	CHECK(!err);

	return 0;
}
