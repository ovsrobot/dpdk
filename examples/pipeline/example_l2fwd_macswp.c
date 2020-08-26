/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <rte_common.h>

#include "rte_swx_pipeline.h"
#include "rte_swx_port_ethdev.h"
#include "rte_swx_port_source_sink.h"
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
static struct rte_swx_field_params ethernet_type[] = {
	{"dst_addr", 48},
	{"src_addr", 48},
	{"ether_type", 16},
};

/*
 * Packet meta-data.
 */
static struct rte_swx_field_params metadata_type[] = {
	{"port", 32},
	{"addr", 48},
};

/*
 * Actions.
 */
static const char *action_macswp_instructions[] = {
	"mov m.addr h.ethernet.dst_addr",
	"mov h.ethernet.dst_addr h.ethernet.src_addr",
	"mov h.ethernet.src_addr m.addr",
	"return",
};

/*
 * Tables.
 */
static const char *table_stub_actions[] = {"macswp"};

static struct rte_swx_pipeline_table_params table_stub_params = {
	/* Match. */
	.fields = NULL,
	.n_fields = 0,

	/* Action. */
	.action_names = table_stub_actions,
	.n_actions = RTE_DIM(table_stub_actions),
	.default_action_name = "macswp",
	.default_action_data = NULL,
	.default_action_is_const = 0,
};

/*
 * Pipeline.
 */
static const char *pipeline_instructions[] = {
	"rx m.port",
	"extract h.ethernet",
	"table stub",
	"xor m.port 1",
	"emit h.ethernet",
	"tx m.port",
};

int
pipeline_setup_l2fwd_macswp(struct rte_swx_pipeline *p);

int
pipeline_setup_l2fwd_macswp(struct rte_swx_pipeline *p)
{
	int err;

	/*
	 * Packet headers.
	 */
	err = rte_swx_pipeline_struct_type_register(p,
		"ethernet_type",
		ethernet_type,
		RTE_DIM(ethernet_type));
	CHECK(!err);

	err = rte_swx_pipeline_packet_header_register(p,
		"ethernet",
		"ethernet_type");
	CHECK(!err);

	/*
	 * Packet meta-data.
	 */
	err = rte_swx_pipeline_struct_type_register(p,
		"metadata_type",
		metadata_type,
		RTE_DIM(metadata_type));
	CHECK(!err);

	err = rte_swx_pipeline_packet_metadata_register(p,
		"metadata_type");
	CHECK(!err);

	/*
	 * Actions.
	 */
	err = rte_swx_pipeline_action_config(p,
		"macswp",
		NULL,
		action_macswp_instructions,
		RTE_DIM(action_macswp_instructions));
	CHECK(!err);

	/*
	 * Tables.
	 */
	err = rte_swx_pipeline_table_config(p,
		"stub",
		&table_stub_params,
		NULL,
		NULL,
		0);
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
