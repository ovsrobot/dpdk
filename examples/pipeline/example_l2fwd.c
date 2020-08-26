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

/*
 * Packet meta-data.
 */
static struct rte_swx_field_params metadata_type[] = {
	{"port_in", 32},
	{"port_out", 32},
};

/*
 * Actions.
 */
static const char *action_passthrough_instructions[] = {
	"return",
};

/*
 * Tables.
 */
static const char *table_stub_actions[] = {"passthrough"};

static struct rte_swx_pipeline_table_params table_stub_params = {
	/* Match. */
	.fields = NULL,
	.n_fields = 0,

	/* Action. */
	.action_names = table_stub_actions,
	.n_actions = RTE_DIM(table_stub_actions),
	.default_action_name = "passthrough",
	.default_action_data = NULL,
	.default_action_is_const = 0,
};

/*
 * Pipeline.
 */
static const char *pipeline_instructions[] = {
	"rx m.port_in",
	"table stub",
	"tx m.port_in",
};

int
pipeline_setup_l2fwd(struct rte_swx_pipeline *p);

int
pipeline_setup_l2fwd(struct rte_swx_pipeline *p)
{
	int err;

	/*
	 * Packet headers.
	 */

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
		"passthrough",
		NULL,
		action_passthrough_instructions,
		RTE_DIM(action_passthrough_instructions));
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
