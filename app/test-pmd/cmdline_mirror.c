/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <stdlib.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include <rte_ethdev.h>

#include "testpmd.h"
#include "cmdline_mirror.h"

/* *** Create MIRROR port Object *** */
struct cmd_create_port_mirror_result {
	cmdline_fixed_string_t create;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t mirror;
	uint16_t port_id;
	uint16_t target_id;
};

static cmdline_parse_token_string_t cmd_create_port_mirror_create =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_mirror_result, create, "create");
static cmdline_parse_token_string_t cmd_create_port_mirror_port =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_mirror_result, port, "port");
static cmdline_parse_token_string_t cmd_create_port_mirror_mirror =
	TOKEN_STRING_INITIALIZER(struct cmd_create_port_mirror_result, mirror, "mirror");
static cmdline_parse_token_num_t cmd_create_port_mirror_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_create_port_mirror_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_create_port_mirror_target_id =
	TOKEN_NUM_INITIALIZER(struct cmd_create_port_mirror_result, target_id, RTE_UINT16);

static void cmd_create_port_mirror_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	const struct cmd_create_port_mirror_result *res = parsed_result;
	/* TODO these should be set by command */
	struct rte_eth_mirror_conf mirror_conf = {
		.flags = RTE_ETH_MIRROR_DIRECTION_INGRESS | RTE_ETH_MIRROR_DIRECTION_EGRESS
	};
	int ret;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	if (port_id_is_invalid(res->target_id, ENABLED_WARN))
		return;

	mirror_conf.target = res->target_id;

	ret = rte_eth_add_mirror(res->port_id,  &mirror_conf);
	if (ret != 0)
		fprintf(stderr, "%s\n", rte_strerror(-ret));
}

cmdline_parse_inst_t cmd_create_port_mirror = {
	.f = cmd_create_port_mirror_parsed,
	.data = NULL,
	.help_str = "create port mirror <port_id> <target_id>",
	.tokens = {
		(void *)&cmd_create_port_mirror_create,
		(void *)&cmd_create_port_mirror_port,
		(void *)&cmd_create_port_mirror_mirror,
		(void *)&cmd_create_port_mirror_port_id,
		(void *)&cmd_create_port_mirror_target_id,
		NULL
	},
};

/* *** Delete Port Mirror Object *** */
struct cmd_delete_port_mirror_result {
	cmdline_fixed_string_t delete;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t mirror;
	uint16_t port_id;
	uint16_t target_id;
};

static void cmd_delete_port_mirror_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	const struct cmd_delete_port_mirror_result *res = parsed_result;
	int ret;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	ret = rte_eth_remove_mirror(res->port_id, res->target_id);
	if (ret != 0)
		fprintf(stderr, "%s\n", rte_strerror(-ret));
}

static cmdline_parse_token_string_t cmd_delete_port_mirror_delete =
	TOKEN_STRING_INITIALIZER(struct cmd_delete_port_mirror_result, delete, "delete");
static cmdline_parse_token_string_t cmd_delete_port_mirror_port =
	TOKEN_STRING_INITIALIZER(struct cmd_delete_port_mirror_result, port, "port");
static cmdline_parse_token_string_t cmd_delete_port_mirror_mirror =
	TOKEN_STRING_INITIALIZER(struct cmd_delete_port_mirror_result, mirror, "mirror");
static cmdline_parse_token_num_t cmd_delete_port_mirror_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_delete_port_mirror_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_delete_port_mirror_target_id =
	TOKEN_NUM_INITIALIZER(struct cmd_delete_port_mirror_result, target_id, RTE_UINT16);

cmdline_parse_inst_t cmd_delete_port_mirror = {
	.f = cmd_delete_port_mirror_parsed,
	.data = NULL,
	.help_str = "delete port mirror <port_id> <target_id>",
	.tokens = {
		(void *)&cmd_delete_port_mirror_delete,
		(void *)&cmd_delete_port_mirror_port,
		(void *)&cmd_delete_port_mirror_mirror,
		(void *)&cmd_delete_port_mirror_port_id,
		(void *)&cmd_delete_port_mirror_target_id,
		NULL
	},
};

/* *** Show Port Mirror Stats *** */
struct cmd_show_port_mirror_stats_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t mirror;
	cmdline_fixed_string_t stats;
	uint16_t port_id;
	uint32_t target_id;
};

static cmdline_parse_token_string_t cmd_show_port_mirror_stats_show =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, show, "show");
static cmdline_parse_token_string_t cmd_show_port_mirror_stats_port =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, port, "port");
static cmdline_parse_token_string_t cmd_show_port_mirror_stats_mirror =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, mirror, "mirror");
static cmdline_parse_token_string_t cmd_show_port_mirror_stats_stats =
	TOKEN_STRING_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, stats, "stats");
static cmdline_parse_token_num_t cmd_show_port_mirror_stats_port_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_show_port_mirror_stats_target_id =
	TOKEN_NUM_INITIALIZER(
		struct cmd_show_port_mirror_stats_result, target_id, RTE_UINT32);

static void cmd_show_port_mirror_stats_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl,
	__rte_unused void *data)
{
	struct cmd_show_port_mirror_stats_result *res = parsed_result;
	struct rte_eth_mirror_stats stats;
	uint32_t target_id = res->target_id;
	uint16_t port_id = res->port_id;
	int ret;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;

	if (port_id_is_invalid(target_id, ENABLED_WARN))
		return;

	ret = rte_eth_mirror_stats_get(port_id, target_id, &stats);
	if (ret != 0) {
		fprintf(stderr,
			"%s: Error failed to get stats for mirror from %u to %u: %d\n",
			__func__, port_id, target_id, ret);
		return;
	}

	printf("Packets: %" PRIu64 "\n", stats.packets);
	printf("No mbuf: %" PRIu64 "\n", stats.nombuf);
	printf("Tx Full: %" PRIu64 "\n", stats.full);
}

cmdline_parse_inst_t cmd_show_port_mirror_stats = {
	.f = cmd_show_port_mirror_stats_parsed,
	.data = NULL,
	.help_str = "show port mirror stats <port_id> <target_id>",
	.tokens = {
		(void *)&cmd_show_port_mirror_stats_show,
		(void *)&cmd_show_port_mirror_stats_port,
		(void *)&cmd_show_port_mirror_stats_mirror,
		(void *)&cmd_show_port_mirror_stats_stats,
		(void *)&cmd_show_port_mirror_stats_port_id,
		(void *)&cmd_show_port_mirror_stats_target_id,
		NULL
	},
};
