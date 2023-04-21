/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <stdlib.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "cmdline_graph.h"
#include "testgraph.h"

/* *** Show supported node details *** */
struct cmd_show_node_list_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t node_list;
};

static cmdline_parse_token_string_t cmd_show_node_list_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_node_list_result, show, "show");
static cmdline_parse_token_string_t cmd_show_node_list_node_list =
	TOKEN_STRING_INITIALIZER(struct cmd_show_node_list_result, node_list, "node_list");

static void
cmd_show_node_list_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			  __rte_unused void *data)
{
	rte_node_t node_cnt = rte_node_max_count();
	rte_node_t id;

	printf("\n**** Supported Graph Nodes ****\n");
	for (id = 0; id < node_cnt; id++)
		printf("%s\n", rte_node_id_to_name(id));

	printf("********************************\n");
}

cmdline_parse_inst_t cmd_show_node_list = {
	.f = cmd_show_node_list_parsed,
	.data = NULL,
	.help_str = "show node_list",
	.tokens = {
			(void *)&cmd_show_node_list_show,
			(void *)&cmd_show_node_list_node_list,
			NULL,
		},
};

/* *** Set lcore config *** */
struct cmd_set_lcore_config_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t lcore_config;
	cmdline_multi_string_t token_string;
};

static cmdline_parse_token_string_t cmd_set_lcore_config_set =
	TOKEN_STRING_INITIALIZER(struct cmd_set_lcore_config_result, set, "set");
static cmdline_parse_token_string_t cmd_set_lcore_config_lcore_config =
	TOKEN_STRING_INITIALIZER(struct cmd_set_lcore_config_result, lcore_config, "lcore_config");
static cmdline_parse_token_string_t cmd_set_lcore_config_token_string = TOKEN_STRING_INITIALIZER(
	struct cmd_set_lcore_config_result, token_string, TOKEN_STRING_MULTI);

static void
cmd_set_lcore_config_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			    __rte_unused void *data)
{
	struct cmd_set_lcore_config_result *res = parsed_result;
	const char *t_str = res->token_string;
	int ret;

	/* Parse string */
	ret = parse_config(t_str);
	if (ret) {
		printf(" lcore_config string parse error\n");
		return;
	}

	validate_config();
}

cmdline_parse_inst_t cmd_set_lcore_config = {
	.f = cmd_set_lcore_config_parsed,
	.data = NULL,
	.help_str = "set lcore_config "
		    "(port,queue,lcore),[(port,queue,lcore) ... (port,queue,lcore)]",
	.tokens = {
			(void *)&cmd_set_lcore_config_set,
			(void *)&cmd_set_lcore_config_lcore_config,
			(void *)&cmd_set_lcore_config_token_string,
			NULL,
		},
};

/* *** Create graph *** */
struct cmd_create_graph_result {
	cmdline_fixed_string_t create_graph;
	cmdline_multi_string_t token_string;
};

static cmdline_parse_token_string_t cmd_create_graph_create_graph =
	TOKEN_STRING_INITIALIZER(struct cmd_create_graph_result, create_graph, "create_graph");
static cmdline_parse_token_string_t cmd_create_graph_token_string =
	TOKEN_STRING_INITIALIZER(struct cmd_create_graph_result, token_string, TOKEN_STRING_MULTI);

static void
cmd_create_graph_parsed(void *parsed_result, __rte_unused struct cmdline *cl,
			__rte_unused void *data)
{
	struct cmd_create_graph_result *res = parsed_result;
	const char *t_str = res->token_string;
	uint64_t valid_nodes = 0;
	int ret;

	ret = parse_node_patterns(t_str);
	if (ret) {
		printf("parse_node_patterns failed\n");
		cleanup_node_pattern();
		return;
	}

	ret = validate_node_names(&valid_nodes);
	if (ret) {
		printf("validate_node_names() failed\n");
		cleanup_node_pattern();
		return;
	}

	nb_conf = ethdev_ports_setup();

	ethdev_rxq_configure();
	ethdev_txq_configure();

	ret = configure_graph_nodes(valid_nodes);
	if (ret) {
		printf("configure_graph_nodes() failed\n");
		cleanup_node_pattern();
		return;
	}

	start_eth_ports();
	check_all_ports_link_status(enabled_port_mask);

	ret = create_graph(node_pattern, num_patterns);
	if (ret)
		rte_exit(EXIT_FAILURE, "create_graph: err=%d\n", ret);

	stats = create_graph_cluster_stats();
	if (stats == NULL)
		rte_exit(EXIT_FAILURE, "create_graph_cluster_stats() failed\n");
}

cmdline_parse_inst_t cmd_create_graph = {
	.f = cmd_create_graph_parsed,
	.data = NULL,
	.help_str = "create_graph "
		    "[node_name0,node_name1,node_name2 ... node_nameX]",
	.tokens = {
			(void *)&cmd_create_graph_create_graph,
			(void *)&cmd_create_graph_token_string,
			NULL,
		},
};

/**** Destroy graph ****/
struct cmd_destroy_graph_result {
	cmdline_fixed_string_t destroy_graph;
};

static cmdline_parse_token_string_t cmd_destroy_graph_destroy_graph =
	TOKEN_STRING_INITIALIZER(struct cmd_destroy_graph_result, destroy_graph, "destroy_graph");

static void
cmd_destroy_graph_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			 __rte_unused void *data)
{
	uint32_t lcore_id;

	run_graph_walk = false;
	graph_walk_quit = true;

	RTE_LCORE_FOREACH_WORKER(lcore_id)
		rte_eal_wait_lcore(lcore_id);

	destroy_graph();
	stop_eth_ports();
}

cmdline_parse_inst_t cmd_destroy_graph = {
	.f = cmd_destroy_graph_parsed,
	.data = NULL,
	.help_str = "destroy_graph",
	.tokens = {
			(void *)&cmd_destroy_graph_destroy_graph,
			NULL,
		},
};

/**** Start graph_walk ****/
struct cmd_start_graph_walk_result {
	cmdline_fixed_string_t start;
	cmdline_fixed_string_t graph_walk;
};

static cmdline_parse_token_string_t cmd_start_graph_walk_start =
	TOKEN_STRING_INITIALIZER(struct cmd_start_graph_walk_result, start, "start");
static cmdline_parse_token_string_t cmd_start_graph_walk_graph_walk =
	TOKEN_STRING_INITIALIZER(struct cmd_start_graph_walk_result, graph_walk, "graph_walk");

static void
cmd_start_graph_walk_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			    __rte_unused void *data)
{
	static bool launch_graph_walk;

	if (!launch_graph_walk) {
		rte_eal_mp_remote_launch(graph_main_loop, NULL, SKIP_MAIN);
		launch_graph_walk = true;
	}

	run_graph_walk = true;
}

cmdline_parse_inst_t cmd_start_graph_walk = {
	.f = cmd_start_graph_walk_parsed,
	.data = NULL,
	.help_str = "start graph_walk",
	.tokens = {
			(void *)&cmd_start_graph_walk_start,
			(void *)&cmd_start_graph_walk_graph_walk,
			NULL,
		},
};

/**** Stop graph_walk ****/
struct cmd_stop_graph_walk_result {
	cmdline_fixed_string_t stop;
	cmdline_fixed_string_t graph_walk;
};

static cmdline_parse_token_string_t cmd_stop_graph_walk_stop =
	TOKEN_STRING_INITIALIZER(struct cmd_stop_graph_walk_result, stop, "stop");
static cmdline_parse_token_string_t cmd_stop_graph_walk_graph_walk =
	TOKEN_STRING_INITIALIZER(struct cmd_stop_graph_walk_result, graph_walk, "graph_walk");

static void
cmd_stop_graph_walk_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			   __rte_unused void *data)
{
	run_graph_walk = false;
}

cmdline_parse_inst_t cmd_stop_graph_walk = {
	.f = cmd_stop_graph_walk_parsed,
	.data = NULL,
	.help_str = "stop graph_walk",
	.tokens = {
			(void *)&cmd_stop_graph_walk_stop,
			(void *)&cmd_stop_graph_walk_graph_walk,
			NULL,
		},
};

/**** Show graph_stats ****/
struct cmd_show_graph_stats_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t graph_stats;
};

static cmdline_parse_token_string_t cmd_show_graph_stats_show =
	TOKEN_STRING_INITIALIZER(struct cmd_show_graph_stats_result, show, "show");
static cmdline_parse_token_string_t cmd_show_graph_stats_graph_stats =
	TOKEN_STRING_INITIALIZER(struct cmd_show_graph_stats_result, graph_stats, "graph_stats");

static void
cmd_show_graph_stats_parsed(__rte_unused void *parsed_result, __rte_unused struct cmdline *cl,
			    __rte_unused void *data)
{
	if (rte_graph_has_stats_feature()) {
		if (stats)
			rte_graph_cluster_stats_get(stats, 0);
	} else {
		printf(" graph stats feature not enabled in rte_config.\n");
	}
}

cmdline_parse_inst_t cmd_show_graph_stats = {
	.f = cmd_show_graph_stats_parsed,
	.data = NULL,
	.help_str = "show graph_stats",
	.tokens = {
			(void *)&cmd_show_graph_stats_show,
			(void *)&cmd_show_graph_stats_graph_stats,
			NULL,
		},
};
