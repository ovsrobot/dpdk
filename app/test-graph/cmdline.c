/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <stdlib.h>

#include <cmdline.h>
#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_rdline.h>
#include <cmdline_socket.h>

#include "cmdline_graph.h"
#include "testgraph.h"

static struct cmdline *testgraph_cl;
static cmdline_parse_ctx_t *main_ctx;

/* *** Help command with introduction. *** */
struct cmd_help_brief_result {
	cmdline_fixed_string_t help;
};

static void
cmd_help_brief_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_printf(cl,
		       "\n"
		       "Help is available for the following sections:\n\n"
		       "    help control                    : Start and stop graph walk.\n"
		       "    help display                    : Displaying port, stats and config "
		       "information.\n"
		       "    help config                     : Configuration information.\n"
		       "    help all                        : All of the above sections.\n\n");
}

static cmdline_parse_token_string_t cmd_help_brief_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_brief_result, help, "help");

static cmdline_parse_inst_t cmd_help_brief = {
	.f = cmd_help_brief_parsed,
	.data = NULL,
	.help_str = "help: Show help",
	.tokens = {
			(void *)&cmd_help_brief_help,
			NULL,
		},
};

/* *** Help command with help sections. *** */
struct cmd_help_long_result {
	cmdline_fixed_string_t help;
	cmdline_fixed_string_t section;
};

static void
cmd_help_long_parsed(void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	int show_all = 0;
	struct cmd_help_long_result *res = parsed_result;

	if (!strcmp(res->section, "all"))
		show_all = 1;

	if (show_all || !strcmp(res->section, "control")) {

		cmdline_printf(cl, "\n"
				   "Control forwarding:\n"
				   "-------------------\n\n"

				   "start graph_walk\n"
				   " Start graph_walk on worker threads.\n\n"

				   "stop graph_walk\n"
				   " Stop worker threads from running graph_walk.\n\n"

				   "quit\n"
				   "    Quit to prompt.\n\n");
	}

	if (show_all || !strcmp(res->section, "display")) {

		cmdline_printf(cl,
			       "\n"
			       "Display:\n"
			       "--------\n\n"

			       "show node_list\n"
			       " Display the list of supported nodes.\n\n"

			       "show graph_stats\n"
			       " Display the node statistics of graph cluster.\n\n");
	}

	if (show_all || !strcmp(res->section, "config")) {
		cmdline_printf(cl, "\n"
				   "Configuration:\n"
				   "--------------\n"
				   "set lcore_config (port_id0,rxq0,lcore_idX),..."
				   ".....,(port_idX,rxqX,lcoreidY)\n"
				   " Set lcore configuration.\n\n"

				   "create_graph (node0_name,node1_name,...,nodeX_name)\n"
				   " Create graph instances using the provided node details.\n\n"

				   "destroy_graph\n"
				   " Destroy the graph instances.\n\n");
	}
}

static cmdline_parse_token_string_t cmd_help_long_help =
	TOKEN_STRING_INITIALIZER(struct cmd_help_long_result, help, "help");

static cmdline_parse_token_string_t cmd_help_long_section = TOKEN_STRING_INITIALIZER(
	struct cmd_help_long_result, section, "all#control#display#config");

static cmdline_parse_inst_t cmd_help_long = {
	.f = cmd_help_long_parsed,
	.data = NULL,
	.help_str = "help all|control|display|config: "
		    "Show help",
	.tokens = {
			(void *)&cmd_help_long_help,
			(void *)&cmd_help_long_section,
			NULL,
		},
};

/* *** QUIT *** */
struct cmd_quit_result {
	cmdline_fixed_string_t quit;
};

static void
cmd_quit_parsed(__rte_unused void *parsed_result, struct cmdline *cl, __rte_unused void *data)
{
	cmdline_quit(cl);
}

static cmdline_parse_token_string_t cmd_quit_quit =
	TOKEN_STRING_INITIALIZER(struct cmd_quit_result, quit, "quit");

static cmdline_parse_inst_t cmd_quit = {
	.f = cmd_quit_parsed,
	.data = NULL,
	.help_str = "quit: Exit application",
	.tokens = {
			(void *)&cmd_quit_quit,
			NULL,
		},
};

/* list of instructions */
static cmdline_parse_ctx_t builtin_ctx[] = {
	(cmdline_parse_inst_t *)&cmd_help_brief,
	(cmdline_parse_inst_t *)&cmd_help_long,
	(cmdline_parse_inst_t *)&cmd_quit,
	(cmdline_parse_inst_t *)&cmd_show_node_list,
	(cmdline_parse_inst_t *)&cmd_set_lcore_config,
	(cmdline_parse_inst_t *)&cmd_create_graph,
	(cmdline_parse_inst_t *)&cmd_destroy_graph,
	(cmdline_parse_inst_t *)&cmd_start_graph_walk,
	(cmdline_parse_inst_t *)&cmd_stop_graph_walk,
	(cmdline_parse_inst_t *)&cmd_show_graph_stats,
	NULL,
};

int
init_cmdline(void)
{
	unsigned int count;
	unsigned int i;

	count = 0;
	for (i = 0; builtin_ctx[i] != NULL; i++)
		count++;

	/* cmdline expects a NULL terminated array */
	main_ctx = calloc(count + 1, sizeof(main_ctx[0]));
	if (main_ctx == NULL)
		return -1;

	count = 0;
	for (i = 0; builtin_ctx[i] != NULL; i++, count++)
		main_ctx[count] = builtin_ctx[i];

	return 0;
}

void
prompt_exit(void)
{
	cmdline_quit(testgraph_cl);
}

/* prompt function, called from main on MAIN lcore */
void
prompt(void)
{
	testgraph_cl = cmdline_stdin_new(main_ctx, "testgraph> ");
	if (testgraph_cl == NULL) {
		fprintf(stderr, "Failed to create stdin based cmdline context\n");
		return;
	}

	cmdline_interact(testgraph_cl);
	cmdline_stdin_exit(testgraph_cl);
}
