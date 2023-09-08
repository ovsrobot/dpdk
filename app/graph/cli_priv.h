/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_CLI_PRIV_H
#define APP_GRAPH_CLI_PRIV_H

#include "cli.h"

struct cli_node {
	STAILQ_ENTRY(cli_node) next;	 /**< Next node in the list. */
	char cmd[APP_CLI_CMD_NAME_SIZE]; /**< Name of the command. */
	cli_module_t process;		 /**< Command process function. */
	cli_module_t usage;		/**< Help command process function. */
};

STAILQ_HEAD(cli_node_head, cli_node);

#endif
