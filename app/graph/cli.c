/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include <rte_node_ip4_api.h>
#include <rte_node_ip6_api.h>

#include "cli_priv.h"
#include "module_api.h"

#define CMD_MAX_TOKENS 256
#define MAX_LINE_SIZE 2048

static struct cli_node_head module_list = STAILQ_HEAD_INITIALIZER(module_list);

#define PARSE_DELIMITER " \f\n\r\t\v"

static int
tokenize_string_parse(char *string, char *tokens[], uint32_t *n_tokens)
{
	uint32_t i;

	if ((string == NULL) ||
		(tokens == NULL) ||
		(*n_tokens < 1))
		return -EINVAL;

	for (i = 0; i < *n_tokens; i++) {
		tokens[i] = strtok_r(string, PARSE_DELIMITER, &string);
		if (tokens[i] == NULL)
			break;
	}

	if ((i == *n_tokens) && strtok_r(string, PARSE_DELIMITER, &string))
		return -E2BIG;

	*n_tokens = i;
	return 0;
}

static int
is_comment(char *in)
{
	if ((strlen(in) && index("!#%;", in[0])) ||
		(strncmp(in, "//", 2) == 0) ||
		(strncmp(in, "--", 2) == 0))
		return 1;

	return 0;
}

static bool
module_list_has_cmd_registered(const char *cmd)
{
	struct cli_node *node;

	STAILQ_FOREACH(node, &module_list, next) {
		if (strcmp(node->cmd, cmd) == 0) {
			rte_errno = EEXIST;
			return 1;
		}
	}
	return 0;
}

void
cli_module_register(const struct cli_module *module)
{
	struct cli_node *node;

	/* Check sanity */
	if (module == NULL || module->process == NULL) {
		rte_errno = EINVAL;
		return;
	}

	/* Check for duplicate name */
	if (module_list_has_cmd_registered(module->cmd)) {
		printf("module %s is already registered\n", module->cmd);
		return;
	}

	node = malloc(sizeof(struct cli_node));
	if (node == NULL) {
		rte_errno = ENOMEM;
		return;
	}

	/* Initialize the node */
	if (rte_strscpy(node->cmd, module->cmd, APP_CLI_CMD_NAME_SIZE) < 0) {
		free(node);
		return;
	}
	node->process = module->process;
	node->usage = module->usage;

	/* Add the node at tail */
	STAILQ_INSERT_TAIL(&module_list, node, next);
}

void
cli_process(char *in, char *out, size_t out_size, void *obj)
{
	char *tokens[CMD_MAX_TOKENS];
	struct cli_node *node;
	uint32_t n_tokens;
	int rc;

	if (is_comment(in))
		return;

	n_tokens = RTE_DIM(tokens);
	rc = tokenize_string_parse(in, tokens, &n_tokens);
	if (rc) {
		snprintf(out, out_size, MSG_ARG_TOO_MANY, "");
		return;
	}

	if (n_tokens == 0)
		return;

	if ((n_tokens == 1) && strcmp(tokens[0], "help") == 0) {
		STAILQ_FOREACH(node, &module_list, next) {
			node->usage(tokens, n_tokens, out, out_size, obj);
		}
		return;
	}

	if ((n_tokens >= 2) && strcmp(tokens[0], "help") == 0) {
		STAILQ_FOREACH(node, &module_list, next) {
			if (strcmp(node->cmd, tokens[1]) == 0) {
				node->usage(tokens, n_tokens, out, out_size, obj);
				return;
			}
		}
		snprintf(out, out_size, MSG_CMD_UNKNOWN, tokens[0]);
		return;
	}

	STAILQ_FOREACH(node, &module_list, next) {
		if (strcmp(node->cmd, tokens[0]) == 0) {
			rc = node->process(tokens, n_tokens, out, out_size, obj);
			if (rc < 0)
				snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

			return;
		}
	}

	snprintf(out, out_size, MSG_CMD_UNKNOWN, tokens[0]);
}

int
cli_script_process(const char *file_name, size_t msg_in_len_max, size_t msg_out_len_max, void *obj)
{
	char *msg_in = NULL, *msg_out = NULL;
	FILE *f = NULL;

	/* Check input arguments */
	if ((file_name == NULL) || (strlen(file_name) == 0) || (msg_in_len_max == 0) ||
	    (msg_out_len_max == 0))
		return -EINVAL;

	msg_in = malloc(msg_in_len_max + 1);
	msg_out = malloc(msg_out_len_max + 1);
	if ((msg_in == NULL) || (msg_out == NULL)) {
		free(msg_out);
		free(msg_in);
		return -ENOMEM;
	}

	/* Open input file */
	f = fopen(file_name, "r");
	if (f == NULL) {
		free(msg_out);
		free(msg_in);
		return -EIO;
	}

	/* Read file */
	while (1) {
		if (fgets(msg_in, msg_in_len_max + 1, f) == NULL)
			break;

		msg_out[0] = 0;

		cli_process(msg_in, msg_out, msg_out_len_max, obj);

		if (strlen(msg_out))
			printf("%s", msg_out);
	}

	/* Close file */
	fclose(f);
	free(msg_out);
	free(msg_in);
	return 0;
}
