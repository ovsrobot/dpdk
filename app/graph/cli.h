/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#ifndef APP_GRAPH_CLI_H
#define APP_GRAPH_CLI_H

/* Macros */
#define MSG_OUT_OF_MEMORY   "Not enough memory.\n"
#define MSG_CMD_UNKNOWN     "Unknown command \"%s\".\n"
#define MSG_CMD_UNIMPLEM    "Command \"%s\" not implemented.\n"
#define MSG_ARG_NOT_ENOUGH  "Not enough arguments for command \"%s\".\n"
#define MSG_ARG_TOO_MANY    "Too many arguments for command \"%s\".\n"
#define MSG_ARG_MISMATCH    "Wrong number of arguments for command \"%s\".\n"
#define MSG_ARG_NOT_FOUND   "Argument \"%s\" not found.\n"
#define MSG_ARG_INVALID     "Invalid value for argument \"%s\".\n"
#define MSG_FILE_ERR        "Error in file \"%s\" at line %u.\n"
#define MSG_FILE_NOT_ENOUGH "Not enough rules in file \"%s\".\n"
#define MSG_CMD_FAIL        "Command \"%s\" failed.\n"

#define APP_CLI_CMD_NAME_SIZE	64

/* Typedefs */
typedef int (*cli_module_t)(char **tokens, uint32_t n_tokens, char *out, size_t out_size,
			     void *obj);

/* Structures */
struct cli_module {
	char cmd[APP_CLI_CMD_NAME_SIZE]; /**< Name of the command to be registered. */
	cli_module_t process; /**< Command process function. */
	cli_module_t usage; /**< Help command process function. */
};

/* APIs */
void cli_module_register(const struct cli_module *module);

#define CLI_REGISTER(module)			\
	RTE_INIT(cli_register_##module)		\
	{					\
		cli_module_register(&module);	\
	}

void cli_process(char *in, char *out, size_t out_size, void *arg);

int cli_script_process(const char *file_name, size_t msg_in_len_max, size_t msg_out_len_max,
		       void *arg);

#endif
