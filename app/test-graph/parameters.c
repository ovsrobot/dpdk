/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Marvell International Ltd.
 */

#include <getopt.h>
#include <stdlib.h>

#include "testgraph.h"

static const char short_options[] = "p:" /* portmask */
				    "P"	 /* promiscuous */
				    "i"	 /* interactive */
	;

#define CMD_LINE_OPT_CONFIG	   "config"
#define CMD_LINE_OPT_NODE_PATTERN  "node-pattern"
#define CMD_LINE_OPT_INTERACTIVE   "interactive"
#define CMD_LINE_OPT_NO_NUMA	   "no-numa"
#define CMD_LINE_OPT_PER_PORT_POOL "per-port-pool"
enum {
	/* Long options mapped to a short option */

	/* First long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_NODE_PATTERN_NUM,
	CMD_LINE_OPT_INTERACTIVE_NUM,
	CMD_LINE_OPT_NO_NUMA_NUM,
	CMD_LINE_OPT_PARSE_PER_PORT_POOL,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_NODE_PATTERN, 1, 0, CMD_LINE_OPT_NODE_PATTERN_NUM},
	{CMD_LINE_OPT_INTERACTIVE, 0, 0, CMD_LINE_OPT_INTERACTIVE_NUM},
	{CMD_LINE_OPT_NO_NUMA, 0, 0, CMD_LINE_OPT_NO_NUMA_NUM},
	{CMD_LINE_OPT_PER_PORT_POOL, 0, 0, CMD_LINE_OPT_PARSE_PER_PORT_POOL},
	{NULL, 0, 0, 0},
};

/* Display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr,
		"%s [EAL options] --"
		" -p PORTMASK"
		" [-P]"
		" [-i]"
		" --config (port,queue,lcore)[,(port,queue,lcore)]"
		" --node-pattern (node_name0,node_name1[,node_nameX)]"
		" [--no-numa]"
		" [--per-port-pool]"
		" [--interactive]"

		"  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  -i : Enter interactive mode\n"
		"  --config (port,queue,lcore): Rx queue configuration\n"
		"  --node-pattern (node_names): node patterns to create graph\n"
		"  --no-numa: Disable numa awareness\n"
		"  --per-port-pool: Use separate buffer pool per port\n"
		"  --interactive: Enter interactive mode\n",
		prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* Parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return 0;

	return pm;
}

/* Parse the argument given in the command line of the application */
int
parse_cmdline_args(int argc, char **argv)
{
	char *prgname = argv[0];
	int option_index;
	char **argvopt;
	int opt, ret;

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options, lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* Portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				fprintf(stderr, "Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;

		/* Long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				fprintf(stderr, "Invalid config\n");
				print_usage(prgname);
				return -1;
			}
			break;
		case CMD_LINE_OPT_NODE_PATTERN_NUM:
			ret = parse_node_patterns(optarg);
			if (ret) {
				fprintf(stderr, "Invalid node_patterns\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_INTERACTIVE_NUM:
		case 'i':
			printf("Interactive-mode selected\n");
			interactive = 1;
			break;

		case CMD_LINE_OPT_NO_NUMA_NUM:
			numa_on = 0;
			break;

		case CMD_LINE_OPT_PARSE_PER_PORT_POOL:
			printf("Per port buffer pool is enabled\n");
			per_port_pool = 1;
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind - 1] = prgname;
	ret = optind - 1;
	optind = 1; /* Reset getopt lib */

	return ret;
}
