/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_node_ip4_api.h>

#include "module_api.h"

static const char
cmd_ipv4_lookup_help[] = "ipv4_lookup route add ipv4 <ip> netmask <mask> via <ip>";

struct ipv4_route_config route4[MAX_ROUTE_ENTRIES];

static uint8_t
convert_netmask_to_depth(uint32_t netmask)
{
	uint8_t zerobits = 0;

	while ((netmask & 0x1) == 0) {
		netmask = netmask >> 1;
		zerobits++;
	}

	return (32 - zerobits);
}

static int
route_ip4_add(struct ipv4_route_config *route)
{
	int i;

	for (i = 0; i < MAX_ROUTE_ENTRIES; i++) {
		if (!route4[i].is_used)
			break;
	}

	if (i == MAX_ROUTE_ENTRIES)
		return -ENOMEM;

	route4[i].ip = route->ip;
	route4[i].netmask = route->netmask;
	route4[i].via = route->via;
	route4[i].is_used = true;
	return 0;
}

int
route_ip4_add_to_lookup(void)
{
	struct ipv4_route_config *route = NULL;
	int rc = -EINVAL;
	uint8_t depth;
	int portid, i;

	for (i = 0; i < MAX_ROUTE_ENTRIES; i++) {
		if (route4[i].is_used)
			route = &route4[i];

		portid = ethdev_portid_by_ip4(route->via);
		if (portid < 0) {
			printf("Invalid portid found to install the route\n");
			return rc;
		}

		depth = convert_netmask_to_depth(route->netmask);

		rc = rte_node_ip4_route_add(route->ip, depth, portid,
					     RTE_NODE_IP4_LOOKUP_NEXT_REWRITE);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int
cli_ipv4_lookup_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		     size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "--------------------------- ipv4_lookup command help --------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ipv4_lookup_help);
	return 0;
}

static int
cli_ipv4_lookup(char **tokens, uint32_t n_tokens, char *out, size_t out_size,
		void *obj __rte_unused)
{
	struct ipv4_route_config config;
	int rc = -EINVAL;

	if (n_tokens != 9) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (parser_ip4_read(&config.ip, tokens[4])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ipv4");
		goto exit;
	}

	if (strcmp(tokens[5], "netmask")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "netmask");
		goto exit;
	}

	if (parser_ip4_read(&config.netmask, tokens[6])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "netmask");
		goto exit;
	}

	if (strcmp(tokens[7], "via")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "via");
		goto exit;
	}

	if (parser_ip4_read(&config.via, tokens[8])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "via ip");
		goto exit;
	}

	rc = route_ip4_add(&config);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static struct cli_module ipv4_lookup = {
	.cmd = "ipv4_lookup",
	.process = cli_ipv4_lookup,
	.usage = cli_ipv4_lookup_help,
};

CLI_REGISTER(ipv4_lookup);
