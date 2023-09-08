/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_node_ip6_api.h>

#include "module_api.h"

static const char
cmd_ipv6_lookup_help[] = "ipv6_lookup route add ipv6 <ip> netmask <mask> via <ip>";

struct ipv6_route_config route6[MAX_ROUTE_ENTRIES];

static uint8_t
convert_ip6_netmask_to_depth(uint8_t *netmask)
{
	uint8_t setbits = 0;
	uint8_t mask;
	int i;

	for (i = 0; i < ETHDEV_IPV6_ADDR_LEN; i++) {
		mask = netmask[i];
		while (mask & 0x80) {
			mask = mask << 1;
			setbits++;
		}
	}

	return setbits;
}

static int
route_ip6_add(struct ipv6_route_config *route)
{
	int i, j;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!route6[i].is_used)
			break;
	}

	if (i == RTE_MAX_ETHPORTS)
		return -ENOMEM;

	for (j = 0; j < ETHDEV_IPV6_ADDR_LEN; j++) {
		route6[i].ip[j] = route->ip[j];
		route6[i].mask[j] = route->mask[j];
		route6[i].gateway[j] = route->gateway[j];
	}
	route6[i].is_used = true;

	return 0;
}

int
route_ip6_add_to_lookup(void)
{
	struct ipv6_route_config *route = NULL;
	int rc = -EINVAL;
	uint8_t depth;
	int portid, i;

	for (i = 0; i < MAX_ROUTE_ENTRIES; i++) {
		if (route6[i].is_used)
			route = &route6[i];

		portid = ethdev_portid_by_ip6(route->gateway);
		if (portid < 0) {
			printf("Invalid portid found to install the route\n");
			return rc;
		}

		depth = convert_ip6_netmask_to_depth(route->mask);

		rc = rte_node_ip6_route_add(route->ip, depth, portid,
					     RTE_NODE_IP6_LOOKUP_NEXT_REWRITE);
		if (rc < 0)
			return rc;
	}

	return 0;
}

static int
cli_ipv6_lookup_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		     size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "--------------------------- ipv6_lookup command help --------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ipv6_lookup_help);
	return 0;
}

static int
cli_ipv6_lookup(char **tokens, uint32_t n_tokens, char *out, size_t out_size,
		void *obj __rte_unused)
{
	struct ipv6_route_config config;
	int rc = -EINVAL;

	if (n_tokens != 9) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (parser_ip6_read(config.ip, tokens[4])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ipv6");
		goto exit;
	}

	if (strcmp(tokens[5], "netmask")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "netmask");
		goto exit;
	}

	if (parser_ip6_read(config.mask, tokens[6])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "netmask");
		goto exit;
	}

	if (strcmp(tokens[7], "via")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "via");
		goto exit;
	}

	if (parser_ip6_read(config.gateway, tokens[8])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "gateway ip");
		goto exit;
	}

	rc = route_ip6_add(&config);
	if (rc)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static struct cli_module ipv6_lookup = {
	.cmd = "ipv6_lookup",
	.process = cli_ipv6_lookup,
	.usage = cli_ipv6_lookup_help,
};

CLI_REGISTER(ipv6_lookup);
