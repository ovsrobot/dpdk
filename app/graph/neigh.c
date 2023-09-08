/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_node_ip4_api.h>
#include <rte_node_ip6_api.h>

#include "neigh_priv.h"
#include "module_api.h"

static const char
cmd_neigh_v4_help[] = "neigh add ipv4 <ip> <mac>";

static const char
cmd_neigh_v6_help[] = "neigh add ipv6 <ip> <mac>";

struct ipv4_neigh_config neigh4[MAX_NEIGH_ENTRIES];
struct ipv6_neigh_config neigh6[MAX_NEIGH_ENTRIES];

static int
neigh_ip4_add(uint32_t ip, uint64_t mac)
{
	int i;

	for (i = 0; i < MAX_NEIGH_ENTRIES; i++) {
		if (!neigh4[i].is_used)
			break;
	}

	if (i == MAX_NEIGH_ENTRIES)
		return -ENOMEM;

	neigh4[i].ip = ip;
	neigh4[i].mac = mac;
	neigh4[i].is_used = true;
	return 0;
}

static int
neigh_ip6_add(uint8_t *ip, uint64_t mac)
{
	int i, j;

	for (i = 0; i < MAX_NEIGH_ENTRIES; i++) {
		if (!neigh6[i].is_used)
			break;
	}

	if (i == MAX_NEIGH_ENTRIES)
		return -ENOMEM;

	for (j = 0; j < ETHDEV_IPV6_ADDR_LEN; j++)
		neigh6[i].ip[j] = ip[j];

	neigh6[i].mac = mac;
	neigh6[i].is_used = true;
	return 0;
}

int
neigh_ip4_add_to_rewrite(void)
{
	uint8_t data[2 * RTE_ETHER_ADDR_LEN];
	uint8_t len = 2 * RTE_ETHER_ADDR_LEN;
	struct rte_ether_addr smac = {0};
	struct ipv4_neigh_config *neigh;
	int16_t portid = 0;
	int rc, i;

	for (i = 0; i < MAX_NEIGH_ENTRIES; i++) {
		if (!neigh4[i].is_used)
			continue;

		neigh = &neigh4[i];
		portid = ethdev_portid_by_ip4(neigh->ip);
		if (portid < 0) {
			printf("Invalid portid found to add  neigh\n");
			return -EINVAL;
		}

		memset(data, 0, len);

		/* Copy dst mac */
		rte_memcpy((void *)&data[0], (void *)&neigh->mac, RTE_ETHER_ADDR_LEN);

		/* Copy src mac */
		rc = rte_eth_macaddr_get(portid, &smac);
		if (rc < 0) {
			printf("Cannot get MAC address: err=%d, port=%d\n", rc, portid);
			return rc;
		}

		rte_memcpy(&data[RTE_ETHER_ADDR_LEN], smac.addr_bytes, RTE_ETHER_ADDR_LEN);

		rc = rte_node_ip4_rewrite_add(portid, data, len, portid);
		if (rc < 0) {
			printf("Error in writing rewrite data: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	return 0;
}

int
neigh_ip6_add_to_rewrite(void)
{
	uint8_t data[2 * RTE_ETHER_ADDR_LEN];
	uint8_t len = 2 * RTE_ETHER_ADDR_LEN;
	struct rte_ether_addr smac = {0};
	struct ipv6_neigh_config *neigh;
	int16_t portid = 0;
	int rc, i;

	for (i = 0; i < MAX_NEIGH_ENTRIES; i++) {
		if (!neigh6[i].is_used)
			continue;

		neigh = &neigh6[i];
		portid = ethdev_portid_by_ip6(neigh->ip);
		if (portid < 0) {
			printf("Invalid portid found to add neigh\n");
			return -EINVAL;
		}

		memset(data, 0, len);

		/* Copy dst mac */
		rte_memcpy((void *)&data[0], (void *)&neigh->mac, RTE_ETHER_ADDR_LEN);

		/* Copy src mac */
		rc = rte_eth_macaddr_get(portid, &smac);
		if (rc < 0) {
			printf("Cannot get MAC address: err=%d, port=%d\n",
				rc, portid);
			return rc;
		}

		rte_memcpy(&data[RTE_ETHER_ADDR_LEN], smac.addr_bytes, RTE_ETHER_ADDR_LEN);

		rc = rte_node_ip6_rewrite_add(portid, data, len, portid);
		if (rc < 0) {
			printf("Error in writing rewrite data: err=%d, port=%d\n", rc, portid);
			return rc;
		}
	}

	return 0;
}

static int
cmd_neigh_v4(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	int rc = -EINVAL;
	uint64_t mac;
	uint32_t ip;

	if (n_tokens != 5) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (strcmp(tokens[1], "add")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "add");
		goto exit;
	}

	if (strcmp(tokens[2], "ipv4")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "ipv4");
		goto exit;
	}

	if (parser_ip4_read(&ip, tokens[3])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ip");
		goto exit;
	}

	if (parser_mac_read(&mac, tokens[4])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "mac");
		goto exit;
	}

	rc = neigh_ip4_add(ip, mac);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static int
cmd_neigh_v6(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	uint8_t ip[ETHDEV_IPV6_ADDR_LEN];
	int rc = -EINVAL;
	uint64_t mac;

	if (n_tokens != 5) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (strcmp(tokens[1], "add")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "add");
		goto exit;
	}

	if (strcmp(tokens[2], "ipv6")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "ipv6");
		goto exit;
	}

	if (parser_ip6_read(ip, tokens[3])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ip");
		goto exit;
	}

	if (parser_mac_read(&mac, tokens[4])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "mac");
		goto exit;
	}

	rc = neigh_ip6_add(ip, mac);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static int
cli_neigh_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		     size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "----------------------------- neigh command help -----------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_neigh_v4_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_neigh_v6_help);
	return 0;
}

static int
cli_neigh(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj)
{
	if (strcmp(tokens[2], "ipv4") == 0)
		return cmd_neigh_v4(tokens, n_tokens, out, out_size, obj);
	else
		return cmd_neigh_v6(tokens, n_tokens, out, out_size, obj);
}

static struct cli_module neigh = {
	.cmd = "neigh",
	.process = cli_neigh,
	.usage = cli_neigh_help,
};

CLI_REGISTER(neigh);
