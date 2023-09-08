/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdlib.h>
#include <string.h>

#include <rte_ethdev.h>

#include "ethdev_rx_priv.h"
#include "module_api.h"

static const char
cmd_ethdev_rx_help[] = "ethdev_rx map port <ethdev_name> queue <q_num> core <core_id>";

static struct lcore_params lcore_params_array[ETHDEV_RX_LCORE_PARAMS_MAX];
struct rte_node_ethdev_config ethdev_conf[RTE_MAX_ETHPORTS];
struct lcore_params *lcore_params = lcore_params_array;
struct lcore_conf lcore_conf[RTE_MAX_LCORE];
uint16_t nb_lcore_params;

static void
rx_map_configure(uint8_t port_id, uint32_t queue, uint32_t core)
{
	uint8_t n_rx_queue;

	n_rx_queue = lcore_conf[core].n_rx_queue;
	lcore_conf[core].rx_queue_list[n_rx_queue].port_id = port_id;
	lcore_conf[core].rx_queue_list[n_rx_queue].queue_id = queue;
	lcore_conf[core].n_rx_queue++;
}

uint8_t
ethdev_rx_num_rx_queues_get(uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue + 1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE,
					 "Queue ids of the port %d must be"
					 " in sequence and must start with 0\n",
					 lcore_params[i].port_id);
		}
	}

	return (uint8_t)(++queue);
}

static int
ethdev_rx_map_add(char *name, uint32_t queue, uint32_t core)
{
	uint16_t port_id;
	int rc;

	if (nb_lcore_params >= ETHDEV_RX_LCORE_PARAMS_MAX)
		return -EINVAL;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc)
		return -EINVAL;

	rx_map_configure(port_id, queue, core);

	lcore_params_array[nb_lcore_params].port_id = port_id;
	lcore_params_array[nb_lcore_params].queue_id = queue;
	lcore_params_array[nb_lcore_params].lcore_id = core;
	nb_lcore_params++;
	return 0;
}

static int
cli_ethdev_rx_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		   size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "---------------------------- ethdev_rx command help ---------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_rx_help);
	return 0;
}

static int
cli_ethdev_rx(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	char name[RTE_ETH_NAME_MAX_LEN];
	uint32_t core_id, queue;
	int rc = -EINVAL;

	if (n_tokens != 8) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	strcpy(name, tokens[3]);

	if (strcmp(tokens[4], "queue") != 0) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "rxq");
		goto exit;
	}

	if (parser_uint32_read(&queue, tokens[5]) != 0) {
		snprintf(out, out_size, MSG_ARG_INVALID, "queue");
		goto exit;
	}

	if (strcmp(tokens[6], "core") != 0) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "core_id");
		goto exit;
	}

	if (parser_uint32_read(&core_id, tokens[7]) != 0) {
		snprintf(out, out_size, MSG_ARG_INVALID, "queue");
		goto exit;
	}

	rc = ethdev_rx_map_add(name, queue, core_id);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

exit:
	return rc;
}

static struct cli_module ethdev_rx = {
	.cmd = "ethdev_rx",
	.process = cli_ethdev_rx,
	.usage = cli_ethdev_rx_help,
};

CLI_REGISTER(ethdev_rx);
