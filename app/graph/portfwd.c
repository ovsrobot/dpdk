/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cmdline_parse.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline_socket.h>
#include <rte_ethdev.h>
#include <rte_node_ip4_api.h>

#include "module_api.h"
#include "portfwd_priv.h"

static const char
cmd_ethdev_l2fwd_help[] = "ethdev forward <tx_dev_name> <rx_dev_name>";

static struct prt_fw pfw = TAILQ_HEAD_INITIALIZER(pfw);

struct port_forwarding *
find_pf_entry_rx_port(uint16_t portid_rx)
{
	struct port_forwarding *port_fwd;

	TAILQ_FOREACH(port_fwd, &pfw, next) {
		if (port_fwd->rx_port == portid_rx)
			return port_fwd;
	}
	return NULL;
}

static struct port_forwarding *
find_l2_entry(uint16_t portid_tx, uint16_t portid_rx)
{
	struct port_forwarding *port_fwd;

	TAILQ_FOREACH(port_fwd, &pfw, next) {
		if ((port_fwd->tx_port == portid_tx) &&
				(port_fwd->rx_port == portid_rx))
			return port_fwd;
	}
	return NULL;
}

static int
ethdev_pfw_config(char *tx_name, char *rx_name)
{
	struct port_forwarding *pfwd;
	uint16_t portid_rx = 0;
	uint16_t portid_tx = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(tx_name, &portid_tx);
	if (rc < 0)
		return rc;

	rc = rte_eth_dev_get_port_by_name(rx_name, &portid_rx);
	if (rc < 0)
		return rc;

	pfwd = find_l2_entry(portid_tx, portid_rx);
	if (!pfwd) {
		pfwd = malloc(sizeof(struct port_forwarding));
		pfwd->tx_port = portid_tx;
		pfwd->rx_port = portid_rx;
		TAILQ_INSERT_TAIL(&pfw, pfwd, next);
		return 0;
	}

	return rc;
}

static void
cli_ethdev_forward(void *parsed_result, __rte_unused struct cmdline *cl, void *data __rte_unused)
{
	struct ethdev_fwd_cmd_tokens *res = parsed_result;
	int rc = -EINVAL;

	rc = ethdev_pfw_config(res->tx_dev, res->rx_dev);
	if (rc < 0)
		printf(MSG_CMD_FAIL, res->cmd);
}


cmdline_parse_token_string_t ethdev_l2_cmd =
	TOKEN_STRING_INITIALIZER(struct ethdev_fwd_cmd_tokens, cmd, "ethdev");
cmdline_parse_token_string_t ethdev_fwd_cmd =
	TOKEN_STRING_INITIALIZER(struct ethdev_fwd_cmd_tokens, fwd, "forward");
cmdline_parse_token_string_t ethdev_tx_device =
	TOKEN_STRING_INITIALIZER(struct ethdev_fwd_cmd_tokens, tx_dev, NULL);
cmdline_parse_token_string_t ethdev_rx_device =
	TOKEN_STRING_INITIALIZER(struct ethdev_fwd_cmd_tokens, rx_dev, NULL);

cmdline_parse_inst_t ethdev_forward_cmd_ctx = {
	.f = cli_ethdev_forward,
	.data = NULL,
	.help_str = cmd_ethdev_l2fwd_help,
	.tokens = {
		(void *)&ethdev_l2_cmd,
		(void *)&ethdev_fwd_cmd,
		(void *)&ethdev_tx_device,
		(void *)&ethdev_rx_device,
		NULL,
	},
};

