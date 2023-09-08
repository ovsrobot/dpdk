/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Marvell.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_bitops.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>

#include "ethdev_priv.h"
#include "module_api.h"

static const char
cmd_ethdev_mtu_help[] = "ethdev <ethdev_name> mtu <mtu_sz>";

static const char
cmd_ethdev_prom_mode_help[] = "ethdev <ethdev_name> promiscuous <on/off>";

static const char
cmd_ethdev_help[] = "ethdev <ethdev_name> rxq <n_queues> txq <n_queues> <mempool_name> "
		    "[mtu <mtu_sz>]";
static const char
cmd_ethdev_show_help[] = "ethdev <ethdev_name> show";

static const char
cmd_ethdev_ip4_addr_help[] = "ethdev <ethdev_name> ip4 addr add <ip> netmask <mask>";

static const char
cmd_ethdev_ip6_addr_help[] = "ethdev <ethdev_name> ip6 addr add <ip> netmask <mask>";

static struct rte_eth_conf port_conf_default = {
	.link_speeds = 0,
	.rxmode = {
		.mq_mode = RTE_ETH_MQ_RX_NONE,
		.mtu = 9000 - (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN), /* Jumbo frame MTU */
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_key_len = 40,
			.rss_hf = 0,
		},
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
	.lpbk_mode = 0,
};

uint32_t enabled_port_mask;
struct ethdev port_list[RTE_MAX_ETHPORTS];

void *
ethdev_mempool_list_by_portid(uint16_t portid)
{
	if (portid >= RTE_MAX_ETHPORTS)
		return NULL;

	return &port_list[portid].config.rx.mp;
}

int16_t
ethdev_portid_by_ip4(uint32_t ip)
{
	int portid = -EINVAL;
	int i;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if ((port_list[i].ip4_addr.ip & route4[i].netmask) == (ip & route4[i].netmask))
			break;
	}

	if (i == RTE_MAX_ETHPORTS)
		return portid;

	return port_list[i].config.port_id;
}

int16_t
ethdev_portid_by_ip6(uint8_t *ip)
{
	int portid = -EINVAL;
	int i, j;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		for (j = 0; j < ETHDEV_IPV6_ADDR_LEN; j++) {
			if ((port_list[i].ip6_addr.ip[j] & route6[i].mask[j]) !=
			    (ip[j] & route6[i].mask[j]))
				break;
		}

		if (j == ETHDEV_IPV6_ADDR_LEN)
			break;
	}

	if (i == RTE_MAX_ETHPORTS)
		return portid;

	return port_list[i].config.port_id;
}

void
ethdev_stop(void)
{
	uint16_t portid;
	int rc;

	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		printf("Closing port %d...", portid);
		rc = rte_eth_dev_stop(portid);
		if (rc != 0)
			printf("Failed to stop port %u: %s\n",
					portid, rte_strerror(-rc));
		rte_eth_dev_close(portid);
		printf(" Done\n");
	}

	/* clean up the EAL */
	rte_eal_cleanup();
	printf("Bye...\n");
}

void
ethdev_start(void)
{
	uint16_t portid;
	int rc;

	RTE_ETH_FOREACH_DEV(portid)
	{
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;

		rc = rte_eth_dev_start(portid);
		if (rc < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err=%d, port=%d\n", rc, portid);
	}
}


static int
ethdev_show(const char *name, char **out, size_t *out_size)
{
	uint16_t mtu = 0, port_id = 0;
	struct rte_eth_dev_info info;
	struct rte_eth_stats stats;
	struct rte_ether_addr addr;
	struct rte_eth_link link;
	uint32_t length;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc < 0)
		return rc;

	rte_eth_dev_info_get(port_id, &info);
	rte_eth_stats_get(port_id, &stats);
	rte_eth_macaddr_get(port_id, &addr);
	rte_eth_link_get(port_id, &link);
	rte_eth_dev_get_mtu(port_id, &mtu);

	snprintf(*out, *out_size,
		 "%s: flags=<%s> mtu %u\n"
		 "\tether " RTE_ETHER_ADDR_PRT_FMT " rxqueues %u txqueues %u\n"
		 "\tport# %u  speed %s\n"
		 "\tRX packets %" PRIu64"  bytes %" PRIu64"\n"
		 "\tRX errors %" PRIu64"  missed %" PRIu64"  no-mbuf %" PRIu64"\n"
		 "\tTX packets %" PRIu64"  bytes %" PRIu64"\n"
		 "\tTX errors %" PRIu64"\n\n",
		 name,
		 link.link_status ? "UP" : "DOWN",
		 mtu,
		 RTE_ETHER_ADDR_BYTES(&addr),
		 info.nb_rx_queues,
		 info.nb_tx_queues,
		 port_id,
		 rte_eth_link_speed_to_str(link.link_speed),
		 stats.ipackets,
		 stats.ibytes,
		 stats.ierrors,
		 stats.imissed,
		 stats.rx_nombuf,
		 stats.opackets,
		 stats.obytes,
		 stats.oerrors);

	length = strlen(*out);
	*out_size -= length;
	*out += length;
	return 0;
}

static int
ethdev_ip4_addr_add(const char *name, struct ipv4_addr_config *config)
{
	uint16_t portid = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	port_list[portid].ip4_addr.ip = config->ip;
	port_list[portid].ip4_addr.mask = config->mask;
	return 0;
}

static int
ethdev_ip6_addr_add(const char *name, struct ipv6_addr_config *config)
{
	uint16_t portid = 0;
	int rc, i;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	for (i = 0; i < ETHDEV_IPV6_ADDR_LEN; i++) {
		port_list[portid].ip6_addr.ip[i] = config->ip[i];
		port_list[portid].ip6_addr.mask[i] = config->mask[i];
	}

	return 0;
}

static int
ethdev_prom_mode_config(const char *name, bool enable)
{
	uint16_t portid = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	if (enable)
		rc = rte_eth_promiscuous_enable(portid);
	else
		rc = rte_eth_promiscuous_disable(portid);

	if (rc < 0)
		return rc;

	port_list[portid].config.promiscuous = enable;
	return 0;
}

static int
ethdev_mtu_config(const char *name, uint32_t mtu)
{
	uint16_t portid = 0;
	int rc;

	rc = rte_eth_dev_get_port_by_name(name, &portid);
	if (rc < 0)
		return rc;

	rc = rte_eth_dev_set_mtu(portid, mtu);
	if (rc < 0)
		return rc;

	port_list[portid].config.mtu = mtu;
	return 0;
}

static int
ethdev_process(const char *name, struct ethdev_config *params)
{
	struct rte_eth_dev_info port_info;
	struct rte_eth_conf port_conf;
	struct ethdev_rss_config *rss;
	struct rte_mempool *mempool;
	struct rte_ether_addr smac;
	int numa_node, rc;
	uint16_t port_id = 0;
	uint32_t i;

	/* Check input params */
	if (!name || !name[0] || !params || !params->rx.n_queues || !params->rx.queue_size ||
	    !params->tx.n_queues || !params->tx.queue_size)
		return -EINVAL;

	rc = rte_eth_dev_get_port_by_name(name, &port_id);
	if (rc)
		return -EINVAL;

	rc = rte_eth_dev_info_get(port_id, &port_info);
	if (rc)
		return -EINVAL;

	mempool = rte_mempool_lookup(params->rx.mempool_name);
	if (!mempool)
		return -EINVAL;

	params->rx.mp = mempool;

	rss = params->rx.rss;
	if (rss) {
		if (!port_info.reta_size || port_info.reta_size > RTE_ETH_RSS_RETA_SIZE_512)
			return -EINVAL;

		if (!rss->n_queues || rss->n_queues >= ETHDEV_RXQ_RSS_MAX)
			return -EINVAL;

		for (i = 0; i < rss->n_queues; i++)
			if (rss->queue_id[i] >= port_info.max_rx_queues)
				return -EINVAL;
	}

	/* Port */
	memcpy(&port_conf, &port_conf_default, sizeof(struct rte_eth_conf));
	if (rss) {
		uint64_t rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;

		port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_hf = rss_hf & port_info.flow_type_rss_offloads;
	}

	numa_node = rte_eth_dev_socket_id(port_id);
	if (numa_node == SOCKET_ID_ANY)
		numa_node = 0;

	if (params->mtu)
		port_conf.rxmode.mtu = params->mtu;

	rc = rte_eth_dev_configure(port_id, params->rx.n_queues, params->tx.n_queues,
				       &port_conf);
	if (rc < 0)
		return -EINVAL;

	rc = rte_eth_macaddr_get(port_id, &smac);
	if (rc < 0)
		return -EINVAL;

	printf("Port_id = %d srcmac = %x:%x:%x:%x:%x:%x\n", port_id,
		smac.addr_bytes[0], smac.addr_bytes[1],
		smac.addr_bytes[2], smac.addr_bytes[3],
		smac.addr_bytes[4], smac.addr_bytes[5]);

	/* Port RX */
	for (i = 0; i < params->rx.n_queues; i++) {
		rc = rte_eth_rx_queue_setup(port_id, i, params->rx.queue_size, numa_node, NULL,
			mempool);
		if (rc < 0)
			return -EINVAL;
	}

	/* Port TX */
	for (i = 0; i < params->tx.n_queues; i++) {
		rc = rte_eth_tx_queue_setup(port_id, i, params->tx.queue_size, numa_node, NULL);
		if (rc < 0)
			return -EINVAL;
	}

	memcpy(&port_list[port_id].config, params, sizeof(struct ethdev_config));
	memcpy(port_list[port_id].config.dev_name, name, strlen(name));
	port_list[port_id].config.port_id = port_id;
	enabled_port_mask |= RTE_BIT32(port_id);
	return 0;
}

static int
cmd_ethdev_mtu(char **tokens, uint32_t n_tokens __rte_unused, char *out, size_t out_size,
	       void *obj __rte_unused)
{
	int rc = -EINVAL;
	uint32_t mtu = 0;

	if (n_tokens != 4) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		return rc;
	}

	if (parser_uint32_read(&mtu, tokens[3]) != 0) {
		snprintf(out, out_size, MSG_ARG_INVALID, "mtu_sz");
		return rc;
	}

	rc = ethdev_mtu_config(tokens[1], mtu);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

	return rc;
}

static int
cmd_ethdev_prom_mode(char **tokens, uint32_t n_tokens __rte_unused, char *out, size_t out_size,
		     void *obj __rte_unused)
{
	bool enable = false;
	int rc = -EINVAL;

	if (n_tokens != 4) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		return rc;
	}

	if (strcmp(tokens[3], "on") == 0)
		enable = true;

	rc = ethdev_prom_mode_config(tokens[1], enable);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

	return rc;
}

static int
cmd_ip4_addr(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	struct ipv4_addr_config config;
	int rc = -EINVAL;

	if (n_tokens != 8) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (strcmp(tokens[3], "addr")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "addr");
		goto exit;
	}

	if (strcmp(tokens[4], "add")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "add");
		goto exit;
	}

	if (parser_ip4_read(&config.ip, tokens[5])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ip");
		goto exit;
	}

	if (strcmp(tokens[6], "netmask")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "netmask");
		goto exit;
	}

	if (parser_ip4_read(&config.mask, tokens[7])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "netmask");
		goto exit;
	}

	rc = ethdev_ip4_addr_add(tokens[1], &config);
	if (rc < 0)
		snprintf(out, out_size, MSG_ARG_INVALID, tokens[0]);

exit:
	return rc;
}

static int
cmd_ip6_addr(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	struct ipv6_addr_config config;
	int rc = -EINVAL;

	if (n_tokens != 8) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		goto exit;
	}

	if (strcmp(tokens[3], "addr")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "addr");
		goto exit;
	}

	if (strcmp(tokens[4], "add")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "add");
		goto exit;
	}

	if (parser_ip6_read(config.ip, tokens[5])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "ip");
		goto exit;
	}

	if (strcmp(tokens[6], "netmask")) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "netmask");
		goto exit;
	}

	if (parser_ip6_read(config.mask, tokens[7])) {
		snprintf(out, out_size, MSG_ARG_INVALID, "netmask");
		goto exit;
	}

	rc = ethdev_ip6_addr_add(tokens[1], &config);
	if (rc < 0)
		snprintf(out, out_size, MSG_ARG_INVALID, tokens[0]);

exit:
	return rc;
}

static int
cmd_ethdev_show(char **tokens, uint32_t n_tokens, char *out, size_t out_size,
	void *obj __rte_unused)
{
	int rc = -EINVAL;

	if (n_tokens != 3) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		return rc;
	}

	rc = ethdev_show(tokens[1], &out, &out_size);
	if (rc < 0)
		snprintf(out, out_size, MSG_ARG_INVALID, tokens[0]);

	return rc;
}

static int
cmd_ethdev(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj __rte_unused)
{
	struct ethdev_config config;
	char *name;
	int rc;

	if (n_tokens < 7) {
		snprintf(out, out_size, MSG_ARG_MISMATCH, tokens[0]);
		return -EINVAL;
	}

	memset(&config, 0, sizeof(struct ethdev_config));
	name = tokens[1];

	if (strcmp(tokens[2], "rxq") != 0) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "rxq");
		return -EINVAL;
	}

	if (parser_uint32_read(&config.rx.n_queues, tokens[3]) != 0) {
		snprintf(out, out_size, MSG_ARG_INVALID, "n_queues");
		return -EINVAL;
	}

	if (strcmp(tokens[4], "txq") != 0) {
		snprintf(out, out_size, MSG_ARG_NOT_FOUND, "txq");
		return -EINVAL;
	}

	if (parser_uint32_read(&config.tx.n_queues, tokens[5]) != 0) {
		snprintf(out, out_size, MSG_ARG_INVALID, "n_queues");
		return -EINVAL;
	}

	mempcpy(config.rx.mempool_name, tokens[6], strlen(tokens[6]));

	if (n_tokens > 7) {
		if (strcmp(tokens[7], "mtu") != 0) {
			snprintf(out, out_size, MSG_ARG_NOT_FOUND, "mtu");
			return -EINVAL;
		}

		if (parser_uint32_read(&config.mtu, tokens[8]) != 0) {
			snprintf(out, out_size, MSG_ARG_INVALID, "mtu_sz");
			return -EINVAL;
		}
	}

	config.tx.queue_size = ETHDEV_TX_DESC_DEFAULT;
	config.rx.queue_size = ETHDEV_RX_DESC_DEFAULT;

	rc = ethdev_process(name, &config);
	if (rc < 0)
		snprintf(out, out_size, MSG_CMD_FAIL, tokens[0]);

	return rc;
}

static int
cli_ethdev_help(char **tokens __rte_unused, uint32_t n_tokens __rte_unused, char *out,
		   size_t out_size, void *obj __rte_unused)
{
	size_t len;

	len = strlen(out);
	snprintf(out + len, out_size, "\n%s\n",
		 "----------------------------- ethdev command help -----------------------------");

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_ip4_addr_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_ip6_addr_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_prom_mode_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_mtu_help);

	len = strlen(out);
	snprintf(out + len, out_size, "%s\n", cmd_ethdev_show_help);

	return 0;
}

static int
cli_ethdev(char **tokens, uint32_t n_tokens, char *out, size_t out_size, void *obj)
{
	if (strcmp(tokens[2], "show") == 0)
		return cmd_ethdev_show(tokens, n_tokens, out, out_size, obj);
	else if (strcmp(tokens[2], "mtu") == 0)
		return cmd_ethdev_mtu(tokens, n_tokens, out, out_size, obj);
	else if (strcmp(tokens[2], "promiscuous") == 0)
		return cmd_ethdev_prom_mode(tokens, n_tokens, out, out_size, obj);
	else if (strcmp(tokens[2], "ip4") == 0)
		return cmd_ip4_addr(tokens, n_tokens, out, out_size, obj);
	else if (strcmp(tokens[2], "ip6") == 0)
		return cmd_ip6_addr(tokens, n_tokens, out, out_size, obj);
	else
		return cmd_ethdev(tokens, n_tokens, out, out_size, obj);
}

static struct cli_module ethdev = {
	.cmd = "ethdev",
	.process = cli_ethdev,
	.usage = cli_ethdev_help,
};

CLI_REGISTER(ethdev);
