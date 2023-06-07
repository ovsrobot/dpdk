/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2017 Intel Corporation
 */
#include <ctype.h>
#include <stdlib.h>

#include <rte_kvargs.h>
#include <rte_telemetry.h>

#include "rte_ethdev.h"
#include "ethdev_driver.h"
#include "sff_telemetry.h"

static int
eth_dev_parse_port_params(const char *params __rte_unused, uint16_t *port_id,
		char **end_param, bool has_next)
{
	uint64_t pi;

	if (params == NULL || strlen(params) == 0 ||
		!isdigit(*params) || port_id == NULL)
		return -EINVAL;

	pi = strtoul(params, end_param, 0);
	if (**end_param != '\0' && !has_next)
		RTE_ETHDEV_LOG(NOTICE,
			"Extra parameters passed to ethdev telemetry command, ignoring\n");

	if (pi >= UINT16_MAX || !rte_eth_dev_is_valid_port(pi))
		return -EINVAL;

	*port_id = pi;

	return 0;
}

static int
eth_dev_handle_port_list(const char *cmd __rte_unused,
		const char *params __rte_unused,
		struct rte_tel_data *d)
{
	int port_id;

	rte_tel_data_start_array(d, RTE_TEL_INT_VAL);
	RTE_ETH_FOREACH_DEV(port_id)
		rte_tel_data_add_array_int(d, port_id);
	return 0;
}

static void
eth_dev_add_port_queue_stats(struct rte_tel_data *d, uint64_t *q_stats,
		const char *stat_name)
{
	int q;
	struct rte_tel_data *q_data = rte_tel_data_alloc();
	if (q_data == NULL)
		return;
	rte_tel_data_start_array(q_data, RTE_TEL_UINT_VAL);
	for (q = 0; q < RTE_ETHDEV_QUEUE_STAT_CNTRS; q++)
		rte_tel_data_add_array_uint(q_data, q_stats[q]);
	rte_tel_data_add_dict_container(d, stat_name, q_data, 0);
}

static int
eth_dev_parse_hide_zero(const char *key, const char *value, void *extra_args)
{
	RTE_SET_USED(key);

	if (value == NULL)
		return -1;

	if (strcmp(value, "true") == 0)
		*(bool *)extra_args = true;
	else if (strcmp(value, "false") == 0)
		*(bool *)extra_args = false;
	else
		return -1;

	return 0;
}

#define ADD_DICT_STAT(stats, s) rte_tel_data_add_dict_uint(d, #s, stats.s)

static int
eth_dev_handle_port_stats(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	struct rte_eth_stats stats;
	uint16_t port_id;
	char *end_param;
	int ret;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	ret = rte_eth_stats_get(port_id, &stats);
	if (ret < 0)
		return -1;

	rte_tel_data_start_dict(d);
	ADD_DICT_STAT(stats, ipackets);
	ADD_DICT_STAT(stats, opackets);
	ADD_DICT_STAT(stats, ibytes);
	ADD_DICT_STAT(stats, obytes);
	ADD_DICT_STAT(stats, imissed);
	ADD_DICT_STAT(stats, ierrors);
	ADD_DICT_STAT(stats, oerrors);
	ADD_DICT_STAT(stats, rx_nombuf);
	eth_dev_add_port_queue_stats(d, stats.q_ipackets, "q_ipackets");
	eth_dev_add_port_queue_stats(d, stats.q_opackets, "q_opackets");
	eth_dev_add_port_queue_stats(d, stats.q_ibytes, "q_ibytes");
	eth_dev_add_port_queue_stats(d, stats.q_obytes, "q_obytes");
	eth_dev_add_port_queue_stats(d, stats.q_errors, "q_errors");

	return 0;
}

static int
eth_dev_handle_port_xstats(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	const char *const valid_keys[] = { "hide_zero", NULL };
	struct rte_eth_xstat *eth_xstats;
	struct rte_eth_xstat_name *xstat_names;
	struct rte_kvargs *kvlist;
	bool hide_zero = false;
	uint16_t port_id;
	char *end_param;
	int num_xstats;
	int i, ret;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, true);
	if (ret < 0)
		return ret;

	if (*end_param != '\0') {
		kvlist = rte_kvargs_parse(end_param, valid_keys);
		ret = rte_kvargs_process(kvlist, NULL, eth_dev_parse_hide_zero, &hide_zero);
		if (kvlist == NULL || ret != 0)
			RTE_ETHDEV_LOG(NOTICE,
				"Unknown extra parameters passed to ethdev telemetry command, ignoring\n");
		rte_kvargs_free(kvlist);
	}

	num_xstats = rte_eth_xstats_get(port_id, NULL, 0);
	if (num_xstats < 0)
		return -1;

	/* use one malloc for both names and stats */
	eth_xstats = malloc((sizeof(struct rte_eth_xstat) +
			sizeof(struct rte_eth_xstat_name)) * num_xstats);
	if (eth_xstats == NULL)
		return -1;
	xstat_names = (void *)&eth_xstats[num_xstats];

	ret = rte_eth_xstats_get_names(port_id, xstat_names, num_xstats);
	if (ret < 0 || ret > num_xstats) {
		free(eth_xstats);
		return -1;
	}

	ret = rte_eth_xstats_get(port_id, eth_xstats, num_xstats);
	if (ret < 0 || ret > num_xstats) {
		free(eth_xstats);
		return -1;
	}

	rte_tel_data_start_dict(d);
	for (i = 0; i < num_xstats; i++) {
		if (hide_zero && eth_xstats[i].value == 0)
			continue;
		rte_tel_data_add_dict_uint(d, xstat_names[i].name,
					   eth_xstats[i].value);
	}
	free(eth_xstats);
	return 0;
}

#ifndef RTE_EXEC_ENV_WINDOWS
static int
eth_dev_handle_port_dump_priv(const char *cmd __rte_unused,
			const char *params,
			struct rte_tel_data *d)
{
	char *buf, *end_param;
	uint16_t port_id;
	int ret;
	FILE *f;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	buf = calloc(RTE_TEL_MAX_SINGLE_STRING_LEN, sizeof(char));
	if (buf == NULL)
		return -ENOMEM;

	f = fmemopen(buf, RTE_TEL_MAX_SINGLE_STRING_LEN - 1, "w+");
	if (f == NULL) {
		free(buf);
		return -EINVAL;
	}

	ret = rte_eth_dev_priv_dump(port_id, f);
	fclose(f);
	if (ret == 0) {
		rte_tel_data_start_dict(d);
		rte_tel_data_string(d, buf);
	}

	free(buf);
	return 0;
}
#endif /* !RTE_EXEC_ENV_WINDOWS */

static int
eth_dev_handle_port_link_status(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	static const char *status_str = "status";
	struct rte_eth_link link;
	uint16_t port_id;
	char *end_param;
	int ret;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	ret = rte_eth_link_get_nowait(port_id, &link);
	if (ret < 0)
		return -1;

	rte_tel_data_start_dict(d);
	if (!link.link_status) {
		rte_tel_data_add_dict_string(d, status_str, "DOWN");
		return 0;
	}
	rte_tel_data_add_dict_string(d, status_str, "UP");
	rte_tel_data_add_dict_uint(d, "speed", link.link_speed);
	rte_tel_data_add_dict_string(d, "duplex",
			(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
				"full-duplex" : "half-duplex");
	return 0;
}

static void
eth_dev_parse_rx_offloads(uint64_t offload, struct rte_tel_data *d)
{
	uint64_t i;

	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);
	for (i = 0; i < CHAR_BIT * sizeof(offload); i++) {
		if ((offload & RTE_BIT64(i)) != 0)
			rte_tel_data_add_array_string(d,
				rte_eth_dev_rx_offload_name(offload & RTE_BIT64(i)));
	}
}

static void
eth_dev_parse_tx_offloads(uint64_t offload, struct rte_tel_data *d)
{
	uint64_t i;

	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);
	for (i = 0; i < CHAR_BIT * sizeof(offload); i++) {
		if ((offload & RTE_BIT64(i)) != 0)
			rte_tel_data_add_array_string(d,
				rte_eth_dev_tx_offload_name(offload & RTE_BIT64(i)));
	}
}

static int
eth_dev_handle_port_info(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	struct rte_tel_data *rx_offload, *tx_offload;
	struct rte_tel_data *rxq_state, *txq_state;
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	struct rte_eth_dev *eth_dev;
	uint16_t port_id;
	char *end_param;
	int ret;
	int i;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	eth_dev = &rte_eth_devices[port_id];

	rxq_state = rte_tel_data_alloc();
	if (rxq_state == NULL)
		return -ENOMEM;

	txq_state = rte_tel_data_alloc();
	if (txq_state == NULL)
		goto free_rxq_state;

	rx_offload = rte_tel_data_alloc();
	if (rx_offload == NULL)
		goto free_txq_state;

	tx_offload = rte_tel_data_alloc();
	if (tx_offload == NULL)
		goto free_rx_offload;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_string(d, "name", eth_dev->data->name);
	rte_tel_data_add_dict_int(d, "state", eth_dev->state);
	rte_tel_data_add_dict_int(d, "nb_rx_queues",
			eth_dev->data->nb_rx_queues);
	rte_tel_data_add_dict_int(d, "nb_tx_queues",
			eth_dev->data->nb_tx_queues);
	rte_tel_data_add_dict_int(d, "port_id", eth_dev->data->port_id);
	rte_tel_data_add_dict_int(d, "mtu", eth_dev->data->mtu);
	rte_tel_data_add_dict_uint(d, "rx_mbuf_size_min",
			eth_dev->data->min_rx_buf_size);
	rte_ether_format_addr(mac_addr, sizeof(mac_addr),
			eth_dev->data->mac_addrs);
	rte_tel_data_add_dict_string(d, "mac_addr", mac_addr);
	rte_tel_data_add_dict_int(d, "promiscuous",
			eth_dev->data->promiscuous);
	rte_tel_data_add_dict_int(d, "scattered_rx",
			eth_dev->data->scattered_rx);
	rte_tel_data_add_dict_int(d, "all_multicast",
			eth_dev->data->all_multicast);
	rte_tel_data_add_dict_int(d, "dev_started", eth_dev->data->dev_started);
	rte_tel_data_add_dict_int(d, "lro", eth_dev->data->lro);
	rte_tel_data_add_dict_int(d, "dev_configured",
			eth_dev->data->dev_configured);

	rte_tel_data_start_array(rxq_state, RTE_TEL_INT_VAL);
	for (i = 0; i < eth_dev->data->nb_rx_queues; i++)
		rte_tel_data_add_array_int(rxq_state,
				eth_dev->data->rx_queue_state[i]);

	rte_tel_data_start_array(txq_state, RTE_TEL_INT_VAL);
	for (i = 0; i < eth_dev->data->nb_tx_queues; i++)
		rte_tel_data_add_array_int(txq_state,
				eth_dev->data->tx_queue_state[i]);

	rte_tel_data_add_dict_container(d, "rxq_state", rxq_state, 0);
	rte_tel_data_add_dict_container(d, "txq_state", txq_state, 0);
	rte_tel_data_add_dict_int(d, "numa_node", eth_dev->data->numa_node);
	rte_tel_data_add_dict_uint_hex(d, "dev_flags",
			eth_dev->data->dev_flags, 0);

	eth_dev_parse_rx_offloads(eth_dev->data->dev_conf.rxmode.offloads,
			rx_offload);
	rte_tel_data_add_dict_container(d, "rx_offloads", rx_offload, 0);
	eth_dev_parse_tx_offloads(eth_dev->data->dev_conf.txmode.offloads,
			tx_offload);
	rte_tel_data_add_dict_container(d, "tx_offloads", tx_offload, 0);

	rte_tel_data_add_dict_uint_hex(d, "ethdev_rss_hf",
			eth_dev->data->dev_conf.rx_adv_conf.rss_conf.rss_hf, 0);

	return 0;

free_rx_offload:
	rte_tel_data_free(rx_offload);
free_txq_state:
	rte_tel_data_free(txq_state);
free_rxq_state:
	rte_tel_data_free(rxq_state);

	return -ENOMEM;
}

static int
eth_dev_handle_port_macs(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	char mac_addr[RTE_ETHER_ADDR_FMT_SIZE];
	struct rte_eth_dev_info dev_info;
	struct rte_eth_dev *eth_dev;
	uint16_t port_id;
	char *end_param;
	uint32_t i;
	int ret;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	ret = rte_eth_dev_info_get(port_id, &dev_info);
	if (ret != 0)
		return ret;

	eth_dev = &rte_eth_devices[port_id];
	rte_tel_data_start_array(d, RTE_TEL_STRING_VAL);
	for (i = 0; i < dev_info.max_mac_addrs; i++) {
		if (rte_is_zero_ether_addr(&eth_dev->data->mac_addrs[i]))
			continue;

		rte_ether_format_addr(mac_addr, sizeof(mac_addr),
			&eth_dev->data->mac_addrs[i]);
		rte_tel_data_add_array_string(d, mac_addr);
	}

	return 0;
}

static int
eth_dev_handle_port_flow_ctrl(const char *cmd __rte_unused,
		const char *params,
		struct rte_tel_data *d)
{
	struct rte_eth_fc_conf fc_conf;
	uint16_t port_id;
	char *end_param;
	bool rx_fc_en;
	bool tx_fc_en;
	int ret;

	ret = eth_dev_parse_port_params(params, &port_id, &end_param, false);
	if (ret < 0)
		return ret;

	ret = rte_eth_dev_flow_ctrl_get(port_id, &fc_conf);
	if (ret != 0) {
		RTE_ETHDEV_LOG(ERR,
			"Failed to get flow ctrl info, ret = %d\n", ret);
		return ret;
	}

	rx_fc_en = fc_conf.mode == RTE_ETH_FC_RX_PAUSE ||
		   fc_conf.mode == RTE_ETH_FC_FULL;
	tx_fc_en = fc_conf.mode == RTE_ETH_FC_TX_PAUSE ||
		   fc_conf.mode == RTE_ETH_FC_FULL;

	rte_tel_data_start_dict(d);
	rte_tel_data_add_dict_uint_hex(d, "high_waterline", fc_conf.high_water, 0);
	rte_tel_data_add_dict_uint_hex(d, "low_waterline", fc_conf.low_water, 0);
	rte_tel_data_add_dict_uint_hex(d, "pause_time", fc_conf.pause_time, 0);
	rte_tel_data_add_dict_string(d, "send_xon", fc_conf.send_xon ? "on" : "off");
	rte_tel_data_add_dict_string(d, "mac_ctrl_frame_fwd",
			fc_conf.mac_ctrl_frame_fwd ? "on" : "off");
	rte_tel_data_add_dict_string(d, "rx_pause", rx_fc_en ? "on" : "off");
	rte_tel_data_add_dict_string(d, "tx_pause", tx_fc_en ? "on" : "off");
	rte_tel_data_add_dict_string(d, "autoneg", fc_conf.autoneg ? "on" : "off");

	return 0;
}

RTE_INIT(ethdev_init_telemetry)
{
	rte_telemetry_register_cmd("/ethdev/list", eth_dev_handle_port_list,
			"Returns list of available ethdev ports. Takes no parameters");
	rte_telemetry_register_cmd("/ethdev/stats", eth_dev_handle_port_stats,
			"Returns the common stats for a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/xstats", eth_dev_handle_port_xstats,
			"Returns the extended stats for a port. Parameters: int port_id,hide_zero=true|false(Optional for indicates hide zero xstats)");
#ifndef RTE_EXEC_ENV_WINDOWS
	rte_telemetry_register_cmd("/ethdev/dump_priv", eth_dev_handle_port_dump_priv,
			"Returns dump private information for a port. Parameters: int port_id");
#endif
	rte_telemetry_register_cmd("/ethdev/link_status",
			eth_dev_handle_port_link_status,
			"Returns the link status for a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/info", eth_dev_handle_port_info,
			"Returns the device info for a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/module_eeprom", eth_dev_handle_port_module_eeprom,
			"Returns module EEPROM info with SFF specs. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/macs", eth_dev_handle_port_macs,
			"Returns the MAC addresses for a port. Parameters: int port_id");
	rte_telemetry_register_cmd("/ethdev/flow_ctrl", eth_dev_handle_port_flow_ctrl,
			"Returns flow ctrl info for a port. Parameters: int port_id");
}
