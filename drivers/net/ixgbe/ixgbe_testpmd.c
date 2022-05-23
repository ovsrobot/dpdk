/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation.
 */

#include <ethdev_driver.h>
#include "ixgbe_ethdev.h"
#include "rte_pmd_ixgbe.h"

#include <cmdline_parse_etheraddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>

#include "testpmd.h"

static uint8_t
hexa_digit_to_value(char hexa_digit)
{
	if ((hexa_digit >= '0') && (hexa_digit <= '9'))
		return (uint8_t)(hexa_digit - '0');
	if ((hexa_digit >= 'a') && (hexa_digit <= 'f'))
		return (uint8_t)((hexa_digit - 'a') + 10);
	if ((hexa_digit >= 'A') && (hexa_digit <= 'F'))
		return (uint8_t)((hexa_digit - 'A') + 10);
	/* Invalid hexa digit */
	return 0xFF;
}

static uint8_t
parse_and_check_key_hexa_digit(char *key, int idx)
{
	uint8_t hexa_v;

	hexa_v = hexa_digit_to_value(key[idx]);
	if (hexa_v == 0xFF)
		fprintf(stderr,
			"invalid key: character %c at position %d is not a valid hexa digit\n",
			key[idx], idx);
	return hexa_v;
}

static int
vf_tc_min_bw_parse_bw_list(uint8_t *bw_list, uint8_t *tc_num, char *str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char *end;
	char *str_fld[16];
	uint16_t i;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL) {
		fprintf(stderr,
			"The bandwidth-list should be '(bw1, bw2, ...)'\n");
		return -1;
	}
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL) {
		fprintf(stderr,
			"The bandwidth-list should be '(bw1, bw2, ...)'\n");
		return -1;
	}
	size = p0 - p;
	if (size >= sizeof(s)) {
		fprintf(stderr,
			"The string size exceeds the internal buffer size\n");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, 16, ',');
	if (ret <= 0) {
		fprintf(stderr, "Failed to get the bandwidth list.\n");
		return -1;
	}
	*tc_num = ret;
	for (i = 0; i < ret; i++)
		bw_list[i] = (uint8_t)strtoul(str_fld[i], &end, 0);

	return 0;
}

/* Common result structure for vf split drop enable */
struct cmd_vf_split_drop_en_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t vf;
	cmdline_fixed_string_t split;
	cmdline_fixed_string_t drop;
	portid_t port_id;
	uint16_t vf_id;
	cmdline_fixed_string_t on_off;
};

/* Common CLI fields for vf split drop enable disable */
static cmdline_parse_token_string_t cmd_vf_split_drop_en_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_split_drop_en_result,
		set, "set");
static cmdline_parse_token_string_t cmd_vf_split_drop_en_vf =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_split_drop_en_result,
		vf, "vf");
static cmdline_parse_token_string_t cmd_vf_split_drop_en_split =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_split_drop_en_result,
		split, "split");
static cmdline_parse_token_string_t cmd_vf_split_drop_en_drop =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_split_drop_en_result,
		drop, "drop");
static cmdline_parse_token_num_t cmd_vf_split_drop_en_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_split_drop_en_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_vf_split_drop_en_vf_id =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_split_drop_en_result,
		vf_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_vf_split_drop_en_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_split_drop_en_result,
		on_off, "on#off");

static void
cmd_set_vf_split_drop_en_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_vf_split_drop_en_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_on = (strcmp(res->on_off, "on") == 0) ? 1 : 0;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	ret = rte_pmd_ixgbe_set_vf_split_drop_en(res->port_id, res->vf_id,
			is_on);
	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		fprintf(stderr, "invalid vf_id %d or is_on %d\n",
			res->vf_id, is_on);
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "not supported on port %d\n", res->port_id);
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_set_vf_split_drop_en = {
	.f = cmd_set_vf_split_drop_en_parsed,
	.data = NULL,
	.help_str = "set vf split drop <port_id> <vf_id> on|off",
	.tokens = {
		(void *)&cmd_vf_split_drop_en_set,
		(void *)&cmd_vf_split_drop_en_vf,
		(void *)&cmd_vf_split_drop_en_split,
		(void *)&cmd_vf_split_drop_en_drop,
		(void *)&cmd_vf_split_drop_en_port_id,
		(void *)&cmd_vf_split_drop_en_vf_id,
		(void *)&cmd_vf_split_drop_en_on_off,
		NULL,
	},
};

/* MACsec configuration */

/* Common result structure for MACsec offload enable */
struct cmd_macsec_offload_on_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t offload;
	portid_t port_id;
	cmdline_fixed_string_t on;
	cmdline_fixed_string_t encrypt;
	cmdline_fixed_string_t en_on_off;
	cmdline_fixed_string_t replay_protect;
	cmdline_fixed_string_t rp_on_off;
};

/* Common CLI fields for MACsec offload disable */
static cmdline_parse_token_string_t cmd_macsec_offload_on_set =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		set, "set");
static cmdline_parse_token_string_t cmd_macsec_offload_on_macsec =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		macsec, "macsec");
static cmdline_parse_token_string_t cmd_macsec_offload_on_offload =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		offload, "offload");
static cmdline_parse_token_num_t cmd_macsec_offload_on_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_offload_on_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_macsec_offload_on_on =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		on, "on");
static cmdline_parse_token_string_t cmd_macsec_offload_on_encrypt =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		encrypt, "encrypt");
static cmdline_parse_token_string_t cmd_macsec_offload_on_en_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		en_on_off, "on#off");
static cmdline_parse_token_string_t cmd_macsec_offload_on_replay_protect =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		replay_protect, "replay-protect");
static cmdline_parse_token_string_t cmd_macsec_offload_on_rp_on_off =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_on_result,
		rp_on_off, "on#off");

static void
cmd_set_macsec_offload_on_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_macsec_offload_on_result *res = parsed_result;
	int ret = -ENOTSUP;
	portid_t port_id = res->port_id;
	int en = (strcmp(res->en_on_off, "on") == 0) ? 1 : 0;
	int rp = (strcmp(res->rp_on_off, "on") == 0) ? 1 : 0;
	struct rte_eth_dev_info dev_info;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(port_id)) {
		fprintf(stderr, "Please stop port %d first\n", port_id);
		return;
	}

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MACSEC_INSERT)
		ret = rte_pmd_ixgbe_macsec_enable(port_id, en, rp);

	switch (ret) {
	case 0:
		ports[port_id].dev_conf.txmode.offloads |=
						RTE_ETH_TX_OFFLOAD_MACSEC_INSERT;
		cmd_reconfig_device_queue(port_id, 1, 1);
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "not supported on port %d\n", port_id);
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_set_macsec_offload_on = {
	.f = cmd_set_macsec_offload_on_parsed,
	.data = NULL,
	.help_str = "set macsec offload <port_id> on "
		"encrypt on|off replay-protect on|off",
	.tokens = {
		(void *)&cmd_macsec_offload_on_set,
		(void *)&cmd_macsec_offload_on_macsec,
		(void *)&cmd_macsec_offload_on_offload,
		(void *)&cmd_macsec_offload_on_port_id,
		(void *)&cmd_macsec_offload_on_on,
		(void *)&cmd_macsec_offload_on_encrypt,
		(void *)&cmd_macsec_offload_on_en_on_off,
		(void *)&cmd_macsec_offload_on_replay_protect,
		(void *)&cmd_macsec_offload_on_rp_on_off,
		NULL,
	},
};

/* Common result structure for MACsec offload disable */
struct cmd_macsec_offload_off_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t offload;
	portid_t port_id;
	cmdline_fixed_string_t off;
};

/* Common CLI fields for MACsec offload disable */
static cmdline_parse_token_string_t cmd_macsec_offload_off_set =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_off_result,
		set, "set");
static cmdline_parse_token_string_t cmd_macsec_offload_off_macsec =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_off_result,
		macsec, "macsec");
static cmdline_parse_token_string_t cmd_macsec_offload_off_offload =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_off_result,
		offload, "offload");
static cmdline_parse_token_num_t cmd_macsec_offload_off_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_offload_off_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_macsec_offload_off_off =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_offload_off_result,
		off, "off");

static void
cmd_set_macsec_offload_off_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_macsec_offload_off_result *res = parsed_result;
	int ret = -ENOTSUP;
	struct rte_eth_dev_info dev_info;
	portid_t port_id = res->port_id;

	if (port_id_is_invalid(port_id, ENABLED_WARN))
		return;
	if (!port_is_stopped(port_id)) {
		fprintf(stderr, "Please stop port %d first\n", port_id);
		return;
	}

	ret = eth_dev_info_get_print_err(port_id, &dev_info);
	if (ret != 0)
		return;

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MACSEC_INSERT)
		ret = rte_pmd_ixgbe_macsec_disable(port_id);
	switch (ret) {
	case 0:
		ports[port_id].dev_conf.txmode.offloads &=
						~RTE_ETH_TX_OFFLOAD_MACSEC_INSERT;
		cmd_reconfig_device_queue(port_id, 1, 1);
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "not supported on port %d\n", port_id);
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_set_macsec_offload_off = {
	.f = cmd_set_macsec_offload_off_parsed,
	.data = NULL,
	.help_str = "set macsec offload <port_id> off",
	.tokens = {
		(void *)&cmd_macsec_offload_off_set,
		(void *)&cmd_macsec_offload_off_macsec,
		(void *)&cmd_macsec_offload_off_offload,
		(void *)&cmd_macsec_offload_off_port_id,
		(void *)&cmd_macsec_offload_off_off,
		NULL,
	},
};

/* Common result structure for MACsec secure connection configure */
struct cmd_macsec_sc_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t sc;
	cmdline_fixed_string_t tx_rx;
	portid_t port_id;
	struct rte_ether_addr mac;
	uint16_t pi;
};

/* Common CLI fields for MACsec secure connection configure */
static cmdline_parse_token_string_t cmd_macsec_sc_set =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sc_result,
		set, "set");
static cmdline_parse_token_string_t cmd_macsec_sc_macsec =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sc_result,
		macsec, "macsec");
static cmdline_parse_token_string_t cmd_macsec_sc_sc =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sc_result,
		sc, "sc");
static cmdline_parse_token_string_t cmd_macsec_sc_tx_rx =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sc_result,
		tx_rx, "tx#rx");
static cmdline_parse_token_num_t cmd_macsec_sc_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sc_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_etheraddr_t cmd_macsec_sc_mac =
	TOKEN_ETHERADDR_INITIALIZER(struct cmd_macsec_sc_result,
		mac);
static cmdline_parse_token_num_t cmd_macsec_sc_pi =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sc_result,
		pi, RTE_UINT16);

static void
cmd_set_macsec_sc_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_macsec_sc_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_tx = (strcmp(res->tx_rx, "tx") == 0) ? 1 : 0;

	ret = is_tx ?
		rte_pmd_ixgbe_macsec_config_txsc(res->port_id,
				res->mac.addr_bytes) :
		rte_pmd_ixgbe_macsec_config_rxsc(res->port_id,
				res->mac.addr_bytes, res->pi);
	switch (ret) {
	case 0:
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "not supported on port %d\n", res->port_id);
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_set_macsec_sc = {
	.f = cmd_set_macsec_sc_parsed,
	.data = NULL,
	.help_str = "set macsec sc tx|rx <port_id> <mac> <pi>",
	.tokens = {
		(void *)&cmd_macsec_sc_set,
		(void *)&cmd_macsec_sc_macsec,
		(void *)&cmd_macsec_sc_sc,
		(void *)&cmd_macsec_sc_tx_rx,
		(void *)&cmd_macsec_sc_port_id,
		(void *)&cmd_macsec_sc_mac,
		(void *)&cmd_macsec_sc_pi,
		NULL,
	},
};

/* Common result structure for MACsec secure connection configure */
struct cmd_macsec_sa_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t macsec;
	cmdline_fixed_string_t sa;
	cmdline_fixed_string_t tx_rx;
	portid_t port_id;
	uint8_t idx;
	uint8_t an;
	uint32_t pn;
	cmdline_fixed_string_t key;
};

/* Common CLI fields for MACsec secure connection configure */
static cmdline_parse_token_string_t cmd_macsec_sa_set =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sa_result,
		set, "set");
static cmdline_parse_token_string_t cmd_macsec_sa_macsec =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sa_result,
		macsec, "macsec");
static cmdline_parse_token_string_t cmd_macsec_sa_sa =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sa_result,
		sa, "sa");
static cmdline_parse_token_string_t cmd_macsec_sa_tx_rx =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sa_result,
		tx_rx, "tx#rx");
static cmdline_parse_token_num_t cmd_macsec_sa_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sa_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_num_t cmd_macsec_sa_idx =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sa_result,
		idx, RTE_UINT8);
static cmdline_parse_token_num_t cmd_macsec_sa_an =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sa_result,
		an, RTE_UINT8);
static cmdline_parse_token_num_t cmd_macsec_sa_pn =
	TOKEN_NUM_INITIALIZER(struct cmd_macsec_sa_result,
		pn, RTE_UINT32);
static cmdline_parse_token_string_t cmd_macsec_sa_key =
	TOKEN_STRING_INITIALIZER(struct cmd_macsec_sa_result,
		key, NULL);

static void
cmd_set_macsec_sa_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_macsec_sa_result *res = parsed_result;
	int ret = -ENOTSUP;
	int is_tx = (strcmp(res->tx_rx, "tx") == 0) ? 1 : 0;
	uint8_t key[16] = { 0 };
	uint8_t xdgt0;
	uint8_t xdgt1;
	int key_len;
	int i;

	key_len = strlen(res->key) / 2;
	if (key_len > 16)
		key_len = 16;

	for (i = 0; i < key_len; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(res->key, (i * 2));
		if (xdgt0 == 0xFF)
			return;
		xdgt1 = parse_and_check_key_hexa_digit(res->key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return;
		key[i] = (uint8_t)((xdgt0 * 16) + xdgt1);
	}

	ret = is_tx ?
		rte_pmd_ixgbe_macsec_select_txsa(res->port_id,
			res->idx, res->an, res->pn, key) :
		rte_pmd_ixgbe_macsec_select_rxsa(res->port_id,
			res->idx, res->an, res->pn, key);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		fprintf(stderr, "invalid idx %d or an %d\n", res->idx, res->an);
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "not supported on port %d\n", res->port_id);
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

struct cmd_vf_tc_bw_result {
	cmdline_fixed_string_t set;
	cmdline_fixed_string_t tc;
	cmdline_fixed_string_t tx;
	cmdline_fixed_string_t min_bw;
	portid_t port_id;
	cmdline_fixed_string_t bw_list;
};

static cmdline_parse_token_string_t cmd_vf_tc_bw_set =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		set, "set");
static cmdline_parse_token_string_t cmd_vf_tc_bw_tc =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		tc, "tc");
static cmdline_parse_token_string_t cmd_vf_tc_bw_tx =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		tx, "tx");
static cmdline_parse_token_string_t cmd_vf_tc_bw_min_bw =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		min_bw, "min-bandwidth");
static cmdline_parse_token_num_t cmd_vf_tc_bw_port_id =
	TOKEN_NUM_INITIALIZER(struct cmd_vf_tc_bw_result,
		port_id, RTE_UINT16);
static cmdline_parse_token_string_t cmd_vf_tc_bw_bw_list =
	TOKEN_STRING_INITIALIZER(struct cmd_vf_tc_bw_result,
		bw_list, NULL);

static cmdline_parse_inst_t cmd_set_macsec_sa = {
	.f = cmd_set_macsec_sa_parsed,
	.data = NULL,
	.help_str = "set macsec sa tx|rx <port_id> <idx> <an> <pn> <key>",
	.tokens = {
		(void *)&cmd_macsec_sa_set,
		(void *)&cmd_macsec_sa_macsec,
		(void *)&cmd_macsec_sa_sa,
		(void *)&cmd_macsec_sa_tx_rx,
		(void *)&cmd_macsec_sa_port_id,
		(void *)&cmd_macsec_sa_idx,
		(void *)&cmd_macsec_sa_an,
		(void *)&cmd_macsec_sa_pn,
		(void *)&cmd_macsec_sa_key,
		NULL,
	},
};

static void
cmd_tc_min_bw_parsed(void *parsed_result,
	__rte_unused struct cmdline *cl, __rte_unused void *data)
{
	struct cmd_vf_tc_bw_result *res = parsed_result;
	struct rte_port *port;
	uint8_t tc_num;
	uint8_t bw[16];
	int ret = -ENOTSUP;

	if (port_id_is_invalid(res->port_id, ENABLED_WARN))
		return;

	port = &ports[res->port_id];
	/** Check if the port is not started **/
	if (port->port_status != RTE_PORT_STOPPED) {
		fprintf(stderr, "Please stop port %d first\n", res->port_id);
		return;
	}

	ret = vf_tc_min_bw_parse_bw_list(bw, &tc_num, res->bw_list);
	if (ret)
		return;

	ret = rte_pmd_ixgbe_set_tc_bw_alloc(res->port_id, tc_num, bw);

	switch (ret) {
	case 0:
		break;
	case -EINVAL:
		fprintf(stderr, "invalid bandwidth\n");
		break;
	case -ENODEV:
		fprintf(stderr, "invalid port_id %d\n", res->port_id);
		break;
	case -ENOTSUP:
		fprintf(stderr, "function not implemented\n");
		break;
	default:
		fprintf(stderr, "programming error: (%s)\n", strerror(-ret));
	}
}

static cmdline_parse_inst_t cmd_tc_min_bw = {
	.f = cmd_tc_min_bw_parsed,
	.data = NULL,
	.help_str = "set tc tx min-bandwidth <port_id> <bw1, bw2, ...>",
	.tokens = {
		(void *)&cmd_vf_tc_bw_set,
		(void *)&cmd_vf_tc_bw_tc,
		(void *)&cmd_vf_tc_bw_tx,
		(void *)&cmd_vf_tc_bw_min_bw,
		(void *)&cmd_vf_tc_bw_port_id,
		(void *)&cmd_vf_tc_bw_bw_list,
		NULL,
	},
};

static struct testpmd_commands ixgbe_cmds = {
	.commands = {
	{
		&cmd_set_vf_split_drop_en,
		"set vf split drop (port_id) (vf_id) (on|off)\n"
		"    Set split drop enable bit for a VF from the PF.\n",
	},
	{
		&cmd_set_macsec_offload_on,
		"set macsec offload (port_id) on encrypt (on|off) replay-protect (on|off)\n"
		"    Enable MACsec offload.\n",
	},
	{
		&cmd_set_macsec_offload_off,
		"set macsec offload (port_id) off\n"
		"    Disable MACsec offload.\n",
	},
	{
		&cmd_set_macsec_sc,
		"set macsec sc (tx|rx) (port_id) (mac) (pi)\n"
		"    Configure MACsec secure connection (SC).\n",
	},
	{
		&cmd_set_macsec_sa,
		"set macsec sa (tx|rx) (port_id) (idx) (an) (pn) (key)\n"
		"    Configure MACsec secure association (SA).\n",
	},
	{
		&cmd_tc_min_bw,
		"set tc tx min-bandwidth (port_id) (bw1, bw2, ...)\n"
		"    Set all TCs' min bandwidth(%%) for all PF and VFs.\n",
	},
	{ NULL, NULL },
	},
};
TESTPMD_ADD_DRIVER_COMMANDS(ixgbe_cmds)
