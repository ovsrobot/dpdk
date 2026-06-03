/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#include <rte_bus.h>
#include <eal_export.h>

#include "sxe2_common_log.h"
#include "sxe2_ethdev.h"
#include "sxe2_stats.h"
#include "sxe2_testpmd_lib.h"

struct rte_mempool *g_sess_pool;

bool g_sxe2_ipsec_mgt_init;
struct sxe2_ipsec_session_mgt g_tx_session[SXE2_IPSEC_PORT_MAX][SXE2_IPSEC_SESSION_MAX];
struct sxe2_ipsec_session_mgt g_rx_session[SXE2_IPSEC_PORT_MAX][SXE2_IPSEC_SESSION_MAX];
uint16_t g_tx_sess_id[SXE2_IPSEC_PORT_MAX] = {0};
uint16_t g_esp_header_offset[SXE2_IPSEC_PORT_MAX] = {0};

static bool sxe2_is_supported(struct rte_eth_dev *dev)
{
	return sxe2_ethdev_check(dev);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_testpmd_sched_reset, 26.07)
int32_t
sxe2_testpmd_sched_reset(uint16_t port_id)
{
	struct rte_eth_dev   *dev     = NULL;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		return -ENODEV;
	}

	return sxe2_sched_reset(dev);
}

extern const char *sxe2_flow_type_name[SXE2_FLOW_TYPE_MAX];

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_flow_rule_dump, 26.07)
int32_t
sxe2_flow_rule_dump(uint16_t port_id, struct cmdline *cl)
{
	struct rte_eth_dev            *dev           = NULL;
	struct sxe2_adapter           *adapter       = NULL;
	int32_t                            ret       = -1;
	struct rte_flow_list_t        *flow_list     = NULL;
	struct rte_flow               *flow          = NULL;
	uint32_t                            index         = 0;
	struct sxe2_flow              *hw_flow       = NULL;
	uint8_t i = 0;

	const char *sxe2_flow_engine_name[SXE2_FLOW_ENGINE_MAX] = {
		[SXE2_FLOW_ENGINE_ACL] = "acl",
		[SXE2_FLOW_ENGINE_RSS] = "rss",
		[SXE2_FLOW_ENGINE_SWITCH] = "switch",
		[SXE2_FLOW_ENGINE_FNAV] = "fnav",
	};
	const char *sxe2_flow_action_name[SXE2_FLOW_ACTION_MAX] = {
		[SXE2_FLOW_ACTION_DROP] = "drop",
		[SXE2_FLOW_ACTION_TC_REDIRECT] = "tc_redirect",
		[SXE2_FLOW_ACTION_TO_VSI] = "to_vsi",
		[SXE2_FLOW_ACTION_TO_VSI_LIST] = "to_vsi_list",
		[SXE2_FLOW_ACTION_PASSTHRU] = "passthru",
		[SXE2_FLOW_ACTION_QUEUE] = "queue",
		[SXE2_FLOW_ACTION_Q_REGION] = "q_region",
		[SXE2_FLOW_ACTION_MARK] = "mark",
		[SXE2_FLOW_ACTION_COUNT] = "count",
		[SXE2_FLOW_ACTION_RSS] = "rss",
	};

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev");
		ret = -ENODEV;
		goto l_end;
	}
	adapter = SXE2_DEV_PRIVATE_TO_ADAPTER(dev);
	flow_list = &adapter->flow_ctxt.rte_flow_list;
	cmdline_printf(cl, "Dump sxe2 flow rule:\n");
	TAILQ_FOREACH(flow, flow_list, next) {
		cmdline_printf(cl, "rule index: %d\n", index++);
		TAILQ_FOREACH(hw_flow, &flow->sxe2_flow_list, next) {
			cmdline_printf(cl, "\thw flow id: %d\n", hw_flow->flow_id);
			cmdline_printf(cl, "\t\ttype: %s\n",
					sxe2_flow_type_name[hw_flow->meta.flow_type]);
			cmdline_printf(cl, "\t\tprio: %d\n", hw_flow->meta.flow_prio);
			cmdline_printf(cl, "\t\tsrc vsi: %d,rule vsi: %d\n",
				hw_flow->meta.flow_src_vsi, hw_flow->meta.flow_rule_vsi);
			cmdline_printf(cl, "\t\tengine type: %s\n",
				sxe2_flow_engine_name[hw_flow->engine_type]);
			cmdline_printf(cl, "\t\taction:");
			for (i = 0; i < SXE2_FLOW_ACTION_MAX; i++) {
				if (sxe2_test_bit(i, hw_flow->action.act_types))
					cmdline_printf(cl, "%s ", sxe2_flow_action_name[i]);
			}
			cmdline_printf(cl, "\n");
		}
	}
	cmdline_printf(cl, "Dump sxe2 flow rule end.\n");
	ret = 0;
l_end:
	return ret;
}

static const char *tunnel_type_list[SXE2_UDP_TUNNEL_MAX] = {
	[SXE2_UDP_TUNNEL_PROTOCOL_VXLAN] = "vxlan",
	[SXE2_UDP_TUNNEL_PROTOCOL_VXLAN_GPE] = "vxlan-gpe",
	[SXE2_UDP_TUNNEL_PROTOCOL_GENEVE] = "geneve",
	[SXE2_UDP_TUNNEL_PROTOCOL_GTP_C] = "gtp-c",
	[SXE2_UDP_TUNNEL_PROTOCOL_GTP_U] = "gtp-u",
	[SXE2_UDP_TUNNEL_PROTOCOL_PFCP] = "pfcp",
	[SXE2_UDP_TUNNEL_PROTOCOL_ECPRI] = "ecpri",
	[SXE2_UDP_TUNNEL_PROTOCOL_MPLS] = "mpls",
	[SXE2_UDP_TUNNEL_PROTOCOL_NVGRE] = "nvgre",
	[SXE2_UDP_TUNNEL_PROTOCOL_L2TP] = "l2tp",
	[SXE2_UDP_TUNNEL_PROTOCOL_TEREDO] = "teredo"
};

static enum sxe2_udp_tunnel_protocol sxe2_udp_tunnel_type_str2proto(const char *tunnel_type)
{
	enum sxe2_udp_tunnel_protocol proto;

	for (proto = 0; proto < SXE2_UDP_TUNNEL_MAX; proto++) {
		if (tunnel_type_list[proto] != NULL &&
		    strcmp(tunnel_type_list[proto], tunnel_type) == 0) {
			break;
		}
	}

	return proto;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_udp_tunnel_operations, 26.07)
int32_t
sxe2_udp_tunnel_operations(uint16_t port_id, struct cmdline *cl, uint8_t action,
			   uint16_t udp_port, const char *tunnel_type)
{
	enum sxe2_udp_tunnel_protocol proto = sxe2_udp_tunnel_type_str2proto(tunnel_type);
	struct rte_eth_dev            *dev = NULL;
	struct sxe2_adapter           *adapter = NULL;
	struct sxe2_udp_tunnel_cfg    tunnel_config = { 0 };
	int32_t ret   = -1;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	if (proto >= SXE2_UDP_TUNNEL_MAX) {
		cmdline_printf(cl, "Invalid tunnel type!\n");
		goto l_end;
	}
	adapter = dev->data->dev_private;
	switch (action) {
	case SXE2_TESTPMD_CMD_UDP_TUNNEL_ADD:
		ret = sxe2_udp_tunnel_port_add_common(adapter, proto, udp_port);
		break;
	case SXE2_TESTPMD_CMD_UDP_TUNNEL_DEL:
		ret = sxe2_udp_tunnel_port_del_common(adapter, proto, udp_port);
		break;
	case SXE2_TESTPMD_CMD_UDP_TUNNEL_GET:
		tunnel_config.protocol = proto;
		ret = sxe2_udp_tunnel_port_get_common(adapter, &tunnel_config);
		if (!ret) {
			cmdline_printf(cl, "Dump firmware udp tunnel config: [proto:%s, port:%d,"
				"enable:%d, src/dst:%d/%d, used:%d]\n",
				 tunnel_type_list[proto], tunnel_config.fw_port,
				 tunnel_config.fw_status, tunnel_config.fw_src_en,
				 tunnel_config.fw_dst_en, tunnel_config.fw_used);
		}
		break;
	default:
	break;
	}

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_stats_info_show, 26.07)
int32_t
sxe2_stats_info_show(uint16_t port_id)
{
	struct rte_eth_dev *dev = NULL;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		return -ENODEV;
	}

	return 0;
}

static int32_t sxe2_ipsec_init_mempools(void *sec_ctx)
{
	uint16_t nb_sess = 8192;
	uint32_t sess_sz;
	char s[64];
	int32_t ret = -1;

	sess_sz = rte_security_session_get_size(sec_ctx);
	if (g_sess_pool == NULL) {
		snprintf(s, sizeof(s), "sess_pool");
		g_sess_pool = rte_mempool_create(s, nb_sess, sess_sz,
				MEMPOOL_CACHE_SIZE, 0,
				NULL, NULL, NULL, NULL,
				SOCKET_ID_ANY, 0);
		if (g_sess_pool == NULL) {
			ret = -ENOMEM;
			PMD_LOG_ERR(DRV, "Failed to malloc session pool memory.");
			goto l_end;
		}
	}
	ret = 0;

l_end:
	return ret;
}

static void sxe2_ipsec_init_session_mgt(void)
{
	uint16_t i;
	uint8_t port_id;

	if (g_sxe2_ipsec_mgt_init)
		return;

	for (port_id = 0; port_id < SXE2_IPSEC_PORT_MAX; port_id++) {
		for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
			g_tx_session[port_id][i].session = NULL;
			g_tx_session[port_id][i].encrypt_algo = SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL;
			g_tx_session[port_id][i].auth_algo = SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL;
			g_tx_session[port_id][i].session_id = i;
			g_tx_session[port_id][i].status = 0;
		}
	}

	for (port_id = 0; port_id < SXE2_IPSEC_PORT_MAX; port_id++) {
		for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
			g_rx_session[port_id][i].session = NULL;
			g_rx_session[port_id][i].encrypt_algo = SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL;
			g_rx_session[port_id][i].auth_algo = SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL;
			g_rx_session[port_id][i].session_id = i;
			g_rx_session[port_id][i].status = 0;
		}
	}

	g_sxe2_ipsec_mgt_init = true;
}

static uint16_t sxe2_ipsec_session_mgt_alloc(enum sxe2_testpmd_ipsec_dir dir, uint16_t port_id)
{
	uint16_t i;
	uint16_t index = 0XFFFF;
	struct sxe2_ipsec_session_mgt *mgt = NULL;

	if (dir == SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS)
		mgt = g_tx_session[port_id];
	else
		mgt = g_rx_session[port_id];

	for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
		if (mgt[i].status == 0) {
			index = i;
			mgt[i].status = 1;
			break;
		}
	}

	return index;
}

static void sxe2_ipsec_session_mgt_free(enum sxe2_testpmd_ipsec_dir dir,
					uint16_t index, uint16_t port_id)
{
	struct sxe2_ipsec_session_mgt *mgt = NULL;

	if (dir == SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS)
		mgt = g_tx_session[port_id];
	else
		mgt = g_rx_session[port_id];

	mgt[index].session = NULL;
	mgt[index].status = 0;
}

static int32_t sxe2_ipsec_egress_construct(struct cmdline *cl,
					   struct rte_crypto_sym_xform **xform,
					   struct sxe2_ipsec_conf_param *param)
{
	struct rte_crypto_sym_xform *cur_xform = NULL;
	struct rte_crypto_sym_xform *next_xform = NULL;
	int32_t ret = -1;

	cur_xform = rte_zmalloc("current xform",
				sizeof(struct rte_crypto_sym_xform), 0);
	if (cur_xform == NULL) {
		ret = -ENOMEM;
		cmdline_printf(cl, "Failed to malloc memory!\n");
		goto l_end;
	}
	cur_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	cur_xform->cipher.op = RTE_CRYPTO_CIPHER_OP_ENCRYPT;
	if (param->encrypt_algo == SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC)
		cur_xform->cipher.algo = SXE2_RTE_CRYPTO_CIPHER_AES_CBC;
	else
		cur_xform->cipher.algo = SXE2_RTE_RTE_CRYPTO_CIPHER_SM4_CBC;
	cur_xform->cipher.key.length = param->enc_len;
	cur_xform->cipher.key.data = param->enc_key;

	if (param->auth_algo == SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL) {
		ret = 0;
		goto l_end;
	}

	next_xform = rte_zmalloc("next xform",
				sizeof(struct rte_crypto_sym_xform), 0);
	if (next_xform == NULL) {
		rte_free(cur_xform);
		ret = -ENOMEM;
		cmdline_printf(cl, "Failed to malloc memory!\n");
		goto l_end;
	}
	next_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	next_xform->auth.op = RTE_CRYPTO_AUTH_OP_GENERATE;
	if (param->auth_algo == SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC)
		next_xform->auth.algo = SXE2_RTE_CRYPTO_AUTH_SHA256_HMAC;
	else
		next_xform->auth.algo = SXE2_RTE_CRYPTO_AUTH_SM3_HMAC;
	next_xform->auth.key.length = param->auth_len;
	next_xform->auth.key.data = param->auth_key;
	cur_xform->next = next_xform;
	ret = 0;

l_end:
	*xform = cur_xform;
	return ret;
}

static int32_t sxe2_ipsec_ingress_construct(struct cmdline *cl,
					    struct rte_crypto_sym_xform **xform,
					    struct sxe2_ipsec_conf_param *param)
{
	struct rte_crypto_sym_xform *cur_xform = NULL;
	struct rte_crypto_sym_xform *next_xform = NULL;
	int32_t ret = -1;

	cur_xform = rte_zmalloc("current xform",
				sizeof(struct rte_crypto_sym_xform), 0);
	if (cur_xform == NULL) {
		ret = -ENOMEM;
		cmdline_printf(cl, "Failed to malloc memory!\n");
		goto l_end;
	}

	if (param->auth_algo == SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL) {
		cur_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
		cur_xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
		if (param->encrypt_algo == SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC)
			cur_xform->cipher.algo = SXE2_RTE_CRYPTO_CIPHER_AES_CBC;
		else
			cur_xform->cipher.algo = SXE2_RTE_RTE_CRYPTO_CIPHER_SM4_CBC;
		cur_xform->cipher.key.length = param->enc_len;
		cur_xform->cipher.key.data = param->enc_key;
		ret = 0;
		goto l_end;
	}

	cur_xform->type = RTE_CRYPTO_SYM_XFORM_AUTH;
	cur_xform->auth.op = RTE_CRYPTO_AUTH_OP_VERIFY;
	if (param->auth_algo == SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC)
		cur_xform->auth.algo = SXE2_RTE_CRYPTO_AUTH_SHA256_HMAC;
	else
		cur_xform->auth.algo = SXE2_RTE_CRYPTO_AUTH_SM3_HMAC;

	cur_xform->auth.key.length = param->auth_len;
	cur_xform->auth.key.data = param->auth_key;

	next_xform = rte_zmalloc("next xform",
				 sizeof(struct rte_crypto_sym_xform), 0);
	if (next_xform == NULL) {
		rte_free(cur_xform);
		ret = -ENOMEM;
		cmdline_printf(cl, "Failed to malloc memory!\n");
		goto l_end;
	}

	next_xform->type = RTE_CRYPTO_SYM_XFORM_CIPHER;
	next_xform->cipher.op = RTE_CRYPTO_CIPHER_OP_DECRYPT;
	if (param->encrypt_algo == SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC)
		next_xform->cipher.algo = SXE2_RTE_CRYPTO_CIPHER_AES_CBC;
	else
		next_xform->cipher.algo = SXE2_RTE_RTE_CRYPTO_CIPHER_SM4_CBC;
	next_xform->cipher.key.length = param->enc_len;
	next_xform->cipher.key.data = param->enc_key;
	cur_xform->next = next_xform;
	ret = 0;

l_end:
	*xform = cur_xform;
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_ingress_create, 26.07)
int32_t
sxe2_ipsec_ingress_create(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	struct rte_security_session_conf conf;
	struct rte_crypto_sym_xform *encrypt_xform = NULL;
	void *session = NULL;
	struct rte_security_ctx *p_ctx = NULL;
	int32_t ret = -1;
	uint16_t index;
	uint8_t i;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	if (dev->data->dev_started != 0) {
		cmdline_printf(cl, "port %d must be stopped.\n", dev->data->port_id);
		ret = 0;
		goto l_end;
	}

	p_ctx = rte_eth_dev_get_sec_ctx(param->port_id);

	if (g_sess_pool == NULL) {
		ret = sxe2_ipsec_init_mempools(p_ctx);
		if (ret)
			goto l_end;
	}

	sxe2_ipsec_init_session_mgt();

	memset(&conf, 0, sizeof(conf));
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO;
	conf.ipsec.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	conf.ipsec.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	conf.ipsec.direction = RTE_SECURITY_IPSEC_SA_DIR_INGRESS;
	conf.ipsec.spi = param->spi;
	conf.ipsec.udp.sport = param->sport;
	conf.ipsec.udp.dport = param->dport;
	conf.ipsec.tunnel.type = param->ip_addr.type;
	if (param->sport || param->dport)
		conf.ipsec.options.udp_encap = true;
	if (param->ip_addr.type == RTE_SECURITY_IPSEC_TUNNEL_IPV4)
		conf.ipsec.tunnel.ipv4.dst_ip.s_addr = param->ip_addr.dst_ipv4;
	else
		memcpy(&conf.ipsec.tunnel.ipv6.dst_addr,
		       &param->ip_addr.dst_ipv6,
		       sizeof(param->ip_addr.dst_ipv6));

	ret = sxe2_ipsec_ingress_construct(cl, &encrypt_xform, param);
	if (ret)
		goto l_end;
	conf.crypto_xform = encrypt_xform;

	session = rte_security_session_create(p_ctx, &conf, g_sess_pool);
	if (session == NULL) {
		ret = -1;
		goto l_free;
	}

	index = sxe2_ipsec_session_mgt_alloc(param->dir, param->port_id);
	if (index == 0XFFFF) {
		ret = -1;
		goto l_free;
	}

	g_rx_session[param->port_id][index].session = session;
	g_rx_session[param->port_id][index].encrypt_algo = param->encrypt_algo;
	g_rx_session[param->port_id][index].auth_algo = param->auth_algo;
	for (i = 0; i < 32; i++) {
		g_rx_session[param->port_id][index].enc_key[i] = param->enc_key[i];
		g_rx_session[param->port_id][index].auth_key[i] = param->auth_key[i];
	}
	g_rx_session[param->port_id][index].sport = ntohs(param->sport);
	g_rx_session[param->port_id][index].dport = ntohs(param->dport);
	g_rx_session[param->port_id][index].spi = ntohl(param->spi);
	memcpy(&g_rx_session[param->port_id][index].ip_addr,
	       &param->ip_addr,
	       sizeof(struct sxe2_ipsec_ip_param));

	ret = 0;

l_free:
	if (encrypt_xform->next)
		rte_free(encrypt_xform->next);
	if (encrypt_xform)
		rte_free(encrypt_xform);

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_ingress_destroy, 26.07)
int32_t
sxe2_ipsec_ingress_destroy(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	struct rte_security_ctx *p_ctx = NULL;
	struct rte_security_session *session = NULL;
	int32_t ret = -1;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		cmdline_printf(cl, "Invalid dev.\n");
		ret = -ENODEV;
		goto l_end;
	}

	if (dev->data->dev_started != 0) {
		cmdline_printf(cl, "port %d must be stopped.\n", dev->data->port_id);
		ret = 0;
		goto l_end;
	}

	if (param->session_id >= SXE2_IPSEC_SESSION_MAX) {
		PMD_LOG_ERR(DRV, "Invalid session id.");
		ret = -EINVAL;
		goto l_end;
	}

	if (!g_rx_session[param->port_id][param->session_id].status) {
		PMD_LOG_ERR(DRV, "Invalid session status.");
		ret = -EINVAL;
		goto l_end;
	}

	if (g_rx_session[param->port_id][param->session_id].session == NULL) {
		PMD_LOG_ERR(DRV, "Invalid session data.");
		ret = -EINVAL;
		goto l_end;
	}

	p_ctx = rte_eth_dev_get_sec_ctx(param->port_id);

	session = g_rx_session[param->port_id][param->session_id].session;
	ret = rte_security_session_destroy(p_ctx, session);
	if (ret)
		goto l_end;
	sxe2_ipsec_session_mgt_free(param->dir, param->session_id, param->port_id);

	ret = 0;
l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_ingress_show, 26.07)
int32_t
sxe2_ipsec_ingress_show(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	int32_t ret = -1;
	uint16_t i;
	uint8_t j;
	char encrypt_key[65];
	char auth_key[65];
	const char *encrypt_algo[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC] = "aes-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_SM4_CBC] = "sm4-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL] = "null"
	};

	const char *auth_algo[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC] = "sha-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SM3_HMAC] = "sm3-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL] = "null"
	};

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
		if (g_rx_session[param->port_id][i].status &&
		    g_rx_session[param->port_id][i].session) {
			memset(encrypt_key, '\0', sizeof(encrypt_key));
			memset(auth_key, '\0', sizeof(auth_key));
			for (j = 0; j < 32; j++) {
				sprintf(encrypt_key + 2 * j, "%02x",
					g_rx_session[param->port_id][i].enc_key[j]);
			}

			if (g_rx_session[param->port_id][i].auth_algo !=
			    SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL) {
				for (j = 0; j < 32; j++) {
					sprintf(auth_key + 2 * j, "%02x",
						g_rx_session[param->port_id][i].auth_key[j]);
				}
			}

			cmdline_printf(cl, "session_id:%u, direction:rx ,"
				"encrypt_algo:%s, encrypt_key:0x%s,"
				"auth_algo:%s, auth_key:0x%s, sport:%u, dport:%u, spi:%u\n",
				i,
				encrypt_algo[g_rx_session[param->port_id][i].encrypt_algo],
				encrypt_key,
				auth_algo[g_rx_session[param->port_id][i].auth_algo],
				auth_key,
				g_rx_session[param->port_id][i].sport,
				g_rx_session[param->port_id][i].dport,
				g_rx_session[param->port_id][i].spi);
		}
	}

	ret = 0;

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_egress_create, 26.07)
int32_t
sxe2_ipsec_egress_create(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	struct rte_security_session_conf conf;
	struct rte_crypto_sym_xform *encrypt_xform = NULL;
	void *session = NULL;
	struct rte_security_ctx *p_ctx = NULL;
	int32_t ret = -1;
	uint16_t index;
	uint8_t i;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	if (dev->data->dev_started != 0) {
		cmdline_printf(cl, "port %d must be stopped.\n", dev->data->port_id);
		ret = 0;
		goto l_end;
	}

	p_ctx = rte_eth_dev_get_sec_ctx(param->port_id);

	if (g_sess_pool == NULL) {
		ret = sxe2_ipsec_init_mempools(p_ctx);
		if (ret)
			goto l_end;
	}

	sxe2_ipsec_init_session_mgt();

	memset(&conf, 0, sizeof(conf));
	conf.protocol = RTE_SECURITY_PROTOCOL_IPSEC;
	conf.action_type = RTE_SECURITY_ACTION_TYPE_INLINE_CRYPTO;
	conf.ipsec.mode = RTE_SECURITY_IPSEC_SA_MODE_TUNNEL;
	conf.ipsec.proto = RTE_SECURITY_IPSEC_SA_PROTO_ESP;
	conf.ipsec.direction = RTE_SECURITY_IPSEC_SA_DIR_EGRESS;

	ret = sxe2_ipsec_egress_construct(cl, &encrypt_xform, param);
	if (ret)
		goto l_end;
	conf.crypto_xform = encrypt_xform;

	session = rte_security_session_create(p_ctx, &conf, g_sess_pool);
	if (session == NULL) {
		ret = -1;
		goto l_free;
	}

	index = sxe2_ipsec_session_mgt_alloc(param->dir, param->port_id);
	if (index == 0XFFFF) {
		ret = -1;
		goto l_free;
	}

	g_tx_session[param->port_id][index].session = session;
	g_tx_session[param->port_id][index].encrypt_algo = param->encrypt_algo;
	g_tx_session[param->port_id][index].auth_algo = param->auth_algo;
	for (i = 0; i < 32; i++) {
		g_tx_session[param->port_id][index].enc_key[i] = param->enc_key[i];
		g_tx_session[param->port_id][index].auth_key[i] = param->auth_key[i];
	}
	ret = 0;

l_free:
	if (encrypt_xform->next)
		rte_free(encrypt_xform->next);
	if (encrypt_xform)
		rte_free(encrypt_xform);

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_egress_destroy, 26.07)
int32_t
sxe2_ipsec_egress_destroy(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	struct rte_security_ctx *p_ctx = NULL;
	struct rte_security_session *session = NULL;
	int32_t ret = -1;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	if (dev->data->dev_started != 0) {
		cmdline_printf(cl, "port %d must be stopped.\n", dev->data->port_id);
		ret = 0;
		goto l_end;
	}

	if (param->session_id >= SXE2_IPSEC_SESSION_MAX) {
		PMD_LOG_ERR(DRV, "Invalid session id.");
		ret = -EINVAL;
		goto l_end;
	}

	if (!g_tx_session[param->port_id][param->session_id].status) {
		PMD_LOG_ERR(DRV, "Invalid session status.");
		ret = -EINVAL;
		goto l_end;
	}

	if (g_tx_session[param->port_id][param->session_id].session == NULL) {
		PMD_LOG_ERR(DRV, "Invalid session data.");
		ret = -EINVAL;
		goto l_end;
	}

	p_ctx = rte_eth_dev_get_sec_ctx(param->port_id);

	session = g_tx_session[param->port_id][param->session_id].session;
	ret = rte_security_session_destroy(p_ctx, session);
	if (ret)
		goto l_end;
	sxe2_ipsec_session_mgt_free(param->dir, param->session_id, param->port_id);

	ret = 0;

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_egress_show, 26.07)
int32_t
sxe2_ipsec_egress_show(struct sxe2_ipsec_conf_param *param, struct cmdline *cl)
{
	struct rte_eth_dev *dev       = NULL;
	int32_t ret = -1;
	uint16_t i;
	uint8_t j;
	char encrypt_key[65];
	char auth_key[65];
	const char *encrypt_algo[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC] = "aes-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_SM4_CBC] = "sm4-cbc",
		[SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL] = "null"
	};

	const char *auth_algo[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX] = {
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC] = "sha-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SM3_HMAC] = "sm3-hmac",
		[SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL] = "null"
	};

	RTE_ETH_VALID_PORTID_OR_ERR_RET(param->port_id, -ENODEV);

	dev = &rte_eth_devices[param->port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		ret = -ENODEV;
		goto l_end;
	}

	for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
		if (g_tx_session[param->port_id][i].status &&
		    g_tx_session[param->port_id][i].session) {
			memset(encrypt_key, '\0', sizeof(encrypt_key));
			memset(auth_key, '\0', sizeof(auth_key));
			for (j = 0; j < 32; j++)
				sprintf(encrypt_key + 2 * j, "%02x",
					g_tx_session[param->port_id][i].enc_key[j]);
			if (g_tx_session[param->port_id][i].auth_algo !=
			    SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL)
				for (j = 0; j < 32; j++)
					sprintf(auth_key + 2 * j, "%02x",
						g_tx_session[param->port_id][i].auth_key[j]);

			cmdline_printf(cl, "id:%u, tx , encrypt_algo:%s,"
				"encrypt_key:0x%s, auth_algo:%s, auth_key:0x%s.\n",
				i,
				encrypt_algo[g_tx_session[param->port_id][i].encrypt_algo],
				encrypt_key,
				auth_algo[g_tx_session[param->port_id][i].auth_algo],
				auth_key);
		}
	}

	ret = 0;

l_end:
	return ret;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_conf_get, 26.07)
int32_t
sxe2_ipsec_conf_get(uint16_t port_id, struct cmdline *cl, char type[])
{
	struct rte_eth_dev *dev = NULL;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		return -ENODEV;
	}
	if (!strcmp(type, "session-id"))
		cmdline_printf(cl, "session-id: %u\n",
			g_tx_sess_id[port_id]);
	else if (!strcmp(type, "esp-hdr-offset"))
		cmdline_printf(cl, "esp-hdr-offset: %u\n",
			g_esp_header_offset[port_id]);
	else
		cmdline_printf(cl, "Invalid type: %s\n", type);

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_conf_set, 26.07)
int32_t
sxe2_ipsec_conf_set(uint16_t port_id, struct cmdline *cl, char type[], uint16_t value)
{
	struct rte_eth_dev *dev = NULL;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		PMD_LOG_ERR(DRV, "Invalid dev.");
		return -ENODEV;
	}
	if (!strcmp(type, "session-id")) {
		if (value >= 4096 || !g_tx_session[port_id][value].status) {
			cmdline_printf(cl, "Invalid session-id: %u,"
				"0 <= value <= 4095 or the session is inactive.\n", value);
			return -EINVAL;
		}
		g_tx_sess_id[port_id] = value;
		cmdline_printf(cl, "session-id: %u\n", g_tx_sess_id[port_id]);
	} else if (!strcmp(type, "esp-hdr-offset")) {
		if (value < 34 || value > 512) {
			cmdline_printf(cl, "Invalid esp-hdr-offset: %u,"
				       "34 <= value <= 512.\n", value);
			return -EINVAL;
		}
		g_esp_header_offset[port_id] = value;
		cmdline_printf(cl, "esp-hdr-offset: %u\n",
			g_esp_header_offset[port_id]);
	} else {
		cmdline_printf(cl, "Invalid type: %s\n", type);
	}

	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_stats_show, 26.07)
int32_t
sxe2_ipsec_stats_show(uint16_t port_id)
{
	(void)port_id;
	return 0;
}


RTE_EXPORT_EXPERIMENTAL_SYMBOL(sxe2_ipsec_flush, 26.07)
int32_t
sxe2_ipsec_flush(uint16_t port_id, struct cmdline *cl)
{
	struct rte_eth_dev   *dev     = NULL;
	struct rte_security_ctx *p_ctx = NULL;
	struct rte_security_session *session = NULL;
	int32_t ret = -1;
	uint16_t i;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	dev = &rte_eth_devices[port_id];
	if (!sxe2_is_supported(dev)) {
		cmdline_printf(cl, "Invalid dev.\n");
		ret = -ENODEV;
		goto l_end;
	}

	if (dev->data->dev_started != 0) {
		cmdline_printf(cl, "port %d must be stopped.\n", dev->data->port_id);
		ret = 0;
		goto l_end;
	}

	p_ctx = rte_eth_dev_get_sec_ctx(port_id);

	g_esp_header_offset[port_id] = 0;
	g_tx_sess_id[port_id] = 0;

	for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
		session = g_tx_session[port_id][i].session;
		if (g_tx_session[port_id][i].status && session) {
			ret = rte_security_session_destroy(p_ctx, session);
			if (ret)
				cmdline_printf(cl, "failed to destroy tx session: %d.\n", i);
			else
				sxe2_ipsec_session_mgt_free(SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS,
							    i, port_id);
		}
	}

	for (i = 0; i < SXE2_IPSEC_SESSION_MAX; i++) {
		session = g_rx_session[port_id][i].session;
		if (g_rx_session[port_id][i].status && session) {
			ret = rte_security_session_destroy(p_ctx, session);
			if (ret)
				cmdline_printf(cl, "failed to destroy rx session: %d.\n", i);
			else
				sxe2_ipsec_session_mgt_free(SXE2_TESTPMD_CMD_IPSEC_DIR_INGRESS,
							    i, port_id);
		}
	}

	g_sxe2_ipsec_mgt_init = false;
	ret = 0;

l_end:
	return ret;
}
