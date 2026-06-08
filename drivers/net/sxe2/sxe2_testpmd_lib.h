
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_TESTPMD_LIB_H__
#define __SXE2_TESTPMD_LIB_H__
#include <cmdline.h>
#include "sxe2_ipsec.h"

#define SXE2_IPSEC_SESSION_MAX (4096)
#define SXE2_IPSEC_PORT_MAX  RTE_MAX_ETHPORTS
#define MEMPOOL_CACHE_SIZE (512 / 2)

enum {
	SXE2_TESTPMD_CMD_UDP_TUNNEL_ADD = 0,
	SXE2_TESTPMD_CMD_UDP_TUNNEL_DEL = 1,
	SXE2_TESTPMD_CMD_UDP_TUNNEL_GET = 2,
	SXE2_TESTPMD_CMD_UDP_TUNNEL_MAX,
};

enum sxe2_testpmd_ipsec_op {
	SXE2_TESTPMD_CMD_IPSEC_OP_ADD = 0,
	SXE2_TESTPMD_CMD_IPSEC_OP_RM = 1,
	SXE2_TESTPMD_CMD_IPSEC_OP_SHOW = 2,
	SXE2_TESTPMD_CMD_IPSEC_OP_MAX,
};

enum sxe2_testpmd_ipsec_dir {
	SXE2_TESTPMD_CMD_IPSEC_DIR_EGRESS = 0,
	SXE2_TESTPMD_CMD_IPSEC_DIR_INGRESS = 1,
	SXE2_TESTPMD_CMD_IPSEC_DIR_MAX,
};

enum sxe2_testpmd_ipsec_encrypt_algo {
	SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_AES_CBC = 0,
	SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_SM4_CBC = 1,
	SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_NULL = 2,
	SXE2_TESTPMD_CMD_IPSEC_EN_ALGO_MAX,
};

enum sxe2_testpmd_ipsec_auth_algo {
	SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SHA_HMAC = 0,
	SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_SM3_HMAC = 1,
	SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_NULL = 2,
	SXE2_TESTPMD_CMD_IPSEC_AUTH_ALGO_MAX,
};

struct sxe2_ipsec_conf_param {
	enum sxe2_testpmd_ipsec_dir dir;
	enum sxe2_testpmd_ipsec_op op;
	enum sxe2_testpmd_ipsec_encrypt_algo encrypt_algo;
	enum sxe2_testpmd_ipsec_auth_algo auth_algo;
	struct sxe2_ipsec_ip_param ip_addr;
	uint32_t spi;
	uint16_t port_id;
	uint16_t session_id;
	uint16_t sport;
	uint16_t dport;
	uint8_t enc_key[32];
	uint8_t enc_len;
	uint8_t auth_key[32];
	uint8_t auth_len;
};

struct sxe2_ipsec_session_mgt {
	void *session;
	enum sxe2_testpmd_ipsec_encrypt_algo encrypt_algo;
	enum sxe2_testpmd_ipsec_auth_algo auth_algo;
	struct sxe2_ipsec_ip_param ip_addr;
	uint32_t spi;
	uint16_t session_id;
	uint16_t sport;
	uint16_t dport;
	uint8_t enc_key[32];
	uint8_t auth_key[32];
	uint8_t status;
};

__rte_experimental
int32_t
sxe2_testpmd_sched_reset(uint16_t port_id);

__rte_experimental
int32_t
sxe2_flow_rule_dump(uint16_t port_id, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_udp_tunnel_operations(uint16_t port_id, struct cmdline *cl, uint8_t action,
			   uint16_t udp_port, const char *tunnel_type);

__rte_experimental
int32_t
sxe2_stats_info_show(uint16_t port_id);

__rte_experimental
int32_t
sxe2_ipsec_ingress_create(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_ingress_destroy(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_ingress_show(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_egress_create(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_egress_destroy(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_egress_show(struct sxe2_ipsec_conf_param *param, struct cmdline *cl);

__rte_experimental
int32_t
sxe2_ipsec_conf_get(uint16_t port_id, struct cmdline *cl, char type[]);

__rte_experimental
int32_t
sxe2_ipsec_conf_set(uint16_t port_id, struct cmdline *cl, char type[], uint16_t value);

__rte_experimental
int32_t
sxe2_ipsec_stats_show(uint16_t port_id);

__rte_experimental
int32_t
sxe2_ipsec_flush(uint16_t port_id, struct cmdline *cl);

extern struct sxe2_ipsec_session_mgt g_tx_session[SXE2_IPSEC_PORT_MAX][SXE2_IPSEC_SESSION_MAX];
extern uint16_t g_tx_sess_id[SXE2_IPSEC_PORT_MAX];
extern uint16_t g_esp_header_offset[SXE2_IPSEC_PORT_MAX];
extern struct rte_mempool *g_sess_pool;

#endif /* __SXE2_TESTPMD_LIB_H__ */
