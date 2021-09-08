/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2021 Beijing WangXun Technology Co., Ltd.
 * Copyright(c) 2010-2017 Intel Corporation
 */

#ifndef NGBE_IPSEC_H_
#define NGBE_IPSEC_H_

#include <rte_ethdev.h>
#include <rte_ethdev_core.h>
#include <rte_security.h>

#define IPSRXMOD_VALID                                    0x00000001
#define IPSRXMOD_PROTO                                    0x00000004
#define IPSRXMOD_DECRYPT                                  0x00000008
#define IPSRXMOD_IPV6                                     0x00000010

#define IPSEC_MAX_RX_IP_COUNT           16
#define IPSEC_MAX_SA_COUNT              16

#define ESP_ICV_SIZE 16
#define ESP_TRAILER_SIZE 2

enum ngbe_operation {
	NGBE_OP_AUTHENTICATED_ENCRYPTION,
	NGBE_OP_AUTHENTICATED_DECRYPTION
};

/**
 * Generic IP address structure
 * TODO: Find better location for this rte_net.h possibly.
 **/
struct ipaddr {
	enum ipaddr_type {
		IPv4,
		IPv6
	} type;
	/**< IP Address Type - IPv4/IPv6 */

	union {
		uint32_t ipv4;
		uint32_t ipv6[4];
	};
};

/** inline crypto private session structure */
struct ngbe_crypto_session {
	enum ngbe_operation op;
	const uint8_t *key;
	uint32_t key_len;
	uint32_t salt;
	uint32_t sa_index;
	uint32_t spi;
	struct ipaddr src_ip;
	struct ipaddr dst_ip;
	struct rte_eth_dev *dev;
} __rte_cache_aligned;

struct ngbe_crypto_rx_ip_table {
	struct ipaddr ip;
	uint16_t ref_count;
};
struct ngbe_crypto_rx_sa_table {
	uint32_t spi;
	uint32_t ip_index;
	uint8_t  mode;
	uint8_t  used;
};

struct ngbe_crypto_tx_sa_table {
	uint32_t spi;
	uint8_t  used;
};

union ngbe_crypto_tx_desc_md {
	uint64_t data;
	struct {
		/**< SA table index */
		uint32_t sa_idx;
		/**< ICV and ESP trailer length */
		uint8_t pad_len;
		/**< enable encryption */
		uint8_t enc;
	};
};

struct ngbe_ipsec {
	struct ngbe_crypto_rx_ip_table rx_ip_tbl[IPSEC_MAX_RX_IP_COUNT];
	struct ngbe_crypto_rx_sa_table rx_sa_tbl[IPSEC_MAX_SA_COUNT];
	struct ngbe_crypto_tx_sa_table tx_sa_tbl[IPSEC_MAX_SA_COUNT];
};

int ngbe_crypto_enable_ipsec(struct rte_eth_dev *dev);

#endif /*NGBE_IPSEC_H_*/
