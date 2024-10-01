/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2020 Intel Corporation
 */

#ifndef _RTE_NET_CRC_H_
#define _RTE_NET_CRC_H_

#ifdef __cplusplus
extern "C" {
#endif

/** CRC types */
enum rte_net_crc_type {
	RTE_NET_CRC16_CCITT = 0,
	RTE_NET_CRC32_ETH,
	RTE_NET_CRC_REQS
};

/** CRC compute algorithm */
enum rte_net_crc_alg {
	RTE_NET_CRC_SCALAR = 0,
	RTE_NET_CRC_SSE42,
	RTE_NET_CRC_NEON,
	RTE_NET_CRC_AVX512,
};

struct rte_net_crc {
	enum rte_net_crc_alg alg;
	enum rte_net_crc_type type;
};

struct rte_net_crc rte_net_crc_set(enum rte_net_crc_alg alg,
	enum rte_net_crc_type type);

uint32_t rte_net_crc(const struct rte_net_crc *ctx,
	const void *data, const uint32_t data_len);

#ifdef __cplusplus
}
#endif


#endif /* _RTE_NET_CRC_H_ */
