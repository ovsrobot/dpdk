/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2020 Intel Corporation
 */

#ifndef _RTE_NET_CRC_H_
#define _RTE_NET_CRC_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef uint32_t
(*rte_net_crc_handler)(const uint8_t *data, uint32_t data_len);

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
	enum rte_net_crc_type type;
	rte_net_crc_handler crc;
};

/**
 * This API set the CRC computation algorithm (i.e. scalar version,
 * x86 64-bit sse4.2 intrinsic version, etc.) and internal data
 * structure.
 *
 * @param alg
 *   This parameter is used to select the CRC implementation version.
 *   - RTE_NET_CRC_SCALAR
 *   - RTE_NET_CRC_SSE42 (Use 64-bit SSE4.2 intrinsic)
 *   - RTE_NET_CRC_NEON (Use ARM Neon intrinsic)
 *   - RTE_NET_CRC_AVX512 (Use 512-bit AVX intrinsic)
 */
void
rte_net_crc_set_alg(enum rte_net_crc_alg alg);

/**
 * CRC compute API
 *
 * @param data
 *   Pointer to the packet data for CRC computation
 * @param data_len
 *   Data length for CRC computation
 * @param type
 *   CRC type (enum rte_net_crc_type)
 *
 * @return
 *   CRC value
 */
uint32_t
rte_net_crc_calc(const void *data,
	uint32_t data_len,
	enum rte_net_crc_type type);

struct rte_net_crc rte_net_crc_set(enum rte_net_crc_type type,
	enum rte_net_crc_alg alg);

uint32_t rte_net_crc(const struct rte_net_crc *ctx,
	const void *data, const uint32_t data_len);

#ifdef __cplusplus
}
#endif


#endif /* _RTE_NET_CRC_H_ */
