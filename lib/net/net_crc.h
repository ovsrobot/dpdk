/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _NET_CRC_H_
#define _NET_CRC_H_

#include <rte_compat.h>

__rte_internal
void
rte_net_crc_sse42_init(void);

__rte_internal
uint32_t
rte_crc16_ccitt_sse42_handler(const uint8_t *data, uint32_t data_len);

__rte_internal
uint32_t
rte_crc32_eth_sse42_handler(const uint8_t *data, uint32_t data_len);

__rte_internal
void
rte_net_crc_avx512_init(void);

__rte_internal
uint32_t
rte_crc16_ccitt_avx512_handler(const uint8_t *data, uint32_t data_len);

__rte_internal
uint32_t
rte_crc32_eth_avx512_handler(const uint8_t *data, uint32_t data_len);

__rte_internal
void
rte_net_crc_neon_init(void);

__rte_internal
uint32_t
rte_crc16_ccitt_neon_handler(const uint8_t *data, uint32_t data_len);

__rte_internal
uint32_t
rte_crc32_eth_neon_handler(const uint8_t *data, uint32_t data_len);

#endif /* _NET_CRC_H_ */
