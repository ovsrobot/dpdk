/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2016 Mellanox Technologies, Ltd
 */

#ifndef _RTE_ESP_H_
#define _RTE_ESP_H_

/**
 * @file
 *
 * ESP-related defines
 */

#include <assert.h>
#include <stdalign.h>

#include <rte_byteorder.h>

/**
 * ESP Header
 */
struct __rte_aligned(2) rte_esp_hdr {
	rte_be32_t spi;  /**< Security Parameters Index */
	rte_be32_t seq;  /**< packet sequence number */
} __rte_packed;

static_assert(sizeof(struct rte_esp_hdr) == 8,
		"sizeof(struct rte_esp_hdr) == 8");
static_assert(alignof(struct rte_esp_hdr) == 2,
		"alignof(struct rte_esp_hdr) == 2");

/**
 * ESP Trailer
 */
struct rte_esp_tail {
	uint8_t pad_len;     /**< number of pad bytes (0-255) */
	uint8_t next_proto;  /**< IPv4 or IPv6 or next layer header */
} __rte_packed;

#endif /* RTE_ESP_H_ */
