/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_FLOW_H_
#define _XSC_FLOW_H_

#include <rte_byteorder.h>

#include "xsc_dev.h"
#include "xsc_utils.h"

/* xsc flow */
struct xsc_ipat_key {
	uint16_t logical_in_port:11;
} __rte_packed;

struct xsc_ipat_action {
	uint64_t rsv0:64;
	uint16_t rsv1:9;
	uint16_t dst_info:11;
	uint64_t rsv2:34;
	uint8_t vld:1;
} __rte_packed;

struct xsc_epat_key {
	uint16_t dst_info:11;
} __rte_packed;

struct xsc_epat_action {
	uint8_t rsv0[14];
	uint8_t rsv1:4;
	uint8_t dst_port:4;
	uint8_t rss_hash_func:2;
	uint8_t rss_hash_template:5;
	uint8_t rss_en:1;
	uint8_t qp_num:8;
	uint16_t rx_qp_id_ofst:12;
	uint16_t rsv3:4;
	uint8_t rsv4:7;
	uint8_t vld:1;
} __rte_packed;

struct xsc_pct_v4_key {
	uint16_t rsv0[20];
	uint16_t rsv1:13;
	uint16_t logical_in_port:11;
	uint8_t rsv2:8;
} __rte_packed;

struct xsc_pct_action {
	uint32_t rsv0:29;
	uint16_t dst_info:11;
	uint8_t rsv1:3;
} __rte_packed;

int xsc_create_pct(struct rte_eth_dev *dev, uint16_t logical_in_port,
	uint16_t dst_info, uint32_t priority);
int xsc_destroy_pct(struct rte_eth_dev *dev, uint16_t logical_in_port, uint32_t priority);
int xsc_create_ipat(struct rte_eth_dev *dev, uint16_t logic_in_port, uint16_t dst_info);
int xsc_destroy_ipat(struct rte_eth_dev *dev, uint16_t logic_in_port);
int xsc_create_epat(struct rte_eth_dev *dev, uint16_t dst_info, uint8_t dst_port,
	uint16_t qpn_ofst, uint8_t qp_num);
int xsc_destroy_epat(struct rte_eth_dev *dev, uint16_t dst_info);

#endif

