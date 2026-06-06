/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_TXRX_CHECK_MBUF_H__
#define __SXE2_TXRX_CHECK_MBUF_H__

#include <rte_common.h>
#include <rte_net.h>
#include <rte_vect.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <ethdev_driver.h>

struct offload_info {
	uint16_t ethertype;
	uint8_t  gso_enable;
	uint16_t l2_len;
	uint16_t l3_len;
	uint16_t l4_len;
	uint8_t  l4_proto;
	uint8_t  is_tunnel;
	uint16_t outer_ethertype;
	uint16_t outer_l2_len;
	uint16_t outer_l3_len;
	uint8_t  outer_l4_proto;
	uint16_t tso_segsz;
	uint16_t tunnel_tso_segsz;
	uint32_t pkt_len;
};

struct simple_gre_hdr {
	uint16_t flags;
	uint16_t proto;
};

__rte_unused int32_t sxe2_txrx_check_mbuf(struct rte_mbuf *m);
#endif /* __SXE2_TXRX_CHECK_MBUF_H__ */
