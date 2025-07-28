/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_RX_COMMON_H__
#define __SXE_RX_COMMON_H__

void __rte_cold __sxe_rx_function_set(struct rte_eth_dev *dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed);

s32 __sxe_rx_descriptor_status(void *rx_queue, u16 offset);

u16 __sxe_pkts_recv(void *rx_queue, struct rte_mbuf **rx_pkts,
		u16 pkts_num);

const u32 *__sxe_dev_supported_ptypes_get(struct rte_eth_dev *dev, size_t *no_of_elements);
#endif
