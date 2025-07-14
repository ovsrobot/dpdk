/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_OFFLOAD_COMMON_H__
#define __SXE_OFFLOAD_COMMON_H__

u64 __sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev);

u64 __sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev);

u64 __sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev);

#endif
