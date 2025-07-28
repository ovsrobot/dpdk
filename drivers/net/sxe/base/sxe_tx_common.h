/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_TX_COMMON_H__
#define __SXE_TX_COMMON_H__

int __sxe_tx_descriptor_status(void *tx_queue, u16 offset);

u16 __sxe_pkts_xmit_with_offload(void *tx_queue, struct rte_mbuf **tx_pkts, u16 pkts_num);

#endif
