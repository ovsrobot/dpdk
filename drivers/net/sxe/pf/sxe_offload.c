/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include "sxe.h"
#include "sxe_offload.h"
#include "sxe_logs.h"
#include "sxe_compat_version.h"
#include "sxe_queue_common.h"
#include "sxe_offload_common.h"

#define SXE_4_BIT_WIDTH  (CHAR_BIT / 2)
#define SXE_4_BIT_MASK   RTE_LEN2MASK(SXE_4_BIT_WIDTH, u8)
#define SXE_8_BIT_WIDTH  CHAR_BIT
#define SXE_8_BIT_MASK   UINT8_MAX

u64 sxe_rx_queue_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_queue_offload_capa_get(dev);
}

u64 sxe_rx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_port_offload_capa_get(dev);
}

u64 sxe_tx_queue_offload_capa_get(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

u64 sxe_tx_port_offload_capa_get(struct rte_eth_dev *dev)
{
	return __sxe_tx_port_offload_capa_get(dev);
}
