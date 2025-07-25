/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>

#include "sxe_types.h"
#include "sxe_offload_common.h"
#include "sxevf_offload.h"

u64 sxevf_rx_queue_offloads_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_queue_offload_capa_get(dev);
}

u64 sxevf_rx_port_offloads_get(struct rte_eth_dev *dev)
{
	return __sxe_rx_port_offload_capa_get(dev);
}

u64 sxevf_tx_queue_offloads_get(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);

	return 0;
}

u64 sxevf_tx_port_offloads_get(struct rte_eth_dev *dev)
{
	return __sxe_tx_port_offload_capa_get(dev);
}
