/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_COMPAT_VERSION_H__
#define __SXE_COMPAT_VERSION_H__

#include <stdbool.h>

struct rte_eth_dev;
enum rte_eth_event_type;

int sxe_eth_dev_callback_process(struct rte_eth_dev *dev,
	enum rte_eth_event_type event, void *ret_param);

#define PCI_REG_WC_WRITE

#ifndef PCI_REG_WC_WRITE
#define rte_write32_wc rte_write32
#define rte_write32_wc_relaxed rte_write32_relaxed
#endif

#define SXE_PCI_INTR_HANDLE(pci_dev) \
	((pci_dev)->intr_handle)
#define SXE_DEV_FNAV_CONF(dev) \
	(&((struct sxe_adapter *)(dev)->data->dev_private)->fnav_conf)
#define RTE_ADAPTER_HAVE_FNAV_CONF
#define SXE_GET_FRAME_SIZE(dev) \
	((dev)->data->mtu + SXE_ETH_OVERHEAD)

#define DEV_RX_OFFLOAD_CHECKSUM RTE_ETH_RX_OFFLOAD_CHECKSUM
#define ETH_DCB_NUM_USER_PRIORITIES RTE_ETH_DCB_NUM_USER_PRIORITIES

#endif
