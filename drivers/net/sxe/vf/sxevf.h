/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXEVF_H__
#define __SXEVF_H__

#include <rte_pci.h>

#include "sxevf_irq.h"
#include "sxevf_hw.h"
#include "sxevf_filter.h"
#include "sxevf_stats.h"

#define SXEVF_DEVARG_LINK_CHECK		   "link_check"

struct sxevf_adapter {
	s8 name[PCI_PRI_STR_SIZE + 1];
	u8 max_rx_queue;
	u8 max_tx_queue;

	struct sxevf_hw hw;
	struct sxevf_irq_context irq_ctxt;
	struct sxevf_vlan_context vlan_ctxt;
	struct sxevf_mac_filter_context mac_filter_ctxt;
	struct sxevf_stats_info stats_info;

	pthread_t link_thread_tid;
	u8 link_check;
	bool stop;
	bool rx_batch_alloc_allowed;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SIMD
	bool rx_vec_allowed;
#endif
	u8 rss_reta_updated;
};

struct sxevf_thread_param {
	struct rte_eth_dev *dev;
	pthread_barrier_t barrier;
};

#endif
