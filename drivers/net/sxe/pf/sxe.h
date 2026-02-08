/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_H__
#define __SXE_H__

#include <rte_pci.h>
#include <rte_time.h>

#include <stdbool.h>
#include "sxe_types.h"
#include "sxe_filter.h"
#include "sxe_irq.h"
#include "sxe_stats.h"
#include "sxe_phy.h"
#include "sxe_hw.h"

struct sxe_hw;

#define SXE_LPBK_DISABLED   0x0
#define SXE_LPBK_ENABLED	0x1

#define PCI_VENDOR_ID_STARS	  0x1FF2
#define SXE_DEV_ID_ASIC		  0x10a1

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"

#ifdef RTE_PMD_PACKET_PREFETCH
#define rte_packet_prefetch(p)  rte_prefetch1(p)
#else
#define rte_packet_prefetch(p) \
	do { \
	} while (0)
#endif

#define RTE_PMD_USE_PREFETCH

#ifdef RTE_PMD_USE_PREFETCH
#define rte_sxe_prefetch(p)   rte_prefetch0(p)
#else
#define rte_sxe_prefetch(p)   do {} while (0)
#endif

struct sxe_adapter {
	struct sxe_hw hw;

	struct sxe_irq_context irq_ctxt;

	bool rx_batch_alloc_allowed;
	s8 name[PCI_PRI_STR_SIZE + 1];
};

s32 sxe_hw_reset(struct sxe_hw *hw);

void sxe_hw_start(struct sxe_hw *hw);

bool sxe_is_supported(struct rte_eth_dev *dev);

#endif
