/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_IRQ_H__
#define __SXE2_IRQ_H__

#include <ethdev_driver.h>

#include "sxe2_type.h"
#include "sxe2_drv_cmd.h"

#define SXE2_IRQ_MAX_CNT 2048

#define SXE2_LAN_MSIX_MIN_CNT 1

#define SXE2_EVENT_IRQ_IDX 0

#define SXE2_MAX_INTR_QUEUE_NUM   256

#define SXE2_IRQ_NAME_MAX_LEN     (IFNAMSIZ + 16)

#define SXE2_ITR_1000K  1
#define SXE2_ITR_500K   2
#define SXE2_ITR_50K    20

#define SXE2_ITR_INTERVAL_NORMAL  (SXE2_ITR_50K)
#define SXE2_ITR_INTERVAL_LOW     (SXE2_ITR_1000K)

struct sxe2_fwc_msix_caps;
struct sxe2_adapter;

struct sxe2_irq_context {
	struct rte_intr_handle *reset_handle;
	s32 reset_event_fd;
	s32 other_event_fd;

	u16 max_cnt_hw;
	u16 base_idx_in_func;

	u16 rxq_avail_cnt;
	u16 rxq_base_idx_in_pf;

	u16 rxq_irq_cnt;
	u32 *rxq_msix_idx;
	s32 *rxq_event_fd;
};

#endif
