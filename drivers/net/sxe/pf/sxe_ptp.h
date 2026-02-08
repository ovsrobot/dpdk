/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_PTP_H__
#define __SXE_PTP_H__

s32 sxe_timesync_enable(struct rte_eth_dev *dev);

s32 sxe_timesync_disable(struct rte_eth_dev *dev);

s32 sxe_timesync_read_rx_timestamp(struct rte_eth_dev *dev,
				 struct timespec *timestamp,
				 u32 flags __rte_unused);

s32 sxe_timesync_read_tx_timestamp(struct rte_eth_dev *dev,
				 struct timespec *timestamp);

s32 sxe_timesync_adjust_time(struct rte_eth_dev *dev, s64 delta);

s32 sxe_timesync_read_time(struct rte_eth_dev *dev, struct timespec *ts);

s32 sxe_timesync_write_time(struct rte_eth_dev *dev,
					const struct timespec *ts);

#endif
