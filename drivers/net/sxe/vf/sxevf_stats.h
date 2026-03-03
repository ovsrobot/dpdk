/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXEVF_STATS_H__
#define __SXEVF_STATS_H__

#include "sxevf_hw.h"

struct sxevf_stats_field {
	s8  name[RTE_ETH_XSTATS_NAME_SIZE];
	u32 offset;
};

struct sxevf_stats_info {
	struct sxevf_hw_stats hw_stats;
};

int sxevf_eth_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *stats,
			struct eth_queue_stats *qstats __rte_unused);

s32 sxevf_dev_stats_reset(struct rte_eth_dev *eth_dev);

s32 sxevf_xstats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_xstat *xstats,
				u32 usr_cnt);

s32 sxevf_xstats_names_get(__rte_unused struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, __rte_unused unsigned int usr_cnt);

#endif
