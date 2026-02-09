/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_STATS_H__
#define __SXE_STATS_H__

#include <rte_ethdev.h>
#include <rte_ethdev_core.h>
#include <ethdev_driver.h>
#include "sxe_hw.h"

#define SXE_STATS_FIELD_NAME_SIZE  50

struct sxe_sw_stats {
	u64 hw_csum_rx_error;
};

struct sxe_stats_map {
	u32 txq_stats_map[SXE_QUEUE_STATS_MAP_REG_NUM];
	u32 rxq_stats_map[SXE_QUEUE_STATS_MAP_REG_NUM];
};

struct sxe_stats_info {
	struct sxe_sw_stats  sw_stats;
	struct sxe_mac_stats hw_stats;
	struct sxe_stats_map stats_map;
};

struct sxe_stats_field {
	s8  name[SXE_STATS_FIELD_NAME_SIZE];
	u32 offset;
};

int sxe_eth_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *stats,
		      struct eth_queue_stats *qstats);

int sxe_stats_reset(struct rte_eth_dev *eth_dev);

int sxe_xstats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_xstat *xstats,
				u32 cnt);

int sxe_xstats_reset(struct rte_eth_dev *eth_dev);


int sxe_xstats_names_get(__rte_unused struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, __rte_unused unsigned int size);

int sxe_xstats_get_by_id(struct rte_eth_dev *eth_dev,
					const u64 *ids,
					u64 *values, u32 usr_cnt);

int sxe_xstats_names_get_by_id(struct rte_eth_dev *eth_dev,
	const u64 *ids,
	struct rte_eth_xstat_name *xstats_names,
	u32 usr_cnt);


int sxe_queue_stats_mapping_set(struct rte_eth_dev *eth_dev,
				  u16 queue_id,
				  u8 stat_reg_idx,
				  u8 is_rx);

void sxe_queue_stats_map_restore(struct rte_eth_dev *eth_dev);

void sxe_queue_stats_map_reset(struct rte_eth_dev *eth_dev);

#endif
