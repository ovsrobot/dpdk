/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_STATS_H_
#define _SSSNIC_ETHDEV_STATS_H_

int sssnic_ethdev_stats_get(struct rte_eth_dev *ethdev,
	struct rte_eth_stats *stats);
int sssnic_ethdev_stats_reset(struct rte_eth_dev *ethdev);
int sssnic_ethdev_xstats_get_names(struct rte_eth_dev *ethdev,
	struct rte_eth_xstat_name *xstats_names,
	__rte_unused unsigned int limit);
int sssnic_ethdev_xstats_get(struct rte_eth_dev *ethdev,
	struct rte_eth_xstat *xstats, unsigned int n);
int sssnic_ethdev_xstats_reset(struct rte_eth_dev *ethdev);

#endif /* _SSSNIC_ETHDEV_STATS_H_ */
