/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_RSS_H_
#define _SSSNIC_ETHDEV_RSS_H_

int sssnic_ethdev_rss_hash_update(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_conf *rss_conf);
int sssnic_ethdev_rss_hash_config_get(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_conf *rss_conf);
int sssnic_ethdev_rss_reta_update(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size);
int sssnic_ethdev_rss_reta_query(struct rte_eth_dev *ethdev,
	struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size);
int sssnic_ethdev_rss_reta_reset(struct rte_eth_dev *ethdev);
int sssnic_ethdev_rss_setup(struct rte_eth_dev *ethdev);
int sssnic_ethdev_rss_shutdown(struct rte_eth_dev *ethdev);

#endif /* _SSSNIC_ETHDEV_RSS_H_ */
