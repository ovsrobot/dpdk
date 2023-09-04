/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_RX_H_
#define _SSSNIC_ETHDEV_RX_H_

struct sssnic_ethdev_rxq_stats {
	uint64_t packets;
	uint64_t bytes;
	uint64_t csum_errors;
	uint64_t other_errors;
	uint64_t nombuf;
	uint64_t burst;
};

int sssnic_ethdev_rx_queue_setup(struct rte_eth_dev *ethdev,
	uint16_t rx_queue_id, uint16_t nb_rx_desc, unsigned int socket_id,
	const struct rte_eth_rxconf *rx_conf, struct rte_mempool *mb_pool);
void sssnic_ethdev_rx_queue_release(struct rte_eth_dev *ethdev,
	uint16_t queue_id);
void sssnic_ethdev_rx_queue_all_release(struct rte_eth_dev *ethdev);
int sssnic_ethdev_rx_queue_start(struct rte_eth_dev *ethdev, uint16_t queue_id);
int sssnic_ethdev_rx_queue_stop(struct rte_eth_dev *ethdev, uint16_t queue_id);
int sssnic_ethdev_rx_queue_all_start(struct rte_eth_dev *ethdev);
int sssnic_ethdev_rx_queue_all_stop(struct rte_eth_dev *ethdev);

#endif
