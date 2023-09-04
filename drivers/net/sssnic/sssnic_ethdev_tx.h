/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#ifndef _SSSNIC_ETHDEV_TX_H_
#define _SSSNIC_ETHDEV_TX_H_

struct sssnic_ethdev_txq_stats {
	uint64_t packets;
	uint64_t bytes;
	uint64_t nobuf;
	uint64_t zero_len_segs;
	uint64_t too_large_pkts;
	uint64_t too_many_segs;
	uint64_t null_segs;
	uint64_t offload_errors;
	uint64_t burst;
};

int sssnic_ethdev_tx_queue_setup(struct rte_eth_dev *ethdev,
	uint16_t tx_queue_id, uint16_t nb_tx_desc, unsigned int socket_id,
	const struct rte_eth_txconf *tx_conf);
void sssnic_ethdev_tx_queue_release(struct rte_eth_dev *ethdev,
	uint16_t queue_id);
void sssnic_ethdev_tx_queue_all_release(struct rte_eth_dev *ethdev);
int sssnic_ethdev_tx_queue_start(struct rte_eth_dev *ethdev, uint16_t queue_id);
int sssnic_ethdev_tx_queue_stop(struct rte_eth_dev *ethdev, uint16_t queue_id);
int sssnic_ethdev_tx_queue_all_start(struct rte_eth_dev *ethdev);
void sssnic_ethdev_tx_queue_all_stop(struct rte_eth_dev *ethdev);
int sssnic_ethdev_tx_queues_ctx_init(struct rte_eth_dev *ethdev);
int sssnic_ethdev_tx_offload_ctx_reset(struct rte_eth_dev *ethdev);
uint16_t sssnic_ethdev_tx_queue_depth_get(struct rte_eth_dev *ethdev,
	uint16_t qid);
int sssnic_ethdev_tx_ci_attr_init(struct rte_eth_dev *ethdev);
int sssnic_ethdev_tx_max_size_set(struct rte_eth_dev *ethdev, uint16_t size);
int sssnic_ethdev_tx_queue_stats_get(struct rte_eth_dev *ethdev, uint16_t qid,
	struct sssnic_ethdev_txq_stats *stats);
void sssnic_ethdev_tx_queue_stats_clear(struct rte_eth_dev *ethdev,
	uint16_t qid);
uint16_t sssnic_ethdev_tx_pkt_burst(void *tx_queue, struct rte_mbuf **tx_pkts,
	uint16_t nb_pkts);

#endif /* _SSSNIC_ETHDEV_TX_H_ */
