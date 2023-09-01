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

#endif /* _SSSNIC_ETHDEV_TX_H_ */
