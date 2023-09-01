/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "sssnic_ethdev.h"
#include "sssnic_ethdev_rx.h"
#include "sssnic_ethdev_tx.h"
#include "sssnic_ethdev_stats.h"
#include "base/sssnic_hw.h"
#include "base/sssnic_api.h"

struct sssnic_ethdev_xstats_name_off {
	char name[RTE_ETH_XSTATS_NAME_SIZE];
	uint32_t offset;
};

#define SSSNIC_ETHDEV_XSTATS_STR_OFF(stats_type, field)                        \
	{ #field, offsetof(struct stats_type, field) }

#define SSSNIC_ETHDEV_XSTATS_VALUE(data, idx, name_off)                        \
	(*(uint64_t *)(((uint8_t *)(data)) + (name_off)[idx].offset))

#define SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(field)                                 \
	SSSNIC_ETHDEV_XSTATS_STR_OFF(sssnic_ethdev_rxq_stats, field)

#define SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(field)                                 \
	SSSNIC_ETHDEV_XSTATS_STR_OFF(sssnic_ethdev_txq_stats, field)

#define SSSNIC_ETHDEV_PORT_STATS_STR_OFF(field)                                \
	SSSNIC_ETHDEV_XSTATS_STR_OFF(sssnic_port_stats, field)

#define SSSNIC_ETHDEV_MAC_STATS_STR_OFF(field)                                 \
	SSSNIC_ETHDEV_XSTATS_STR_OFF(sssnic_mac_stats, field)

static const struct sssnic_ethdev_xstats_name_off rxq_stats_strings[] = {
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(packets),
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(bytes),
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(csum_errors),
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(other_errors),
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(nombuf),
	SSSNIC_ETHDEV_RXQ_STATS_STR_OFF(burst),
};
#define SSSNIC_ETHDEV_NB_RXQ_XSTATS RTE_DIM(rxq_stats_strings)

static const struct sssnic_ethdev_xstats_name_off txq_stats_strings[] = {
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(packets),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(bytes),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(nobuf),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(zero_len_segs),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(too_large_pkts),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(too_many_segs),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(null_segs),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(offload_errors),
	SSSNIC_ETHDEV_TXQ_STATS_STR_OFF(burst),
};
#define SSSNIC_ETHDEV_NB_TXQ_XSTATS RTE_DIM(txq_stats_strings)

static const struct sssnic_ethdev_xstats_name_off port_stats_strings[] = {
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_ucast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_ucast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_mcast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_mcast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_bcast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_bcast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_discards),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(rx_errors),

	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_ucast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_ucast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_mcast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_mcast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_bcast_pkts),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_bcast_bytes),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_discards),
	SSSNIC_ETHDEV_PORT_STATS_STR_OFF(tx_errors),
};
#define SSSNIC_ETHDEV_NB_PORT_XSTATS RTE_DIM(port_stats_strings)

static const struct sssnic_ethdev_xstats_name_off mac_stats_strings[] = {
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_fragment_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_undersize_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_undermin_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_64b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_65b_127b_pkt),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_128b_255b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_256b_511b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_512b_1023b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_1024b_1518b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_1519b_2047b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_2048b_4095b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_4096b_8191b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_8192b_9216b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_9217b_12287b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_12288b_16383b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_1519b_bad_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_1519b_good_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_oversize_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_jabber_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_bad_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_bad_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_good_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_good_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_total_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_total_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_unicast_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_multicast_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_broadcast_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pause_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri0_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri1_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri2_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri3_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri4_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri5_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri6_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_pfc_pri7_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_control_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_symbol_error_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_fcs_error_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(rx_unfilter_pkts),

	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_fragment_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_undersize_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_undermin_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_64b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_65b_127b_pkt),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_128b_255b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_256b_511b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_512b_1023b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_1024b_1518b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_1519b_2047b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_2048b_4095b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_4096b_8191b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_8192b_9216b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_9217b_12287b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_12288b_16383b_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_1519b_bad_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_1519b_good_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_oversize_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_jabber_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_bad_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_bad_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_good_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_good_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_total_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_total_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_unicast_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_multicast_bytes),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_broadcast_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pause_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri0_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri1_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri2_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri3_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri4_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri5_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri6_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_pfc_pri7_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_control_pkts),
	SSSNIC_ETHDEV_MAC_STATS_STR_OFF(tx_debug_bad_pkts),
};
#define SSSNIC_ETHDEV_NB_MAC_XSTATS RTE_DIM(mac_stats_strings)

int
sssnic_ethdev_stats_get(struct rte_eth_dev *ethdev, struct rte_eth_stats *stats)
{
	struct sssnic_port_stats port_stats;
	struct sssnic_ethdev_rxq_stats rxq_stats;
	struct sssnic_ethdev_txq_stats txq_stats;
	int ret;
	uint16_t numq, qid;

	ret = sssnic_port_stats_get(SSSNIC_ETHDEV_TO_HW(ethdev), &port_stats);
	if (ret != 0) {
		PMD_DRV_LOG(ERR, "Failed to get port stats");
		return ret;
	}

	stats->ipackets = port_stats.rx_ucast_pkts + port_stats.rx_mcast_pkts +
			  port_stats.rx_bcast_pkts;
	stats->ibytes = port_stats.rx_ucast_bytes + port_stats.rx_mcast_bytes +
			port_stats.rx_bcast_bytes;
	stats->opackets = port_stats.tx_ucast_pkts + port_stats.tx_mcast_pkts +
			  port_stats.tx_bcast_pkts;
	stats->obytes = port_stats.tx_ucast_bytes + port_stats.tx_mcast_bytes +
			port_stats.tx_bcast_bytes;

	stats->imissed = port_stats.rx_discards;
	stats->oerrors = port_stats.tx_discards;

	ethdev->data->rx_mbuf_alloc_failed = 0;

	numq = RTE_MIN(ethdev->data->nb_rx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	for (qid = 0; qid < numq; qid++) {
		sssnic_ethdev_rx_queue_stats_get(ethdev, qid, &rxq_stats);
		stats->q_ipackets[qid] = rxq_stats.packets;
		stats->q_ibytes[qid] = rxq_stats.bytes;
		stats->ierrors +=
			rxq_stats.csum_errors + rxq_stats.other_errors;
		ethdev->data->rx_mbuf_alloc_failed += rxq_stats.nombuf;
	}

	numq = RTE_MIN(ethdev->data->nb_tx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	for (qid = 0; qid < numq; qid++) {
		sssnic_ethdev_tx_queue_stats_get(ethdev, qid, &txq_stats);
		stats->q_opackets[qid] = txq_stats.packets;
		stats->q_obytes[qid] = txq_stats.bytes;
		stats->oerrors += txq_stats.nobuf + txq_stats.too_large_pkts +
				  txq_stats.zero_len_segs +
				  txq_stats.offload_errors +
				  txq_stats.null_segs + txq_stats.too_many_segs;
	}

	return 0;
}

int
sssnic_ethdev_stats_reset(struct rte_eth_dev *ethdev)
{
	int ret;
	uint16_t numq, qid;

	ret = sssnic_port_stats_clear(SSSNIC_ETHDEV_TO_HW(ethdev));
	if (ret)
		PMD_DRV_LOG(ERR, "Failed to clear port stats");

	numq = RTE_MIN(ethdev->data->nb_rx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	for (qid = 0; qid < numq; qid++)
		sssnic_ethdev_rx_queue_stats_clear(ethdev, qid);

	numq = RTE_MIN(ethdev->data->nb_tx_queues, RTE_ETHDEV_QUEUE_STAT_CNTRS);
	for (qid = 0; qid < numq; qid++)
		sssnic_ethdev_tx_queue_stats_clear(ethdev, qid);

	return 0;
}

static uint32_t
sssnic_ethdev_xstats_num_calc(struct rte_eth_dev *ethdev)
{
	return SSSNIC_ETHDEV_NB_PORT_XSTATS + SSSNIC_ETHDEV_NB_MAC_XSTATS +
	       (SSSNIC_ETHDEV_NB_TXQ_XSTATS * ethdev->data->nb_tx_queues) +
	       (SSSNIC_ETHDEV_NB_RXQ_XSTATS * ethdev->data->nb_rx_queues);
}

int
sssnic_ethdev_xstats_get_names(struct rte_eth_dev *ethdev,
	struct rte_eth_xstat_name *xstats_names,
	__rte_unused unsigned int limit)
{
	uint16_t i, qid, count = 0;

	if (xstats_names == NULL)
		return sssnic_ethdev_xstats_num_calc(ethdev);

	for (qid = 0; qid < ethdev->data->nb_rx_queues; qid++) {
		for (i = 0; i < SSSNIC_ETHDEV_NB_RXQ_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				RTE_ETH_XSTATS_NAME_SIZE, "rx_q%u_%s", qid,
				rxq_stats_strings[i].name);
			count++;
		}
	}

	for (qid = 0; qid < ethdev->data->nb_tx_queues; qid++) {
		for (i = 0; i < SSSNIC_ETHDEV_NB_TXQ_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				RTE_ETH_XSTATS_NAME_SIZE, "tx_q%u_%s", qid,
				txq_stats_strings[i].name);
			count++;
		}
	}

	for (i = 0; i < SSSNIC_ETHDEV_NB_PORT_XSTATS; i++) {
		snprintf(xstats_names[count].name, RTE_ETH_XSTATS_NAME_SIZE,
			"port_%s", port_stats_strings[i].name);
		count++;
	}

	for (i = 0; i < SSSNIC_ETHDEV_NB_MAC_XSTATS; i++) {
		snprintf(xstats_names[count].name, RTE_ETH_XSTATS_NAME_SIZE,
			"mac_%s", mac_stats_strings[i].name);
		count++;
	}

	return count;
}

int
sssnic_ethdev_xstats_get(struct rte_eth_dev *ethdev,
	struct rte_eth_xstat *xstats, unsigned int n)
{
	struct sssnic_hw *hw = SSSNIC_ETHDEV_TO_HW(ethdev);
	int ret;
	uint16_t i, qid, count = 0;
	struct {
		struct sssnic_ethdev_rxq_stats rxq;
		struct sssnic_ethdev_txq_stats txq;
		struct sssnic_port_stats port;
		struct sssnic_mac_stats mac;
	} *stats;

	if (n < sssnic_ethdev_xstats_num_calc(ethdev))
		return count;

	stats = rte_zmalloc(NULL, sizeof(*stats), 0);
	if (stats == NULL) {
		PMD_DRV_LOG(ERR, "Failed to alloc memory for xstats");
		return -ENOMEM;
	}

	for (qid = 0; qid < ethdev->data->nb_rx_queues; qid++) {
		sssnic_ethdev_rx_queue_stats_get(ethdev, qid, &stats->rxq);
		for (i = 0; i < SSSNIC_ETHDEV_NB_RXQ_XSTATS; i++) {
			xstats[count].value =
				SSSNIC_ETHDEV_XSTATS_VALUE(&stats->rxq, i,
					rxq_stats_strings);
			count++;
		}
	}

	for (qid = 0; qid < ethdev->data->nb_tx_queues; qid++) {
		sssnic_ethdev_tx_queue_stats_get(ethdev, qid, &stats->txq);
		for (i = 0; i < SSSNIC_ETHDEV_NB_TXQ_XSTATS; i++) {
			xstats[count].value =
				SSSNIC_ETHDEV_XSTATS_VALUE(&stats->txq,
					i, txq_stats_strings);
			count++;
		}
	}

	ret = sssnic_port_stats_get(hw, &stats->port);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to get port %u stats",
			ethdev->data->port_id);
		goto out;
	}

	for (i = 0; i < SSSNIC_ETHDEV_NB_PORT_XSTATS; i++) {
		xstats[count].value = SSSNIC_ETHDEV_XSTATS_VALUE(&stats->port,
			i, port_stats_strings);
		count++;
	}

	ret = sssnic_mac_stats_get(hw, &stats->mac);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to get port %u mac stats",
			ethdev->data->port_id);
		goto out;
	}

	for (i = 0; i < SSSNIC_ETHDEV_NB_MAC_XSTATS; i++) {
		xstats[count].value = SSSNIC_ETHDEV_XSTATS_VALUE(&stats->mac, i,
			mac_stats_strings);
		count++;
	}

	ret = count;

out:
	rte_free(stats);
	return ret;
}

int
sssnic_ethdev_xstats_reset(struct rte_eth_dev *ethdev)
{
	int ret;

	ret = sssnic_ethdev_stats_reset(ethdev);
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to clear port %u  basic stats",
			ethdev->data->port_id);
		return ret;
	}

	ret = sssnic_mac_stats_clear(SSSNIC_ETHDEV_TO_HW(ethdev));
	if (ret) {
		PMD_DRV_LOG(ERR, "Failed to clear port %u MAC stats",
			ethdev->data->port_id);
		return ret;
	}

	return 0;
}
