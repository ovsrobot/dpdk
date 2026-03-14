/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include "sxe_stats.h"
#include "sxe.h"
#include "sxe_logs.h"
#include "sxe_errno.h"
#include "sxe_queue.h"
#include "sxe_compat_platform.h"
#include <rte_string_fns.h>

#define SXE_STAT_MAP_WIDTH 8
#define SXE_STAT_MAP_CNT 4
#define SXE_STAT_MAP_MASK 0x0F

#define SXE_QUEUE_STAT_COUNT ARRAY_SIZE(stats_info->hw_stats.qprc)

static const struct sxe_stats_field sxe_xstats_sw_field[] = {
	{"rx_l3_l4_xsum_error", offsetof(struct sxe_sw_stats,
		hw_csum_rx_error)},
};

static const struct sxe_stats_field sxe_xstats_mac_field[] = {
	{"rx_crc_errors", offsetof(struct sxe_mac_stats, crcerrs)},
	{"rx_error_bytes", offsetof(struct sxe_mac_stats, errbc)},
	{"rx_length_errors", offsetof(struct sxe_mac_stats, rlec)},
	{"rx_size_64_packets", offsetof(struct sxe_mac_stats, prc64)},
	{"rx_size_65_to_127_packets", offsetof(struct sxe_mac_stats, prc127)},
	{"rx_size_128_to_255_packets", offsetof(struct sxe_mac_stats, prc255)},
	{"rx_size_256_to_511_packets", offsetof(struct sxe_mac_stats, prc511)},
	{"rx_size_512_to_1023_packets", offsetof(struct sxe_mac_stats,
		prc1023)},
	{"rx_size_1024_to_max_packets", offsetof(struct sxe_mac_stats,
		prc1522)},
	{"rx_broadcast_packets", offsetof(struct sxe_mac_stats, bprc)},
	{"rx_multicast_packets", offsetof(struct sxe_mac_stats, mprc)},
	{"rx_fragment_errors", offsetof(struct sxe_mac_stats, rfc)},
	{"rx_undersize_errors", offsetof(struct sxe_mac_stats, ruc)},
	{"rx_oversize_errors", offsetof(struct sxe_mac_stats, roc)},
	{"rx_jabber_errors", offsetof(struct sxe_mac_stats, rjc)},
	{"rx_size_packets", offsetof(struct sxe_mac_stats, tpr)},
	{"rx_size_bytes", offsetof(struct sxe_mac_stats, tor)},
	{"tx_size_packets", offsetof(struct sxe_mac_stats, tpt)},
	{"tx_size_64_packets", offsetof(struct sxe_mac_stats, ptc64)},
	{"tx_size_65_to_127_packets", offsetof(struct sxe_mac_stats, ptc127)},
	{"tx_size_128_to_255_packets", offsetof(struct sxe_mac_stats, ptc255)},
	{"tx_size_256_to_511_packets", offsetof(struct sxe_mac_stats, ptc511)},
	{"tx_size_512_to_1023_packets", offsetof(struct sxe_mac_stats,
		ptc1023)},
	{"tx_size_1024_to_max_packets", offsetof(struct sxe_mac_stats,
		ptc1522)},
	{"tx_multicast_packets", offsetof(struct sxe_mac_stats, mptc)},
	{"tx_broadcast_packets", offsetof(struct sxe_mac_stats, bptc)},

	{"flow_navigator_add_filters", offsetof(struct sxe_mac_stats,
		fnavadd)},
	{"flow_navigator_remove_filters", offsetof(struct sxe_mac_stats,
		fnavrmv)},
	{"flow_navigator_filters_add_errs", offsetof(struct sxe_mac_stats,
		fnavadderr)},
	{"flow_navigator_filters_remove_errs", offsetof(struct sxe_mac_stats,
		fnavrmverr)},
	{"flow_navigator_matched_filters", offsetof(struct sxe_mac_stats,
		fnavmatch)},
	{"flow_navigator_missed_filters", offsetof(struct sxe_mac_stats,
		fnavmiss)},
};

static const struct sxe_stats_field sxe_xstats_fc_field[] = {
	{"dropped", offsetof(struct sxe_mac_stats, mpc)},
	{"rx_xon_xoff_packets", offsetof(struct sxe_mac_stats, prcpf)},
	{"tx_xon_xoff_packets", offsetof(struct sxe_mac_stats, pfct)},
};

#define SXE_XSTAT_SW_CNT  ARRAY_SIZE(sxe_xstats_sw_field)

#define SXE_XSTAT_MAC_CNT ARRAY_SIZE(sxe_xstats_mac_field)

#define SXE_XSTAT_FC_CNT ARRAY_SIZE(sxe_xstats_fc_field)

#define SXE_FC_PRIO_VALUES 8

#define SXE_XSTAT_CNT  (SXE_XSTAT_MAC_CNT + SXE_XSTAT_SW_CNT + \
			SXE_XSTAT_FC_CNT * SXE_FC_PRIO_VALUES)

#ifdef SXE_TEST
u32 sxe_xstats_cnt_get(void)
{
	return SXE_XSTAT_CNT;
}
#endif

int sxe_eth_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *stats,
		      struct eth_queue_stats *qstats)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_stats_info *stats_info = &adapter->stats_info;
	struct sxe_hw *hw = &adapter->hw;
	u32 i;
	u64 rx_packets = 0;
	u64 rx_bytes = 0;
	s32 ret = 0;

	sxe_hw_stats_get(hw, &stats_info->hw_stats);

	if (stats == NULL) {
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "input param stats is null.");
		goto l_out;
	}

	for (i = 0; i < SXE_QUEUE_STAT_COUNT; i++) {
		rx_packets += stats_info->hw_stats.qprc[i];
		rx_bytes += stats_info->hw_stats.qbrc[i];
		if (qstats && i < RTE_ETHDEV_QUEUE_STAT_CNTRS) {
			qstats->q_ipackets[i] = stats_info->hw_stats.qprc[i];
			qstats->q_opackets[i] = stats_info->hw_stats.qptc[i];
			qstats->q_ibytes[i] = stats_info->hw_stats.qbrc[i];
			qstats->q_obytes[i] = stats_info->hw_stats.qbtc[i];
			qstats->q_errors[i] = stats_info->hw_stats.qprdc[i];
		}
	}

	stats->ipackets = rx_packets;
	stats->ibytes = rx_bytes;
	stats->opackets = stats_info->hw_stats.gptc;
	stats->obytes = stats_info->hw_stats.gotc;

	stats->imissed  = 0;
	stats->ierrors  = stats_info->hw_stats.crcerrs +
			  stats_info->hw_stats.rlec +
			  stats_info->hw_stats.ruc +
			  stats_info->hw_stats.roc +
			  stats_info->hw_stats.rfc;

	stats->oerrors  = 0;

l_out:
	return ret;
}

static s32 sxe_hw_xstat_offset_get(u32 id, u32 *offset)
{
	s32 ret = 0;
	u32 size = SXE_XSTAT_MAC_CNT;

	if (id < size) {
		*offset = sxe_xstats_mac_field[id].offset;
	} else {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "invalid id:%u exceed stats size cnt:%u.",
				id, size);
	}

	return ret;
}

static s32 sxe_sw_xstat_offset_get(u32 id, u32 *offset)
{
	s32 ret = 0;
	u32 size = SXE_XSTAT_SW_CNT;

	if (id < size) {
		*offset = sxe_xstats_sw_field[id].offset;
	} else {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "invalid id:%u exceed stats size cnt:%u.",
				id, size);
	}

	return ret;
}

static s32 sxe_fc_xstat_field_offset_get(u32 id, u8 priority, u32 *offset)
{
	s32 ret = 0;
	u32 size = SXE_XSTAT_FC_CNT;

	if (id < size) {
		*offset = sxe_xstats_fc_field[id].offset + (sizeof(u64) * priority);
	} else {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "invalid id:%u exceed stats size cnt:%u.",
				id, size);
	}

	return ret;
}

static void sxe_sw_stats_get(struct rte_eth_dev *eth_dev,
				struct sxe_sw_stats *stats)
{
	u32 i;
	u64 hw_csum_rx_error = 0;
	sxe_rx_queue_s *rxq;

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		hw_csum_rx_error += rxq->rx_stats.csum_err;
	}
	stats->hw_csum_rx_error = hw_csum_rx_error;
}

int sxe_xstats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_xstat *xstats,
				u32 usr_cnt)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_stats_info *stats_info = &adapter->stats_info;
	struct sxe_hw *hw = &adapter->hw;
	u32 i;
	u32 cnt;
	s32 ret;
	u32 offset;
	u8 prio;

	cnt = SXE_XSTAT_CNT;
	PMD_LOG_INFO(DRV, "xstat size:%u. hw xstat field cnt: %" SXE_PRIU64
			"fc xstat field cnt: %" SXE_PRIU64, cnt,
			(u64)SXE_XSTAT_MAC_CNT, (u64)SXE_XSTAT_FC_CNT);

	if (usr_cnt < cnt) {
		ret = cnt;
		PMD_LOG_ERR(DRV, "user usr_cnt:%u less than stats cnt:%u.",
				usr_cnt, cnt);
		goto l_out;
	}

	sxe_hw_stats_get(hw, &stats_info->hw_stats);
	sxe_sw_stats_get(eth_dev, &stats_info->sw_stats);

	if (xstats == NULL) {
		ret = 0;
		PMD_LOG_ERR(DRV, "usr_cnt:%u, input param xstats is null.", usr_cnt);
		goto l_out;
	}

	cnt = 0;
	for (i = 0; i < SXE_XSTAT_MAC_CNT; i++) {
		sxe_hw_xstat_offset_get(i, &offset);
		xstats[cnt].value = *(u64 *)(((s8 *)(&stats_info->hw_stats)) + offset);
		xstats[cnt].id = cnt;
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_SW_CNT; i++) {
		sxe_sw_xstat_offset_get(i, &offset);
		xstats[cnt].value = *(u64 *)(((s8 *)(&stats_info->sw_stats)) + offset);
		xstats[cnt].id = cnt;
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_FC_CNT; i++) {
		for (prio = 0; prio < SXE_FC_PRIO_VALUES; prio++) {
			sxe_fc_xstat_field_offset_get(i, prio, &offset);
			xstats[cnt].value = *(u64 *)(((s8 *)(&stats_info->hw_stats))
					  + offset);
			xstats[cnt].id = cnt;
			cnt++;
		}
	}

	ret = cnt;
	PMD_LOG_INFO(DRV, "usr_cnt:%u stats cnt:%u stats done.", usr_cnt, cnt);

l_out:
	return ret;
}

int sxe_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_stats_info *stats_info = &adapter->stats_info;
	struct sxe_hw *hw = &adapter->hw;
	sxe_rx_queue_s *rxq;
	u32 i;

	sxe_eth_stats_get(eth_dev, NULL, NULL);
	sxe_hw_stats_seq_clean(hw, &stats_info->hw_stats);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		memset(&rxq->rx_stats, 0, sizeof(rxq->rx_stats));
	}

	memset(&stats_info->hw_stats, 0, sizeof(stats_info->hw_stats));
	memset(&stats_info->sw_stats, 0, sizeof(stats_info->sw_stats));

	return 0;
}

int sxe_xstats_reset(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_stats_info *stats_info = &adapter->stats_info;
	struct sxe_hw *hw = &adapter->hw;
	sxe_rx_queue_s *rxq;
	u32 size = SXE_XSTAT_CNT;
	u32 i;

	sxe_xstats_get(eth_dev, NULL, size);
	sxe_hw_stats_seq_clean(hw, &stats_info->hw_stats);

	for (i = 0; i < eth_dev->data->nb_rx_queues; i++) {
		rxq = eth_dev->data->rx_queues[i];
		memset(&rxq->rx_stats, 0, sizeof(rxq->rx_stats));
	}

	memset(&stats_info->hw_stats, 0, sizeof(stats_info->hw_stats));
	memset(&stats_info->sw_stats, 0, sizeof(stats_info->sw_stats));

	return 0;
}

int sxe_xstats_names_get(__rte_unused struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, __rte_unused unsigned int usr_cnt)
{
	u32 i = 0;
	u32 cnt = 0;
	s32 ret;
	u8 prio;

	if (xstats_names == NULL) {
		ret = SXE_XSTAT_CNT;
		PMD_LOG_INFO(DRV, "xstats field size:%u.", ret);
		goto l_out;
	}

	if (usr_cnt < SXE_XSTAT_CNT) {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "max: %" SXE_PRIU64 " usr_cnt:%u invalid.(err:%d)",
				(u64)SXE_XSTAT_CNT, usr_cnt, ret);
		goto l_out;
	}

	for (i = 0; i < SXE_XSTAT_MAC_CNT; i++) {
		strlcpy(xstats_names[cnt].name,
			sxe_xstats_mac_field[i].name,
			sizeof(xstats_names[cnt].name));
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_SW_CNT; i++) {
		strlcpy(xstats_names[cnt].name,
			sxe_xstats_sw_field[i].name,
			sizeof(xstats_names[cnt].name));
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_FC_CNT; i++) {
		for (prio = 0; prio < SXE_FC_PRIO_VALUES; prio++) {
			snprintf(xstats_names[cnt].name,
				sizeof(xstats_names[cnt].name),
				"priority%u_%s", prio,
				sxe_xstats_fc_field[i].name);
			cnt++;
		}
	}

	ret = cnt;

l_out:
	return ret;
}

static s32 sxe_all_xstats_value_get(struct rte_eth_dev *eth_dev,
						u64 *values, u32 usr_cnt)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_stats_info *stats_info = &adapter->stats_info;
	struct sxe_hw *hw = &adapter->hw;
	u32 size = SXE_XSTAT_CNT;
	s32 ret;
	u32 offset;
	u32 cnt = 0;
	u32 i;
	u8 prio;

	if (usr_cnt < size) {
		PMD_LOG_WARN(DRV, "ids null usr_cnt:%u less than xstats"
				 " cnt:%u, return xstat cnt.",
				  usr_cnt, size);
		ret = size;
		goto l_out;
	}

	sxe_hw_stats_get(hw, &stats_info->hw_stats);
	sxe_sw_stats_get(eth_dev, &stats_info->sw_stats);

	if (values == NULL) {
		PMD_LOG_WARN(DRV, "ids and values null, "
				 "read clean stats regs");
		ret = 0;
		goto l_out;
	}

	for (i = 0; i < SXE_XSTAT_MAC_CNT; i++) {
		sxe_hw_xstat_offset_get(i, &offset);
		values[cnt] = *(u64 *)(((s8 *)(&stats_info->hw_stats)) + offset);
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_SW_CNT; i++) {
		sxe_sw_xstat_offset_get(i, &offset);
		values[cnt] = *(u64 *)(((s8 *)(&stats_info->sw_stats)) + offset);
		cnt++;
	}

	for (i = 0; i < SXE_XSTAT_FC_CNT; i++) {
		for (prio = 0; prio < SXE_FC_PRIO_VALUES; prio++) {
			sxe_fc_xstat_field_offset_get(i, prio, &offset);
			values[cnt] = *(u64 *)(((s8 *)(&stats_info->hw_stats))
					  + offset);
			cnt++;
		}
	}

	ret = cnt;

l_out:
	return ret;
}

int sxe_xstats_get_by_id(struct rte_eth_dev *eth_dev,
					const u64 *ids,
					u64 *values, u32 usr_cnt)
{
	s32 ret;
	u32 size = SXE_XSTAT_CNT;
	u32 i;
	u64 *value_all = (u64 *)malloc(size * sizeof(u64));
	if (value_all == NULL) {
		perror("value_all malloc failed");
		return -ENOMEM;
	}

	if (ids == NULL) {
		ret = sxe_all_xstats_value_get(eth_dev, values, usr_cnt);
		goto l_out;
	}

	if (values == NULL) {
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "invalid param values.");
		goto l_out;
	}

	sxe_all_xstats_value_get(eth_dev, value_all, size);

	for (i = 0; i < usr_cnt; i++) {
		if (ids[i] >= size) {
			PMD_LOG_ERR(DRV, "index:%u invalid ids:%" SXE_PRIU64, i, ids[i]);
			ret = -EINVAL;
			goto l_out;
		}
		values[i] = value_all[ids[i]];
	}

	ret = usr_cnt;

l_out:
	if (value_all != NULL)
		free(value_all);

	return ret;
}

int sxe_xstats_names_get_by_id(struct rte_eth_dev *eth_dev,
	const u64 *ids,
	struct rte_eth_xstat_name *xstats_names,
	u32 usr_cnt)
{
	s32 ret;
	u32 i;
	u32 size = SXE_XSTAT_CNT;
	struct rte_eth_xstat_name *xstat_names_all =
	(struct rte_eth_xstat_name *)malloc(size * sizeof(struct rte_eth_xstat_name));
	if (xstat_names_all == NULL) {
		perror("xstat_names_all malloc failed");
		return -ENOMEM;
	}

	if (ids == NULL) {
		ret = sxe_xstats_names_get(eth_dev, xstats_names, usr_cnt);
		goto l_out;
	}

	sxe_xstats_names_get(eth_dev, xstat_names_all, size);
	for (i = 0; i < usr_cnt; i++) {
		if (ids[i] >= size) {
			PMD_LOG_ERR(DRV, "index:%u invalid ids:%" SXE_PRIU64, i, ids[i]);
			ret = -EINVAL;
			goto l_out;
		}
		strlcpy(xstats_names[ids[i]].name,
			xstat_names_all[ids[i]].name,
			sizeof(xstats_names[ids[i]].name));
	}

	ret = usr_cnt;

l_out:
	if (xstat_names_all != NULL)
		free(xstat_names_all);

	return ret;
}

int sxe_queue_stats_mapping_set(struct rte_eth_dev *eth_dev,
				  u16 queue_id,
				  u8 stat_reg_idx,
				  u8 is_rx)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_stats_map *stats_map = &adapter->stats_info.stats_map;
	u32 qsmr_mask = 0;
	u32 map_mask = SXE_STAT_MAP_MASK;
	u8 reg_idx;
	u8 map_idx;
	s32 ret = 0;

	reg_idx = queue_id / SXE_STAT_MAP_CNT;
	if (reg_idx >= SXE_QUEUE_STATS_MAP_REG_NUM) {
		ret = -EIO;
		PMD_LOG_ERR(DRV, "invalid queue_id:%u reg_idx exceeded "
				"max map cnt:%u.(err:%d)",
				queue_id, SXE_QUEUE_STATS_MAP_REG_NUM, ret);
		goto l_out;
	}

	map_idx = (u8)(queue_id % SXE_STAT_MAP_CNT);
	map_mask <<= (SXE_STAT_MAP_WIDTH * map_idx);

	if (!is_rx)
		stats_map->txq_stats_map[reg_idx] &= ~map_mask;
	else
		stats_map->rxq_stats_map[reg_idx] &= ~map_mask;

	qsmr_mask = (stat_reg_idx & SXE_STAT_MAP_MASK) << (SXE_STAT_MAP_WIDTH * map_idx);
	if (!is_rx) {
		stats_map->txq_stats_map[reg_idx] |= qsmr_mask;
		sxe_hw_txq_stat_map_set(hw, reg_idx, stats_map->txq_stats_map[reg_idx]);
	} else {
		stats_map->rxq_stats_map[reg_idx] |= qsmr_mask;
		sxe_hw_rxq_stat_map_set(hw, reg_idx, stats_map->rxq_stats_map[reg_idx]);
	}

	PMD_LOG_INFO(DRV, "port %u %s queue_id %d stat map to stat reg[%u] "
			 "%s[%u] 0x%08x ",
			 (u16)(eth_dev->data->port_id), is_rx ? "RX" : "TX",
			 queue_id, stat_reg_idx,
			 is_rx ? "RQSMR" : "TQSM", reg_idx,
			 is_rx ? stats_map->rxq_stats_map[reg_idx] :
			 stats_map->txq_stats_map[reg_idx]);

l_out:
	return ret;
}

void sxe_queue_stats_map_restore(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_stats_map *stats_map = &adapter->stats_info.stats_map;
	u8 reg_idx;

	for (reg_idx = 0; reg_idx < SXE_QUEUE_STATS_MAP_REG_NUM; reg_idx++) {
		sxe_hw_txq_stat_map_set(hw, reg_idx, stats_map->txq_stats_map[reg_idx]);
		sxe_hw_rxq_stat_map_set(hw, reg_idx, stats_map->rxq_stats_map[reg_idx]);
	}
}

void sxe_queue_stats_map_reset(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u8 reg_idx;

	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	for (reg_idx = 0; reg_idx < SXE_QUEUE_STATS_MAP_REG_NUM; reg_idx++) {
		sxe_hw_txq_stat_map_set(hw, reg_idx, 0);
		sxe_hw_rxq_stat_map_set(hw, reg_idx, 0);
	}
}
