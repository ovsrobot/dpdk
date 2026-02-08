/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_ethdev.h>
#include <ethdev_driver.h>
#include "sxevf_stats.h"
#include "sxe_logs.h"
#include "sxe_errno.h"
#include "sxevf.h"

#define SXE_HW_XSTATS_CNT (sizeof(sxevf_xstats_field) / \
			  sizeof(sxevf_xstats_field[0]))

static const struct sxevf_stats_field sxevf_xstats_field[] = {
	{"rx_multicast_packets", offsetof(struct sxevf_hw_stats, vfmprc)},
};

#ifdef SXE_TEST
static u32 sxevf_xstats_cnt_get(void)
{
	return SXE_HW_XSTATS_CNT;
}
#endif

int sxevf_eth_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *stats,
			struct eth_queue_stats *qstats __rte_unused)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;
	struct sxevf_hw *hw = &adapter->hw;
	s32 ret = 0;

	sxevf_packet_stats_get(hw, &stats_info->hw_stats);

	if (stats == NULL) {
		ret = -EINVAL;
		PMD_LOG_ERR(DRV, "input param stats is null.");
		goto l_out;
	}

	stats->ipackets = stats_info->hw_stats.vfgprc;
	stats->ibytes   = stats_info->hw_stats.vfgorc;
	stats->opackets = stats_info->hw_stats.vfgptc;
	stats->obytes   = stats_info->hw_stats.vfgotc - stats->opackets * RTE_ETHER_CRC_LEN;

l_out:
	return ret;
}

s32 sxevf_dev_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;

	sxevf_eth_stats_get(eth_dev, NULL, NULL);

	stats_info->hw_stats.vfgprc = 0;
	stats_info->hw_stats.vfgorc = 0;
	stats_info->hw_stats.vfgptc = 0;
	stats_info->hw_stats.vfgotc = 0;
	stats_info->hw_stats.vfmprc = 0;

	return 0;
}

static s32 sxevf_hw_xstat_offset_get(u32 id, u32 *offset)
{
	s32 ret = 0;
	u32 size = SXE_HW_XSTATS_CNT;

	if (id < size) {
		*offset = sxevf_xstats_field[id].offset;
	} else {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "invalid id:%u exceed stats size cnt:%u.",
				id, size);
	}

	return ret;
}

s32 sxevf_xstats_get(struct rte_eth_dev *eth_dev,
				struct rte_eth_xstat *xstats,
				u32 usr_cnt)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_stats_info *stats_info = &adapter->stats_info;
	struct sxevf_hw *hw = &adapter->hw;
	u32 i;
	u32 cnt;
	s32 ret;
	u32 offset;

	cnt = SXE_HW_XSTATS_CNT;
	PMD_LOG_INFO(DRV, "xstat size:%u. hw xstat field cnt:%" SXE_PRIU64,
			cnt,
			(u64)SXE_HW_XSTATS_CNT);

	if (usr_cnt < cnt) {
		ret = cnt;
		PMD_LOG_ERR(DRV, "user usr_cnt:%u less than stats cnt:%u.",
				usr_cnt, cnt);
		goto l_out;
	}

	sxevf_packet_stats_get(hw, &stats_info->hw_stats);

	if (xstats == NULL) {
		ret = 0;
		PMD_LOG_ERR(DRV, "usr_cnt:%u, input param xstats is null.",
					usr_cnt);
		goto l_out;
	}

	cnt = 0;
	for (i = 0; i < SXE_HW_XSTATS_CNT; i++) {
		sxevf_hw_xstat_offset_get(i, &offset);
		xstats[cnt].value = *(u_long *)(((s8 *)(&stats_info->hw_stats)) + offset);
		xstats[cnt].id = cnt;
		cnt++;
	}

	ret = SXE_HW_XSTATS_CNT;

l_out:
	return ret;
}

s32 sxevf_xstats_names_get(__rte_unused struct rte_eth_dev *dev,
	struct rte_eth_xstat_name *xstats_names, __rte_unused unsigned int usr_cnt)
{
	u32 i = 0;
	u32 cnt = 0;
	s32 ret;

	if (xstats_names == NULL) {
		ret = SXE_HW_XSTATS_CNT;
		PMD_LOG_INFO(DRV, "xstats field size:%u.", ret);
		goto l_out;
	} else if (usr_cnt < SXE_HW_XSTATS_CNT) {
		ret = -ENOMEM;
		PMD_LOG_ERR(DRV, "usr_cnt:%u invalid.(err:%d).", usr_cnt, ret);
		goto l_out;
	}

	for (i = 0; i < SXE_HW_XSTATS_CNT; i++) {
		strlcpy(xstats_names[cnt].name,
			sxevf_xstats_field[i].name,
			sizeof(xstats_names[cnt].name));
		cnt++;
	}

	ret = cnt;

l_out:
	return ret;
}

#endif
