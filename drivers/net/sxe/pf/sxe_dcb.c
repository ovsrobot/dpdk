/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include "sxe.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe_phy.h"
#include "sxe_errno.h"
#include "sxe_offload.h"
#include "sxe_ethdev.h"
#include "sxe_compat_version.h"
#include "rte_pmd_sxe.h"
#include <eal_export.h>

#define DCB_RX_CONFIG  1
#define DCB_TX_CONFIG  1

#define DCB_CREDIT_QUANTUM	64
#define MAX_CREDIT_REFILL	   511
#define MAX_CREDIT			  4095

void sxe_dcb_init(struct rte_eth_dev *dev)
{
	u8 i;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_dcb_config *cfg = &adapter->dcb_ctxt.config;
	struct sxe_tc_config *tc;
	u8 dcb_max_tc = SXE_DCB_MAX_TRAFFIC_CLASS;

	memset(cfg, 0, sizeof(struct sxe_dcb_config));

	cfg->num_tcs.pg_tcs = dcb_max_tc;
	cfg->num_tcs.pfc_tcs = dcb_max_tc;
	for (i = 0; i < dcb_max_tc; i++) {
		tc = &cfg->tc_config[i];
		tc->channel[DCB_PATH_TX].bwg_id = i;
		tc->channel[DCB_PATH_TX].bwg_percent =
				 (u8)(100 / dcb_max_tc + (i & 1));
		tc->channel[DCB_PATH_RX].bwg_id = i;
		tc->channel[DCB_PATH_RX].bwg_percent =
				 (u8)(100 / dcb_max_tc + (i & 1));
		tc->pfc_type = pfc_disabled;
	}

	tc = &cfg->tc_config[0];
	tc->channel[DCB_PATH_TX].up_to_tc_bitmap = 0xFF;
	tc->channel[DCB_PATH_RX].up_to_tc_bitmap = 0xFF;
	for (i = 0; i < MAX_BW_GROUP; i++) {
		cfg->bwg_link_percent[DCB_PATH_TX][i] = 100;
		cfg->bwg_link_percent[DCB_PATH_RX][i] = 100;
	}
	cfg->rx_pba_config = SXE_DCB_PBA_EQUAL;
	cfg->pfc_mode_enable = false;
	cfg->vmdq_active = true;
	cfg->round_robin_enable = false;
}

static u8 sxe_dcb_get_tc_from_up(struct sxe_dcb_config *cfg,
					u8 direction, u8 up)
{
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];
	u8 prio_mask = BIT(up);
	u8 tc = cfg->num_tcs.pg_tcs;

	if (!tc)
		goto l_ret;

	for (tc--; tc; tc--) {
		if (prio_mask & tc_config[tc].channel[direction].up_to_tc_bitmap)
			break;
	}

l_ret:
	LOG_DEBUG("up[%u] to tc[%u]", up, tc);
	return tc;
}

static void sxe_dcb_up2tc_map_parse(struct sxe_dcb_config *cfg,
						u8 direction, u8 *map)
{
	u8 up;

	for (up = 0; up < MAX_USER_PRIORITY; up++) {
		map[up] = sxe_dcb_get_tc_from_up(cfg, direction, up);
		LOG_DEBUG("up[%u] --- up2tc_map[%u]", up, map[up]);
	}
}

s32 sxe_priority_flow_ctrl_set(struct rte_eth_dev *dev,
					struct rte_eth_pfc_conf *pfc_conf)
{
	s32 ret;
	u32 rx_buf_size;
	u32 max_high_water;
	u8 tc_idx;
	u8  up2tc_map[MAX_USER_PRIORITY] = { 0 };
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	struct sxe_dcb_config *dcb_config = &adapter->dcb_ctxt.config;

	static const enum sxe_fc_mode fcmode[] = {
		SXE_FC_NONE,
		SXE_FC_RX_PAUSE,
		SXE_FC_TX_PAUSE,
		SXE_FC_FULL,
	};

	PMD_INIT_FUNC_TRACE();

	sxe_dcb_up2tc_map_parse(dcb_config, DCB_PATH_RX, up2tc_map);
	tc_idx = up2tc_map[pfc_conf->priority];
	rx_buf_size = sxe_hw_rx_pkt_buf_size_get(hw, tc_idx);
	PMD_LOG_DEBUG(INIT, "Rx packet buffer size = 0x%x", rx_buf_size);

	max_high_water = (rx_buf_size -
			RTE_ETHER_MAX_LEN) >> SXE_RX_PKT_BUF_SIZE_SHIFT;
	if (pfc_conf->fc.high_water > max_high_water ||
		pfc_conf->fc.high_water <= pfc_conf->fc.low_water) {
		PMD_LOG_ERR(INIT, "Invalid high/low water setup value in KB, "
				"high water=0x%x, low water=0x%x",
				pfc_conf->fc.high_water, pfc_conf->fc.low_water);
		PMD_LOG_ERR(INIT, "High_water must <= 0x%x", max_high_water);
		ret = -EINVAL;
		goto l_end;
	}

	sxe_hw_fc_requested_mode_set(hw, fcmode[pfc_conf->fc.mode]);
	sxe_hw_fc_pause_time_set(hw, pfc_conf->fc.pause_time);
	sxe_hw_fc_send_xon_set(hw, pfc_conf->fc.send_xon);
	sxe_hw_fc_tc_low_water_mark_set(hw, tc_idx, pfc_conf->fc.low_water);
	sxe_hw_fc_tc_high_water_mark_set(hw, tc_idx, pfc_conf->fc.high_water);

	ret = sxe_pfc_enable(adapter, tc_idx);

	if (ret == 0 || ret == SXE_ERR_FC_NOT_NEGOTIATED) {
		PMD_LOG_DEBUG(INIT, "pfc set end ret = %d", ret);
		ret = 0;
		goto l_end;
	}

	PMD_LOG_ERR(INIT, "sxe_dcb_pfc_enable = 0x%x", ret);
	ret = -EIO;
l_end:
	return ret;
}

s32 sxe_get_dcb_info(struct rte_eth_dev *dev,
			struct rte_eth_dcb_info *dcb_info)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_dcb_config *dcb_config = &adapter->dcb_ctxt.config;

	struct sxe_tc_config *tc;
	struct rte_eth_dcb_tc_queue_mapping *tc_queue;
	u8 tcs_num;
	u8 i, j;

	if (dev->data->dev_conf.rxmode.mq_mode & RTE_ETH_MQ_RX_DCB_FLAG)
		dcb_info->nb_tcs = dcb_config->num_tcs.pg_tcs;
	else
		dcb_info->nb_tcs = 1;

	tc_queue = &dcb_info->tc_queue;
	tcs_num = dcb_info->nb_tcs;

	if (dcb_config->vmdq_active) {
		struct rte_eth_vmdq_dcb_conf *vmdq_rx_conf =
				&dev->data->dev_conf.rx_adv_conf.vmdq_dcb_conf;
		for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++)
			dcb_info->prio_tc[i] = vmdq_rx_conf->dcb_tc[i];

		if (RTE_ETH_DEV_SRIOV(dev).active > 0) {
			for (j = 0; j < tcs_num; j++) {
				tc_queue->tc_rxq[0][j].base = j;
				tc_queue->tc_rxq[0][j].nb_queue = 1;
				tc_queue->tc_txq[0][j].base = j;
				tc_queue->tc_txq[0][j].nb_queue = 1;
			}
		} else {
			for (i = 0; i < vmdq_rx_conf->nb_queue_pools; i++) {
				for (j = 0; j < tcs_num; j++) {
					tc_queue->tc_rxq[i][j].base =
						i * tcs_num + j;
					tc_queue->tc_rxq[i][j].nb_queue = 1;
					tc_queue->tc_txq[i][j].base =
						i * tcs_num + j;
					tc_queue->tc_txq[i][j].nb_queue = 1;
				}
			}
		}
	} else {
		struct rte_eth_dcb_rx_conf *rx_conf =
				&dev->data->dev_conf.rx_adv_conf.dcb_rx_conf;
		for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++)
			dcb_info->prio_tc[i] = rx_conf->dcb_tc[i];

		if (dcb_info->nb_tcs == RTE_ETH_4_TCS) {
			for (i = 0; i < dcb_info->nb_tcs; i++) {
				dcb_info->tc_queue.tc_rxq[0][i].base = i * 32;
				dcb_info->tc_queue.tc_rxq[0][i].nb_queue = 16;
			}

			dcb_info->tc_queue.tc_txq[0][0].base = 0;
			dcb_info->tc_queue.tc_txq[0][1].base = 64;
			dcb_info->tc_queue.tc_txq[0][2].base = 96;
			dcb_info->tc_queue.tc_txq[0][3].base = 112;
			dcb_info->tc_queue.tc_txq[0][0].nb_queue = 64;
			dcb_info->tc_queue.tc_txq[0][1].nb_queue = 32;
			dcb_info->tc_queue.tc_txq[0][2].nb_queue = 16;
			dcb_info->tc_queue.tc_txq[0][3].nb_queue = 16;
		} else if (dcb_info->nb_tcs == RTE_ETH_8_TCS) {
			for (i = 0; i < dcb_info->nb_tcs; i++) {
				dcb_info->tc_queue.tc_rxq[0][i].base = i * 16;
				dcb_info->tc_queue.tc_rxq[0][i].nb_queue = 16;
			}

			dcb_info->tc_queue.tc_txq[0][0].base = 0;
			dcb_info->tc_queue.tc_txq[0][1].base = 32;
			dcb_info->tc_queue.tc_txq[0][2].base = 64;
			dcb_info->tc_queue.tc_txq[0][3].base = 80;
			dcb_info->tc_queue.tc_txq[0][4].base = 96;
			dcb_info->tc_queue.tc_txq[0][5].base = 104;
			dcb_info->tc_queue.tc_txq[0][6].base = 112;
			dcb_info->tc_queue.tc_txq[0][7].base = 120;
			dcb_info->tc_queue.tc_txq[0][0].nb_queue = 32;
			dcb_info->tc_queue.tc_txq[0][1].nb_queue = 32;
			dcb_info->tc_queue.tc_txq[0][2].nb_queue = 16;
			dcb_info->tc_queue.tc_txq[0][3].nb_queue = 16;
			dcb_info->tc_queue.tc_txq[0][4].nb_queue = 8;
			dcb_info->tc_queue.tc_txq[0][5].nb_queue = 8;
			dcb_info->tc_queue.tc_txq[0][6].nb_queue = 8;
			dcb_info->tc_queue.tc_txq[0][7].nb_queue = 8;
		}
	}

	for (i = 0; i < dcb_info->nb_tcs; i++) {
		tc = &dcb_config->tc_config[i];
		dcb_info->tc_bws[i] = tc->channel[DCB_PATH_TX].bwg_percent;
	}

	return 0;
}

static void sxe_dcb_vmdq_rx_param_get(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config)
{
	struct rte_eth_vmdq_dcb_conf *vmdq_rx_conf =
			&dev->data->dev_conf.rx_adv_conf.vmdq_dcb_conf;
	struct sxe_tc_config *tc;
	u8 i, j;

	if (vmdq_rx_conf->nb_queue_pools == RTE_ETH_16_POOLS) {
		dcb_config->num_tcs.pg_tcs = RTE_ETH_8_TCS;
		dcb_config->num_tcs.pfc_tcs = RTE_ETH_8_TCS;
	} else {
		dcb_config->num_tcs.pg_tcs = RTE_ETH_4_TCS;
		dcb_config->num_tcs.pfc_tcs = RTE_ETH_4_TCS;
	}

	for (j = 0; j < MAX_TRAFFIC_CLASS; j++) {
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_RX].up_to_tc_bitmap = 0;
	}

	for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = vmdq_rx_conf->dcb_tc[i];
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_RX].up_to_tc_bitmap |=
						(u8)(1 << i);
	}
}

void sxe_dcb_vmdq_rx_hw_configure(struct rte_eth_dev *dev)
{
	struct rte_eth_vmdq_dcb_conf *cfg;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	enum rte_eth_nb_pools pools_num;
	u16 i;

	PMD_INIT_FUNC_TRACE();
	cfg = &dev->data->dev_conf.rx_adv_conf.vmdq_dcb_conf;
	pools_num = cfg->nb_queue_pools;

	if (pools_num != RTE_ETH_16_POOLS && pools_num != RTE_ETH_32_POOLS) {
		sxe_rss_disable(dev);
		return;
	}

	sxe_hw_dcb_vmdq_mq_configure(hw, pools_num);

	sxe_hw_dcb_vmdq_default_pool_configure(hw,
						cfg->enable_default_pool,
						cfg->default_pool);

	sxe_hw_dcb_vmdq_up_2_tc_configure(hw, cfg->dcb_tc);

	sxe_hw_dcb_vmdq_vlan_configure(hw, pools_num);

	for (i = 0; i < cfg->nb_pool_maps; i++) {
		sxe_hw_dcb_vmdq_pool_configure(hw,
					i, cfg->pool_map[i].vlan_id,
					cfg->pool_map[i].pools);
	}
}

static void sxe_dcb_rx_param_get(struct rte_eth_dev *dev,
		struct sxe_dcb_config *dcb_config)
{
	struct rte_eth_dcb_rx_conf *rx_conf =
			&dev->data->dev_conf.rx_adv_conf.dcb_rx_conf;
	struct sxe_tc_config *tc;
	u8 i, j;

	dcb_config->num_tcs.pg_tcs = (u8)rx_conf->nb_tcs;
	dcb_config->num_tcs.pfc_tcs = (u8)rx_conf->nb_tcs;

	for (j = 0; j < MAX_TRAFFIC_CLASS; j++) {
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_RX].up_to_tc_bitmap = 0;
	}

	for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = rx_conf->dcb_tc[i];
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_RX].up_to_tc_bitmap |=
						(u8)(1 << i);
	}
}

static void sxe_dcb_rx_hw_configure(struct rte_eth_dev *dev,
			   struct sxe_dcb_config *dcb_config)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();
	sxe_hw_dcb_rx_configure(hw, dcb_config->vmdq_active,
				RTE_ETH_DEV_SRIOV(dev).active,
				dcb_config->num_tcs.pg_tcs);
}

static void sxe_dcb_vmdq_tx_param_get(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config)
{
	struct rte_eth_vmdq_dcb_tx_conf *vmdq_tx_conf =
			&dev->data->dev_conf.tx_adv_conf.vmdq_dcb_tx_conf;
	struct sxe_tc_config *tc;
	u8 i, j;

	if (vmdq_tx_conf->nb_queue_pools == RTE_ETH_16_POOLS) {
		dcb_config->num_tcs.pg_tcs = RTE_ETH_8_TCS;
		dcb_config->num_tcs.pfc_tcs = RTE_ETH_8_TCS;
	} else {
		dcb_config->num_tcs.pg_tcs = RTE_ETH_4_TCS;
		dcb_config->num_tcs.pfc_tcs = RTE_ETH_4_TCS;
	}

	for (j = 0; j < MAX_TRAFFIC_CLASS; j++) {
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_TX].up_to_tc_bitmap = 0;
	}

	for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = vmdq_tx_conf->dcb_tc[i];
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_TX].up_to_tc_bitmap |=
						(u8)(1 << i);
	}
}

static void sxe_dcb_vmdq_tx_hw_configure(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config)
{
	struct rte_eth_vmdq_dcb_tx_conf *vmdq_tx_conf =
			&dev->data->dev_conf.tx_adv_conf.vmdq_dcb_tx_conf;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_pool_xmit_enable(hw, 0, (u8)vmdq_tx_conf->nb_queue_pools);

	sxe_hw_dcb_tx_configure(hw, dcb_config->vmdq_active,
				dcb_config->num_tcs.pg_tcs);
}

static void sxe_dcb_tx_param_get(struct rte_eth_dev *dev,
		struct sxe_dcb_config *dcb_config)
{
	struct rte_eth_dcb_tx_conf *tx_conf =
			&dev->data->dev_conf.tx_adv_conf.dcb_tx_conf;
	struct sxe_tc_config *tc;
	u8 i, j;

	dcb_config->num_tcs.pg_tcs = (u8)tx_conf->nb_tcs;
	dcb_config->num_tcs.pfc_tcs = (u8)tx_conf->nb_tcs;

	for (j = 0; j < MAX_TRAFFIC_CLASS; j++) {
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_TX].up_to_tc_bitmap = 0;
	}

	for (i = 0; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++) {
		j = tx_conf->dcb_tc[i];
		tc = &dcb_config->tc_config[j];
		tc->channel[DCB_PATH_TX].up_to_tc_bitmap |=
						(u8)(1 << i);
	}
}

static u32 sxe_dcb_min_credit_get(u32 max_frame)
{
	return ((max_frame / 2) + DCB_CREDIT_QUANTUM - 1) /
				DCB_CREDIT_QUANTUM;
}

static u16 sxe_dcb_cee_tc_link_percent_get(struct sxe_dcb_config *cee_config,
			u8 direction, u8 tc_index)
{
	u8  bw_percent;
	u16 link_percentage;
	struct sxe_tc_bw_alloc *tc_info;

	tc_info = &cee_config->tc_config[tc_index].channel[direction];
	link_percentage =
		cee_config->bwg_link_percent[direction][tc_info->bwg_id];
	bw_percent = tc_info->bwg_percent;

	link_percentage = (link_percentage * bw_percent) / 100;

	return link_percentage;
}

static u32 sxe_dcb_cee_min_link_percent_get(struct sxe_dcb_config *cee_config,
		u8 direction)
{
	u8  tc_index;
	u16 link_percentage;
	u32 min_link_percent = 100;

	for (tc_index = 0; tc_index < MAX_TRAFFIC_CLASS; tc_index++) {
		link_percentage = sxe_dcb_cee_tc_link_percent_get(cee_config,
					direction, tc_index);

		if (link_percentage && link_percentage < min_link_percent)
			min_link_percent = link_percentage;
	}

	return min_link_percent;
}

static s32 sxe_dcb_cee_tc_credits_calculate(struct sxe_hw *hw,
				   struct sxe_dcb_config *cee_config,
				   u32 max_frame, u8 direction)
{
	s32 ret = 0;
	struct sxe_adapter *adapter = hw->adapter;
	struct sxe_tc_bw_alloc *tc_info;
	u32 min_credit;
	u32 total_credit;
	u32 min_link_percent;
	u32 credit_refill;
	u32 credit_max;
	u16 link_percentage;
	u8  tc_index;

	LOG_DEBUG_BDF("cee_config[%p] input max_frame[%u] direction[%s]",
			cee_config, max_frame, direction ? "RX" : "TX");

	min_credit = sxe_dcb_min_credit_get(max_frame);
	LOG_DEBUG_BDF("cee_config[%p] max_frame[%u] got min_credit[%u]",
			cee_config, max_frame, min_credit);

	min_link_percent = sxe_dcb_cee_min_link_percent_get(cee_config, direction);
	LOG_DEBUG_BDF("cee_config[%p] direction[%s] got min_link_percent[%u]",
			cee_config, direction ? "RX" : "TX", min_link_percent);

	total_credit = (min_credit / min_link_percent) + 1;
	LOG_DEBUG_BDF("cee_config[%p] total_credit=%u", cee_config, total_credit);

	for (tc_index = 0; tc_index < MAX_TRAFFIC_CLASS; tc_index++) {
		tc_info = &cee_config->tc_config[tc_index].channel[direction];

		link_percentage = sxe_dcb_cee_tc_link_percent_get(cee_config,
					direction, tc_index);
		LOG_DEBUG_BDF("tc[%u] bwg_percent=%u, link_percentage=%u",
			tc_index, tc_info->bwg_percent, link_percentage);

		if (tc_info->bwg_percent > 0 && link_percentage == 0)
			link_percentage = 1;

		tc_info->link_percent = (u8)link_percentage;

		credit_refill = RTE_MIN(link_percentage * total_credit,
					(u32)MAX_CREDIT_REFILL);

		if (credit_refill < min_credit)
			credit_refill = min_credit;

		tc_info->data_credits_refill = (u16)credit_refill;
		LOG_DEBUG_BDF("tc[%u] credit_refill=%u",
					tc_index, credit_refill);

		credit_max = (link_percentage * MAX_CREDIT) / 100;

		if (credit_max < min_credit)
			credit_max = min_credit;
		LOG_DEBUG_BDF("tc[%u] credit_max=%u",
					tc_index, credit_max);

		if (direction == DCB_PATH_TX)
			cee_config->tc_config[tc_index].desc_credits_max =
				(u16)credit_max;

		tc_info->data_credits_max = (u16)credit_max;
	}

	return ret;
}

static void sxe_dcb_cee_refill_parse(struct sxe_dcb_config *cfg,
					u8 direction, u16 *refill)
{
	u32 tc;
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];

	for (tc = 0; tc < MAX_TRAFFIC_CLASS; tc++) {
		refill[tc] = tc_config[tc].channel[direction].data_credits_refill;
		LOG_DEBUG("tc[%u] --- refill[%u]", tc, refill[tc]);
	}
}

static void sxe_dcb_cee_max_credits_parse(struct sxe_dcb_config *cfg,
						u16 *max_credits)
{
	u32 tc;
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];

	for (tc = 0; tc < MAX_TRAFFIC_CLASS; tc++) {
		max_credits[tc] = tc_config[tc].desc_credits_max;
		LOG_DEBUG("tc[%u] --- max_credits[%u]", tc, max_credits[tc]);
	}
}

static void sxe_dcb_cee_bwgid_parse(struct sxe_dcb_config *cfg,
					u8 direction, u8 *bwgid)
{
	u32 tc;
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];

	for (tc = 0; tc < MAX_TRAFFIC_CLASS; tc++) {
		bwgid[tc] = tc_config[tc].channel[direction].bwg_id;
		LOG_DEBUG("tc[%u] --- bwgid[%u]", tc, bwgid[tc]);
	}
}

static void sxe_dcb_cee_prio_parse(struct sxe_dcb_config *cfg,
					u8 direction, u8 *ptype)
{
	u32 tc;
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];

	for (tc = 0; tc < MAX_TRAFFIC_CLASS; tc++) {
		ptype[tc] = tc_config[tc].channel[direction].prio_type;
		LOG_DEBUG("tc[%u] --- ptype[%u]", tc, ptype[tc]);
	}
}

static void sxe_dcb_cee_pfc_parse(struct sxe_dcb_config *cfg,
						u8 *map, u8 *pfc_en)
{
	u32 up;
	struct sxe_tc_config *tc_config = &cfg->tc_config[0];

	for (*pfc_en = 0, up = 0; up < MAX_TRAFFIC_CLASS; up++) {
		if (tc_config[map[up]].pfc_type != pfc_disabled)
			*pfc_en |= BIT(up);
	}
	LOG_DEBUG("cfg[%p] pfc_en[0x%x]", cfg, *pfc_en);
}

static s32 sxe_dcb_tc_stats_configure(struct sxe_hw *hw,
					struct sxe_dcb_config *dcb_config)
{
	s32 ret = 0;
	u8 tc_count = 8;
	bool vmdq_active = false;

	if (dcb_config != NULL) {
		tc_count = dcb_config->num_tcs.pg_tcs;
		vmdq_active = dcb_config->vmdq_active;
	}

	if (!((tc_count == 8 && !vmdq_active) || tc_count == 4)) {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(INIT, "dcb tc stats configure failed, "
				"tc_num = %u, vmdq_active = %s",
				tc_count, vmdq_active ? "on" : "off");
		goto l_end;
	}

	sxe_hw_dcb_tc_stats_configure(hw, tc_count, vmdq_active);

l_end:
	return ret;
}

static void sxe_dcb_rx_mq_mode_configure(struct rte_eth_dev *dev,
					struct sxe_dcb_config *dcb_config,
					u8 *rx_configured)
{
	switch (dev->data->dev_conf.rxmode.mq_mode) {
	case RTE_ETH_MQ_RX_VMDQ_DCB:
		dcb_config->vmdq_active = true;
		*rx_configured = DCB_RX_CONFIG;

		sxe_dcb_vmdq_rx_param_get(dev, dcb_config);
		sxe_dcb_vmdq_rx_hw_configure(dev);
		break;
	case RTE_ETH_MQ_RX_DCB:
	case RTE_ETH_MQ_RX_DCB_RSS:
		dcb_config->vmdq_active = false;
		*rx_configured = DCB_RX_CONFIG;

		sxe_dcb_rx_param_get(dev, dcb_config);
		sxe_dcb_rx_hw_configure(dev, dcb_config);
		break;
	default:
		PMD_LOG_ERR(INIT, "Incorrect DCB RX mode configuration");
		break;
	}
}

static void sxe_dcb_tx_mq_mode_configure(struct rte_eth_dev *dev,
					struct sxe_dcb_config *dcb_config,
					u8 *tx_configured)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	switch (dev->data->dev_conf.txmode.mq_mode) {
	case RTE_ETH_MQ_TX_VMDQ_DCB:
		dcb_config->vmdq_active = true;
		*tx_configured = DCB_TX_CONFIG;

		sxe_dcb_vmdq_tx_param_get(dev, dcb_config);
		sxe_dcb_vmdq_tx_hw_configure(dev, dcb_config);
		break;

	case RTE_ETH_MQ_TX_DCB:
		dcb_config->vmdq_active = false;
		*tx_configured = DCB_TX_CONFIG;

		sxe_dcb_tx_param_get(dev, dcb_config);
		sxe_hw_dcb_tx_configure(hw, dcb_config->vmdq_active,
				dcb_config->num_tcs.pg_tcs);
		break;
	default:
		PMD_LOG_ERR(INIT, "Incorrect DCB TX mode configuration");
		break;
	}
}

static void sxe_dcb_bwg_percentage_alloc(struct rte_eth_dev *dev,
				struct sxe_dcb_config *dcb_config, u8 *map)
{
	u8 i;
	struct sxe_tc_config *tc;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_bw_config *bw_conf = &adapter->dcb_ctxt.bw_config;

	u8 nb_tcs = dcb_config->num_tcs.pfc_tcs;

	if (nb_tcs == RTE_ETH_4_TCS) {
		for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
			if (map[i] >= nb_tcs) {
				PMD_LOG_INFO(DRV, "map[up-%u] to tc[%u] not exist, "
								"change to tc 0", i, map[i]);
				map[i] = 0;
			}
		}

		for (i = 0; i < nb_tcs; i++) {
			tc = &dcb_config->tc_config[i];
			if (bw_conf->tc_num != nb_tcs) {
				tc->channel[DCB_PATH_TX].bwg_percent =
							(u8)(100 / nb_tcs);
		}
		tc->channel[DCB_PATH_RX].bwg_percent =
					(u8)(100 / nb_tcs);
		}
		for (; i < MAX_TRAFFIC_CLASS; i++) {
			tc = &dcb_config->tc_config[i];
			tc->channel[DCB_PATH_TX].bwg_percent = 0;
			tc->channel[DCB_PATH_RX].bwg_percent = 0;
		}
	} else {
		for (i = 0; i < nb_tcs; i++) {
			tc = &dcb_config->tc_config[i];
			if (bw_conf->tc_num != nb_tcs) {
				tc->channel[DCB_PATH_TX].bwg_percent =
					(u8)(100 / nb_tcs + (i & 1));
			}

			tc->channel[DCB_PATH_RX].bwg_percent =
				(u8)(100 / nb_tcs + (i & 1));
		}
	}
}

static void sxe_dcb_rx_pkt_buf_configure(struct sxe_hw *hw,
						u16 rx_buffer_size, u8 tcs_num)
{
	u8 i;
	u16 pbsize;

	pbsize = (u16)(rx_buffer_size / tcs_num);

	for (i = 0; i < tcs_num; i++)
		sxe_hw_rx_pkt_buf_size_set(hw, i, pbsize);

	for (; i < RTE_ETH_DCB_NUM_USER_PRIORITIES; i++)
		sxe_hw_rx_pkt_buf_size_set(hw, i, 0);
}

static void sxe_dcb_tx_pkt_buf_configure(struct sxe_hw *hw, u8 tcs_num)
{
	sxe_hw_tx_pkt_buf_switch(hw, false);

	sxe_hw_tx_pkt_buf_size_configure(hw, tcs_num);
	sxe_hw_tx_pkt_buf_thresh_configure(hw, tcs_num, true);

	sxe_hw_tx_pkt_buf_switch(hw, true);
}

static void sxe_dcb_rx_configure(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config, u8 *map)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u8 tsa[MAX_TRAFFIC_CLASS]	 = {0};
	u8 bwgid[MAX_TRAFFIC_CLASS]   = {0};
	u16 refill[MAX_TRAFFIC_CLASS] = {0};
	u16 max[MAX_TRAFFIC_CLASS]	= {0};

	sxe_dcb_rx_pkt_buf_configure(hw, SXE_RX_PKT_BUF_SIZE, dcb_config->num_tcs.pg_tcs);

	sxe_dcb_cee_refill_parse(dcb_config, DCB_PATH_RX, refill);
	sxe_dcb_cee_bwgid_parse(dcb_config, DCB_PATH_RX, bwgid);
	sxe_dcb_cee_prio_parse(dcb_config, DCB_PATH_RX, tsa);
	sxe_dcb_cee_max_credits_parse(dcb_config, max);

	sxe_hw_dcb_rx_bw_alloc_configure(hw, refill, max,
				bwgid, tsa, map, MAX_USER_PRIORITY);
}

static void sxe_dcb_tx_configure(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config, u8 *map)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u8 tsa[MAX_TRAFFIC_CLASS]	 = {0};
	u8 bwgid[MAX_TRAFFIC_CLASS]   = {0};
	u16 refill[MAX_TRAFFIC_CLASS] = {0};
	u16 max[MAX_TRAFFIC_CLASS]	= {0};

	sxe_dcb_tx_pkt_buf_configure(hw, dcb_config->num_tcs.pg_tcs);

	sxe_dcb_cee_refill_parse(dcb_config, DCB_PATH_TX, refill);
	sxe_dcb_cee_max_credits_parse(dcb_config, max);
	sxe_dcb_cee_bwgid_parse(dcb_config, DCB_PATH_TX, bwgid);
	sxe_dcb_cee_prio_parse(dcb_config, DCB_PATH_TX, tsa);

	sxe_hw_dcb_tx_desc_bw_alloc_configure(hw, refill, max, bwgid, tsa);
	sxe_hw_dcb_tx_data_bw_alloc_configure(hw, refill, max,
				bwgid, tsa, map, MAX_USER_PRIORITY);
}

static void sxe_dcb_pfc_configure(struct sxe_hw *hw,
					struct sxe_dcb_config *dcb_config,
					u8 *map)
{
	u8 nb_tcs = dcb_config->num_tcs.pg_tcs;
	u16 pbsize;
	u8 i, pfc_en;
	struct sxe_tc_config *tc;

	pbsize = (u16)(SXE_RX_PKT_BUF_SIZE / nb_tcs);
	for (i = 0; i < nb_tcs; i++) {
		sxe_hw_fc_tc_high_water_mark_set(hw, i, (pbsize * 3) / 4);
		sxe_hw_fc_tc_low_water_mark_set(hw, i, pbsize / 4);

		tc = &dcb_config->tc_config[i];
		tc->pfc_type = pfc_enabled_full;
	}

	sxe_dcb_cee_pfc_parse(dcb_config, map, &pfc_en);
	if (dcb_config->num_tcs.pfc_tcs == RTE_ETH_4_TCS)
		pfc_en &= 0x0F;

	sxe_hw_dcb_pfc_configure(hw, pfc_en, map, MAX_USER_PRIORITY);
}

static void sxe_dcb_hw_configure(struct rte_eth_dev *dev,
			struct sxe_dcb_config *dcb_config)
{
	u8 rx_configured = 0;
	u8 tx_configured = 0;
	u8 map[MAX_TRAFFIC_CLASS] = {0};
	u32 max_frame = dev->data->mtu + SXE_ETH_DEAD_LOAD;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	sxe_dcb_rx_mq_mode_configure(dev, dcb_config, &rx_configured);
	sxe_dcb_tx_mq_mode_configure(dev, dcb_config, &tx_configured);

	sxe_dcb_up2tc_map_parse(dcb_config, DCB_PATH_RX, map);

	sxe_dcb_bwg_percentage_alloc(dev, dcb_config, map);

	sxe_dcb_cee_tc_credits_calculate(hw, dcb_config, max_frame, DCB_PATH_TX);
	sxe_dcb_cee_tc_credits_calculate(hw, dcb_config, max_frame, DCB_PATH_RX);

	if (rx_configured)
		sxe_dcb_rx_configure(dev, dcb_config, map);

	if (tx_configured)
		sxe_dcb_tx_configure(dev, dcb_config, map);

	sxe_dcb_tc_stats_configure(hw, dcb_config);

	if (dev->data->dev_conf.dcb_capability_en & RTE_ETH_DCB_PFC_SUPPORT)
		sxe_dcb_pfc_configure(hw, dcb_config, map);
}

void sxe_dcb_configure(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;

	struct sxe_dcb_config *dcb_cfg = &adapter->dcb_ctxt.config;
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;

	PMD_INIT_FUNC_TRACE();

	if (dev_conf->rxmode.mq_mode != RTE_ETH_MQ_RX_VMDQ_DCB &&
		dev_conf->rxmode.mq_mode != RTE_ETH_MQ_RX_DCB &&
		dev_conf->rxmode.mq_mode != RTE_ETH_MQ_RX_DCB_RSS) {
		PMD_LOG_INFO(INIT, "dcb config failed, cause mq_mode=0x%x",
				(u8)dev_conf->rxmode.mq_mode);
		return;
	}

	if (dev->data->nb_rx_queues > RTE_ETH_DCB_NUM_QUEUES) {
		PMD_LOG_INFO(INIT, "dcb config failed, cause nb_rx_queues=%u > %u",
			dev->data->nb_rx_queues, RTE_ETH_DCB_NUM_QUEUES);
		return;
	}

	sxe_dcb_hw_configure(dev, dcb_cfg);
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_sxe_tc_bw_set, 26.03)
s32 rte_pmd_sxe_tc_bw_set(u8 port, u8 tc_num, u8 *bw_weight)
{
	struct sxe_adapter *adapter;
	struct rte_eth_dev *dev;
	struct sxe_dcb_config *dcb_config;
	struct sxe_tc_config *tc;
	struct rte_eth_conf *eth_conf;
	struct sxe_bw_config *bw_conf;
	u8 i;
	u8 nb_tcs;
	u16 sum;
	s32 ret = 0;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];
	if (!sxe_is_supported(dev)) {
		ret = -ENOTSUP;
		goto l_end;
	}

	if (tc_num > MAX_TRAFFIC_CLASS) {
		PMD_LOG_ERR(DRV, "TCs should be no more than %d.",
				MAX_TRAFFIC_CLASS);
		ret = -EINVAL;
		goto l_end;
	}

	adapter = dev->data->dev_private;
	dcb_config = &adapter->dcb_ctxt.config;
	bw_conf = &adapter->dcb_ctxt.bw_config;
	eth_conf = &dev->data->dev_conf;

	if (eth_conf->txmode.mq_mode == RTE_ETH_MQ_TX_DCB) {
		nb_tcs = eth_conf->tx_adv_conf.dcb_tx_conf.nb_tcs;
	} else if (eth_conf->txmode.mq_mode == RTE_ETH_MQ_TX_VMDQ_DCB) {
		if (eth_conf->tx_adv_conf.vmdq_dcb_tx_conf.nb_queue_pools ==
			RTE_ETH_32_POOLS) {
			nb_tcs = RTE_ETH_4_TCS;
		} else {
			nb_tcs = RTE_ETH_8_TCS;
		}
	} else {
		nb_tcs = 1;
	}

	if (nb_tcs != tc_num) {
		PMD_LOG_ERR(DRV,
				"Weight should be set for all %d enabled TCs.",
				nb_tcs);
		ret = -EINVAL;
		goto l_end;
	}

	sum = 0;
	for (i = 0; i < nb_tcs; i++)
		sum += bw_weight[i];

	if (sum != 100) {
		PMD_LOG_ERR(DRV,
				"The summary of the TC weight should be 100.");
		ret = -EINVAL;
		goto l_end;
	}

	for (i = 0; i < nb_tcs; i++) {
		tc = &dcb_config->tc_config[i];
		tc->channel[DCB_PATH_TX].bwg_percent = bw_weight[i];
	}

	for (; i < MAX_TRAFFIC_CLASS; i++) {
		tc = &dcb_config->tc_config[i];
		tc->channel[DCB_PATH_TX].bwg_percent = 0;
	}

	bw_conf->tc_num = nb_tcs;

l_end:
	return ret;
}
