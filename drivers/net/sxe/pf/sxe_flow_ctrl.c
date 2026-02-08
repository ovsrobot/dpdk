/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#include "sxe.h"
#include "sxe_logs.h"
#include "sxe_hw.h"
#include "sxe_flow_ctrl.h"
#include "sxe_phy.h"
#include "sxe_compat_version.h"

s32 sxe_flow_ctrl_enable(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	struct sxe_adapter *adapter = dev->data->dev_private;

	ret = sxe_fc_enable(adapter);
	PMD_LOG_DEBUG(INIT, "fc enable");

	return ret;
}

s32 sxe_flow_ctrl_get(struct rte_eth_dev *dev,
					struct rte_eth_fc_conf *fc_conf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	bool rx_pause_on;
	bool tx_pause_on;

	fc_conf->pause_time = sxe_hw_fc_pause_time_get(hw);
	fc_conf->high_water = sxe_hw_fc_tc_high_water_mark_get(hw, 0);
	fc_conf->low_water = sxe_hw_fc_tc_low_water_mark_get(hw, 0);
	fc_conf->send_xon = sxe_hw_fc_send_xon_get(hw);
	fc_conf->autoneg = !sxe_hw_is_fc_autoneg_disabled(hw);

	fc_conf->mac_ctrl_frame_fwd = 1;

	sxe_hw_fc_status_get(hw, &rx_pause_on, &tx_pause_on);

	if (rx_pause_on && tx_pause_on)
		fc_conf->mode = RTE_ETH_FC_FULL;
	else if (rx_pause_on)
		fc_conf->mode = RTE_ETH_FC_RX_PAUSE;
	else if (tx_pause_on)
		fc_conf->mode = RTE_ETH_FC_TX_PAUSE;
	else
		fc_conf->mode = RTE_ETH_FC_NONE;

	return 0;
}

s32 sxe_flow_ctrl_set(struct rte_eth_dev *dev,
					struct rte_eth_fc_conf *fc_conf)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret;
	u32 rx_buf_size;
	u32 max_high_water;
	enum sxe_fc_mode rte_2_sxe_fcmode[] = {
		SXE_FC_NONE,
		SXE_FC_RX_PAUSE,
		SXE_FC_TX_PAUSE,
		SXE_FC_FULL,
	};

	PMD_INIT_FUNC_TRACE();

	rx_buf_size = sxe_hw_rx_pkt_buf_size_get(hw, 0);
	PMD_LOG_DEBUG(INIT, "Rx packet buffer size = 0x%x", rx_buf_size);

	max_high_water = (rx_buf_size -
			RTE_ETHER_MAX_LEN) >> SXE_RX_PKT_BUF_SIZE_SHIFT;
	if (fc_conf->high_water > max_high_water ||
		fc_conf->high_water < fc_conf->low_water) {
		PMD_LOG_ERR(INIT, "Invalid high/low water setup value in KB");
		PMD_LOG_ERR(INIT, "High_water must <= 0x%x", max_high_water);
		ret = -EINVAL;
		goto l_end;
	}

	sxe_hw_fc_requested_mode_set(hw, rte_2_sxe_fcmode[fc_conf->mode]);
	sxe_hw_fc_pause_time_set(hw, fc_conf->pause_time);
	sxe_hw_fc_tc_high_water_mark_set(hw, 0, fc_conf->high_water);
	sxe_hw_fc_tc_low_water_mark_set(hw, 0, fc_conf->low_water);
	sxe_hw_fc_send_xon_set(hw, fc_conf->send_xon);
	sxe_hw_fc_autoneg_disable_set(hw, !fc_conf->autoneg);

	ret = sxe_flow_ctrl_enable(dev);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "sxe_flow_ctrl_enable = 0x%x", ret);
		ret = -EIO;
	}

l_end:
	return ret;
}
