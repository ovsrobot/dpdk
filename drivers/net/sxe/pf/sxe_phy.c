/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <rte_cycles.h>
#include <rte_net.h>

#include "sxe.h"
#include "sxe_hw.h"
#include "sxe_phy.h"
#include "drv_msg.h"
#include "sxe_phy.h"
#include "sxe_logs.h"
#include "sxe_errno.h"
#include "sxe_ethdev.h"
#include "sxe_filter.h"
#include "sxe_pmd_hdc.h"
#include "sxe_filter.h"
#include "sxe_compat_version.h"

#define SXE_WAIT_LINK_UP_FAILED	1
#define SXE_WARNING_TIMEOUT	9000
#define SXE_CHG_SFP_RATE_MS	 40
#define SXE_1G_WAIT_PCS_MS	  100
#define SXE_10G_WAIT_PCS_MS	 100
#define SXE_HZ_TRANSTO_MS	   1000
#define SXE_AN_COMPLETE_TIME	5
#define SXE_10G_WAIT_13_TIME	13
#define SXE_10G_WAIT_5_TIME	 5

static uint32_t sxe_setup_link_thread_handler(void *param)
{
	s32 ret;
	struct rte_eth_dev *dev = (struct rte_eth_dev *)param;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u32 allowed_speeds = 0;
	u32 conf_speeds = 0;
	u32 speed = 0;
	bool autoneg = false;

	rte_thread_detach(rte_thread_self());

	sxe_sfp_link_capabilities_get(adapter, &allowed_speeds, &autoneg);

	sxe_conf_speed_get(dev, &conf_speeds);

	speed = (conf_speeds & allowed_speeds) ? (conf_speeds & allowed_speeds) :
		allowed_speeds;

	if (adapter->phy_ctxt.sfp_info.multispeed_fiber)
		ret = sxe_multispeed_sfp_link_configure(dev, speed, true);
	else
		ret = sxe_sfp_link_configure(dev);
	if (ret)
		PMD_LOG_ERR(INIT, "link setup failed, ret=%d", ret);

	irq->action &= ~SXE_IRQ_LINK_CONFIG;
	rte_atomic_store_explicit(&adapter->link_thread_running, 0, rte_memory_order_seq_cst);

	return 0;
}

void sxe_wait_setup_link_complete(struct rte_eth_dev *dev,
						uint32_t timeout_ms)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	uint32_t timeout = timeout_ms ? timeout_ms : SXE_WARNING_TIMEOUT;

	while (rte_atomic_load_explicit(&adapter->link_thread_running,
		rte_memory_order_seq_cst)) {
		rte_delay_us_sleep(1000);
		timeout--;

		if (timeout_ms) {
			if (!timeout)
				return;

		} else if (!timeout) {
			timeout = SXE_WARNING_TIMEOUT;
			PMD_LOG_ERR(INIT, "link thread not complete too long time!");
		}
	}
}

static s32 sxe_an_cap_get(struct sxe_adapter *adapter, sxe_an_cap_s *an_cap)
{
	s32 ret;
	struct sxe_hw *hw = &adapter->hw;

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_AN_CAP_GET,
				NULL, 0,
				(void *)an_cap, sizeof(*an_cap));
	if (ret)
		PMD_LOG_ERR(INIT, "hdc trans failed ret=%d, cmd:negotiaton cap get", ret);

	return ret;
}

s32 sxe_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	u32 i;
	bool link_up, orig_link_up;
	struct rte_eth_link link;
	sxe_an_cap_s an_cap;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	sxe_link_speed link_speed = SXE_LINK_SPEED_UNKNOWN;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -1;

	PMD_LOG_INFO(INIT, "link update start...");

	memset(&link, 0, sizeof(link));
	link.link_status = RTE_ETH_LINK_DOWN;
	link.link_speed  = RTE_ETH_SPEED_NUM_NONE;
	link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	link.link_autoneg = !(dev->data->dev_conf.link_speeds &
						RTE_ETH_LINK_SPEED_FIXED);

	if (irq->action & SXE_IRQ_LINK_CONFIG) {
		PMD_LOG_INFO(INIT, "other link config thread exist");
		goto l_end;
	}

	if (dev->data->dev_conf.intr_conf.lsc)
		wait_to_complete = 0;

	sxe_link_info_get(adapter, &link_speed, &orig_link_up);
	sxe_link_info_get(adapter, &link_speed, &link_up);

	if (orig_link_up != link_up) {
		PMD_LOG_INFO(INIT, "link status %s to %s",
			(orig_link_up ? "up" : "down"),
			(link_up ? "up" : "down"));
	}

	if (wait_to_complete) {
		for (i = 0; i < SXE_LINK_UP_TIME; i++) {
			if (link_up)
				break;

			rte_delay_us_sleep(100000);

			sxe_link_info_get(adapter, &link_speed, &link_up);
		}
	}

	if (!link_up) {
		sxe_wait_setup_link_complete(dev, 0);
		if (!rte_atomic_exchange_explicit(&adapter->link_thread_running, 1,
				rte_memory_order_seq_cst)) {
			if (rte_atomic_load_explicit(&adapter->is_stopping,
				rte_memory_order_seq_cst) ||
				adapter->phy_ctxt.sfp_tx_laser_disabled) {
				PMD_LOG_INFO(INIT, "not create sxe_setup_link_thread_handler thread, "
						"tx_laser_disabled %d.",
						adapter->phy_ctxt.sfp_tx_laser_disabled);
				rte_atomic_store_explicit(&adapter->link_thread_running, 0,
					rte_memory_order_seq_cst);
			} else {
				irq->action |= SXE_IRQ_LINK_CONFIG;
				irq->to_pcs_init = true;
				if (rte_thread_create_internal_control(&adapter->link_thread_tid,
					"sxe-link-handler",
					sxe_setup_link_thread_handler, dev) < 0) {
					PMD_LOG_ERR(INIT,
						"Create link thread failed!");
					rte_atomic_store_explicit(&adapter->link_thread_running, 0,
						rte_memory_order_seq_cst);
				}
			}
		} else {
			PMD_LOG_ERR(INIT, "other link thread is running now!");
		}
		goto l_end;
	}

	link.link_status = RTE_ETH_LINK_UP;
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	switch (link_speed) {
	case SXE_LINK_SPEED_1GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_1G;
		if (adapter->phy_ctxt.sfp_tx_laser_disabled) {
			PMD_LOG_INFO(INIT, "tx laser disabled, link state is down.");
			link.link_status = RTE_ETH_LINK_DOWN;
			link.link_speed = RTE_ETH_SPEED_NUM_NONE;
		} else {
			for (i = 0; i < SXE_AN_COMPLETE_TIME; i++) {
				sxe_an_cap_get(adapter, &an_cap);
				if (an_cap.peer.remote_fault != SXE_REMOTE_UNKNOWN)
					break;
				rte_delay_us_sleep(100000);
			}
		}
		break;

	case SXE_LINK_SPEED_10GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_10G;
		break;
	default:
		link.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	}

l_end:
	PMD_LOG_INFO(INIT, "link update end, up=%x, speed=%x",
						link.link_status, link_speed);
	return rte_eth_linkstatus_set(dev, &link);
}

s32 sxe_link_status_update(struct rte_eth_dev *dev)
{
	u32 i;
	bool link_up;
	struct rte_eth_link link;
	sxe_an_cap_s an_cap;
	struct sxe_adapter *adapter = dev->data->dev_private;
	sxe_link_speed link_speed = SXE_LINK_SPEED_UNKNOWN;

	PMD_LOG_INFO(INIT, "link status update start...");

	memset(&link, 0, sizeof(link));
	link.link_status = RTE_ETH_LINK_DOWN;
	link.link_speed  = RTE_ETH_SPEED_NUM_NONE;
	link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	link.link_autoneg = !(dev->data->dev_conf.link_speeds &
						RTE_ETH_LINK_SPEED_FIXED);

	sxe_link_info_get(adapter, &link_speed, &link_up);
	if (!link_up) {
		PMD_LOG_INFO(INIT, "link status is down.");
		goto l_end;
	}

	link.link_status = RTE_ETH_LINK_UP;
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	switch (link_speed) {
	case SXE_LINK_SPEED_1GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_1G;
		for (i = 0; i < SXE_AN_COMPLETE_TIME; i++) {
			sxe_an_cap_get(adapter, &an_cap);
			if (an_cap.peer.remote_fault != SXE_REMOTE_UNKNOWN)
				break;

			rte_delay_us_sleep(100000);
		}
		break;

	case SXE_LINK_SPEED_10GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_10G;
		break;
	default:
		link.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	}

l_end:
	PMD_LOG_INFO(INIT, "link status update end, up=%x, speed=%x",
						link.link_status, link_speed);
	return rte_eth_linkstatus_set(dev, &link);
}

int sxe_dev_set_link_up(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = (struct sxe_adapter *)dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	sxe_sfp_tx_laser_enable(adapter);

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);
	sxe_hw_specific_irq_enable(hw, SXE_EIMS_LSC);
	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);

	sxe_link_update(dev, 0);

	return 0;
}

int sxe_dev_set_link_down(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = (struct sxe_adapter *)dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	sxe_sfp_tx_laser_disable(adapter);

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);
	sxe_hw_specific_irq_disable(hw, SXE_EIMS_LSC);
	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);

	sxe_link_update(dev, 0);

	return 0;
}


static s32 sxe_sfp_eeprom_read(struct sxe_adapter *adapter, u16 offset,
					u16 len, u8 *data)
{
	s32 ret;
	struct sxe_sfp_rw_req req;
	struct sxe_sfp_read_resp *resp;
	u16 resp_len = sizeof(struct sxe_sfp_read_resp) + len;
	struct sxe_hw *hw = &adapter->hw;

	if (!data) {
		ret = -EINVAL;
		PMD_LOG_ERR(INIT, "sfp read buff == NULL");
		goto l_end;
	}

	if (len > SXE_SFP_EEPROM_SIZE_MAX) {
		ret = -EINVAL;
		PMD_LOG_ERR(INIT, "sfp read size[%u] > eeprom max size[%d], ret=%d",
					len, SXE_SFP_EEPROM_SIZE_MAX, ret);
		goto l_end;
	}

	PMD_LOG_INFO(INIT, "sfp read, offset=%u, len=%u", offset, len);

	req.len = len;
	req.offset = offset;

	resp = malloc(resp_len);
	if (!resp) {
		ret = -ENOMEM;
		PMD_LOG_ERR(INIT, "sfp read, alloc resp mem failed");
		goto l_end;
	}

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_SFP_READ,
				(void *)&req, sizeof(struct sxe_sfp_rw_req),
				(void *)resp, resp_len);
	if (ret) {
		PMD_LOG_ERR(INIT, "sfp read, hdc failed, offset=%u, len=%u, ret=%d",
					offset, len, ret);
		ret = -EIO;
		goto l_free;
	}

	if (resp->len != len) {
		ret = -EIO;
		PMD_LOG_ERR(INIT, "sfp read failed, offset=%u, len=%u", offset, len);
		goto l_free;
	}

	memcpy(data, resp->resp, len);

l_free:
	free(resp);

l_end:
	return ret;
}

static s32 sxe_sfp_tx_laser_ctrl(struct sxe_adapter *adapter, bool is_disable)
{
	s32 ret;
	sxe_spp_tx_able_s laser_disable;
	struct sxe_hw *hw = &adapter->hw;

	laser_disable.is_disable = is_disable;
	adapter->phy_ctxt.sfp_tx_laser_disabled = is_disable;
	PMD_LOG_INFO(INIT, "sfp tx laser ctrl start, is_disable=%x", is_disable);
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_TX_DIS_CTRL,
				&laser_disable, sizeof(laser_disable),
				NULL, 0);
	if (ret) {
		PMD_LOG_ERR(INIT, "sfp tx laser ctrl failed, ret=%d", ret);
		goto l_end;
	}

	PMD_LOG_INFO(INIT, "sfp tx laser ctrl success, is_disable=%x", is_disable);

l_end:
	return ret;
}

void sxe_sfp_tx_laser_enable(struct sxe_adapter *adapter)
{
	sxe_sfp_tx_laser_ctrl(adapter, false);
}

void sxe_sfp_tx_laser_disable(struct sxe_adapter *adapter)
{
	sxe_sfp_tx_laser_ctrl(adapter, true);
}

s32 sxe_sfp_reset(struct sxe_adapter *adapter)
{
	PMD_LOG_INFO(INIT, "auto_restart:%u.", adapter->hw.mac.auto_restart);

	if (adapter->hw.mac.auto_restart) {
		sxe_sfp_tx_laser_disable(adapter);
		sxe_sfp_tx_laser_enable(adapter);
		adapter->hw.mac.auto_restart = false;
	}

	return 0;
}

void sxe_sfp_link_capabilities_get(struct sxe_adapter *adapter, u32 *speed,
							bool *autoneg)
{
	struct sxe_sfp_info *sfp = &adapter->phy_ctxt.sfp_info;

	*speed = 0;

	if (sfp->type == SXE_SFP_TYPE_1G_CU ||
		sfp->type == SXE_SFP_TYPE_1G_SXLX) {
		*speed = SXE_LINK_SPEED_1GB_FULL;
		*autoneg = true;
		goto l_end;
	}

	*speed = SXE_LINK_SPEED_10GB_FULL;
	*autoneg = false;

	if (sfp->multispeed_fiber) {
		*speed |= SXE_LINK_SPEED_10GB_FULL | SXE_LINK_SPEED_1GB_FULL;
		*autoneg = true;
	}

l_end:
	PMD_LOG_INFO(INIT, "sfp link speed cap=%d", *speed);
}

s32 sxe_sfp_rate_select(struct sxe_adapter *adapter, sxe_sfp_rate_e rate)
{
	s32 ret;
	sxe_sfp_rate_able_s rate_able;
	struct sxe_hw *hw = &adapter->hw;

	rate_able.rate = rate;
	PMD_LOG_INFO(INIT, "sfp tx rate select start, rate=%d", rate);
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_RATE_SELECT,
				&rate_able, sizeof(rate_able),
				NULL, 0);
	if (ret)
		PMD_LOG_ERR(INIT, "sfp rate select failed, ret=%d", ret);

	PMD_LOG_INFO(INIT, "sfp tx rate select end, rate=%d", rate);

	return ret;
}

s32 sxe_pcs_sds_init(struct rte_eth_dev *dev,
				sxe_pcs_mode_e mode, u32 max_frame)
{
	s32 ret;
	bool keep_crc = false;
	sxe_pcs_cfg_s pcs_cfg;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	struct rte_eth_rxmode *rx_conf = &dev->data->dev_conf.rxmode;

	if (rx_conf->offloads & RTE_ETH_RX_OFFLOAD_KEEP_CRC)
		keep_crc = true;
	sxe_hw_crc_strip_config(hw, keep_crc);

	pcs_cfg.mode = mode;
	pcs_cfg.mtu  = max_frame;
	sxe_sfp_tx_laser_disable(adapter);
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_PCS_SDS_INIT,
				(void *)&pcs_cfg, sizeof(pcs_cfg),
				NULL, 0);
	irq->to_pcs_init = false;
	sxe_sfp_tx_laser_enable(adapter);
	if (ret) {
		LOG_ERROR_BDF("hdc trans failed ret=%d, cmd:pcs init", ret);
		goto l_end;
	}

	sxe_fc_mac_addr_set(adapter);

	LOG_INFO_BDF("mode:%u max_frame:0x%x pcs sds init done.",
			 mode, max_frame);
l_end:
	return ret;
}

s32 sxe_conf_speed_get(struct rte_eth_dev *dev, u32 *conf_speeds)
{
	s32 ret = 0;
	u32 *link_speeds;
	u32 allowed_speeds;

	link_speeds = &dev->data->dev_conf.link_speeds;
	allowed_speeds = RTE_ETH_LINK_SPEED_1G |
			RTE_ETH_LINK_SPEED_10G;

	if (((*link_speeds) >> 1) & ~(allowed_speeds >> 1)) {
		PMD_LOG_ERR(INIT, "invalid link setting, link_speed=%x",
						*link_speeds);
		ret = -EINVAL;
		goto l_end;
	}

	*conf_speeds = SXE_LINK_SPEED_UNKNOWN;
	if (*link_speeds == RTE_ETH_LINK_SPEED_AUTONEG) {
		*conf_speeds = SXE_LINK_SPEED_1GB_FULL |
				 SXE_LINK_SPEED_10GB_FULL;
	} else {
		if (*link_speeds & RTE_ETH_LINK_SPEED_10G)
			*conf_speeds |= SXE_LINK_SPEED_10GB_FULL;

		if (*link_speeds & RTE_ETH_LINK_SPEED_1G)
			*conf_speeds |= SXE_LINK_SPEED_1GB_FULL;
	}

l_end:
	return ret;
}

s32 sxe_multispeed_sfp_link_configure(struct rte_eth_dev *dev, u32 speed, bool is_in_thread)
{
	s32 ret;
	bool autoneg, link_up;
	u32 i, speed_cap, link_speed, speedcnt = 0;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u32 highest_link_speed = SXE_LINK_SPEED_UNKNOWN;
	u32 frame_size = adapter->mtu + SXE_ETH_DEAD_LOAD;
	u8 wait_time = is_in_thread ? SXE_10G_WAIT_13_TIME : SXE_10G_WAIT_5_TIME;

	sxe_sfp_link_capabilities_get(adapter, &speed_cap, &autoneg);

	speed &= speed_cap;

	if (speed & SXE_LINK_SPEED_10GB_FULL) {
		PMD_LOG_DEBUG(INIT, "10G link cfg start");
		irq->to_pcs_init = true;

		speedcnt++;
		highest_link_speed = SXE_LINK_SPEED_10GB_FULL;

		ret = sxe_sfp_rate_select(adapter, SXE_SFP_RATE_10G);
		if (ret) {
			PMD_LOG_ERR(INIT, "set sfp rate failed, ret=%d", ret);
			goto l_end;
		}

		rte_delay_us_sleep((SXE_CHG_SFP_RATE_MS * SXE_HZ_TRANSTO_MS));

		ret = sxe_pcs_sds_init(dev, SXE_PCS_MODE_10GBASE_KR_WO,
						frame_size);
		if (ret)
			goto l_end;


		for (i = 0; i < wait_time; i++) {
			rte_delay_us_sleep((SXE_10G_WAIT_PCS_MS * SXE_HZ_TRANSTO_MS));

			sxe_link_info_get(adapter, &link_speed, &link_up);
			if (link_up) {
				PMD_LOG_INFO(INIT, "link cfg end, link up, speed is 10G");
				goto l_out;
			}
		}

		PMD_LOG_WARN(INIT, "10G link cfg failed, retry...");
	}

	if (speed & SXE_LINK_SPEED_1GB_FULL) {
		PMD_LOG_DEBUG(INIT, "1G link cfg start");
		irq->to_pcs_init = true;

		speedcnt++;
		if (highest_link_speed == SXE_LINK_SPEED_UNKNOWN)
			highest_link_speed = SXE_LINK_SPEED_1GB_FULL;

		ret = sxe_sfp_rate_select(adapter, SXE_SFP_RATE_1G);
		if (ret) {
			PMD_LOG_ERR(INIT, "set sfp rate failed, ret=%d", ret);
			goto l_end;
		}

		rte_delay_us_sleep((SXE_CHG_SFP_RATE_MS * SXE_HZ_TRANSTO_MS));

		ret = sxe_pcs_sds_init(dev, SXE_PCS_MODE_1000BASE_KX_W,
						frame_size);
		if (ret)
			goto l_end;


		rte_delay_us_sleep(SXE_1G_WAIT_PCS_MS * SXE_HZ_TRANSTO_MS);

		sxe_link_status_update(dev);

		link_up = sxe_hw_is_link_state_up(hw);
		if (link_up) {
			PMD_LOG_INFO(INIT, "link cfg end, link up, speed is 1G");
			goto l_out;
		}

		PMD_LOG_WARN(INIT, "1G link cfg failed, retry...");
	}

	if (speedcnt > 1)
		ret = sxe_multispeed_sfp_link_configure(dev, highest_link_speed, is_in_thread);

l_out:

	adapter->phy_ctxt.autoneg_advertised = 0;

	if (speed & SXE_LINK_SPEED_10GB_FULL)
		adapter->phy_ctxt.autoneg_advertised |= SXE_LINK_SPEED_10GB_FULL;

	if (speed & SXE_LINK_SPEED_1GB_FULL)
		adapter->phy_ctxt.autoneg_advertised |= SXE_LINK_SPEED_1GB_FULL;

l_end:
	return ret;
}

void sxe_link_info_get(struct sxe_adapter *adapter, u32 *link_speed, bool *link_up)
{
	struct sxe_hw *hw = &adapter->hw;

	*link_up = sxe_hw_is_link_state_up(hw);
	if (false == *link_up) {
		PMD_LOG_INFO(INIT, "link state =%d, (1=link_up, 0=link_down)",
								*link_up);
		*link_speed = SXE_LINK_SPEED_UNKNOWN;
	} else {
		*link_speed = sxe_hw_link_speed_get(hw);
	}
}

static s32 sxe_sfp_fc_autoneg(struct sxe_adapter *adapter)
{
	s32 ret;
	sxe_an_cap_s an_cap;
	struct sxe_hw *hw = &adapter->hw;

	ret = sxe_an_cap_get(adapter, &an_cap);
	if (ret) {
		PMD_LOG_ERR(INIT, "get auto negotiate capacity failed, ret=%d", ret);
		goto l_end;
	}

	if ((an_cap.local.pause_cap & SXE_PAUSE_CAP_SYMMETRIC_PAUSE) &&
		(an_cap.peer.pause_cap & SXE_PAUSE_CAP_SYMMETRIC_PAUSE)) {
		if (hw->fc.requested_mode == SXE_FC_FULL) {
			hw->fc.current_mode = SXE_FC_FULL;
			PMD_LOG_DEBUG(INIT, "Flow Control = FULL.");
		} else {
			hw->fc.current_mode = SXE_FC_RX_PAUSE;
			PMD_LOG_DEBUG(INIT, "Flow Control=RX PAUSE frames only");
		}
	} else if ((an_cap.local.pause_cap == SXE_PAUSE_CAP_ASYMMETRIC_PAUSE) &&
		(an_cap.peer.pause_cap == SXE_PAUSE_CAP_BOTH_PAUSE)) {
		hw->fc.current_mode = SXE_FC_TX_PAUSE;
		PMD_LOG_DEBUG(INIT, "Flow Control = TX PAUSE frames only.");
	} else if ((an_cap.local.pause_cap == SXE_PAUSE_CAP_BOTH_PAUSE) &&
		(an_cap.peer.pause_cap == SXE_PAUSE_CAP_ASYMMETRIC_PAUSE)) {
		hw->fc.current_mode = SXE_FC_RX_PAUSE;
		PMD_LOG_DEBUG(INIT, "Flow Control = RX PAUSE frames only.");
	} else {
		hw->fc.current_mode = SXE_FC_NONE;
		PMD_LOG_DEBUG(INIT, "Flow Control = NONE.");
	}

l_end:
	return ret;
}

static void sxe_fc_autoneg(struct sxe_adapter *adapter)
{
	struct sxe_hw *hw = &adapter->hw;

	s32 ret = -SXE_ERR_FC_NOT_NEGOTIATED;
	bool link_up;
	u32 link_speed;
	if (hw->fc.disable_fc_autoneg) {
		PMD_LOG_INFO(INIT, "disable fc autoneg");
		goto l_end;
	}

	sxe_link_info_get(adapter, &link_speed, &link_up);
	if (!link_up) {
		PMD_LOG_INFO(INIT, "link down, don't fc autoneg");
		goto l_end;
	}

	if (link_speed != SXE_LINK_SPEED_1GB_FULL) {
		PMD_LOG_INFO(INIT, "link speed=%x, (0x80=10G, 0x20=1G), "
			"don't fc autoneg", link_speed);
		goto l_end;
	}

	ret = sxe_sfp_fc_autoneg(adapter);
l_end:
	if (ret)
		hw->fc.current_mode = hw->fc.requested_mode;
}

s32 sxe_fc_enable(struct sxe_adapter *adapter)
{
	s32 ret = 0;
	u32 i;
	struct sxe_hw *hw = &adapter->hw;

	if (!hw->fc.pause_time) {
		PMD_LOG_ERR(INIT, "link fc disabled since pause time is 0");
		ret = -SXE_ERR_INVALID_LINK_SETTINGS;
		goto l_end;
	}

	for (i = 0; i < MAX_TRAFFIC_CLASS; i++) {
		if ((hw->fc.current_mode & SXE_FC_TX_PAUSE) &&
			hw->fc.high_water[i]) {
			if (!hw->fc.low_water[i] ||
				hw->fc.low_water[i] >= hw->fc.high_water[i]) {
				PMD_LOG_DEBUG(INIT, "invalid water mark configuration, "
					"tc[%u] low_water=%u, high_water=%u",
					i, hw->fc.low_water[i],
					hw->fc.high_water[i]);
				ret = -SXE_ERR_INVALID_LINK_SETTINGS;
				goto l_end;
			}
		}
	}

	/* auto negotiation flow control local capability configuration */
	sxe_fc_autoneg_localcap_set(hw);

	sxe_fc_autoneg(adapter);

	ret = sxe_hw_fc_enable(hw);
	if (ret)
		PMD_LOG_ERR(INIT, "link fc enable failed, ret=%d", ret);

l_end:
	return ret;
}

s32 sxe_pfc_enable(struct sxe_adapter *adapter, u8 tc_idx)
{
	s32 ret;
	struct sxe_hw *hw = &adapter->hw;

	if (!hw->fc.pause_time) {
		LOG_ERROR_BDF("link fc disabled since pause time is 0");
		ret = -SXE_ERR_INVALID_LINK_SETTINGS;
		goto l_ret;
	}

	if (hw->fc.current_mode & SXE_FC_TX_PAUSE) {
		if (!hw->fc.high_water[tc_idx] || !hw->fc.low_water[tc_idx]) {
			LOG_ERROR_BDF("Invalid water mark configuration");
			ret = SXE_ERR_INVALID_LINK_SETTINGS;
			goto l_ret;
		}

		if (hw->fc.low_water[tc_idx] >= hw->fc.high_water[tc_idx]) {
			LOG_ERROR_BDF("Invalid water mark configuration");
			ret = SXE_ERR_INVALID_LINK_SETTINGS;
			goto l_ret;
		}
	}

	sxe_fc_autoneg(adapter);

	ret = sxe_hw_pfc_enable(hw, tc_idx);
	if (ret)
		PMD_LOG_ERR(INIT, "link fc enable failed, ret=%d", ret);

l_ret:
	return ret;
}
s32 sxe_sfp_identify(struct sxe_adapter *adapter)
{
	s32 ret;
	enum sxe_sfp_type sfp_type;
	u8 sfp_comp_code[SXE_SFP_COMP_CODE_SIZE];
	struct sxe_sfp_info *sfp = &adapter->phy_ctxt.sfp_info;

	PMD_LOG_INFO(INIT, "sfp identify start");

	ret = sxe_sfp_eeprom_read(adapter, SXE_SFF_BASE_ADDR,
				SXE_SFP_COMP_CODE_SIZE, sfp_comp_code);
	if (ret) {
		sfp_type = SXE_SFP_TYPE_UNKNOWN;
		PMD_LOG_ERR(INIT, "get sfp identifier failed, ret=%d", ret);
		goto l_end;
	}

	PMD_LOG_INFO(INIT, "sfp identifier=%x, cable_technology=%x, "
			"10GB_code=%x, 1GB_code=%x",
		sfp_comp_code[SXE_SFF_IDENTIFIER],
		sfp_comp_code[SXE_SFF_CABLE_TECHNOLOGY],
		sfp_comp_code[SXE_SFF_10GBE_COMP_CODES],
		sfp_comp_code[SXE_SFF_1GBE_COMP_CODES]);

	if (sfp_comp_code[SXE_SFF_IDENTIFIER] != SXE_SFF_IDENTIFIER_SFP) {
		LOG_WARN("sfp type get failed, offset=%d, type=%x",
			SXE_SFF_IDENTIFIER, sfp_comp_code[SXE_SFF_IDENTIFIER]);
		sfp_type = SXE_SFP_TYPE_UNKNOWN;
		ret = -SXE_ERR_SFF_NOT_SUPPORTED;
		goto l_end;
	}

	if (sfp_comp_code[SXE_SFF_CABLE_TECHNOLOGY] & SXE_SFF_DA_PASSIVE_CABLE) {
		sfp_type = SXE_SFP_TYPE_DA_CU;
	}  else if (sfp_comp_code[SXE_SFF_10GBE_COMP_CODES] &
		(SXE_SFF_10GBASESR_CAPABLE | SXE_SFF_10GBASELR_CAPABLE)) {
		sfp_type = SXE_SFP_TYPE_SRLR;
	} else if (sfp_comp_code[SXE_SFF_1GBE_COMP_CODES] &
		SXE_SFF_1GBASET_CAPABLE) {
		sfp_type = SXE_SFP_TYPE_1G_CU;
	} else if ((sfp_comp_code[SXE_SFF_1GBE_COMP_CODES] &
		SXE_SFF_1GBASESX_CAPABLE) ||
		(sfp_comp_code[SXE_SFF_1GBE_COMP_CODES] &
		SXE_SFF_1GBASELX_CAPABLE)) {
		sfp_type = SXE_SFP_TYPE_1G_SXLX;
	} else {
		sfp_type = SXE_SFP_TYPE_UNKNOWN;
	}

	sfp->multispeed_fiber = false;
	if (((sfp_comp_code[SXE_SFF_1GBE_COMP_CODES] &
			SXE_SFF_1GBASESX_CAPABLE) &&
		(sfp_comp_code[SXE_SFF_10GBE_COMP_CODES] &
			SXE_SFF_10GBASESR_CAPABLE)) ||
		((sfp_comp_code[SXE_SFF_1GBE_COMP_CODES] &
			SXE_SFF_1GBASELX_CAPABLE) &&
		(sfp_comp_code[SXE_SFF_10GBE_COMP_CODES] &
			SXE_SFF_10GBASELR_CAPABLE))) {
		sfp->multispeed_fiber = true;
	}

	PMD_LOG_INFO(INIT, "identify sfp, sfp_type=%d, is_multispeed=%x",
			sfp_type, sfp->multispeed_fiber);

l_end:
	adapter->phy_ctxt.sfp_info.type = sfp_type;
	return ret;
}

s32 sxe_sfp_link_configure(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	bool an;
	u32 pcs_mode = SXE_PCS_MODE_BUTT;
	u32 speed;
	struct sxe_adapter *adapter = dev->data->dev_private;
	u32 frame_size = adapter->mtu + SXE_ETH_DEAD_LOAD;

	sxe_sfp_link_capabilities_get(adapter, &speed, &an);

	if (speed == SXE_LINK_SPEED_1GB_FULL) {
		pcs_mode = SXE_PCS_MODE_1000BASE_KX_W;
		adapter->phy_ctxt.autoneg_advertised = SXE_LINK_SPEED_1GB_FULL;
	} else if (speed == SXE_LINK_SPEED_10GB_FULL) {
		pcs_mode = SXE_PCS_MODE_10GBASE_KR_WO;
		adapter->phy_ctxt.autoneg_advertised = SXE_LINK_SPEED_10GB_FULL;
	}

	ret = sxe_pcs_sds_init(dev, pcs_mode, frame_size);
	if (ret)
		PMD_LOG_ERR(INIT, "pcs sds init failed, ret=%d", ret);

	if (speed == SXE_LINK_SPEED_1GB_FULL)
		sxe_link_status_update(dev);

	PMD_LOG_INFO(INIT, "link :cfg speed=%x, pcs_mode=%x, atuoreg=%d",
					speed, pcs_mode, an);

	return ret;
}

int sxe_get_module_info(struct rte_eth_dev *dev,
			struct rte_eth_dev_module_info *info)
{
	s32 ret;
	bool page_swap = false;
	u8 sff8472_rev, addr_mode;
	struct sxe_adapter *adapter = dev->data->dev_private;

	ret = sxe_sfp_eeprom_read(adapter, SXE_SFF_8472_COMPLIANCE,
					sizeof(sff8472_rev), &sff8472_rev);
	if (ret) {
		ret = -EIO;
		goto l_end;
	}

	ret = sxe_sfp_eeprom_read(adapter, SXE_SFF_8472_DIAG_MONITOR_TYPE,
					sizeof(addr_mode), &addr_mode);
	if (ret) {
		ret = -EIO;
		goto l_end;
	}

	if (addr_mode & SXE_SFF_ADDRESSING_MODE) {
		PMD_LOG_ERR(DRV, "address change required to access page 0xA2, "
			"but not supported. Please report the module "
			"type to the driver maintainers.");
		page_swap = true;
	}

	if (sff8472_rev == SXE_SFF_8472_UNSUP || page_swap ||
			!(addr_mode & SXE_SFF_DDM_IMPLEMENTED)) {
		info->type = RTE_ETH_MODULE_SFF_8079;
		info->eeprom_len = RTE_ETH_MODULE_SFF_8079_LEN;
	} else {
		info->type = RTE_ETH_MODULE_SFF_8472;
		info->eeprom_len = RTE_ETH_MODULE_SFF_8472_LEN;
	}

	LOG_INFO("sfp support management is %x, eeprom addr mode=%x "
			"eeprom type=%x, eeprom len=%d",
		sff8472_rev, addr_mode, info->type, info->eeprom_len);

l_end:
	return ret;
}

int sxe_get_module_eeprom(struct rte_eth_dev *dev,
				struct rte_dev_eeprom_info *info)
{
	s32 ret;
	u8 *data = info->data;
	struct sxe_adapter *adapter = dev->data->dev_private;

	if (info->length == 0) {
		ret = -EINVAL;
		goto l_end;
	}

	ret = sxe_sfp_eeprom_read(adapter, info->offset, info->length, data);
	if (ret)
		LOG_ERROR("read sfp failed");

l_end:
	return ret;
}


static enum sxe_media_type sxe_media_type_get(struct sxe_adapter *adapter)
{
	enum sxe_media_type type;

	type = SXE_MEDIA_TYPE_FIBER;
	adapter->phy_ctxt.is_sfp = true;

	return type;
}

s32 sxe_phy_init(struct sxe_adapter *adapter)
{
	s32 ret = 0;
	enum sxe_media_type media_type = sxe_media_type_get(adapter);

	if (media_type == SXE_MEDIA_TYPE_FIBER) {
		ret = sxe_sfp_identify(adapter);
		if (ret)
			PMD_LOG_ERR(INIT, "phy identify failed, ret=%d", ret);
	} else {
		PMD_LOG_ERR(INIT, "phy init failed, only support SFP.");
	}

	return ret;
}
