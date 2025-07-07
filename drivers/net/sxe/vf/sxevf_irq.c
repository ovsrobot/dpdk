/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_alarm.h>
#include <rte_interrupts.h>
#include <rte_malloc.h>
#include <bus_pci_driver.h>
#include <eal_interrupts.h>
#include "sxevf.h"
#include "sxe_logs.h"
#include "sxe_errno.h"
#include "sxevf_rx.h"
#include "sxevf_irq.h"
#include "sxevf_msg.h"
#include "sxevf_queue.h"
#include "sxe_compat_version.h"

#define SXEVF_IRQ_LINK_CONFIG	  (u32)(1 << 3)

#define SXEVF_RX_OTHER_IRQ_MASK	 (3)

#define SXEVF_MISC_VEC_ID		RTE_INTR_VEC_ZERO_OFFSET

#define SXEVF_RX_VEC_BASE		  RTE_INTR_VEC_RXTX_OFFSET

#define SXEVF_EITR_INTERVAL_UNIT_NS	2048
#define SXEVF_EITR_ITR_INT_SHIFT		3
#define SXEVF_IRQ_ITR_MASK			  (0x00000FF8)
#define SXEVF_EITR_INTERVAL_US(us) \
	(((us) * 1000 / SXEVF_EITR_INTERVAL_UNIT_NS << SXEVF_EITR_ITR_INT_SHIFT) & \
		SXEVF_IRQ_ITR_MASK)

#define SXEVF_QUEUE_ITR_INTERVAL_DEFAULT   500
#define SXEVF_QUEUE_ITR_INTERVAL   3

void sxevf_intr_disable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_irq_context *irq_ctxt = &adapter->irq_ctxt;

	PMD_INIT_FUNC_TRACE();

	sxevf_irq_disable(hw);

	irq_ctxt->enable_mask = 0;
}

void sxevf_intr_enable(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_irq_context *irq_ctxt = &adapter->irq_ctxt;

	PMD_INIT_FUNC_TRACE();

	sxevf_irq_enable(hw, SXEVF_RX_OTHER_IRQ_MASK);

	irq_ctxt->enable_mask = SXEVF_RX_OTHER_IRQ_MASK;
}

static s32 sxevf_ctrl_msg_check(struct rte_eth_dev *eth_dev)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 ctrl_msg;
	s32 ret;

	ret = sxevf_ctrl_msg_rcv_and_clear(hw, (u32 *)&ctrl_msg,
				SXEVF_MSG_NUM(sizeof(ctrl_msg)));
	if (ret) {
		PMD_LOG_INFO(DRV, "ctrl msg rcv fail due to lock fail.(err:%d)", ret);
		goto l_end;
	}

	if (ctrl_msg & SXEVF_PF_CTRL_MSG_REINIT) {
		sxe_eth_dev_callback_process(eth_dev, RTE_ETH_EVENT_INTR_RESET,
						 NULL);
		PMD_LOG_INFO(DRV, "rcv reinit msg.");
	}

l_end:
	return ret;
}

static s32 sxevf_link_msg_check(struct rte_eth_dev *eth_dev, bool *link_up)
{
	struct sxevf_adapter *adapter = eth_dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	u32 ctrl_msg;
	s32 ret;

	ret = sxevf_ctrl_msg_rcv_and_clear(hw, (u32 *)&ctrl_msg,
				SXEVF_MSG_NUM(sizeof(ctrl_msg)));
	if (ret) {
		PMD_LOG_INFO(DRV, "ctrl msg rcv fail due to lock fail.(err:%d)", ret);
		goto l_end;
	}

	if (ctrl_msg & SXEVF_PF_CTRL_MSG_NETDEV_DOWN) {
		*link_up = false;
		PMD_LOG_INFO(DRV, "rcv ctrl msg:0x%x need link down.", ctrl_msg);
	} else if (ctrl_msg & SXEVF_PF_CTRL_MSG_LINK_UPDATE) {
		*link_up = true;
		PMD_LOG_INFO(DRV, "rcv ctrl msg:0x%x physical link up.", ctrl_msg);
	}

l_end:
	return ret;
}

static void sxevf_mbx_irq_handler(void *data)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)data;

	sxevf_intr_disable(eth_dev);

	sxevf_ctrl_msg_check(eth_dev);

	sxevf_intr_enable(eth_dev);
}

void sxevf_irq_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *irq_handle = SXE_PCI_INTR_HANDLE(pci_dev);

	sxevf_intr_disable(eth_dev);

	rte_intr_callback_register(irq_handle,
				   sxevf_mbx_irq_handler, eth_dev);

	rte_intr_enable(irq_handle);
	sxevf_intr_enable(eth_dev);
}

static s32 sxevf_msix_configure(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	sxevf_rx_queue_s *rx_queue;
	u16 queue_id;
	u16 vector = SXEVF_MISC_VEC_ID;
	u16 base = SXEVF_MISC_VEC_ID;
	u32 irq_interval;
	s32 ret = 0;

	sxevf_event_irq_map(hw, vector);

	if (!rte_intr_dp_is_en(handle)) {
		ret = -SXE_ERR_PARAM;
		PMD_LOG_ERR(DRV, "intr type:%u nb_efd:%u irq unsupported.(err:%d)",
				  handle->type, handle->nb_efd, ret);
		goto l_out;
	}

	if (rte_intr_allow_others(handle)) {
		vector = SXEVF_RX_VEC_BASE;
		base = SXEVF_RX_VEC_BASE;
	}

	irq_interval = SXEVF_EITR_INTERVAL_US(SXEVF_QUEUE_ITR_INTERVAL_DEFAULT);
	if (rte_intr_dp_is_en(handle))
		irq_interval = SXEVF_EITR_INTERVAL_US(SXEVF_QUEUE_ITR_INTERVAL);

	for (queue_id = 0; queue_id < dev->data->nb_rx_queues;
		queue_id++) {
		rx_queue = dev->data->rx_queues[queue_id];
		if (rte_intr_dp_is_en(handle))
			sxevf_ring_irq_interval_set(hw, vector, irq_interval);

		sxevf_hw_ring_irq_map(hw, false,
					rx_queue->reg_idx,
					vector);
		handle->intr_vec[queue_id] = vector;
		PMD_LOG_INFO(DRV,
				"queue id:%u reg_idx:%u vector:%u ",
				queue_id,
				rx_queue->reg_idx,
				vector);
		if (vector < base + handle->nb_efd - 1)
			vector++;
	}

	sxevf_ring_irq_interval_set(hw, 0, irq_interval);

l_out:
	return ret;
}

s32 sxevf_irq_configure(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	u16 irq_num;
	s32 ret = 0;

	if (rte_intr_cap_multiple(handle) &&
		 eth_dev->data->dev_conf.intr_conf.rxq != 0) {
		irq_num = 1;
		if (rte_intr_efd_enable(handle, irq_num)) {
			ret = -SXE_ERR_CONFIG;
			PMD_LOG_ERR(DRV,
					  "intr_handle type:%d irq num:%d invalid",
					  handle->type, irq_num);
			goto l_out;
		}
	}

	if (rte_intr_dp_is_en(handle) && !handle->intr_vec) {
		handle->intr_vec = rte_zmalloc("intr_vec",
					eth_dev->data->nb_rx_queues * sizeof(u32), 0);
		if (handle->intr_vec == NULL) {
			PMD_LOG_ERR(DRV, "rx queue irq vector "
					 "allocate %zuB memory fail.",
					 eth_dev->data->nb_rx_queues * sizeof(u32));
			ret = -ENOMEM;
			goto l_out;
		}
	}

	ret = sxevf_msix_configure(eth_dev);
	if (ret) {
		PMD_LOG_ERR(DRV, "intr type:%u nb_efd:%u irq unsupported.(err:%d)",
				  handle->type, handle->nb_efd, ret);
		goto l_out;
	}

	rte_intr_disable(handle);

	rte_intr_enable(handle);

	sxevf_intr_enable(eth_dev);

	PMD_LOG_INFO(DRV,
			  "intr_handle type:%d rx queue num:%d "
			  "queue irq num:%u total irq num:%u "
			  "config done",
			  handle->type,
			  eth_dev->data->nb_rx_queues,
			  handle->nb_efd,
			  handle->max_intr);

l_out:
	return ret;
}

void sxevf_irq_free(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);

	rte_intr_disable(handle);

	if (handle->intr_vec) {
		rte_free(handle->intr_vec);
		handle->intr_vec = NULL;
	}
}

void sxevf_irq_unregister(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);

	rte_intr_callback_unregister(handle, sxevf_mbx_irq_handler, eth_dev);
}

s32 sxevf_rx_queue_intr_enable(struct rte_eth_dev *dev, u16 queue_id)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_irq_context *irq_ctxt = &adapter->irq_ctxt;
	u32 vector = SXEVF_MISC_VEC_ID;

	RTE_SET_USED(queue_id);

	if (rte_intr_allow_others(intr_handle))
		vector = SXEVF_RX_VEC_BASE;

	irq_ctxt->enable_mask |= (1 << vector);

	sxevf_specific_irq_enable(hw, irq_ctxt->enable_mask);

	rte_intr_ack(intr_handle);

	return 0;
}

s32 sxevf_rx_queue_intr_disable(struct rte_eth_dev *dev, u16 queue_id)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *intr_handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;
	struct sxevf_irq_context *irq_ctxt = &adapter->irq_ctxt;
	u32 vector = SXEVF_MISC_VEC_ID;

	RTE_SET_USED(queue_id);

	if (rte_intr_allow_others(intr_handle))
		vector = SXEVF_RX_VEC_BASE;

	irq_ctxt->enable_mask &= ~(1 << vector);

	sxevf_specific_irq_enable(hw, irq_ctxt->enable_mask);

	return 0;
}

static void sxevf_physical_link_check(struct rte_eth_dev *dev,  u32 *link_speed, bool *link_up)
{
	u32 link_reg, i;
	struct sxevf_adapter *adapter = dev->data->dev_private;
	struct sxevf_hw *hw = &adapter->hw;

	link_reg = sxevf_link_state_get(hw);
	if (!(link_reg & SXE_VFLINKS_UP)) {
		*link_up = false;
		goto l_end;
	}

	for (i = 0; i < 5; i++) {
		sxe_udelay(100);
		link_reg = sxevf_link_state_get(hw);
		if (!(link_reg & SXE_VFLINKS_UP)) {
			*link_up = false;
			goto l_end;
		}
	}

	switch (link_reg & SXE_VFLINKS_SPEED) {
	case SXE_VFLINKS_SPEED_10G:
		*link_speed = SXEVF_LINK_SPEED_10GB_FULL;
		break;
	case SXE_VFLINKS_SPEED_1G:
		*link_speed = SXEVF_LINK_SPEED_1GB_FULL;
		break;
	case SXE_VFLINKS_SPEED_100:
		*link_speed = SXEVF_LINK_SPEED_100_FULL;
		break;
	default:
		*link_speed = SXEVF_LINK_SPEED_UNKNOWN;
	}

	*link_up = true;

l_end:
	PMD_LOG_INFO(DRV, "link up status:%d.", *link_up);
}

static void sxevf_link_info_get(struct rte_eth_dev *dev, int wait_to_complete,
				   u32 *link_speed, bool *link_up)
{
	s32 ret;
	struct sxevf_adapter *adapter = dev->data->dev_private;

	sxevf_physical_link_check(dev, link_speed, link_up);

	if (wait_to_complete == 0 && adapter->link_check == 0) {
		if (*link_speed == SXEVF_LINK_SPEED_UNKNOWN)
			*link_up = false;
		else
			*link_up = true;
		return;
	}

	if (*link_up) {
		ret = sxevf_link_msg_check(dev, link_up);
		if (ret) {
			PMD_LOG_ERR(DRV, "ctrl msg rcv fail, try to next workqueue.");
			return;
		}
	}
}

s32 sxevf_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	bool link_up;
	struct rte_eth_link link;
	u32 link_speed = SXEVF_LINK_SPEED_UNKNOWN;

	PMD_LOG_INFO(INIT, "link update start...");

	memset(&link, 0, sizeof(link));
	link.link_status = RTE_ETH_LINK_DOWN;
	link.link_speed  = RTE_ETH_SPEED_NUM_NONE;
	link.link_duplex = RTE_ETH_LINK_HALF_DUPLEX;
	link.link_autoneg = !(dev->data->dev_conf.link_speeds &
						RTE_ETH_LINK_SPEED_FIXED);

	if (wait_to_complete == 0 || dev->data->dev_conf.intr_conf.lsc)
		wait_to_complete = 0;

	sxevf_link_info_get(dev, wait_to_complete, &link_speed, &link_up);

	if (!link_up) {
		PMD_LOG_ERR(DRV, "other link thread is running now!");

		goto l_end;
	}

	link.link_status = RTE_ETH_LINK_UP;
	link.link_duplex = RTE_ETH_LINK_FULL_DUPLEX;
	switch (link_speed) {
	case SXEVF_LINK_SPEED_1GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_1G;
		break;

	case SXEVF_LINK_SPEED_10GB_FULL:
		link.link_speed = RTE_ETH_SPEED_NUM_10G;
		break;
	default:
		link.link_speed = RTE_ETH_SPEED_NUM_UNKNOWN;
	}

l_end:
	PMD_LOG_INFO(DRV, "link update end, up=%x, speed=%x",
			  link_up, link_speed);
	return rte_eth_linkstatus_set(dev, &link);
}

#endif
