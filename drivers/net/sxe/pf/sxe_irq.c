/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <rte_ethdev.h>
#include <rte_pci.h>
#include <rte_alarm.h>

#include <rte_pci.h>
#include <bus_pci_driver.h>
#include <eal_interrupts.h>

#include <rte_malloc.h>

#include "sxe_irq.h"
#include "sxe_logs.h"
#include "sxe_regs.h"
#include "sxe_hw.h"
#include "sxe.h"
#include "sxe_phy.h"
#include "sxe_queue.h"
#include "sxe_errno.h"
#include "sxe_compat_version.h"
#include "sxe_vf.h"

#define SXE_LINK_DOWN_TIMEOUT 4000
#define SXE_LINK_UP_TIMEOUT   1000

#define SXE_IRQ_MAILBOX		  ((u32)(1 << 1))
#define SXE_IRQ_MACSEC		   ((u32)(1 << 2))

#define SXE_LINK_UP_TIME		 90

#define SXE_MISC_VEC_ID		  RTE_INTR_VEC_ZERO_OFFSET

#define SXE_RX_VEC_BASE		  RTE_INTR_VEC_RXTX_OFFSET

static void sxe_link_info_output(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_eth_link link;

	rte_eth_linkstatus_get(dev, &link);

	PMD_LOG_DEBUG(DRV, "port:%d link status:%s speed %u Mbps %s",
				(u16)(dev->data->port_id),
				link.link_status ? "up" : "down",
				link.link_speed,
				(link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
				"full-duplex" : "half-duplex");

	PMD_LOG_DEBUG(DRV, "pci dev: " PCI_PRI_FMT,
				pci_dev->addr.domain,
				pci_dev->addr.bus,
				pci_dev->addr.devid,
				pci_dev->addr.function);
}

void sxe_event_irq_delayed_handler(void *param)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)param;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *intr_handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	struct sxe_hw *hw = &adapter->hw;
	u32 eicr;

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);

	sxe_hw_all_irq_disable(hw);

	eicr = sxe_hw_irq_cause_get(hw);
	PMD_LOG_DEBUG(DRV, "delay handler eicr:0x%x action:0x%x",
			   eicr, irq->action);

	eicr &= 0xFFFF0000;
	if (rte_atomic_load_explicit(&adapter->link_thread_running, rte_memory_order_seq_cst) &&
		(eicr & SXE_EICR_LSC)) {
		eicr &= ~SXE_EICR_LSC;
		PMD_LOG_DEBUG(DRV, "delay handler keep lsc irq");
	}
	sxe_hw_pending_irq_write_clear(hw, eicr);

	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	if (eicr & SXE_EICR_MAILBOX)
		sxe_mbx_irq_handler(eth_dev);
#endif

	if (irq->action & SXE_IRQ_LINK_UPDATE) {
		sxe_link_update(eth_dev, 0);
		sxe_link_info_output(eth_dev);
		sxe_eth_dev_callback_process(eth_dev, RTE_ETH_EVENT_INTR_LSC, NULL);

		irq->action &= ~SXE_IRQ_LINK_UPDATE;
	}

	irq->enable_mask |= SXE_EIMS_LSC;
	PMD_LOG_DEBUG(DRV, "irq enable mask:0x%x", irq->enable_mask);

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);
	sxe_hw_specific_irq_enable(hw, irq->enable_mask);
	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);

	rte_intr_ack(intr_handle);
}

static void sxe_lsc_irq_handler(struct rte_eth_dev *eth_dev)
{
	struct rte_eth_link link;
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u64 timeout;
	bool link_up;

	rte_eth_linkstatus_get(eth_dev, &link);

	link_up = sxe_hw_is_link_state_up(hw);

	if (!link.link_status && !link_up) {
		PMD_LOG_DEBUG(DRV, "link change irq, down->down, do nothing.");
		return;
	}

	if (irq->to_pcs_init) {
		PMD_LOG_DEBUG(DRV, "to set pcs init, do nothing.");
		return;
	}

	PMD_LOG_INFO(DRV, "link change irq handler start");
	sxe_link_update(eth_dev, 0);
	sxe_link_info_output(eth_dev);

	timeout = link.link_status ? SXE_LINK_DOWN_TIMEOUT :
					SXE_LINK_UP_TIMEOUT;

	if (rte_eal_alarm_set(timeout * 1000,
				  sxe_event_irq_delayed_handler,
				  (void *)eth_dev) < 0) {
		PMD_LOG_ERR(DRV, "submit event irq delay handle fail.");
	} else {
		irq->enable_mask &= ~SXE_EIMS_LSC;
	}

	PMD_LOG_INFO(DRV, "link change irq handler end");
}

static s32 sxe_event_irq_action(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	PMD_LOG_DEBUG(DRV, "event irq action type %d", irq->action);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	/* mailbox irq handler */
	if (irq->action & SXE_IRQ_MAILBOX) {
		sxe_mbx_irq_handler(eth_dev);
		irq->action &= ~SXE_IRQ_MAILBOX;
	}
#endif

	/* lsc irq handler */
	if (irq->action & SXE_IRQ_LINK_UPDATE) {
		sxe_lsc_irq_handler(eth_dev);
		PMD_LOG_INFO(DRV, "link change irq");
	}

	return 0;
}

static void sxe_event_irq_handler(void *data)
{
	struct rte_eth_dev *eth_dev = (struct rte_eth_dev *)data;
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u32 eicr;

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);

	sxe_hw_all_irq_disable(hw);

	eicr = sxe_hw_irq_cause_get(hw);
	PMD_LOG_DEBUG(DRV, "event irq triggered eicr:0x%x", eicr);

	eicr &= 0xFFFF0000;

	sxe_hw_pending_irq_write_clear(hw, eicr);

	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);

	if (eicr & SXE_EICR_LSC)
		irq->action |= SXE_IRQ_LINK_UPDATE;

	if (eicr & SXE_EICR_MAILBOX)
		irq->action |= SXE_IRQ_MAILBOX;

	if (eicr & SXE_EICR_LINKSEC)
		irq->action |= SXE_IRQ_MACSEC;

	sxe_event_irq_action(eth_dev);

	rte_spinlock_lock(&adapter->irq_ctxt.event_irq_lock);
	sxe_hw_specific_irq_enable(hw, irq->enable_mask);
	rte_spinlock_unlock(&adapter->irq_ctxt.event_irq_lock);
}

void sxe_irq_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *irq_handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;

	rte_intr_callback_register(irq_handle,
				   sxe_event_irq_handler, eth_dev);

	rte_spinlock_init(&adapter->irq_ctxt.event_irq_lock);

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	struct sxe_hw *hw = &adapter->hw;
	u32 gpie = 0;

	if (irq_handle->type == RTE_INTR_HANDLE_UIO ||
		irq_handle->type == RTE_INTR_HANDLE_VFIO_MSIX) {
		gpie = sxe_hw_irq_general_reg_get(hw);

		gpie |= SXE_GPIE_MSIX_MODE | SXE_GPIE_OCD;
		sxe_hw_irq_general_reg_set(hw, gpie);
	}
	rte_intr_enable(irq_handle);

	sxe_hw_specific_irq_enable(hw, irq->enable_mask);
#endif
}

static s32 sxe_irq_general_config(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 gpie;
	s32 ret = 0;

	gpie = sxe_hw_irq_general_reg_get(hw);
	if (!rte_intr_dp_is_en(handle) &&
		!(gpie & (SXE_GPIE_MSIX_MODE | SXE_GPIE_PBA_SUPPORT))) {
		ret = -SXE_ERR_CONFIG;
		gpie |= SXE_GPIE_MSIX_MODE;
		PMD_LOG_INFO(DRV, "rx queue irq num:%d gpie:0x%x.",
				  handle->nb_efd, gpie);
	} else {
		gpie |= SXE_GPIE_MSIX_MODE | SXE_GPIE_PBA_SUPPORT |
			SXE_GPIE_OCD | SXE_GPIE_EIAME |
			SXE_GPIE_SPP1_EN | SXE_GPIE_SPP2_EN;
	}

	sxe_hw_irq_general_reg_set(hw, gpie);

	return ret;
}

static void sxe_msix_configure(struct rte_eth_dev *dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_rx_queue *rx_queue;
	s32 ret;
	u16 queue_id;
	u16 vector = SXE_MISC_VEC_ID;
	u16 base = SXE_MISC_VEC_ID;
	u32 irq_interval;
	u32 value;

	ret = sxe_irq_general_config(dev);
	if (ret) {
		PMD_LOG_INFO(DRV, "unsupport msi-x, no need config irq");
		return;
	}

	irq_interval = SXE_EITR_INTERVAL_US(SXE_QUEUE_ITR_INTERVAL_DEFAULT);
	if (rte_intr_allow_others(handle)) {
		vector = SXE_RX_VEC_BASE;
		base = SXE_RX_VEC_BASE;
	}


	if (rte_intr_dp_is_en(handle)) {
		irq_interval = SXE_EITR_INTERVAL_US(SXE_QUEUE_ITR_INTERVAL);
		for (queue_id = 0; queue_id < dev->data->nb_rx_queues;
			queue_id++) {
			rx_queue = dev->data->rx_queues[queue_id];
			if (dev->data->lro == 1) {
				sxe_hw_ring_irq_interval_set(hw, vector,
										irq_interval);
			}

			sxe_hw_ring_irq_map(hw, false,
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
		sxe_hw_event_irq_map(hw, 1, SXE_MISC_VEC_ID);
	}

	sxe_hw_ring_irq_interval_set(hw, 0, irq_interval);

	sxe_hw_ring_irq_auto_disable(hw, true);

	value = SXE_EIMS_ENABLE_MASK;
	value &= ~(SXE_EIMS_OTHER | SXE_EIMS_MAILBOX | SXE_EIMS_LSC);
	sxe_hw_event_irq_auto_clear_set(hw, value);
}

s32 sxe_irq_configure(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	u16 irq_num;
	s32 ret = 0;

	if ((rte_intr_cap_multiple(handle) ||
		 !RTE_ETH_DEV_SRIOV(eth_dev).active) &&
		eth_dev->data->dev_conf.intr_conf.rxq != 0) {
		irq_num = eth_dev->data->nb_rx_queues;
		if (irq_num > SXE_QUEUE_IRQ_NUM_MAX) {
			PMD_LOG_ERR(DRV, "irq_num:%u exceed limit:%u ",
					  irq_num, SXE_QUEUE_IRQ_NUM_MAX);
			ret = -ENOTSUP;
			goto l_out;
		}

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

	sxe_msix_configure(eth_dev);

	sxe_irq_enable(eth_dev);

	PMD_LOG_INFO(DRV,
			  "intr_conf rxq:%u intr_handle type:%d rx queue num:%d "
			  "queue irq num:%u total irq num:%u "
			  "config done",
			  eth_dev->data->dev_conf.intr_conf.rxq,
			  handle->type,
			  eth_dev->data->nb_rx_queues,
			  handle->nb_efd,
			  handle->max_intr);

l_out:
	return ret;
}

void sxe_irq_enable(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	struct sxe_hw *hw = &adapter->hw;

	if (rte_intr_allow_others(handle)) {
		sxe_link_info_output(eth_dev);

		if (eth_dev->data->dev_conf.intr_conf.lsc != 0)
			irq->enable_mask |= SXE_EIMS_LSC;
		else
			irq->enable_mask &= ~SXE_EIMS_LSC;

	} else {
		rte_intr_callback_unregister(handle,
						 sxe_event_irq_handler, eth_dev);
		if (eth_dev->data->dev_conf.intr_conf.lsc != 0)
			PMD_LOG_ERR(DRV, "event irq not support.");
	}

	/* check if rxq interrupt is enabled */
	if (eth_dev->data->dev_conf.intr_conf.rxq != 0 &&
		rte_intr_dp_is_en(handle))
		irq->enable_mask |= SXE_EIMS_RTX_QUEUE;

	rte_intr_enable(handle);

	sxe_hw_specific_irq_enable(hw, irq->enable_mask);

	PMD_LOG_INFO(DRV,
			  "intr_handle type:%d enable irq mask:0x%x",
			  handle->type,
			  irq->enable_mask);
}
void sxe_irq_vec_free(struct rte_intr_handle *handle)
{
	if (handle->intr_vec != NULL) {
		rte_free(handle->intr_vec);
		handle->intr_vec = NULL;
	}
}
void sxe_irq_disable(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);

	if (!rte_intr_allow_others(handle)) {
		rte_intr_callback_register(handle,
					   sxe_event_irq_handler,
					   (void *)eth_dev);
	}

	rte_intr_efd_disable(handle);
	sxe_irq_vec_free(handle);
}
void sxe_irq_uninit(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	u8 retry = 0;
	s32 ret;

	rte_intr_disable(handle);

	do {
		ret = rte_intr_callback_unregister(handle,
				sxe_event_irq_handler, eth_dev);
		if (ret >= 0 || ret == -ENOENT) {
			break;
		} else if (ret != -EAGAIN) {
			PMD_LOG_ERR(DRV,
					"irq handler unregister fail, next to retry");
		}
		rte_delay_ms(100);
	} while (retry++ < (10 + SXE_LINK_UP_TIME));

	rte_eal_alarm_cancel(sxe_event_irq_delayed_handler, eth_dev);
}

s32 sxe_rx_queue_intr_enable(struct rte_eth_dev *eth_dev, u16 queue_id)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct rte_intr_handle *intr_handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u32 mask;

	if (queue_id < 16) {
		sxe_hw_all_irq_disable(hw);
		irq->enable_mask |= (1 << queue_id);
		sxe_hw_specific_irq_enable(hw, irq->enable_mask);
	} else if (queue_id < 32) {
		mask = sxe_hw_ring_irq_switch_get(hw, 0);
		mask &= (1 << queue_id);
		sxe_hw_ring_irq_switch_set(hw, 0, mask);
	} else if (queue_id < 64) {
		mask = sxe_hw_ring_irq_switch_get(hw, 1);
		mask &= (1 << (queue_id - 32));
		sxe_hw_ring_irq_switch_set(hw, 1, mask);
	}

	rte_intr_ack(intr_handle);

	PMD_LOG_INFO(DRV, "queue_id:%u irq enabled enable_mask:0x%x.",
			queue_id, irq->enable_mask);

	return 0;
}

s32 sxe_rx_queue_intr_disable(struct rte_eth_dev *eth_dev, u16 queue_id)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;
	u32 mask;

	if (queue_id < 16) {
		sxe_hw_all_irq_disable(hw);
		irq->enable_mask &= ~(1 << queue_id);
		sxe_hw_specific_irq_enable(hw, irq->enable_mask);
	} else if (queue_id < 32) {
		mask = sxe_hw_ring_irq_switch_get(hw, 0);
		mask &= ~(1 << queue_id);
		sxe_hw_ring_irq_switch_set(hw, 0, mask);
	} else if (queue_id < 64) {
		mask = sxe_hw_ring_irq_switch_get(hw, 1);
		mask &= ~(1 << (queue_id - 32));
		sxe_hw_ring_irq_switch_set(hw, 1, mask);
	}

	PMD_LOG_INFO(DRV, "queue_id:%u irq disabled enable_mask:0x%x.",
			queue_id, irq->enable_mask);

	return 0;
}
