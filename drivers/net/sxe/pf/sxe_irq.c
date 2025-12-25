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
#include "sxe_errno.h"
#include "sxe_compat_version.h"

#define SXE_LINK_DOWN_TIMEOUT 4000
#define SXE_LINK_UP_TIMEOUT   1000

#define SXE_IRQ_MAILBOX		  ((u32)(1 << 1))
#define SXE_IRQ_MACSEC		   ((u32)(1 << 2))

#define SXE_LINK_UP_TIME		 90

#define SXE_MISC_VEC_ID		  RTE_INTR_VEC_ZERO_OFFSET

#define SXE_RX_VEC_BASE		  RTE_INTR_VEC_RXTX_OFFSET

static s32 sxe_event_irq_action(struct rte_eth_dev *eth_dev)
{
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	PMD_LOG_DEBUG(DRV, "event irq action type %d", irq->action);

	/* lsc irq handler */
	if (irq->action & SXE_IRQ_LINK_UPDATE)
		PMD_LOG_INFO(DRV, "link change irq");

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
}

void sxe_irq_vec_free(struct rte_intr_handle *handle)
{
	if (handle->intr_vec != NULL) {
		rte_free(handle->intr_vec);
		handle->intr_vec = NULL;
	}
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
}
