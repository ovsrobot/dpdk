/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <bus_pci_driver.h>
#include <ethdev_driver.h>
#include <dev_driver.h>
#include <ethdev_pci.h>
#include <rte_ethdev.h>
#include <rte_alarm.h>
#include <eal_export.h>
#include "sxe_types.h"
#include "sxe_logs.h"
#include "sxe_compat_platform.h"
#include "sxe_errno.h"
#include "sxe.h"
#include "sxe_hw.h"
#include "sxe_ethdev.h"
#include "sxe_irq.h"
#include "sxe_pmd_hdc.h"
#include "drv_msg.h"
#include "sxe_version.h"
#include "sxe_compat_version.h"
#include <rte_string_fns.h>

#define SXE_DEFAULT_MTU			 1500
#define SXE_ETH_HLEN				14
#define SXE_ETH_FCS_LEN			 4
#define SXE_ETH_FRAME_LEN		   1514

#define SXE_ETH_MAX_LEN  (RTE_ETHER_MTU + SXE_ETH_OVERHEAD)

static s32 sxe_dev_reset(struct rte_eth_dev *eth_dev);

static s32 sxe_dev_configure(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	PMD_INIT_FUNC_TRACE();

l_end:
	return ret;
}

static s32 sxe_dev_start(struct rte_eth_dev *dev)
{
	s32 ret;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_intr_handle *handle = SXE_PCI_INTR_HANDLE(pci_dev);
	struct sxe_irq_context *irq = &adapter->irq_ctxt;

	ret = sxe_fw_time_sync(hw);

	rte_intr_disable(handle);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	sxe_hw_start(hw);

	ret = sxe_irq_configure(dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "irq config fail.");
		goto l_error;
	}

l_end:
	return ret;

l_error:
	PMD_LOG_ERR(INIT, "dev start err, ret=%d", ret);
	sxe_irq_vec_free(handle);
	ret = -EIO;
	goto l_end;
}

static s32 sxe_dev_stop(struct rte_eth_dev *dev)
{
	s32 ret = 0;
	s32 num;
	struct rte_eth_link link;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;

	PMD_INIT_FUNC_TRACE();

	sxe_hw_all_irq_disable(hw);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

l_end:
	return ret;
}

static s32 sxe_dev_close(struct rte_eth_dev *dev)
{
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret = 0;

	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_LOG_INFO(INIT, "not primary, do nothing");
		goto l_end;
	}

	sxe_hw_hdc_drv_status_set(hw, (u32)false);

	ret = sxe_hw_reset(hw);
	if (ret < 0) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_end;
	}

	ret = sxe_dev_stop(dev);
	if (ret)
		PMD_LOG_ERR(INIT, "dev stop fail.(err:%d)", ret);

	sxe_irq_uninit(dev);

l_end:
	return ret;
}

static s32 sxe_dev_infos_get(struct rte_eth_dev *dev,
					struct rte_eth_dev_info *dev_info)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(dev);
	struct rte_eth_conf *dev_conf = &dev->data->dev_conf;

	return 0;
}

static int sxe_get_regs(struct rte_eth_dev *dev,
		  struct rte_dev_reg_info *regs)
{
	s32 ret = 0;
	u32 *data = regs->data;
	struct sxe_adapter *adapter = dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	u32 length = sxe_hw_all_regs_group_num_get();

	if (data == NULL) {
		regs->length = length;
		regs->width = sizeof(uint32_t);
		goto l_end;
	}

	if (regs->length == 0 || regs->length == length) {
		sxe_hw_all_regs_group_read(hw, data);

		goto l_end;
	}

	ret = -ENOTSUP;
	LOG_ERROR("get regs: inval param: regs_len=%u, regs->data=%p, "
			"regs_offset=%u,  regs_width=%u, regs_version=%u",
			regs->length, regs->data,
			regs->offset, regs->width,
			regs->version);

l_end:
	return ret;
}

static int sxe_fw_version_get(struct rte_eth_dev *dev, char *fw_version,
						size_t fw_size)
{
	int ret;
	sxe_version_resp_s resp;
	struct sxe_adapter *adapter = (struct sxe_adapter *)(dev->data->dev_private);
	struct sxe_hw *hw = &adapter->hw;

	ret = sxe_driver_cmd_trans(hw, SXE_CMD_FW_VER_GET,
				NULL, 0,
				(void *)&resp, sizeof(resp));
	if (ret) {
		LOG_ERROR_BDF("get version failed, ret=%d", ret);
		ret = -EIO;
		goto l_end;
	}

	ret = snprintf(fw_version, fw_size, "%s", resp.fw_version);
	if (ret < 0) {
		ret = -EINVAL;
		goto l_end;
	}

	ret += 1;

	if (fw_size >= (size_t)ret)
		ret = 0;

l_end:
	return ret;
}

static const struct eth_dev_ops sxe_eth_dev_ops = {
	.dev_configure		= sxe_dev_configure,
	.dev_start		= sxe_dev_start,
	.dev_stop		= sxe_dev_stop,
	.dev_close		= sxe_dev_close,
	.dev_reset		= sxe_dev_reset,

	.get_reg		= sxe_get_regs,
};

static s32 sxe_hw_base_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
	struct sxe_hw *hw = &adapter->hw;
	s32 ret;

	hw->reg_base_addr = (void *)pci_dev->mem_resource[0].addr;
	PMD_LOG_INFO(INIT, "eth_dev[%u] got reg_base_addr=%p",
			eth_dev->data->port_id, hw->reg_base_addr);
	hw->adapter = adapter;

	strlcpy(adapter->name, pci_dev->device.name, sizeof(adapter->name) - 1);

	sxe_hw_hdc_drv_status_set(hw, (u32)true);

	ret = sxe_hw_reset(hw);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw init failed, ret=%d", ret);
		goto l_out;
	} else {
		sxe_hw_start(hw);
	}

l_out:
	if (ret)
		sxe_hw_hdc_drv_status_set(hw, (u32)false);

	return ret;
}

void sxe_secondary_proc_init(struct rte_eth_dev *eth_dev,
	bool rx_batch_alloc_allowed, bool *rx_vec_allowed)
{
	__sxe_secondary_proc_init(eth_dev, rx_batch_alloc_allowed, rx_vec_allowed);
}

s32 sxe_ethdev_init(struct rte_eth_dev *eth_dev, void *param __rte_unused)
{
	s32 ret = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct sxe_adapter *adapter = eth_dev->data->dev_private;
#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_FILTER_CTRL
	struct sxe_filter_context *filter_info = &adapter->filter_ctxt;
#endif

	eth_dev->dev_ops = &sxe_eth_dev_ops;

	rte_eth_copy_pci_info(eth_dev, pci_dev);

	ret = sxe_hw_base_init(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "hw base init fail.(err:%d)", ret);
		goto l_out;
	}

	sxe_irq_init(eth_dev);

	PMD_LOG_INFO(INIT, "sxe eth dev init done.");

l_out:
	return ret;
}

s32 sxe_ethdev_uninit(struct rte_eth_dev *eth_dev)
{
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_LOG_INFO(INIT, "not primary process ,do nothing");
		goto l_end;
	}

	sxe_dev_close(eth_dev);

l_end:
	return 0;
}

static s32 sxe_dev_reset(struct rte_eth_dev *eth_dev)
{
	s32 ret;

	if (eth_dev->data->sriov.active) {
		ret = -ENOTSUP;
		PMD_LOG_ERR(INIT, "sriov activated, not support reset pf port[%u]",
			eth_dev->data->port_id);
		goto l_end;
	}

	ret = sxe_ethdev_uninit(eth_dev);
	if (ret) {
		PMD_LOG_ERR(INIT, "port[%u] dev uninit failed",
			eth_dev->data->port_id);
		goto l_end;
	}

	ret = sxe_ethdev_init(eth_dev, NULL);
	if (ret) {
		PMD_LOG_ERR(INIT, "port[%u] dev init failed",
			eth_dev->data->port_id);
	}

l_end:
	return ret;
}
