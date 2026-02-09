/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <string.h>
#include <sys/time.h>

#include <rte_log.h>
#include <rte_pci.h>

#include "sxe_version.h"
#include <bus_pci_driver.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <dev_driver.h>

#include "sxe_logs.h"
#include "sxe_types.h"
#include "sxe_hw.h"
#include "sxe_ethdev.h"
#include "sxe.h"
#include "drv_msg.h"
#include "sxe_queue.h"
#include "sxe_errno.h"
#include "sxe_compat_platform.h"
#include "sxe_pmd_hdc.h"
#include "sxe_queue.h"

static const struct rte_pci_id sxe_pci_tbl[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_STARS, SXE_DEV_ID_ASIC) },
	{.vendor_id = 0,}
};

static s32 sxe_probe(struct rte_pci_driver *pci_drv __rte_unused,
					struct rte_pci_device *pci_dev)
{
	s32 ret;

	PMD_LOG_INFO(INIT, "sxe_version[%s], sxe_commit_id[%s], sxe_branch[%s], sxe_build_time[%s]",
		SXE_VERSION, SXE_COMMIT_ID, SXE_BRANCH, SXE_BUILD_TIME);


	/* HDC */
	sxe_hdc_channel_init();

	ret = rte_eth_dev_create(&pci_dev->device, pci_dev->device.name,
				sizeof(struct sxe_adapter),
				eth_dev_pci_specific_init,
				pci_dev,
				sxe_ethdev_init, NULL);
	if (ret) {
		PMD_LOG_ERR(INIT, "sxe pmd eth dev create fail.(err:%d)", ret);
		goto l_out;
	}

	PMD_LOG_DEBUG(INIT, "%s sxe pmd probe done.", pci_dev->device.name);

l_out:
	return ret;
}

static s32 sxe_remove(struct rte_pci_device *pci_dev)
{
	struct rte_eth_dev *eth_dev;
	s32 ret;

	eth_dev = rte_eth_dev_allocated(pci_dev->device.name);
	if (!eth_dev) {
		ret = 0;
		PMD_LOG_ERR(INIT, "sxe pmd dev has removed.");
		goto l_out;
	}

	ret = rte_eth_dev_pci_generic_remove(pci_dev,
					sxe_ethdev_uninit);
	if (ret) {
		PMD_LOG_ERR(INIT, "sxe eth dev remove fail.(err:%d)", ret);
		goto l_out;
	}

	sxe_hdc_channel_uninit();

	PMD_LOG_DEBUG(INIT, "sxe pmd remove done.");

l_out:
	return ret;
}

static struct rte_pci_driver rte_sxe_pmd = {
	.id_table  = sxe_pci_tbl,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe	 = sxe_probe,
	.remove	= sxe_remove,
};

static s32 sxe_mng_reset(struct sxe_hw *hw, bool enable)
{
	s32 ret;
	sxe_mng_rst_s mng_rst;

	mng_rst.enable = enable;
	PMD_LOG_INFO(INIT, "mng reset, enable=%x", enable);

	/* Send reset command */
	ret = sxe_driver_cmd_trans(hw, SXE_CMD_MNG_RST,
				(void *)&mng_rst, sizeof(mng_rst),
				NULL, 0);
	if (ret) {
		PMD_LOG_ERR(INIT, "mng reset failed, ret=%d", ret);
		goto l_end;
	}

	PMD_LOG_INFO(INIT, "mng reset success, enable=%x", enable);

l_end:
	return ret;
}

s32 sxe_hw_reset(struct sxe_hw *hw)
{
	s32 ret;

	/* Rx DBU off */
	sxe_hw_rx_cap_switch_off(hw);

	sxe_hw_all_irq_disable(hw);

	sxe_hw_pending_irq_read_clear(hw);

	sxe_hw_all_ring_disable(hw, SXE_HW_TXRX_RING_NUM_MAX);

	ret = sxe_mng_reset(hw, false);
	if (ret) {
		PMD_LOG_ERR(INIT, "mng reset disable failed, ret=%d", ret);
		goto l_end;
	}

	ret = sxe_hw_nic_reset(hw);
	if (ret) {
		PMD_LOG_ERR(INIT, "nic reset failed, ret=%d", ret);
		goto l_end;
	}

	msleep(50);

	ret = sxe_mng_reset(hw, true);
	if (ret) {
		PMD_LOG_ERR(INIT, "mng reset enable failed, ret=%d", ret);
		goto l_end;
	}

	sxe_hw_uc_addr_clear(hw);
l_end:
	return ret;
}

void sxe_hw_start(struct sxe_hw *hw)
{
	sxe_hw_vlan_filter_array_clear(hw);
	sxe_hw_dcb_rate_limiter_clear(hw, SXE_TXRX_RING_NUM_MAX);

	sxe_fc_autoneg_localcap_set(hw);

	hw->mac.auto_restart = true;
	PMD_LOG_INFO(INIT, "auto_restart:%u.", hw->mac.auto_restart);
}

static bool is_device_supported(struct rte_eth_dev *dev,
					struct rte_pci_driver *drv)
{
	bool ret = true;

	if (strcmp(dev->device->driver->name, drv->driver.name))
		ret = false;

	return ret;
}

bool sxe_is_supported(struct rte_eth_dev *dev)
{
	return is_device_supported(dev, &rte_sxe_pmd);
}

RTE_PMD_REGISTER_PCI(net_sxe, rte_sxe_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_sxe, sxe_pci_tbl);
RTE_PMD_REGISTER_KMOD_DEP(net_sxe, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_LOG_REGISTER_SUFFIX(sxe_log_init, pmd.net.sxe.init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(sxe_log_drv, pmd.net.sxe.drv, NOTICE);

int sxe_eth_dev_callback_process(struct rte_eth_dev *dev,
	enum rte_eth_event_type event, void *ret_param)
{
	return rte_eth_dev_callback_process(dev, event, ret_param);
}
