/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#include <string.h>
#include <sys/time.h>

#include <rte_log.h>
#include <rte_pci.h>

#include "sxe_version.h"
#include "sxe_dpdk_version.h"
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
#include "sxe_errno.h"
#include "sxe_compat_platform.h"
#include "sxe_pmd_hdc.h"

static const struct rte_pci_id sxe_pci_tbl[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_STARS, SXE_DEV_ID_ASIC) },
	{.vendor_id = 0,}
};

s8 g_log_filename[LOG_FILE_NAME_LEN] = {0};

bool is_log_created;

#ifdef SXE_DPDK_DEBUG
void sxe_log_stream_init(void)
{
	FILE *fp;
	struct timeval	tv;
	struct tm *td;
	u8 len;
	s8 time[40];

	if (is_log_created)
		return;

	memset(g_log_filename, 0, LOG_FILE_NAME_LEN);

	len = snprintf(g_log_filename, LOG_FILE_NAME_LEN, "%s%s.",
			  LOG_FILE_PATH, LOG_FILE_PREFIX);

	gettimeofday(&tv, NULL);
	td = localtime(&tv.tv_sec);
	strftime(time, sizeof(time), "%Y-%m-%d-%H:%M:%S", td);

	snprintf(g_log_filename + len, LOG_FILE_NAME_LEN - len,
		"%s", time);

	fp = fopen(g_log_filename, "w+");
	if (fp == NULL) {
		PMD_LOG_ERR(INIT, "open log file:%s fail, errno:%d %s.",
				g_log_filename, errno, strerror(errno));
		return;
	}

	PMD_LOG_NOTICE(INIT, "log stream file:%s.", g_log_filename);

	rte_openlog_stream(fp);

	is_log_created = true;
}
#endif

static s32 sxe_probe(struct rte_pci_driver *pci_drv __rte_unused,
					struct rte_pci_device *pci_dev)
{
	s32 ret;

	PMD_LOG_INFO(INIT, "sxe_version[%s], sxe_commit_id[%s], sxe_branch[%s], sxe_build_time[%s]",
		SXE_VERSION, SXE_COMMIT_ID, SXE_BRANCH, SXE_BUILD_TIME);

#ifdef SXE_DPDK_DEBUG
	sxe_log_stream_init();
#endif

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

	sxe_hw_all_irq_disable(hw);

	sxe_hw_pending_irq_read_clear(hw);

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

l_end:
	return ret;
}

void sxe_hw_start(struct sxe_hw *hw)
{
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

bool is_sxe_supported(struct rte_eth_dev *dev)
{
	return is_device_supported(dev, &rte_sxe_pmd);
}

RTE_PMD_REGISTER_PCI(net_sxe, rte_sxe_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_sxe, sxe_pci_tbl);
RTE_PMD_REGISTER_KMOD_DEP(net_sxe, "* igb_uio | uio_pci_generic | vfio-pci");

#ifdef SXE_DPDK_DEBUG
RTE_LOG_REGISTER_SUFFIX(sxe_log_init, pmd.net.sxe.init, DEBUG);
RTE_LOG_REGISTER_SUFFIX(sxe_log_drv, pmd.net.sxe.drv, DEBUG);
RTE_LOG_REGISTER_SUFFIX(sxe_log_rx, pmd.net.sxe.rx, DEBUG);
RTE_LOG_REGISTER_SUFFIX(sxe_log_tx, pmd.net.sxe.tx, DEBUG);
RTE_LOG_REGISTER_SUFFIX(sxe_log_hw, pmd.net.sxe.tx_hw, DEBUG);
#else
#ifdef DPDK_19_11_6
s32 sxe_log_init;
s32 sxe_log_drv;
RTE_INIT(sxe_init_log)
{
	sxe_log_init = rte_log_register("pmd.net.sxe.init");
	if (sxe_log_init >= 0)
		rte_log_set_level(sxe_log_init, RTE_LOG_NOTICE);

	sxe_log_drv = rte_log_register("pmd.net.sxe.drv");
	if (sxe_log_drv >= 0)
		rte_log_set_level(sxe_log_drv, RTE_LOG_NOTICE);
}
#else
RTE_LOG_REGISTER_SUFFIX(sxe_log_init, pmd.net.sxe.init, NOTICE);
RTE_LOG_REGISTER_SUFFIX(sxe_log_drv, pmd.net.sxe.drv, NOTICE);
#endif
#endif

int sxe_eth_dev_callback_process(struct rte_eth_dev *dev,
	enum rte_eth_event_type event, void *ret_param)
{
	return rte_eth_dev_callback_process(dev, event, ret_param);
}
