/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#if defined SXE_DPDK_L4_FEATURES && defined SXE_DPDK_SRIOV

#include <string.h>
#include <sys/time.h>

#include <rte_log.h>
#include <rte_pci.h>
#include <rte_dev.h>

#include "sxe_version.h"
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <bus_pci_driver.h>

#include "sxevf.h"
#include "sxe_logs.h"
#include "sxevf_ethdev.h"
#include "sxe_queue_common.h"

#define PCI_VENDOR_ID_STARS	  0x1FF2
#define SXEVF_DEV_ID_ASIC		0x10A2

static s32 sxevf_probe(struct rte_pci_driver *pci_drv __rte_unused,
					struct rte_pci_device *pci_dev)
{
	s32 ret;

	PMD_LOG_INFO(INIT, "sxe_version[%s], sxe_commit_id[%s], sxe_branch[%s], sxe_build_time[%s]",
		SXE_VERSION, SXE_COMMIT_ID, SXE_BRANCH, SXE_BUILD_TIME);

#ifdef SXE_DPDK_DEBUG
	sxe_log_stream_init();
#endif

	ret = rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct sxevf_adapter), sxevf_ethdev_init);
	if (ret) {
		PMD_LOG_ERR(INIT, "sxe pmd eth dev create fail.(err:%d)", ret);
		goto l_out;
	}

	PMD_LOG_DEBUG(INIT, "%s sxevf pmd probe done.", pci_dev->device.name);

l_out:
	return ret;
}

static s32 sxevf_remove(struct rte_pci_device *pci_dev)
{
	s32 ret;

	ret = rte_eth_dev_pci_generic_remove(pci_dev,
			sxevf_ethdev_uninit);
	if (ret)
		LOG_ERROR("vf remove fail.(err:%d)", ret);

	return ret;
}

static const struct rte_pci_id sxevf_pci_tbl[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_STARS, SXEVF_DEV_ID_ASIC) },
	{.vendor_id = 0,}
};

static struct rte_pci_driver rte_sxevf_pmd = {
	.id_table  = sxevf_pci_tbl,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe	 = sxevf_probe,
	.remove	= sxevf_remove,
};

RTE_PMD_REGISTER_PCI(net_sxevf, rte_sxevf_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_sxevf, sxevf_pci_tbl);
RTE_PMD_REGISTER_KMOD_DEP(net_sxevf, "* igb_uio | vfio-pci");
RTE_PMD_REGISTER_PARAM_STRING(net_sxevf,
				  SXEVF_DEVARG_LINK_CHECK "=<0|1>");

#endif
