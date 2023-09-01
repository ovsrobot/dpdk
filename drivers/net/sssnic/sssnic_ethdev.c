/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"
#include "base/sssnic_hw.h"

static int
sssnic_ethdev_init(struct rte_eth_dev *ethdev)
{
	RTE_SET_USED(ethdev);
	PMD_INIT_FUNC_TRACE();

	return -EINVAL;
}

static int
sssnic_ethdev_uninit(struct rte_eth_dev *ethdev)
{
	RTE_SET_USED(ethdev);
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	return -EINVAL;
}

static int
sssnic_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_drv);
	PMD_INIT_FUNC_TRACE();

	return rte_eth_dev_pci_generic_probe(pci_dev, 0, sssnic_ethdev_init);
}

static int
sssnic_pci_remove(struct rte_pci_device *pci_dev)
{
	PMD_INIT_FUNC_TRACE();

	return rte_eth_dev_pci_generic_remove(pci_dev, sssnic_ethdev_uninit);
}

static const struct rte_pci_id sssnic_pci_id_map[] = {
	{ RTE_PCI_DEVICE(SSSNIC_PCI_VENDOR_ID, SSSNIC_DEVICE_ID_STD) },
	{ .vendor_id = 0 },
};

static struct rte_pci_driver sssnic_pmd = {
	.id_table = sssnic_pci_id_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = sssnic_pci_probe,
	.remove = sssnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_sssnic, sssnic_pmd);

RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_driver, driver, INFO);
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_init, init, NOTICE);
#ifdef RTE_ETHDEV_DEBUG_RX
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_rx, rx, DEBUG);
#endif /*RTE_ETHDEV_DEBUG_RX*/
#ifdef RTE_ETHDEV_DEBUG_TX
RTE_LOG_REGISTER_SUFFIX(sssnic_logtype_tx, tx, DEBUG);
#endif /*RTE_ETHDEV_DEBUG_TX*/
