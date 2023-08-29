/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2022 Shenzhen 3SNIC Information Technology Co., Ltd.
 */

#include <error.h>
#include <rte_common.h>
#include <ethdev_pci.h>

#include "sssnic_log.h"

static int
sssnic_pci_probe(struct rte_pci_driver *pci_drv, struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_drv);
	RTE_SET_USED(pci_dev);
	PMD_INIT_FUNC_TRACE();
	return -EINVAL;
}

static int
sssnic_pci_remove(struct rte_pci_device *pci_dev)
{
	RTE_SET_USED(pci_dev);
	PMD_INIT_FUNC_TRACE();
	return -EINVAL;
}

static struct rte_pci_driver sssnic_pmd = {
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
