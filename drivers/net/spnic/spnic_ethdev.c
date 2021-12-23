/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "base/spnic_compat.h"
#include "spnic_ethdev.h"

/* Driver-specific log messages type */
int spnic_logtype;

static int spnic_func_init(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct rte_pci_device *pci_dev = NULL;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	/* EAL is secondary and eth_dev is already created */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		PMD_DRV_LOG(INFO, "Initialize %s in secondary process",
			    eth_dev->data->name);

		return 0;
	}

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);
	snprintf(nic_dev->dev_name, sizeof(nic_dev->dev_name),
		 "spnic-%.4x:%.2x:%.2x.%x",
		 pci_dev->addr.domain, pci_dev->addr.bus,
		 pci_dev->addr.devid, pci_dev->addr.function);

	rte_bit_relaxed_set32(SPNIC_DEV_INIT, &nic_dev->dev_status);
	PMD_DRV_LOG(INFO, "Initialize %s in primary succeed",
		    eth_dev->data->name);

	return 0;
}

static int spnic_dev_init(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev;

	pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	PMD_DRV_LOG(INFO, "Initializing spnic-%.4x:%.2x:%.2x.%x in %s process",
		    pci_dev->addr.domain, pci_dev->addr.bus,
		    pci_dev->addr.devid, pci_dev->addr.function,
		    (rte_eal_process_type() == RTE_PROC_PRIMARY) ?
		    "primary" : "secondary");

	return spnic_func_init(eth_dev);
}

static int spnic_dev_uninit(struct rte_eth_dev *dev)
{
	struct spnic_nic_dev *nic_dev;

	nic_dev = SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(dev);
	rte_bit_relaxed_clear32(SPNIC_DEV_INIT, &nic_dev->dev_status);

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	return 0;
}

static struct rte_pci_id pci_id_spnic_map[] = {
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_PF) },
	{ RTE_PCI_DEVICE(PCI_VENDOR_ID_RAMAXEL, SPNIC_DEV_ID_VF) },
	{.vendor_id = 0},
};

static int spnic_pci_probe(__rte_unused struct rte_pci_driver *pci_drv,
			   struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
					     sizeof(struct spnic_nic_dev),
					     spnic_dev_init);
}

static int spnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, spnic_dev_uninit);
}

static struct rte_pci_driver rte_spnic_pmd = {
	.id_table = pci_id_spnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = spnic_pci_probe,
	.remove = spnic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_spnic, rte_spnic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_spnic, pci_id_spnic_map);

RTE_INIT(spnic_init_log)
{
	spnic_logtype = rte_log_register("pmd.net.spnic");
	if (spnic_logtype >= 0)
		rte_log_set_level(spnic_logtype, RTE_LOG_INFO);
}
