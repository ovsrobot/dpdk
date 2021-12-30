/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <ethdev_pci.h>
#include <rte_errno.h>
#include <rte_ether.h>

#include "base/spnic_compat.h"
#include "base/spnic_csr.h"
#include "base/spnic_hwdev.h"
#include "base/spnic_hwif.h"

#include "spnic_ethdev.h"

/* Driver-specific log messages type */
int spnic_logtype;

#define SPNIC_MAX_UC_MAC_ADDRS		128
#define SPNIC_MAX_MC_MAC_ADDRS		128

/**
 * Close the device.
 *
 * @param[in] dev
 *   Pointer to ethernet device structure.
 */
static int spnic_dev_close(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev =
		SPNIC_ETH_DEV_TO_PRIVATE_NIC_DEV(eth_dev);

	if (rte_bit_relaxed_test_and_set32(SPNIC_DEV_CLOSE, &nic_dev->dev_status)) {
		PMD_DRV_LOG(WARNING, "Device %s already closed",
			    nic_dev->dev_name);
		return 0;
	}

	spnic_free_hwdev(nic_dev->hwdev);

	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

	return 0;
}

static int spnic_func_init(struct rte_eth_dev *eth_dev)
{
	struct spnic_nic_dev *nic_dev = NULL;
	struct rte_pci_device *pci_dev = NULL;
	int err;

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

	/* Create hardware device */
	nic_dev->hwdev = rte_zmalloc("spnic_hwdev", sizeof(*nic_dev->hwdev),
				     RTE_CACHE_LINE_SIZE);
	if (!nic_dev->hwdev) {
		PMD_DRV_LOG(ERR, "Allocate hwdev memory failed, dev_name: %s",
			    eth_dev->data->name);
		err = -ENOMEM;
		goto alloc_hwdev_mem_fail;
	}
	nic_dev->hwdev->pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	nic_dev->hwdev->dev_handle = nic_dev;
	nic_dev->hwdev->eth_dev = eth_dev;
	nic_dev->hwdev->port_id = eth_dev->data->port_id;

	err = spnic_init_hwdev(nic_dev->hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init chip hwdev failed, dev_name: %s",
			    eth_dev->data->name);
		goto init_hwdev_fail;
	}

	rte_bit_relaxed_set32(SPNIC_DEV_INIT, &nic_dev->dev_status);
	PMD_DRV_LOG(INFO, "Initialize %s in primary succeed",
		    eth_dev->data->name);

	return 0;

init_hwdev_fail:
	rte_free(nic_dev->hwdev);
	nic_dev->hwdev = NULL;

alloc_hwdev_mem_fail:
	PMD_DRV_LOG(ERR, "Initialize %s in primary failed",
		    eth_dev->data->name);
	return err;
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

	spnic_dev_close(dev);

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
