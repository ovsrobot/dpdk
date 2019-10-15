/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_ethdev_driver.h>
#include <rte_malloc.h>

#include "ionic_logs.h"
#include "ionic.h"
#include "ionic_dev.h"
#include "ionic_mac_api.h"

int ionic_logtype_init;
int ionic_logtype_driver;

static const struct rte_pci_id pci_id_ionic_map[] = {
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_PF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_VF) },
	{ RTE_PCI_DEVICE(IONIC_PENSANDO_VENDOR_ID, IONIC_DEV_ID_ETH_MGMT) },
	{ .vendor_id = 0, /* sentinel */ },
};

/*
 * There is no room in struct rte_pci_driver to keep a reference
 * to the adapter, using a static list for the time being.
 */
static LIST_HEAD(ionic_pci_adapters_list, ionic_adapter) ionic_pci_adapters =
		LIST_HEAD_INITIALIZER(ionic_pci_adapters);
static rte_spinlock_t ionic_pci_adapters_lock = RTE_SPINLOCK_INITIALIZER;

static int
eth_ionic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
		struct rte_pci_device *pci_dev)
{
	struct rte_mem_resource *resource;
	struct ionic_adapter *adapter;
	struct ionic_hw *hw;
	unsigned long i;
	int err;

	/* Multi-process not supported */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return -EPERM;

	ionic_init_print(DEBUG, "Initializing device %s %s",
			pci_dev->device.name,
			rte_eal_process_type() == RTE_PROC_SECONDARY ?
			"[SECONDARY]" : "");

	adapter = rte_zmalloc("ionic", sizeof(*adapter), 0);

	if (!adapter) {
		ionic_init_print(ERR, "OOM");
		return -ENOMEM;
	}

	adapter->pci_dev = pci_dev;
	hw = &adapter->hw;

	hw->device_id = pci_dev->id.device_id;
	hw->vendor_id = pci_dev->id.vendor_id;

	err = ionic_init_mac(hw);
	if (err != 0) {
		ionic_init_print(ERR, "Mac init failed: %d", err);
		return -EIO;
	}

	adapter->is_mgmt_nic = (pci_dev->id.device_id == IONIC_DEV_ID_ETH_MGMT);

	adapter->num_bars = 0;
	for (i = 0; i < PCI_MAX_RESOURCE && i < IONIC_BARS_MAX; i++) {
		resource = &pci_dev->mem_resource[i];
		if (resource->phys_addr == 0 || resource->len == 0)
			continue;
		adapter->bars[adapter->num_bars].vaddr = resource->addr;
		adapter->bars[adapter->num_bars].bus_addr = resource->phys_addr;
		adapter->bars[adapter->num_bars].len = resource->len;
		adapter->num_bars++;
	}

	/* Discover ionic dev resources */

	err = ionic_setup(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot setup device: %d, aborting", err);
		return err;
	}

	err = ionic_identify(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot identify device: %d, aborting",
				err);
		return err;
	}

	err = ionic_init(adapter);
	if (err) {
		ionic_init_print(ERR, "Cannot init device: %d, aborting", err);
		return err;
	}

	rte_spinlock_lock(&ionic_pci_adapters_lock);
	LIST_INSERT_HEAD(&ionic_pci_adapters, adapter, pci_adapters);
	rte_spinlock_unlock(&ionic_pci_adapters_lock);

	return 0;
}

static int
eth_ionic_pci_remove(struct rte_pci_device *pci_dev)
{
	struct ionic_adapter *adapter = NULL;

	rte_spinlock_lock(&ionic_pci_adapters_lock);
	LIST_FOREACH(adapter, &ionic_pci_adapters, pci_adapters) {
		if (adapter->pci_dev == pci_dev)
			break;

		adapter = NULL;
	}
	if (adapter)
		LIST_REMOVE(adapter, pci_adapters);
	rte_spinlock_unlock(&ionic_pci_adapters_lock);

	if (adapter)
		rte_free(adapter);

	return 0;
}

static struct rte_pci_driver rte_ionic_pmd = {
	.id_table = pci_id_ionic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = eth_ionic_pci_probe,
	.remove = eth_ionic_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_ionic, rte_ionic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_ionic, pci_id_ionic_map);
RTE_PMD_REGISTER_KMOD_DEP(net_ionic, "* igb_uio | uio_pci_generic | vfio-pci");

RTE_INIT(ionic_init_log)
{
	ionic_logtype_init = rte_log_register("pmd.net.ionic.init");

	if (ionic_logtype_init >= 0)
		rte_log_set_level(ionic_logtype_init, RTE_LOG_NOTICE);

	ionic_struct_size_checks();

	ionic_logtype_driver = rte_log_register("pmd.net.ionic.driver");

	if (ionic_logtype_driver >= 0)
		rte_log_set_level(ionic_logtype_driver, RTE_LOG_NOTICE);
}
