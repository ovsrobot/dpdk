/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_interrupts.h>
#include <eal_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_vfio.h>
#include <rte_spinlock.h>
#include <rte_log.h>

#include "ntnic_ethdev.h"
#include "ntnic_vf.h"
#include "ntnic_vf_vdpa.h"
#include "nt_util.h"
#include "ntlog.h"

#define NT_HW_NAPATECH_PCI_VENDOR_ID (0x18F4)
#define NT_HW_NAPATECH_PCI_DEVICE_ID_NT200A02_VF (0x051A)
#define NT_HW_NAPATECH_PCI_DEVICE_ID_NT50B01_VF (0x051B)

static const char *get_adapter_name(struct rte_pci_device *pci_dev)
{
	switch (pci_dev->id.vendor_id) {
	case NT_HW_NAPATECH_PCI_VENDOR_ID:
		switch (pci_dev->id.device_id) {
		case NT_HW_NAPATECH_PCI_DEVICE_ID_NT200A02_VF:
			return "NT200A02";
		case NT_HW_NAPATECH_PCI_DEVICE_ID_NT50B01_VF:
			return "NT50B01";
		}
		break;
	}

	return "Unknown";
}

int nt_vf_pci_probe(struct rte_pci_driver *pci_drv,
		    struct rte_pci_device *pci_dev)
{
	const char *adapter_name _unused = get_adapter_name(pci_dev);

	NT_LOG(INF, VDPA, "Probe %s VF : %02x:%02x:%i\n", adapter_name,
	       pci_dev->addr.bus, pci_dev->addr.devid, pci_dev->addr.function);

	/* Create vDPA device for the virtual function interface.*/

	if (ntvf_vdpa_pci_probe(pci_drv, pci_dev) != 0)
		return -1;

	return nthw_create_vf_interface_dpdk(pci_dev);
}

int nt_vf_pci_remove(struct rte_pci_device *pci_dev)
{
	if (ntvf_vdpa_pci_remove(pci_dev) != 0)
		return -1;

	return nthw_remove_vf_interface_dpdk(pci_dev);
}

static const struct rte_pci_id pci_id_nt_vf_map[] = {
	{	RTE_PCI_DEVICE(NT_HW_NAPATECH_PCI_VENDOR_ID,
			       NT_HW_NAPATECH_PCI_DEVICE_ID_NT200A02_VF)
	},
	{	RTE_PCI_DEVICE(NT_HW_NAPATECH_PCI_VENDOR_ID,
			       NT_HW_NAPATECH_PCI_DEVICE_ID_NT50B01_VF)
	},
	{ .vendor_id = 0, /* sentinel */ },
};

static struct rte_pci_driver rte_nt_vf = {
	.id_table = pci_id_nt_vf_map,
	.drv_flags = 0,
	.probe = nt_vf_pci_probe,
	.remove = nt_vf_pci_remove,
};

RTE_PMD_REGISTER_PCI(net_nt_vf, rte_nt_vf);
RTE_PMD_REGISTER_PCI_TABLE(net_nt_vf, pci_id_nt_vf_map);
RTE_PMD_REGISTER_KMOD_DEP(net_nt_vf, "* vfio-pci");
