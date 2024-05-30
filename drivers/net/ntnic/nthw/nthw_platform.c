/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include "nthw_platform_drv.h"

nthw_adapter_id_t nthw_platform_get_nthw_adapter_id(const uint16_t n_pci_device_id)
{
	switch (n_pci_device_id) {
	case NT_HW_PCI_DEVICE_ID_NT40E3:
		return NT_HW_ADAPTER_ID_NT40E3;

	case NT_HW_PCI_DEVICE_ID_NT100E3:
		return NT_HW_ADAPTER_ID_NT100E3;

	case NT_HW_PCI_DEVICE_ID_NT80E3:
		return NT_HW_ADAPTER_ID_NT80E3;

	case NT_HW_PCI_DEVICE_ID_NT40A00:
		return NT_HW_ADAPTER_ID_NT40E3;

	case NT_HW_PCI_DEVICE_ID_NT40A01:
		return NT_HW_ADAPTER_ID_NT40E3;

	case NT_HW_PCI_DEVICE_ID_NT200E3:
		return NT_HW_ADAPTER_ID_NT200E3;

	case NT_HW_PCI_DEVICE_ID_NT200A01:
		return NT_HW_ADAPTER_ID_NT200A01;

	case NT_HW_PCI_DEVICE_ID_NT200D01:
		return NT_HW_ADAPTER_ID_NT200D01;

	case NT_HW_PCI_DEVICE_ID_NT200A02_LENOVO:
	case NT_HW_PCI_DEVICE_ID_NT200A02:
		return NT_HW_ADAPTER_ID_NT200A02;

	case NT_HW_PCI_DEVICE_ID_NT50B01_LENOVO:
	case NT_HW_PCI_DEVICE_ID_NT50B01:
		return NT_HW_ADAPTER_ID_NT50B01;

	case NT_HW_PCI_DEVICE_ID_NT100A01:
		return NT_HW_ADAPTER_ID_NT100A01;

	case NT_HW_PCI_DEVICE_ID_NT400D11:
		return NT_HW_ADAPTER_ID_NT400D11;

	default:
		return NT_HW_ADAPTER_ID_UNKNOWN;
	}
}
