/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_PLATFORM_DRV_H__
#define __NTHW_PLATFORM_DRV_H__

#include "nthw_helper.h"

#define NT_HW_PCI_VENDOR_ID (0x18f4)

#define NT_HW_PCI_DEVICE_ID_NT40E3 (0x145)
#define NT_HW_PCI_DEVICE_ID_NT100E3 (0x155)
#define NT_HW_PCI_DEVICE_ID_NT80E3 (0x165)
#define NT_HW_PCI_DEVICE_ID_NT40A00 (0x175)
#define NT_HW_PCI_DEVICE_ID_NT40A01 (0x185)
#define NT_HW_PCI_DEVICE_ID_NT200E3 (0x195)
#define NT_HW_PCI_DEVICE_ID_NT200A01 (0x1A5)
#define NT_HW_PCI_DEVICE_ID_NT200D01 (0x1B5)
#define NT_HW_PCI_DEVICE_ID_NT200A02 (0x1C5)
#define NT_HW_PCI_DEVICE_ID_NT50B01 (0x1D5)
#define NT_HW_PCI_DEVICE_ID_NT100A01 (0x1E5)

enum nthw_adapter_id_e {
	NT_HW_ADAPTER_ID_UNKNOWN = 0,
	NT_HW_ADAPTER_ID_NT40E3,
	NT_HW_ADAPTER_ID_NT40A01 = NT_HW_ADAPTER_ID_NT40E3,
	NT_HW_ADAPTER_ID_NT50B01,
	NT_HW_ADAPTER_ID_NT80E3,
	NT_HW_ADAPTER_ID_NT100E3,
	NT_HW_ADAPTER_ID_NT100A01,
	NT_HW_ADAPTER_ID_NT200E3,
	NT_HW_ADAPTER_ID_NT200A01,
	NT_HW_ADAPTER_ID_NT200D01,
	NT_HW_ADAPTER_ID_NT200A02,
};

typedef enum nthw_adapter_id_e nthw_adapter_id_t;

nthw_adapter_id_t nthw_platform_get_nthw_adapter_id(const uint16_t n_pci_device_id);

#endif /* __NTHW_PLATFORM_DRV_H__ */
