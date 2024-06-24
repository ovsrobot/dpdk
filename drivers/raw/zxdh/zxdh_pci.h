/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 ZTE Corporation
 */

#ifndef __ZXDH_PCI_H__
#define __ZXDH_PCI_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_pci.h>

#define FILE_PATH_LEN                       (100)
#define PCI_BUFF_LEN                        (16)

struct zxdh_pci_dev {
	uint16_t    vendor_id;
	uint16_t    device_id;
	uint16_t    domain;
	uint8_t     bus;
	uint8_t     devid;
	uint8_t     function;
	char        dirname[FILE_PATH_LEN];
	char        d_name[PCI_BUFF_LEN];
	void       *bar_va[PCI_MAX_RESOURCE];
	uint64_t    bar_pa[PCI_MAX_RESOURCE];
	uint64_t    bar_len[PCI_MAX_RESOURCE];
};

extern struct zxdh_pci_dev gdev;

void zxdh_gdma_pci_dev_munmap(void);
int zxdh_gdma_pci_scan(void);

#ifdef __cplusplus
}
#endif

#endif /* __ZXDH_PCI_H__ */

