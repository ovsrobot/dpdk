/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef NTOSS_SYSTEM_NT_UTIL_H
#define NTOSS_SYSTEM_NT_UTIL_H

#include <stdint.h>

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) RTE_DIM(arr)
#endif

#define PCIIDENT_TO_DOMAIN(pci_ident) ((uint16_t)(((unsigned int)(pci_ident) >> 16) & 0xFFFFU))
#define PCIIDENT_TO_BUSNR(pci_ident) ((uint8_t)(((unsigned int)(pci_ident) >> 8) & 0xFFU))
#define PCIIDENT_TO_DEVNR(pci_ident) ((uint8_t)(((unsigned int)(pci_ident) >> 3) & 0x1FU))
#define PCIIDENT_TO_FUNCNR(pci_ident) ((uint8_t)(((unsigned int)(pci_ident) >> 0) & 0x7U))
#define PCIIDENT_PRINT_STR "%04x:%02x:%02x.%x"
#define BDF_TO_PCIIDENT(dom, bus, dev, fnc) (((dom) << 16) | ((bus) << 8) | ((dev) << 3) | (fnc))

uint64_t nt_os_get_time_monotonic_counter(void);
void nt_os_wait_usec(int val);

uint64_t nt_util_align_size(uint64_t size);


#endif	/* NTOSS_SYSTEM_NT_UTIL_H */
