/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation.
 */

#ifndef _RTE_BUS_PCI_H_
#define _RTE_BUS_PCI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_compat.h>

/**
 * Dump the content of the PCI bus.
 *
 * @param f
 *   A pointer to a file for output
 */
void rte_pci_dump(FILE *f);

/**
 * Read 4 bytes from PCI memory resource.
 *
 * @param name
 *   PCI device name (e.g., 0000:18:00.0).
 * @param idx
 *   Memory resource index.
 * @param data
 *   Data buffer where the bytes should be read into.
 * @param offset
 *   The offset into the PCI memory resource.
 * @return
 *  0 on success, negative value on error.
 */
__rte_experimental
int
rte_pci_mem_rd32(const char *name, uint16_t idx, uint32_t *data, uint64_t offset);

/**
 * Write 4 bytes to PCI memory resource.
 *
 * @param name
 *   PCI device name (e.g., 0000:18:00.0).
 * @param idx
 *   Memory resource index.
 * @param data
 *   Buffer of data that should be written to PCI memory.
 * @param offset
 *   The offset into the PCI memory resource.
 * @return
 *  0 on success, negative value on error.
 */
__rte_experimental
int
rte_pci_mem_wr32(const char *name, uint16_t idx, const uint32_t *data, uint64_t offset);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BUS_PCI_H_ */
