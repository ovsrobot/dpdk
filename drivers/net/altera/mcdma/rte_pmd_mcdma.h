/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2026 Altera Corporation
 */

#ifndef RTE_PMD_MCDMA_H
#define RTE_PMD_MCDMA_H

/**
 * @file rte_pmd_mcdma.h
 *
 * Altera MCDMA PMD specific functions.
 */

#include <stdint.h>
#include <stdio.h>

#include <rte_compat.h>

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Read a 64-bit value from the mapped PIO BAR at @p offset.
 *
 * @param port_id
 *   Port identifier.
 * @param offset
 *   Byte offset from the PIO BAR base (must be 8-byte aligned and fit a
 *   64-bit access within the mapped PIO BAR).
 * @param val
 *   On success, the 64-bit register value is stored here. Untouched on failure.
 *
 * @return
 *   0 on success, negative errno on failure (-EINVAL, -ENODEV).
 */
__rte_experimental
int
rte_pmd_mcdma_pio_read64(uint16_t port_id, uint64_t offset, uint64_t *val);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Write a 64-bit value to the mapped PIO BAR at @p offset.
 *
 * @param port_id
 *   Port identifier.
 * @param offset
 *   Byte offset from the PIO BAR base (must be 8-byte aligned and fit a
 *   64-bit access within the mapped PIO BAR).
 * @param val
 *   Value to write.
 *
 * @return
 *   0 on success, negative errno on failure (-EINVAL, -ENODEV).
 */
__rte_experimental
int
rte_pmd_mcdma_pio_write64(uint16_t port_id, uint64_t offset, uint64_t val);

#endif /* RTE_PMD_MCDMA_H */
