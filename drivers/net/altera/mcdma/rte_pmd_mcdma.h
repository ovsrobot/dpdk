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

/** MCDMA queue direction for PMD APIs. */
enum rte_pmd_mcdma_queue_dir {
	RTE_PMD_MCDMA_QUEUE_RX = 0, /**< Device-to-host (RX). */
	RTE_PMD_MCDMA_QUEUE_TX = 1, /**< Host-to-device (TX). */
};

/** Snapshot of one queue's QCSR registers and driver state. */
struct rte_pmd_mcdma_qcsr {
	uint32_t q_ctrl;
	uint32_t q_start_addr_l;
	uint32_t q_start_addr_h;
	uint32_t q_size;
	uint32_t q_tail_pointer;
	uint32_t q_head_pointer;
	uint32_t q_completed_pointer;
	uint32_t q_consumed_head_addr_l;
	uint32_t q_consumed_head_addr_h;
	uint32_t q_batch_delay;
	uint32_t q_debug_status_1;
	uint32_t q_debug_status_2;
	uint32_t q_data_drp_err_ctr;
	uint32_t q_payload_count;
	uint32_t q_reset;
	uint32_t q_cpl_timeout;

	uint16_t prod_didx;
	uint16_t cons_didx;
	uint16_t freed_cons_didx;
	uint16_t submitted_didx;
	uint32_t num_descs;
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Read QCSR registers and software queue state for one queue.
 *
 * @param port_id
 *   Port identifier.
 * @param queue_id
 *   Queue identifier.
 * @param dir
 *   Queue direction (RX or TX).
 * @param regs
 *   Output register snapshot.
 *
 * @return
 *   0 on success, negative errno on failure.
 */
__rte_experimental
int
rte_pmd_mcdma_qcsr_read(uint16_t port_id, uint16_t queue_id,
			enum rte_pmd_mcdma_queue_dir dir,
			struct rte_pmd_mcdma_qcsr *regs);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Dump QCSR registers and software queue state to a stream.
 *
 * @param port_id
 *   Port identifier.
 * @param queue_id
 *   Queue identifier.
 * @param dir
 *   Queue direction (RX or TX).
 * @param f
 *   Output stream. Uses stdout if NULL.
 *
 * @return
 *   0 on success, negative errno on failure.
 */
__rte_experimental
int
rte_pmd_mcdma_qcsr_dump(uint16_t port_id, uint16_t queue_id,
			enum rte_pmd_mcdma_queue_dir dir, FILE *f);

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
