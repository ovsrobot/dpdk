/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Intel Corporation
 */

#ifndef _RTE_IDXD_INTER_DOM_H_
#define _RTE_IDXD_INTER_DOM_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <rte_compat.h>

/** Allow reading from address space. */
#define RTE_IDXD_WIN_FLAGS_PROT_READ    0x0001
/** Allow writing to address space. */
#define RTE_IDXD_WIN_FLAGS_PROT_WRITE   0x0002
/** If this flag not set, the entire address space will be accessible. */
#define RTE_IDXD_WIN_FLAGS_WIN_CHECK    0x0004
/** Destination addresses are offsets from window base address. */
#define RTE_IDXD_WIN_FLAGS_OFFSET_MODE  0x0008
/* multiple submitter flag. If not set - single submitter type will be used. */
#define RTE_IDXD_WIN_FLAGS_TYPE_SAMS    0x0010

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Create an inter-pasid window to allow another process to access this process'
 * memory. This function returns a file descriptor for the window, that can be
 * used by another process to access this window.
 *
 * @param controller_id
 *   IDXD controller device ID.
 * @param win_addr
 *   Base address of memory chunk being shared (ignored if
 *   `RTE_IDXD_WIN_FLAGS_WIN_CHECK` is not set).
 * @param win_len
 *   Length of memory chunk being shared (ignored if
 *   `RTE_IDXD_WIN_FLAGS_WIN_CHECK` is not set).
 * @param flags
 *   Flags to configure the window.
 * @return
 *   Non-negative on success.
 *   Negative on error.
 */
__rte_experimental
int rte_idxd_window_create(int controller_id, void *win_addr,
	unsigned int win_len, int flags);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Attach to an inter-pasid window of another process. This function expects a
 * file descriptor returned by `rte_idxd_window_create()`, and will set the
 * value pointed to by `handle`. This handle can then be used to perform
 * inter-domain DMA operations.
 *
 * @param controller_id
 *   IDXD controller device ID.
 * @param idpte_fd
 *   File descriptor for another process's window
 * @param handle
 *   Pointer to a variable to receive the handle.
 * @return
 *   0 on success.
 *   Negative on error.
 */
__rte_experimental
int rte_idxd_window_attach(int controller_id, int idpte_fd, uint16_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_IDXD_INTER_DOM_H_ */
