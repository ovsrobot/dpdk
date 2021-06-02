/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Red Hat, Inc.
 */

#ifndef __RTE_FIRMWARE_H__
#define __RTE_FIRMWARE_H__

#include <sys/types.h>

#include <rte_compat.h>

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Load a firmware in a dynamically allocated buffer, dealing with compressed
 * files if libarchive is available.
 *
 * @param name
 *      Firmware filename to load.
 * @param buf
 *      Buffer allocated by this function. If this function succeeds, the
 *      caller is responsible for freeing the buffer.
 * @param bufsz
 *      Size of the data in the buffer.
 *
 * @return
 *      0 if successful.
 *      Negative otherwise, buf and bufsize contents are invalid.
 */
__rte_internal
int
rte_firmware_read(const char *name, void **buf, size_t *bufsz);

#endif
