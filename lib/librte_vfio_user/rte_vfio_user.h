/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_VFIO_USER_H
#define _RTE_VFIO_USER_H

#include <rte_compat.h>

/**
 *  Below APIs are for vfio-user server (device provider) to use:
 *	*rte_vfio_user_register
 *	*rte_vfio_user_unregister
 *	*rte_vfio_user_start
 */

/**
 * Register a vfio-user device.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_register(const char *sock_addr);

/**
 * Unregister a vfio-user device.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_unregister(const char *sock_addr);

/**
 * Start vfio-user handling for the device.
 *
 * This function triggers vfio-user message handling.
 * @param sock_addr
 *   Unix domain socket address
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_start(const char *sock_addr);

#endif
