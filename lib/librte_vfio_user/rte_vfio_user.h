/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_VFIO_USER_H
#define _RTE_VFIO_USER_H

#include <linux/vfio.h>

#include <rte_compat.h>

struct rte_vfio_user_reg_info;

typedef ssize_t (*rte_vfio_user_reg_acc_t)(struct rte_vfio_user_reg_info *reg,
		char *buf, size_t count, loff_t pos, bool iswrite);

struct rte_vfio_user_reg_info {
	rte_vfio_user_reg_acc_t rw;
	void *base;
	int fd;
	struct vfio_region_info *info;
	void *priv;
};

struct rte_vfio_user_regions {
	uint32_t reg_num;
	struct rte_vfio_user_reg_info reg_info[];
};

/**
 *  Below APIs are for vfio-user server (device provider) to use:
 *	*rte_vfio_user_register
 *	*rte_vfio_user_unregister
 *	*rte_vfio_user_start
 *	*rte_vfio_user_set_dev_info
 *	*rte_vfio_user_set_reg_info
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

/**
 * Set the device information for a vfio-user device.
 *
 * This information must be set before calling rte_vfio_user_start, and should
 * not be updated after start. Update after start can be done by unregistration
 * and re-registration, and then the device-level change can be detected by
 * vfio-user client.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @param dev_info
 *   Device information for the vfio-user device
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_set_dev_info(const char *sock_addr,
	struct vfio_device_info *dev_info);

/**
 * Set the region information for a vfio-user device.
 *
 * This information must be set before calling rte_vfio_user_start, and should
 * not be updated after start. Update after start can be done by unregistration
 * and re-registration, and then the device-level change can be detected by
 * vfio-user client.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @param reg
 *   Region information for the vfio-user device
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_set_reg_info(const char *sock_addr,
	struct rte_vfio_user_regions *reg);

#endif
