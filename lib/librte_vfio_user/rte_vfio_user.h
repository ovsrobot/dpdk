/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_VFIO_USER_H
#define _RTE_VFIO_USER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <linux/vfio.h>
#include <sys/types.h>

#include <rte_compat.h>

#define RTE_VUSER_MAX_DMA 256

struct rte_vfio_user_notify_ops {
	/* Add device */
	int (*new_device)(int dev_id);
	/* Remove device */
	void (*destroy_device)(int dev_id);
	/* Update device status */
	int (*update_status)(int dev_id);
	/* Lock or unlock data path */
	int (*lock_dp)(int dev_id, int lock);
	/* Reset device */
	int (*reset_device)(int dev_id);
};

struct rte_vfio_user_mem_reg {
	uint64_t gpa;
	uint64_t size;
	uint64_t fd_offset;
	uint32_t protection;	/* attributes in <sys/mman.h> */
#define RTE_VUSER_MEM_MAPPABLE	(0x1 << 0)
	uint32_t flags;
};

struct rte_vfio_user_mtb_entry {
	uint64_t gpa;
	uint64_t size;
	uint64_t host_user_addr;
	void	 *mmap_addr;
	uint64_t mmap_size;
	int fd;
};

struct rte_vfio_user_mem {
	uint32_t entry_num;
	struct rte_vfio_user_mtb_entry entry[RTE_VUSER_MAX_DMA];
};

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
 *	*rte_vfio_get_sock_addr
 *	*rte_vfio_user_get_mem_table
 *	*rte_vfio_user_set_dev_info
 *	*rte_vfio_user_set_reg_info
 */

/**
 * Register a vfio-user device.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @param ops
 *   Notify ops for the device
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_register(const char *sock_addr,
	const struct rte_vfio_user_notify_ops *ops);

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
 * Get the memory table of a vfio-user device.
 *
 * @param dev_id
 *   Vfio-user device ID
 * @return
 *   Pointer to memory table on success, NULL on failure
 */
__rte_experimental
const struct rte_vfio_user_mem *
rte_vfio_user_get_mem_table(int dev_id);

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

/**
 * Get the socket address for a vfio-user device.
 *
 * @param dev_id
 *   Vfio-user device ID
 * @param[out] buf
 *   Buffer to store socket address
 * @param len
 *   The length of the buffer
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_get_sock_addr(int dev_id, char *buf, size_t len);

#endif
