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

struct rte_vfio_user_irq_info {
	uint32_t irq_num;
	struct vfio_irq_info irq_info[];
};

/**
 *  Below APIs are for vfio-user server (device provider) to use:
 *	*rte_vfio_user_register
 *	*rte_vfio_user_unregister
 *	*rte_vfio_user_start
 *	*rte_vfio_get_sock_addr
 *	*rte_vfio_user_get_mem_table
 *	*rte_vfio_user_get_irq
 *	*rte_vfio_user_set_dev_info
 *	*rte_vfio_user_set_reg_info
 *	*rte_vfio_user_set_irq_info
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

/**
 * Get the irqfds of a vfio-user device.
 *
 * @param dev_id
 *   Vfio-user device ID
 * @param index
 *   irq index
 * @param count
 *   irq count
 * @param[out] fds
 *   Pointer to the irqfds
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_get_irq(int dev_id, uint32_t index, uint32_t count,
	int *fds);

/**
 * Set the irq information for a vfio-user device.
 *
 * This information must be set before calling rte_vfio_user_start, and should
 * not be updated after start. Update after start can be done by unregistration
 * and re-registration, and then the device-level change can be detected by
 * vfio-user client.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @param irq
 *   IRQ information for the vfio-user device
 * @return
 *   0 on success, -1 on failure
 */
__rte_experimental
int
rte_vfio_user_set_irq_info(const char *sock_addr,
	struct rte_vfio_user_irq_info *irq);

/**
 *  Below APIs are for vfio-user client (device consumer) to use:
 *	*rte_vfio_user_attach_dev
 *	*rte_vfio_user_detach_dev
 *	*rte_vfio_user_get_dev_info
 *	*rte_vfio_user_get_reg_info
 *	*rte_vfio_user_get_irq_info
 *	*rte_vfio_user_dma_map
 *	*rte_vfio_user_dma_unmap
 *	*rte_vfio_user_set_irqs
 *	*rte_vfio_user_region_read
 *	*rte_vfio_user_region_write
 *	*rte_vfio_user_reset
 */

/**
 * Attach to a vfio-user device.
 *
 * @param sock_addr
 *   Unix domain socket address
 * @return
 *   - >=0: Success, device attached. Returned value is the device ID.
 *   - <0: Failure on device attach
 */
__rte_experimental
int
rte_vfio_user_attach_dev(const char *sock_addr);

/**
 * Detach from a vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @return
 *   - 0: Success, device detached
 *   - <0: Failure on device detach
 */
__rte_experimental
int
rte_vfio_user_detach_dev(int dev_id);

/**
 * Get device information of a vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param[out] info
 *   A pointer to a structure of type *vfio_device_info* to be filled with the
 *   information of the device.
 * @return
 *   - 0: Success, device information updated
 *   - <0: Failure on get device information
 */
__rte_experimental
int
rte_vfio_user_get_dev_info(int dev_id, struct vfio_device_info *info);

/**
 * Get region information of a vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param[out] info
 *   A pointer to a structure of type *vfio_region_info* to be filled with the
 *   information of the device region.
 * @param[out] fd
 *   A pointer to the file descriptor of the region
 * @return
 *   - 0: Success, region information and file descriptor updated. If the region
 *        can not be mmaped, the file descriptor should be -1.
 *   - <0: Failure on get region information
 */
__rte_experimental
int
rte_vfio_user_get_reg_info(int dev_id, struct vfio_region_info *info,
	int *fd);

/**
 * Get IRQ information of a vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param[out] info
 *   A pointer to a structure of type *vfio_irq_info* to be filled with the
 *   information of the IRQ.
 * @return
 *   - 0: Success, IRQ information updated
 *   - <0: Failure on get IRQ information
 */
__rte_experimental
int
rte_vfio_user_get_irq_info(int dev_id, struct vfio_irq_info *info);

/**
 * Map DMA regions for the vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param mem
 *   A pointer to a structure of type *vfio_user_mem_reg* that identifies
 *   one or several DMA regions.
 * @param fds
 *   A pointer to a list of file descriptors. One file descriptor maps to
 *   one DMA region.
 * @param num
 *   Number of DMA regions (or file descriptors)
 * @return
 *   - 0: Success, all DMA regions are mapped.
 *   - <0: Failure on DMA map. It should be assumed that all DMA regions
 *         are not mapped.
 */
__rte_experimental
int
rte_vfio_user_dma_map(int dev_id, struct rte_vfio_user_mem_reg *mem,
	int *fds, uint32_t num);

/**
 * Unmap DMA regions for the vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param mem
 *   A pointer to a structure of type *vfio_user_mem_reg* that identifies
 *   one or several DMA regions.
 * @param num
 *   Number of DMA regions
 * @return
 *   - 0: Success, all DMA regions are unmapped.
 *   - <0: Failure on DMA unmap. It should be assumed that all DMA regions
 *         are not unmapped.
 */
__rte_experimental
int
rte_vfio_user_dma_unmap(int dev_id, struct rte_vfio_user_mem_reg *mem,
	uint32_t num);

/**
 * Set interrupt signaling, masking, and unmasking for the vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param set
 *   A pointer to a structure of type *vfio_irq_set* that specifies the set
 *   data and action
 * @return
 *   - 0: Success, IRQs are set successfully.
 *   - <0: Failure on IRQ set.
 */
__rte_experimental
int
rte_vfio_user_set_irqs(int dev_id, struct vfio_irq_set *set);

/**
 * Read region of the vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param idx
 *   The region index
 * @param offset
 *   The region offset
 * @param size
 *   Size of the read data
 * @param[out] data
 *   The pointer to data to be filled with correct region data
 * @return
 *   - 0: Success on region read
 *   - <0: Failure on region read
 */
__rte_experimental
int
rte_vfio_user_region_read(int dev_id, uint32_t idx, uint64_t offset,
	uint32_t size, void *data);

/**
 * Write region of the vfio-user device.
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @param idx
 *   The region index
 * @param offset
 *   The region offset
 * @param size
 *   Size of the read data
 * @param data
 *   The pointer to data that will be written to the region
 * @return
 *   - 0: Success on region write
 *   - <0: Failure on region write
 */
__rte_experimental
int
rte_vfio_user_region_write(int dev_id, uint32_t idx, uint64_t offset,
	uint32_t size, const void *data);

/**
 * Reset the vfio-user device
 *
 * @param dev_id
 *   Device ID of the vfio-user device
 * @return
 *   - 0: Success on device reset
 *   - <0: Failure on device reset
 */
__rte_experimental
int
rte_vfio_user_reset(int dev_id);

#endif
