/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 6WIND S.A.
 */

#ifndef _RTE_VFIO_H_
#define _RTE_VFIO_H_

/**
 * @file
 * RTE VFIO. This library provides various VFIO related utility functions.
 */

#include <stdbool.h>
#include <stdint.h>

#include <rte_compat.h>
#include <rte_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef RTE_EXEC_ENV_LINUX

#define RTE_VFIO_DIR "/dev/vfio"
#define RTE_VFIO_CONTAINER_PATH "/dev/vfio/vfio"
#define RTE_VFIO_GROUP_FMT "/dev/vfio/%u"
#define RTE_VFIO_NOIOMMU_GROUP_FMT "/dev/vfio/noiommu-%u"
#define RTE_VFIO_NOIOMMU_MODE "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"
#define RTE_VFIO_IOMMUFD_PATH "/dev/iommu"
#define RTE_VFIO_CDEV_DEVICES_PATH "/dev/vfio/devices"

#endif /* RTE_EXEC_ENV_LINUX */

/* we don't need an actual definition, only pointer is used */
struct vfio_device_info;

#define RTE_VFIO_DEFAULT_CONTAINER_FD (-1)

/* Supported VFIO modes */
enum rte_vfio_mode {
	RTE_VFIO_MODE_NONE = 0, /**< VFIO not enabled */
	RTE_VFIO_MODE_GROUP,    /**< VFIO group mode */
	RTE_VFIO_MODE_NOIOMMU,  /**< VFIO noiommu mode */
	RTE_VFIO_MODE_CDEV,     /**< VFIO cdev mode */
};

/**
 * Set up a device managed by VFIO driver.
 *
 * If the device was not previously assigned to a container using
 * `rte_vfio_container_assign_device()`, default container will be used.
 *
 * This function is only relevant on Linux.
 *
 * @param sysfs_base
 *   Sysfs path prefix.
 * @param dev_addr
 *   Device identifier.
 * @param vfio_dev_fd
 *   Pointer to where VFIO device file descriptor will be stored.
 * @param device_info
 *   Pointer to device information. Can be NULL.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - EINVAL  - Invalid parameters.
 * - EIO     - Error during underlying VFIO operations.
 * - ENOSPC  - No space in VFIO container to track the device.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_setup_device(const char *sysfs_base, const char *dev_addr,
		int *vfio_dev_fd, struct vfio_device_info *device_info);

/**
 * Release a device managed by VFIO driver.
 *
 * This function is only relevant on Linux.
 *
 * @note As a result of this function, all internal resources used by the device will be released,
 *       so if the device was using a non-default container, it will need to be reassigned.
 *
 * @param sysfs_base
 *   Sysfs path prefix.
 * @param dev_addr
 *   Device identifier.
 * @param fd
 *   A previously set up VFIO file descriptor.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - ENOENT  - Device not found in any container.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_release_device(const char *sysfs_base, const char *dev_addr, int fd);

/**
 * Enable VFIO subsystem and check if specified kernel module is loaded.
 *
 * In case of success, `rte_vfio_get_mode()` can be used to retrieve the VFIO mode in use.
 *
 * This function is only relevant on Linux.
 *
 * @param modname
 *   Kernel module name.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENOTSUP - Operation not supported.
 */
int rte_vfio_enable(const char *modname);

/**
 * Check if VFIO subsystem is initialized and a specified kernel module is loaded.
 *
 * This function is only relevant on Linux.
 *
 * @param modname
 *   Kernel module name.
 *
 * @return
 *   1 if enabled.
 *   0 if not enabled or not supported.
 */
int rte_vfio_is_enabled(const char *modname);

/**
 * Get current VFIO mode.
 *
 * This function is only relevant on Linux.
 *
 * @return
 *   VFIO mode currently in use.
 */
enum rte_vfio_mode
rte_vfio_get_mode(void);

/**
 * Check if VFIO NOIOMMU mode is enabled.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @return
 *   1 if enabled.
 *   0 if not enabled or not supported.
 */
int
rte_vfio_noiommu_is_enabled(void);

/**
 * Remove group fd from internal VFIO tracking.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @param vfio_group_fd
 *   VFIO group fd.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENOENT  - Group not found.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_clear_group(int vfio_group_fd);

/**
 * Parse IOMMU group number for a device.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @param sysfs_base
 *   Sysfs path prefix.
 * @param dev_addr
 *   Device identifier.
 * @param iommu_group_num
 *   Pointer to where IOMMU group number will be stored.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_get_group_num(const char *sysfs_base, const char *dev_addr, int *iommu_group_num);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Parse VFIO cdev device number for a device.
 *
 * This function is only relevant on Linux in cdev mode.
 *
 * @param sysfs_base
 *   Sysfs path prefix.
 * @param dev_addr
 *   Device identifier.
 * @param vfio_device_num
 *   Pointer to where VFIO cdev device number will be stored.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
__rte_experimental
int
rte_vfio_get_device_num(const char *sysfs_base, const char *dev_addr, int *vfio_device_num);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Get device information.
 *
 * This function is only relevant on Linux.
 *
 * @param vfio_dev_fd
 *   VFIO device file descriptor.
 * @param device_info
 *   Pointer to device information structure.
 *
 * @return
 * - EINVAL  - Invalid parameters.
 * - EIO     - Underlying VFIO operation failed.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
__rte_experimental
int
rte_vfio_get_device_info(int vfio_dev_fd, struct vfio_device_info *device_info);

/**
 * Get the default VFIO container file descriptor.
 *
 * This function is only relevant on Linux.
 *
 * @return
 *   Non-negative container file descriptor on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_get_container_fd(void);

/**
 * Return file descriptor for an open VFIO group.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @param iommu_group_num
 *   IOMMU group number.
 *
 * @return
 *   Non-negative group file descriptor on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENOENT  - Group not found.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_get_group_fd(int iommu_group_num);

/**
 * Create a new VFIO container for device assignment and DMA mapping.
 *
 * This function is only relevant on Linux.
 *
 * @note Any newly allocated DPDK memory will not be mapped into these
 *       containers by default, user needs to manage DMA mappings for
 *       any container created by this API.
 *
 * @note When creating containers using this API, the container will only be
 *       available in the process that has created it. Sharing containers and
 *       devices between multiple processes is not supported.
 *
 * @return
 *   Non-negative container file descriptor on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - EIO     - Underlying VFIO operation failed.
 * - ENOSPC  - Maximum number of containers reached.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_create(void);

/**
 * Destroy a VFIO container and unmap all devices assigned to it.
 *
 * This function is only relevant on Linux.
 *
 * @param container_fd
 *   File descriptor of container to destroy.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Container not managed by VFIO.
 * - EINVAL  - Invalid container file descriptor.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_destroy(int container_fd);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice.
 *
 * Assign a device to a VFIO container.
 *
 * Doing so will cause `rte_vfio_setup_device()` to set up the device with the VFIO container
 * specified in this assign operation.
 *
 * This function is only relevant on Linux.
 *
 * @param vfio_container_fd
 *   VFIO container file descriptor.
 * @param sysfs_base
 *   Sysfs path prefix.
 * @param dev_addr
 *   Device identifier.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - EEXIST  - Device already assigned to the container.
 * - EINVAL  - Invalid container file descriptor.
 * - EIO     - Error during underlying VFIO operations.
 * - ENOSPC  - No space in VFIO container to assign device.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
__rte_experimental
int
rte_vfio_container_assign_device(int vfio_container_fd,
		const char *sysfs_base, const char *dev_addr);

/**
 * Bind an IOMMU group to a container.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @param container_fd
 *   Container file descriptor.
 * @param iommu_group_num
 *   IOMMU group number to bind to container.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - IOMMU group not managed by VFIO.
 * - EINVAL  - Invalid container file descriptor.
 * - ENOSPC  - No space in VFIO container to track the group.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_group_bind(int container_fd, int iommu_group_num);

/**
 * Unbind an IOMMU group from a container.
 *
 * This function is only relevant on Linux in group mode.
 *
 * @param container_fd
 *   Container file descriptor.
 * @param iommu_group_num
 *   IOMMU group number to unbind from container.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Container not managed by VFIO.
 * - ENOENT  - VFIO group not found in container.
 * - EINVAL  - Invalid container file descriptor.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_group_unbind(int container_fd, int iommu_group_num);

/**
 * Perform DMA mapping for devices in a container.
 *
 * This function is only relevant on Linux.
 *
 * @param container_fd
 *   Container file descriptor. Use RTE_VFIO_DEFAULT_CONTAINER_FD to use the default container.
 * @param vaddr
 *   Starting virtual address of memory to be mapped.
 * @param iova
 *   Starting IOVA address of memory to be mapped.
 * @param len
 *   Length of memory segment being mapped.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - EINVAL  - Invalid parameters.
 * - EIO     - DMA mapping operation failed.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_dma_map(int container_fd, uint64_t vaddr,
		uint64_t iova, uint64_t len);

/**
 * Perform DMA unmapping for devices in a container.
 *
 * This function is only relevant on Linux.
 *
 * @param container_fd
 *   Container file descriptor. Use RTE_VFIO_DEFAULT_CONTAINER_FD to use the default container.
 * @param vaddr
 *   Starting virtual address of memory to be unmapped.
 * @param iova
 *   Starting IOVA address of memory to be unmapped.
 * @param len
 *   Length of memory segment being unmapped.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - EINVAL  - Invalid parameters.
 * - EIO     - DMA unmapping operation failed.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
int
rte_vfio_container_dma_unmap(int container_fd, uint64_t vaddr,
		uint64_t iova, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_VFIO_H_ */
