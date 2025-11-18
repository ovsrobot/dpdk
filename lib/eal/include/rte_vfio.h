/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 6WIND S.A.
 */

#ifndef _RTE_VFIO_H_
#define _RTE_VFIO_H_

/**
 * @file
 * @internal
 *
 * RTE VFIO internal API.
 *
 * This library provides VFIO related utility functions for use by drivers.
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
#define RTE_VFIO_IOMMUFD_PATH "/dev/iommu"
#define RTE_VFIO_CDEV_DEVICES_PATH "/dev/vfio/devices"
#define RTE_VFIO_GROUP_FMT "/dev/vfio/%u"
#define RTE_VFIO_NOIOMMU_GROUP_FMT "/dev/vfio/noiommu-%u"
#define RTE_VFIO_NOIOMMU_MODE "/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"

#endif /* RTE_EXEC_ENV_LINUX */

/* we don't need an actual definition, only pointer is used */
struct vfio_device_info;

#define RTE_VFIO_DEFAULT_CONTAINER_FD (-1)

/**
 * @internal
 * Enumeration of VFIO operational modes.
 *
 * These modes define how VFIO devices are accessed and managed:
 *
 * - RTE_VFIO_MODE_NONE: VFIO is not enabled.
 * - RTE_VFIO_MODE_GROUP: Legacy group mode.
 * - RTE_VFIO_MODE_NOIOMMU: Unsafe no-IOMMU mode.
 * - RTE_VFIO_MODE_CDEV: Character device mode.
 */
enum rte_vfio_mode {
	RTE_VFIO_MODE_NONE = 0, /**< VFIO not enabled */
	RTE_VFIO_MODE_GROUP,    /**< Group mode */
	RTE_VFIO_MODE_NOIOMMU,  /**< Group mode with no IOMMU protection */
	RTE_VFIO_MODE_CDEV,     /**< Device mode */
};

/**
 * @internal
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
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - ENODEV  - Device not managed by VFIO.
 * - ENOSPC  - No space in VFIO container to track the device.
 * - EINVAL  - Invalid parameters.
 * - EIO     - Error during underlying VFIO operations.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int rte_vfio_setup_device(const char *sysfs_base, const char *dev_addr,
		int *vfio_dev_fd);

/**
 * @internal
 * Release a device managed by VFIO driver.
 *
 * This function is only relevant on Linux.
 *
 * @note As a result of this function, all internal resources used by the device will be released,
 *       so if the device was using a non-default container, it will need to be reassigned to the
 *       container before it can be used again.
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
 * - ENOENT  - Device not found in any container.
 * - EINVAL  - Invalid parameters.
 * - EIO     - Error during underlying VFIO operations.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int rte_vfio_release_device(const char *sysfs_base, const char *dev_addr, int fd);

/**
 * @internal
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
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Operation not supported.
 */
__rte_internal
int rte_vfio_enable(const char *modname);

/**
 * @internal
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
__rte_internal
int rte_vfio_is_enabled(const char *modname);

/**
 * @internal
 * Get current VFIO mode.
 *
 * This function is only relevant on Linux.
 *
 * @return
 *   VFIO mode currently in use.
 */
__rte_internal
enum rte_vfio_mode
rte_vfio_get_mode(void);

/**
 * @internal
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
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_get_group_num(const char *sysfs_base, const char *dev_addr, int *iommu_group_num);

/**
 * @internal
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
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_get_device_num(const char *sysfs_base, const char *dev_addr, int *vfio_device_num);

/**
 * @internal
 * Get device information.
 *
 * This function retrieves VFIO device information from an already opened
 * device. The device must be opened with rte_vfio_setup_device() first.
 *
 * This function is only relevant to Linux and will return an error on BSD.
 *
 * @param vfio_dev_fd
 *   VFIO device fd (must be a valid, already opened fd).
 *
 * @param device_info
 *   Pointer to device information structure to be filled.
 *
 * @return
 *   0 on success.
 *   <0 on failure, rte_errno is set.
 *
 * Possible rte_errno values include:
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_get_device_info(int vfio_dev_fd, struct vfio_device_info *device_info);

/**
 * @internal
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
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_get_container_fd(void);

/**
 * @internal
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
 * - ENOSPC  - Maximum number of containers reached.
 * - EIO     - Underlying VFIO operation failed.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_container_create(void);

/**
 * @internal
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
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_container_destroy(int container_fd);

/**
 * @internal
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
 * - ENOSPC  - No space in VFIO container to assign device.
 * - EINVAL  - Invalid container file descriptor.
 * - EIO     - Error during underlying VFIO operations.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_container_assign_device(int vfio_container_fd,
		const char *sysfs_base, const char *dev_addr);

/**
 * @internal
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
 * - EIO     - DMA mapping operation failed.
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_container_dma_map(int container_fd, uint64_t vaddr,
		uint64_t iova, uint64_t len);

/**
 * @internal
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
 * - EIO     - DMA unmapping operation failed.
 * - EINVAL  - Invalid parameters.
 * - ENXIO   - VFIO support not initialized.
 * - ENOTSUP - Unsupported VFIO mode.
 */
__rte_internal
int
rte_vfio_container_dma_unmap(int container_fd, uint64_t vaddr,
		uint64_t iova, uint64_t len);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_VFIO_H_ */
