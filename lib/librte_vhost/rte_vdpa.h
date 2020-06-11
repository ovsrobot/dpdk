/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _RTE_VDPA_H_
#define _RTE_VDPA_H_

/**
 * @file
 *
 * Device specific vhost lib
 */

struct rte_vdpa_device;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Find the device id of a vdpa device from its name
 *
 * @param name
 *  the vdpa device name
 * @return
 *  vDPA device pointer on success, NULL on failure
 */
__rte_experimental
struct rte_vdpa_device *
rte_vdpa_find_device_by_name(const char *name);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the generic device from the vdpa device
 *
 * @param vdpa_dev
 *  the vdpa device pointer
 * @return
 *  generic device pointer on success, NULL on failure
 */
__rte_experimental
struct rte_device *
rte_vdpa_get_rte_device(struct rte_vdpa_device *vdpa_dev);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get number of queue pairs supported by the vDPA device
 *
 * @param dev
 *  vDP device pointer
 * @param queue_num
 *  pointer on where the number of queue is stored
 * @return
 *  0 on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_get_queue_num(struct rte_vdpa_device *dev, uint32_t *queue_num);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the Virtio features supported by the vDPA device
 *
 * @param dev
 *  vDP device pointer
 * @param features
 *  pointer on where the supported features are stored
 * @return
 *  0 on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_get_features(struct rte_vdpa_device *dev, uint64_t *features);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Get the Vhost-user protocol features supported by the vDPA device
 *
 * @param dev
 *  vDP device pointer
 * @param features
 *  pointer on where the supported protocol features are stored
 * @return
 *  0 on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_get_protocol_features(struct rte_vdpa_device *dev, uint64_t *features);

#endif /* _RTE_VDPA_H_ */
