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

#include <stdbool.h>

#include <rte_pci.h>
#include "rte_vhost.h"

#define MAX_VDPA_NAME_LEN 128

struct rte_vdpa_device;

/**
 * vdpa device operations
 */
struct rte_vdpa_dev_ops {
	/** Get capabilities of this device */
	int (*get_queue_num)(struct rte_vdpa_device *dev, uint32_t *queue_num);

	/** Get supported features of this device */
	int (*get_features)(struct rte_vdpa_device *dev, uint64_t *features);

	/** Get supported protocol features of this device */
	int (*get_protocol_features)(struct rte_vdpa_device *dev,
			uint64_t *protocol_features);

	/** Driver configure/close the device */
	int (*dev_conf)(int vid);
	int (*dev_close)(int vid);

	/** Enable/disable this vring */
	int (*set_vring_state)(int vid, int vring, int state);

	/** Set features when changed */
	int (*set_features)(int vid);

	/** Destination operations when migration done */
	int (*migration_done)(int vid);

	/** Get the vfio group fd */
	int (*get_vfio_group_fd)(int vid);

	/** Get the vfio device fd */
	int (*get_vfio_device_fd)(int vid);

	/** Get the notify area info of the queue */
	int (*get_notify_area)(int vid, int qid,
			uint64_t *offset, uint64_t *size);

	/** Reserved for future extension */
	void *reserved[5];
};

/**
 * vdpa device structure includes device address and device operations.
 */
struct rte_vdpa_device {
	TAILQ_ENTRY(rte_vdpa_device) next;
	/** Generic device information */
	struct rte_device *device;
	/** vdpa device operations */
	struct rte_vdpa_dev_ops *ops;
} __rte_cache_aligned;

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Register a vdpa device
 *
 * @param addr
 *  the vdpa device address
 * @param ops
 *  the vdpa device operations
 * @return
 *  vDPA device pointer on success, NULL on failure
 */
__rte_experimental
struct rte_vdpa_device *
rte_vdpa_register_device(struct rte_device *rte_dev,
		struct rte_vdpa_dev_ops *ops);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Unregister a vdpa device
 *
 * @param did
 *  vDPA device pointer
 * @return
 *  device id on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_unregister_device(struct rte_vdpa_device *);

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
 * Enable/Disable host notifier mapping for a vdpa port.
 *
 * @param vid
 *  vhost device id
 * @param enable
 *  true for host notifier map, false for host notifier unmap
 * @return
 *  0 on success, -1 on failure
 */
__rte_experimental
int
rte_vhost_host_notifier_ctrl(int vid, bool enable);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Synchronize the used ring from mediated ring to guest, log dirty
 * page for each writeable buffer, caller should handle the used
 * ring logging before device stop.
 *
 * @param vid
 *  vhost device id
 * @param qid
 *  vhost queue id
 * @param vring_m
 *  mediated virtio ring pointer
 * @return
 *  number of synced used entries on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_relay_vring_used(int vid, uint16_t qid, void *vring_m);

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
