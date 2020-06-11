/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef _RTE_VDPA_H_DEV_
#define _RTE_VDPA_H_DEV_

#include <stdbool.h>

#include "rte_vhost.h"

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
};

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Register a vdpa device
 *
 * @param rte_dev
 *  the generic device pointer
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
 * @param dev
 *  vDPA device pointer
 * @return
 *  device id on success, -1 on failure
 */
__rte_experimental
int
rte_vdpa_unregister_device(struct rte_vdpa_device *dev);

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

#endif /* _RTE_VDPA_DEV_H_ */
