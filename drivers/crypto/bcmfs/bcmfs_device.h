/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Broadcom.
 * All rights reserved.
 */

#ifndef _BCMFS_DEV_H_
#define _BCMFS_DEV_H_

#include <sys/queue.h>

#include <rte_bus_vdev.h>

#include "bcmfs_logs.h"

/* max number of dev nodes */
#define BCMFS_MAX_NODES		4
#define BCMFS_MAX_PATH_LEN	512
#define BCMFS_DEV_NAME_LEN	64

/* Path for BCM-Platform device directory */
#define SYSFS_BCM_PLTFORM_DEVICES    "/sys/bus/platform/devices"

/* Supported devices */
enum bcmfs_device_type {
	BCMFS_SYM_FS4,
	BCMFS_SYM_FS5,
	BCMFS_UNKNOWN
};

struct bcmfs_device {
	TAILQ_ENTRY(bcmfs_device) next;
	/* Directory path for vfio */
	char dirname[BCMFS_MAX_PATH_LEN];
	/* BCMFS device name */
	char name[BCMFS_DEV_NAME_LEN];
	/* Parent vdev */
	struct rte_vdev_device *vdev;
};

#endif /* _BCMFS_DEV_H_ */
