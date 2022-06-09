/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Intel Corporation
 */

#ifndef __AFU_PMD_CORE_H__
#define __AFU_PMD_CORE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <rte_spinlock.h>
#include <rte_bus_ifpga.h>
#include <rte_rawdev.h>

#include "ifpga_rawdev.h"

#define AFU_RAWDEV_MAX_DRVS  32

struct afu_rawdev;

struct afu_ops {
	int (*init)(struct afu_rawdev *dev);
	int (*config)(struct afu_rawdev *dev, void *config,
		size_t config_size);
	int (*start)(struct afu_rawdev *dev);
	int (*stop)(struct afu_rawdev *dev);
	int (*test)(struct afu_rawdev *dev);
	int (*close)(struct afu_rawdev *dev);
	int (*reset)(struct afu_rawdev *dev);
	int (*dump)(struct afu_rawdev *dev, FILE *f);
};

struct afu_shared_data {
	rte_spinlock_t lock;  /* lock for multi-process access */
};

struct afu_rawdev_drv {
	TAILQ_ENTRY(afu_rawdev_drv) next;
	struct rte_afu_uuid uuid;
	struct afu_ops *ops;
};

struct afu_rawdev {
	struct rte_rawdev *rawdev;  /* point to parent raw device */
	struct afu_shared_data *sd;  /* shared data for multi-process */
	struct afu_ops *ops;  /* device operation functions */
	int port;  /* index of port the AFU attached */
	void *addr;  /* base address of AFU registers */
	void *priv;  /* private driver data */
};

static inline struct afu_rawdev *
afu_rawdev_get_priv(const struct rte_rawdev *rawdev)
{
	return rawdev ? (struct afu_rawdev *)rawdev->dev_private : NULL;
}

void afu_pmd_register(struct afu_rawdev_drv *driver);
void afu_pmd_unregister(struct afu_rawdev_drv *driver);

#define AFU_PMD_REGISTER(drv)\
RTE_INIT(afupmdinitfunc_ ##drv)\
{\
	afu_pmd_register(&drv);\
}

#ifdef __cplusplus
}
#endif

#endif /* __AFU_PMD_CORE_H__ */
