/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Intel Corporation
 */

#ifndef __AFU_MF_RAWDEV_H__
#define __AFU_MF_RAWDEV_H__

#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <rte_cycles.h>
#include <rte_bus_ifpga.h>
#include <rte_rawdev.h>

extern int afu_mf_pmd_logtype;

#define AFU_MF_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, afu_mf_pmd_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

#define AFU_MF_PMD_FUNC_TRACE() AFU_MF_PMD_LOG(DEBUG, ">>")

#define AFU_MF_PMD_DEBUG(fmt, args...) \
	AFU_MF_PMD_LOG(DEBUG, fmt, ## args)
#define AFU_MF_PMD_INFO(fmt, args...) \
	AFU_MF_PMD_LOG(INFO, fmt, ## args)
#define AFU_MF_PMD_ERR(fmt, args...) \
	AFU_MF_PMD_LOG(ERR, fmt, ## args)
#define AFU_MF_PMD_WARN(fmt, args...) \
	AFU_MF_PMD_LOG(WARNING, fmt, ## args)

#define CACHE_LINE_SIZE(n)  ((n) << 6)
#define CACHE_LINE_ALIGNED(n)  ((n) >> 6)
#define MHZ(f)  ((f) * 1000000)

#define dsm_poll_timeout(addr, val, cond, invl, timeout) \
({                                                       \
	uint64_t __wait = 0;                                 \
	uint64_t __invl = (invl);                            \
	uint64_t __timeout = (timeout);                      \
	for (; __wait <= __timeout; __wait += __invl) {      \
		(val) = *(addr);                                 \
		if (cond)                                        \
			break;                                       \
		rte_delay_ms(__invl);                            \
	}                                                    \
	(cond) ? 0 : 1;                                      \
})

struct afu_mf_rawdev;

struct afu_mf_ops {
	int (*init)(struct afu_mf_rawdev *dev);
	int (*config)(struct afu_mf_rawdev *dev, void *config,
		size_t config_size);
	int (*start)(struct afu_mf_rawdev *dev);
	int (*stop)(struct afu_mf_rawdev *dev);
	int (*test)(struct afu_mf_rawdev *dev);
	int (*close)(struct afu_mf_rawdev *dev);
	int (*reset)(struct afu_mf_rawdev *dev);
	int (*dump)(struct afu_mf_rawdev *dev, FILE *f);
};

struct afu_mf_drv {
	struct rte_afu_uuid uuid;
	struct afu_mf_ops *ops;
};

struct afu_mf_shared {
	int32_t lock;
};

struct afu_mf_rawdev {
	struct rte_rawdev *rawdev;  /* point to parent raw device */
	struct afu_mf_shared *shared;  /* shared data for multi-process */
	struct afu_mf_ops *ops;  /* device operation functions */
	int port;  /* index of port the AFU attached */
	void *addr;  /* base address of AFU registers */
	void *priv;  /* private driver data */
};

static inline struct afu_mf_rawdev *
afu_mf_rawdev_get_priv(const struct rte_rawdev *rawdev)
{
	return rawdev ? (struct afu_mf_rawdev *)rawdev->dev_private : NULL;
}

#endif /* __AFU_MF_RAWDEV_H__ */
