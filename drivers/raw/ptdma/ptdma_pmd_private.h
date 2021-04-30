/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */

#ifndef _PTDMA_PMD_PRIVATE_H_
#define _PTDMA_PMD_PRIVATE_H_

#include <rte_rawdev.h>
#include "ptdma_rawdev_spec.h"

extern int ptdma_pmd_logtype;

#define PTDMA_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, ptdma_pmd_logtype, "%s(): " fmt "\n", \
			__func__, ##args)

#define PTDMA_PMD_FUNC_TRACE() PTDMA_PMD_LOG(DEBUG, ">>")

#define PTDMA_PMD_ERR(fmt, args...) \
	PTDMA_PMD_LOG(ERR, fmt, ## args)
#define PTDMA_PMD_WARN(fmt, args...) \
	PTDMA_PMD_LOG(WARNING, fmt, ## args)
#define PTDMA_PMD_DEBUG(fmt, args...) \
	PTDMA_PMD_LOG(DEBUG, fmt, ## args)
#define PTDMA_PMD_INFO(fmt, args...) \
	PTDMA_PMD_LOG(INFO, fmt, ## args)

int ptdma_xstats_get(const struct rte_rawdev *dev, const unsigned int ids[],
		uint64_t values[], unsigned int n);
int ptdma_xstats_get_names(const struct rte_rawdev *dev,
		struct rte_rawdev_xstats_name *names,
		unsigned int size);
int ptdma_xstats_reset(struct rte_rawdev *dev, const uint32_t *ids,
		uint32_t nb_ids);
int ptdma_add_queue(struct ptdma_device *dev);

extern int ptdma_rawdev_test(uint16_t dev_id);

#endif /* _PTDMA_PMD_PRIVATE_H_ */


