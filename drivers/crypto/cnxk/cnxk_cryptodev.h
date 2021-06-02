/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#ifndef _CNXK_CRYPTODEV_H_
#define _CNXK_CRYPTODEV_H_

#include <rte_cryptodev.h>

#include "roc_cpt.h"

/*
 * DP logs, toggled out at compile time if level lower than current level.
 * DP logs would be logged under 'PMD' type. So for dynamic logging, the
 * level of 'pmd' has to be used.
 */
#define CPT_LOG_DP(level, fmt, args...) RTE_LOG_DP(level, PMD, fmt "\n", ##args)

#define CPT_LOG_DP_DEBUG(fmt, args...) CPT_LOG_DP(DEBUG, fmt, ##args)
#define CPT_LOG_DP_INFO(fmt, args...)  CPT_LOG_DP(INFO, fmt, ##args)
#define CPT_LOG_DP_WARN(fmt, args...)  CPT_LOG_DP(WARNING, fmt, ##args)
#define CPT_LOG_DP_ERR(fmt, args...)   CPT_LOG_DP(ERR, fmt, ##args)

/**
 * Device private data
 */
struct cnxk_cpt_vf {
	struct roc_cpt cpt;
};

int cnxk_cpt_eng_grp_add(struct roc_cpt *roc_cpt);

#endif /* _CNXK_CRYPTODEV_H_ */
