/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2015-2018 Atomic Rules LLC
 */

#ifndef _ARK_ETHDEV_LOG_H_
#define _ARK_ETHDEV_LOG_H_

#include <inttypes.h>
#include <rte_log.h>
#include "ark_common.h"

extern int ark_ethdev_logtype;

#define ARK_ETHDEV_LOG(level, fmt, args...)	\
	rte_log(RTE_LOG_ ##level, ark_ethdev_logtype, "ARK: " fmt, ## args)


/* Debug macro to enable core debug code */
#ifdef RTE_LIBRTE_ETHDEV_DEBUG
#define ARK_DEBUG_CORE 1
#else
#define ARK_DEBUG_CORE 0
#endif

#endif
