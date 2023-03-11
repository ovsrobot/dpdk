/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_TEST_DEVICE_OPS_
#define _ML_TEST_DEVICE_OPS_

#include <rte_common.h>

#include "test_common.h"

struct test_device {
	/* common data */
	struct test_common cmn;
} __rte_cache_aligned;

#endif /* _ML_TEST_DEVICE_OPS_ */
