/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_TEST_MODEL_OPS_
#define _ML_TEST_MODEL_OPS_

#include <rte_common.h>

#include "test_model_common.h"

struct test_model_ops {
	/* common data */
	struct test_common cmn;

	/* test specific data */
	struct ml_model model[ML_TEST_MAX_MODELS];
} __rte_cache_aligned;

#endif /* _ML_TEST_MODEL_OPS_ */
