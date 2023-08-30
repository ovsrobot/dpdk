/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#include <rte_mldev.h>

#include "mvtvm_ml_model.h"

/* Objects list */
char mvtvm_object_list[ML_MVTVM_MODEL_OBJECT_MAX][RTE_ML_STR_MAX] = {"mod.so", "mod.json",
								     "mod.params"};
