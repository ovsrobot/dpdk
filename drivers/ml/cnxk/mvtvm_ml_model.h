/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#ifndef _MVTVM_ML_MODEL_H_
#define _MVTVM_ML_MODEL_H_

#include <dlpack/dlpack.h>

#include <tvmdp.h>

#include <rte_mldev.h>

#include "cnxk_ml_io.h"

struct cnxk_ml_dev;
struct cnxk_ml_model;
struct cnxk_ml_layer;

/* Maximum number of objects per model */
#define ML_MVTVM_MODEL_OBJECT_MAX 3

/* Objects list */
extern char mvtvm_object_list[ML_MVTVM_MODEL_OBJECT_MAX][RTE_ML_STR_MAX];

/* Model object structure */
struct mvtvm_ml_model_object {
	/* Name */
	char name[RTE_ML_STR_MAX];

	/* Temporary buffer */
	uint8_t *buffer;

	/* Buffer size */
	int64_t size;
};

/* Model fast-path stats */
struct mvtvm_ml_model_xstats {
	/* Total TVM runtime latency, sum of all inferences */
	uint64_t tvm_rt_latency_tot;

	/* TVM runtime latency */
	uint64_t tvm_rt_latency;

	/* Minimum TVM runtime latency */
	uint64_t tvm_rt_latency_min;

	/* Maximum TVM runtime latency */
	uint64_t tvm_rt_latency_max;

	/* Total jobs dequeued */
	uint64_t dequeued_count;

	/* Hardware stats reset index */
	uint64_t tvm_rt_reset_count;
};

struct mvtvm_ml_model_data {
	/* Model metadata */
	struct tvmdp_model_metadata metadata;

	/* Model objects */
	struct tvmdp_model_object object;

	/* TVM runtime callbacks */
	struct tvmrt_glow_callback cb;

	/* Model I/O info */
	struct cnxk_ml_io_info info;

	/* Stats for burst ops */
	struct mvtvm_ml_model_xstats *burst_xstats;
};

int mvtvm_ml_model_blob_parse(struct rte_ml_model_params *params,
			      struct mvtvm_ml_model_object *object);
void mvtvm_ml_model_io_info_update(struct cnxk_ml_model *model);
void mvtvm_ml_model_info_set(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_model *model);
void mvtvm_ml_layer_print(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_layer *layer, FILE *fp);

#endif /* _MVTVM_ML_MODEL_H_ */
