/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#ifndef _ML_TEST_MODEL_COMMON_
#define _ML_TEST_MODEL_COMMON_

#include <rte_mldev.h>

#include "test_common.h"

enum model_state {
	MODEL_INITIAL,
	MODEL_LOADED,
	MODEL_STARTED,
	MODEL_ERROR,
};

struct ml_model {
	uint16_t id;
	struct rte_ml_model_info info;
	enum model_state state;

	uint32_t inp_dsize;
	uint32_t inp_qsize;
	uint32_t out_dsize;
	uint32_t out_qsize;

	uint8_t *input;
	uint8_t *output;

	struct rte_mempool *io_pool;
	uint32_t nb_batches;
};

int ml_model_load(struct ml_test *test, struct ml_options *opt, struct ml_model *model,
		  uint16_t fid);
int ml_model_unload(struct ml_test *test, struct ml_options *opt, struct ml_model *model,
		    uint16_t fid);
int ml_model_start(struct ml_test *test, struct ml_options *opt, struct ml_model *model,
		   uint16_t fid);
int ml_model_stop(struct ml_test *test, struct ml_options *opt, struct ml_model *model,
		  uint16_t fid);

#endif /* _ML_TEST_MODEL_COMMON_ */
