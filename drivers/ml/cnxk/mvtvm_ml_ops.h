/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#ifndef _MVTVM_ML_OPS_H_
#define _MVTVM_ML_OPS_H_

#include <tvmdp.h>

#include <rte_mldev.h>

struct cnxk_ml_dev;
struct cnxk_ml_model;

int mvtvm_ml_dev_configure(struct cnxk_ml_dev *cnxk_mldev, const struct rte_ml_dev_config *conf);
int mvtvm_ml_dev_close(struct cnxk_ml_dev *cnxk_mldev);
int mvtvm_ml_model_load(struct cnxk_ml_dev *cnxk_mldev, struct rte_ml_model_params *params,
			struct cnxk_ml_model *model);
int mvtvm_ml_model_unload(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_model *model);
int mvtvm_ml_model_start(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_model *model);
int mvtvm_ml_model_stop(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_model *model);
int mvtvm_ml_io_quantize(void *device, uint16_t model_id, const char *layer_name,
			 const DLTensor **deq_tensor, void *qbuffer);
int mvtvm_ml_io_dequantize(void *device, uint16_t model_id, const char *layer_name, void *qbuffer,
			   const DLTensor **deq_tensor);

#endif /* _MVTVM_ML_OPS_H_ */
