/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#include <archive.h>
#include <archive_entry.h>

#include <rte_mldev.h>

#include <mldev_utils.h>

#include <roc_api.h>

#include "mvtvm_ml_model.h"

#include "cnxk_ml_dev.h"
#include "cnxk_ml_model.h"
#include "cnxk_ml_utils.h"

/* Objects list */
char mvtvm_object_list[ML_MVTVM_MODEL_OBJECT_MAX][RTE_ML_STR_MAX] = {"mod.so", "mod.json",
								     "mod.params"};

int
mvtvm_ml_model_blob_parse(struct rte_ml_model_params *params, struct mvtvm_ml_model_object *object)
{
	bool object_found[ML_MVTVM_MODEL_OBJECT_MAX] = {false, false, false};
	struct archive_entry *entry;
	struct archive *a;
	uint8_t i;
	int ret;

	/* Open archive */
	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);

	ret = archive_read_open_memory(a, params->addr, params->size);
	if (ret != ARCHIVE_OK)
		return archive_errno(a);

	/* Read archive */
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		for (i = 0; i < ML_MVTVM_MODEL_OBJECT_MAX; i++) {
			if (!object_found[i] &&
			    (strcmp(archive_entry_pathname(entry), mvtvm_object_list[i]) == 0)) {
				memcpy(object[i].name, mvtvm_object_list[i], RTE_ML_STR_MAX);
				object[i].size = archive_entry_size(entry);
				object[i].buffer = rte_malloc(NULL, object[i].size, 0);

				if (archive_read_data(a, object[i].buffer, object[i].size) !=
				    object[i].size) {
					plt_err("Failed to read object from model archive: %s",
						object[i].name);
					goto error;
				}
				object_found[i] = true;
			}
		}
		archive_read_data_skip(a);
	}

	/* Check if all objects are parsed */
	for (i = 0; i < ML_MVTVM_MODEL_OBJECT_MAX; i++) {
		if (!object_found[i]) {
			plt_err("Object %s not found in archive!\n", mvtvm_object_list[i]);
			goto error;
		}
	}
	return 0;

error:
	for (i = 0; i < ML_MVTVM_MODEL_OBJECT_MAX; i++) {
		if (object[i].buffer != NULL)
			rte_free(object[i].buffer);
	}

	return -EINVAL;
}

static enum rte_ml_io_type
mvtvm_ml_io_type_map(uint8_t type)
{
	switch (type) {
	case kDLInt:
		return RTE_ML_IO_TYPE_INT32;
	case kDLUInt:
		return RTE_ML_IO_TYPE_UINT32;
	case kDLFloat:
		return RTE_ML_IO_TYPE_FP32;
	case kDLBfloat:
		return RTE_ML_IO_TYPE_BFLOAT16;
	}

	return RTE_ML_IO_TYPE_UNKNOWN;
}

void
mvtvm_ml_model_io_info_update(struct cnxk_ml_model *model)
{
	struct tvmdp_model_metadata *metadata;
	int32_t i;
	int32_t j;

	if (model->subtype == ML_CNXK_MODEL_SUBTYPE_TVM_MRVL)
		goto tvm_mrvl_model;

	metadata = &model->mvtvm.metadata;

	/* Inputs, set for layer_id = 0 */
	model->mvtvm.info.nb_inputs = metadata->model.num_input;
	model->mvtvm.info.total_input_sz_d = 0;
	model->mvtvm.info.total_input_sz_q = 0;
	for (i = 0; i < metadata->model.num_input; i++) {
		strncpy(model->mvtvm.info.input[i].name, metadata->input[i].name,
			TVMDP_NAME_STRLEN);
		model->mvtvm.info.input[i].dtype =
			mvtvm_ml_io_type_map(metadata->input[i].datatype.code);
		model->mvtvm.info.input[i].qtype =
			mvtvm_ml_io_type_map(metadata->input[i].model_datatype.code);
		model->mvtvm.info.input[i].nb_dims = metadata->input[i].ndim;

		model->mvtvm.info.input[i].nb_elements = 1;
		for (j = 0; j < metadata->input[i].ndim; j++) {
			model->mvtvm.info.input[i].shape[j] = metadata->input[i].shape[j];
			model->mvtvm.info.input[i].nb_elements *= metadata->input[i].shape[j];
		}

		model->mvtvm.info.input[i].sz_d =
			model->mvtvm.info.input[i].nb_elements *
			rte_ml_io_type_size_get(model->mvtvm.info.input[i].dtype);
		model->mvtvm.info.input[i].sz_q =
			model->mvtvm.info.input[i].nb_elements *
			rte_ml_io_type_size_get(model->mvtvm.info.input[i].qtype);

		model->mvtvm.info.total_input_sz_d += model->mvtvm.info.input[i].sz_d;
		model->mvtvm.info.total_input_sz_q += model->mvtvm.info.input[i].sz_q;

		plt_ml_dbg("model_id = %u, input[%u] - sz_d = %u sz_q = %u", model->model_id, i,
			   model->mvtvm.info.input[i].sz_d, model->mvtvm.info.input[i].sz_q);
	}

	/* Outputs, set for nb_layers - 1 */
	model->mvtvm.info.nb_outputs = metadata->model.num_output;
	model->mvtvm.info.total_output_sz_d = 0;
	model->mvtvm.info.total_output_sz_q = 0;
	for (i = 0; i < metadata->model.num_output; i++) {
		strncpy(model->mvtvm.info.output[i].name, metadata->output[i].name,
			TVMDP_NAME_STRLEN);
		model->mvtvm.info.output[i].dtype =
			mvtvm_ml_io_type_map(metadata->output[i].datatype.code);
		model->mvtvm.info.output[i].qtype =
			mvtvm_ml_io_type_map(metadata->output[i].model_datatype.code);
		model->mvtvm.info.output[i].nb_dims = metadata->output[i].ndim;

		model->mvtvm.info.output[i].nb_elements = 1;
		for (j = 0; j < metadata->output[i].ndim; j++) {
			model->mvtvm.info.output[i].shape[j] = metadata->output[i].shape[j];
			model->mvtvm.info.output[i].nb_elements *= metadata->output[i].shape[j];
		}

		model->mvtvm.info.output[i].sz_d =
			model->mvtvm.info.output[i].nb_elements *
			rte_ml_io_type_size_get(model->mvtvm.info.output[i].dtype);
		model->mvtvm.info.output[i].sz_q =
			model->mvtvm.info.output[i].nb_elements *
			rte_ml_io_type_size_get(model->mvtvm.info.output[i].qtype);

		model->mvtvm.info.total_output_sz_d += model->mvtvm.info.output[i].sz_d;
		model->mvtvm.info.total_output_sz_q += model->mvtvm.info.output[i].sz_q;

		plt_ml_dbg("model_id = %u, output[%u] - sz_d = %u sz_q = %u", model->model_id, i,
			   model->mvtvm.info.output[i].sz_d, model->mvtvm.info.output[i].sz_q);
	}

	return;

tvm_mrvl_model:
	cn10k_ml_layer_io_info_update(&model->mvtvm.info, &model->layer[0].glow.metadata);
}

void
mvtvm_ml_model_info_set(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_model *model)
{
	struct tvmdp_model_metadata *metadata;
	struct rte_ml_model_info *info;
	struct rte_ml_io_info *output;
	struct rte_ml_io_info *input;
	uint8_t i;

	info = PLT_PTR_CAST(model->info);
	input = PLT_PTR_ADD(info, sizeof(struct rte_ml_model_info));
	output = PLT_PTR_ADD(input, ML_CNXK_MODEL_MAX_INPUT_OUTPUT * sizeof(struct rte_ml_io_info));

	/* Reset model info */
	memset(info, 0, sizeof(struct rte_ml_model_info));

	if (model->subtype == ML_CNXK_MODEL_SUBTYPE_TVM_MRVL)
		goto tvm_mrvl_model;

	metadata = &model->mvtvm.metadata;
	rte_memcpy(info->name, metadata->model.name, MRVL_ML_MODEL_NAME_LEN);
	snprintf(info->version, RTE_ML_STR_MAX, "%u.%u.%u.%u", metadata->model.version[0],
		 metadata->model.version[1], metadata->model.version[2],
		 metadata->model.version[3]);
	info->model_id = model->model_id;
	info->device_id = cnxk_mldev->mldev->data->dev_id;
	info->io_layout = RTE_ML_IO_LAYOUT_SPLIT;
	info->min_batches = model->batch_size;
	info->max_batches = model->batch_size;
	info->nb_inputs = metadata->model.num_input;
	info->input_info = input;
	info->nb_outputs = metadata->model.num_output;
	info->output_info = output;
	info->wb_size = 0;

	/* Set input info */
	for (i = 0; i < info->nb_inputs; i++) {
		rte_memcpy(input[i].name, metadata->input[i].name, MRVL_ML_INPUT_NAME_LEN);
		input[i].nb_dims = metadata->input[i].ndim;
		input[i].shape = &model->mvtvm.info.input[i].shape[0];
		input[i].type = model->mvtvm.info.input[i].qtype;
		input[i].nb_elements = model->mvtvm.info.input[i].nb_elements;
		input[i].size = model->mvtvm.info.input[i].nb_elements *
				rte_ml_io_type_size_get(model->mvtvm.info.input[i].qtype);
	}

	/* Set output info */
	for (i = 0; i < info->nb_outputs; i++) {
		rte_memcpy(output[i].name, metadata->output[i].name, MRVL_ML_OUTPUT_NAME_LEN);
		output[i].nb_dims = metadata->output[i].ndim;
		output[i].shape = &model->mvtvm.info.output[i].shape[0];
		output[i].type = model->mvtvm.info.output[i].qtype;
		output[i].nb_elements = model->mvtvm.info.output[i].nb_elements;
		output[i].size = model->mvtvm.info.output[i].nb_elements *
				 rte_ml_io_type_size_get(model->mvtvm.info.output[i].qtype);
	}

	return;

tvm_mrvl_model:
	cn10k_ml_model_info_set(cnxk_mldev, model, &model->mvtvm.info,
				&model->layer[0].glow.metadata);
}

void
mvtvm_ml_layer_print(struct cnxk_ml_dev *cnxk_mldev, struct cnxk_ml_layer *layer, FILE *fp)
{
	char str[STR_LEN];
	uint8_t i;

	/* Print debug info */
	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, " Layer Information (Layer ID: %u, Name: %s)\n",
		cnxk_mldev->index_map[layer->index].layer_id, layer->name);
	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, "%*s : %u\n", FIELD_LEN, "layer_id",
		cnxk_mldev->index_map[layer->index].layer_id);
	fprintf(fp, "%*s : %s\n", FIELD_LEN, "name", layer->name);
	fprintf(fp, "%*s : %d\n", FIELD_LEN, "type", layer->type);
	fprintf(fp, "%*s : 0x%016lx\n", FIELD_LEN, "layer", PLT_U64_CAST(layer));
	fprintf(fp, "%*s : %u\n", FIELD_LEN, "batch_size", layer->batch_size);

	/* Print model state */
	if (layer->state == ML_CNXK_LAYER_STATE_LOADED)
		fprintf(fp, "%*s : %s\n", FIELD_LEN, "state", "loaded");
	if (layer->state == ML_CNXK_LAYER_STATE_JOB_ACTIVE)
		fprintf(fp, "%*s : %s\n", FIELD_LEN, "state", "job_active");
	if (layer->state == ML_CNXK_LAYER_STATE_STARTED)
		fprintf(fp, "%*s : %s\n", FIELD_LEN, "state", "started");

	fprintf(fp, "%*s : %u\n", FIELD_LEN, "num_inputs", layer->info.nb_inputs);
	fprintf(fp, "%*s : %u\n", FIELD_LEN, "num_outputs", layer->info.nb_outputs);
	fprintf(fp, "\n");

	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, "%8s  %16s  %12s\n", "input", "input_name", "input_type");
	cnxk_ml_print_line(fp, LINE_LEN);
	for (i = 0; i < layer->info.nb_inputs; i++) {
		fprintf(fp, "%8u  ", i);
		fprintf(fp, "%*s  ", 16, layer->info.input[i].name);
		rte_ml_io_type_to_str(layer->info.input[i].qtype, str, STR_LEN);
		fprintf(fp, "%*s  ", 12, str);
	}
	fprintf(fp, "\n");
	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, "\n");

	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, "%8s  %16s  %12s\n", "output", "output_name", "output_type");
	cnxk_ml_print_line(fp, LINE_LEN);
	for (i = 0; i < layer->info.nb_outputs; i++) {
		fprintf(fp, "%8u  ", i);
		fprintf(fp, "%*s  ", 16, layer->info.output[i].name);
		rte_ml_io_type_to_str(layer->info.output[i].qtype, str, STR_LEN);
		fprintf(fp, "%*s  ", 12, str);
		fprintf(fp, "\n");
	}
	fprintf(fp, "\n");
	cnxk_ml_print_line(fp, LINE_LEN);
	fprintf(fp, "\n");
}
