/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2023 Marvell.
 */

#include <archive.h>
#include <archive_entry.h>

#include <rte_mldev.h>

#include <roc_api.h>

#include "mvtvm_ml_model.h"

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
