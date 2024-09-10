/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMP_H_
#define _ZSDA_COMP_H_

#include <rte_compressdev.h>

#include "zsda_common.h"
#include "zsda_device.h"
#include "zsda_qp.h"

struct zsda_comp_xform {
	enum rte_comp_xform_type type;
	enum rte_comp_checksum_type checksum_type;
};

int zsda_comp_match(const void *op_in);
int zsda_build_comp_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, const uint16_t new_tail);
int zsda_decomp_match(const void *op_in);
int zsda_build_decomp_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, const uint16_t new_tail);
void zsda_comp_callback(void *cookie_in, const struct zsda_cqe *cqe);

#endif
