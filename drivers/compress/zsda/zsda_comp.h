/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_COMP_H_
#define _ZSDA_COMP_H_

#include <rte_compressdev.h>
#include <rte_compressdev_pmd.h>

#include "zsda_common.h"
#include "zsda_device.h"
#include "zsda_qp.h"

struct zsda_comp_xform {
	enum rte_comp_xform_type type;
	enum rte_comp_checksum_type checksum_type;
};

int comp_match(void *op_in);
int build_comp_request(void *op_in, const struct zsda_queue *queue,
		       void **op_cookies, uint16_t new_tail);
int decomp_match(void *op_in);
int build_decomp_request(void *op_in, const struct zsda_queue *queue,
			 void **op_cookies, uint16_t new_tail);
void comp_callbak(void *op, struct zsda_cqe *cqe);

#endif
