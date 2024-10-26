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

int zsda_decomp_match(const void *op_in);

#endif /* _ZSDA_COMP_H_ */
