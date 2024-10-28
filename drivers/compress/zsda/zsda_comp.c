/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "zsda_comp.h"

int
zsda_comp_match(const void *op_in)
{
	const struct rte_comp_op *op = op_in;
	const struct zsda_comp_xform *xform = op->private_xform;

	if (op->op_type != RTE_COMP_OP_STATELESS)
		return 0;

	if (xform->type != RTE_COMP_COMPRESS)
		return 0;

	return 1;
}

int
zsda_decomp_match(const void *op_in)
{
	const struct rte_comp_op *op = op_in;
	const struct zsda_comp_xform *xform = op->private_xform;

	if (op->op_type != RTE_COMP_OP_STATELESS)
		return 0;

	if (xform->type != RTE_COMP_DECOMPRESS)
		return 0;
	return 1;
}
