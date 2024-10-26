/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_H_
#define _ZSDA_SYM_H_

#include "zsda_common.h"
#include "zsda_qp.h"

#include "zsda_sym_session.h"

int zsda_encry_match(const void *op_in);
int zsda_decry_match(const void *op_in);
int zsda_hash_match(const void *op_in);

#endif /* _ZSDA_SYM_H_ */
