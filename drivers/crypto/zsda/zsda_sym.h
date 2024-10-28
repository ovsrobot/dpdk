/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#ifndef _ZSDA_SYM_H_
#define _ZSDA_SYM_H_

#include "zsda_sym_pmd.h"

__rte_unused int
zsda_encry_match(const void *op_in);

__rte_unused int
zsda_decry_match(const void *op_in);

__rte_unused int
zsda_hash_match(const void *op_in);


#endif /* _ZSDA_SYM_H_ */
