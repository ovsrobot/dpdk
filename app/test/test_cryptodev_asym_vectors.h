/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_VECTORS_H_
#define TEST_CRYPTODEV_ASYM_VECTORS_H_

#include <stdint.h>
#include "rte_crypto_asym.h"
#include "test_cryptodev_asym_vectors_def.h"

void atv_free(void *vct);

struct asym_test_modex_vct *atv_modex(int *vct_nb);

struct asym_test_rsa_vct *atv_rsa(int *vct_nb);

#endif /* TEST_CRYPTODEV_ASYM_VECTORS_H_ */
