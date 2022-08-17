/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_RSA_CREATOR_H_
#define TEST_CRYPTODEV_ASYM_RSA_CREATOR_H_

#include <stdlib.h>
#include <stdint.h>

#include "test_cryptodev_asym_vectors_def.h"

int atv_rsa_creator(struct asym_test_rsa_vct* vct, struct asym_test_rsa_rule* rule);

#endif /* TEST_CRYPTODEV_ASYM_RSA_CREATOR_H_ */
