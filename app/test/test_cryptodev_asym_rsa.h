/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_RSA_H_
#define TEST_CRYPTODEV_ASYM_RSA_H_

#include <stdlib.h>
#include <stdint.h>

int ats_rsa_setup(void);

void ats_rsa_teardown(void);

int ats_rsa_run(void);

#endif /* TEST_CRYPTODEV_ASYM_RSA_H_ */
