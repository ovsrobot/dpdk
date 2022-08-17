/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_COMMON_H_
#define TEST_CRYPTODEV_ASYM_COMMON_H_

#include <stdlib.h>
#include <stdint.h>

#include <rte_bus_vdev.h>
#include <rte_common.h>
#include <rte_hexdump.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_pause.h>

#include <rte_cryptodev.h>
#include <rte_crypto.h>

#include "test_cryptodev_asym_types.h"

int ats_common_setup(struct crypto_testsuite_params_asym *ts);

void ats_common_teardown(struct crypto_testsuite_params_asym *ts);

void ats_err_msg_cap(void);

void ats_err_msg_op(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_mod_len(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_inv_alg(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_sess_create(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_sess_init(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_enque(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_burst(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_deq(char *msg, uint32_t len, uint32_t line);

void ats_err_msg_ver(char *msg, uint32_t len, uint32_t line);


#endif /* TEST_CRYPTODEV_ASYM_COMMON_H_ */
