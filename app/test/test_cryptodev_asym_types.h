/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRPTODEV_ASYM_TYPES_H_
#define TEST_CRPTODEV_ASYM_TYPES_H_

#include <rte_cryptodev.h>
#include <rte_crypto.h>

struct crypto_testsuite_params_asym {
	struct rte_mempool *op_mpool;
	struct rte_mempool *session_mpool;
	struct rte_cryptodev_config conf;
	struct rte_cryptodev_qp_conf qp_conf;
	uint8_t valid_devs[RTE_CRYPTO_MAX_DEVS];
	uint8_t valid_dev_count;
};

#endif /* TEST_CRPTODEV_ASYM_TYPES_H_ */
