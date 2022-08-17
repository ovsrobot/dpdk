/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_VECTORS_RULES_H__
#define TEST_CRYPTODEV_ASYM_VECTORS_RULES_H__

#include <stdint.h>

#include "test_cryptodev_asym_vectors_def.h"

static struct asym_test_rsa_rule asym_test_rsa_rules[] =
{
	{
		.key_size 	= 1024,
		.key_type	= RTE_RSA_KEY_TYPE_EXP,
		.padding 	= RTE_CRYPTO_RSA_PADDING_NONE,
		.pt_len 	= 128,
		.operation	= (1UL << RTE_CRYPTO_ASYM_OP_ENCRYPT) |
						(1UL << RTE_CRYPTO_ASYM_OP_DECRYPT)
	},
	{
		.key_size	= 2048,
		.key_type	= RTE_RSA_KEY_TYPE_EXP,
		.padding	= RTE_CRYPTO_RSA_PADDING_NONE,
		.pt_len		= 256,
		.operation	= (1UL << RTE_CRYPTO_ASYM_OP_ENCRYPT) |
						(1UL << RTE_CRYPTO_ASYM_OP_DECRYPT)
	},
	{
		.key_size	= 4096,
		.key_type	= RTE_RSA_KEY_TYPE_EXP,
		.padding	= RTE_CRYPTO_RSA_PADDING_NONE,
		.pt_len		= 512,
		.operation	= (1UL << RTE_CRYPTO_ASYM_OP_ENCRYPT) |
						(1UL << RTE_CRYPTO_ASYM_OP_DECRYPT)
	},
};

static int asym_test_rsa_rules_size = (sizeof(asym_test_rsa_rules)
		/ sizeof(*asym_test_rsa_rules));

#endif /* TEST_CRYPTODEV_ASYM_VECTORS_RULES_H__ */
