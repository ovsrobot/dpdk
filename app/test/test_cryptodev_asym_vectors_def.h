/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Intel Corporation
 */

#ifndef TEST_CRYPTODEV_ASYM_VECTORS_DEF_H__
#define TEST_CRYPTODEV_ASYM_VECTORS_DEF_H__

#include <stdint.h>

#include "rte_crypto_asym.h"

#define ASYM_DATA_SIZE 4096

struct asym_test_rsa_vct {
	enum rte_crypto_asym_xform_type xform_type;
	char description[2048];
	uint64_t op_type_flags;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} pt;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} ct;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} sign;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} digest;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} e;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} d;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} n;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} p;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} q;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} dP;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} dQ;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} qInv;

	uint16_t result_len;
	enum rte_crypto_rsa_padding_type padding;
	int key_exp;
	int key_qt;
};

struct asym_test_rsa_rule
{
	int key_size;
	enum rte_crypto_rsa_priv_key_type key_type;
	enum rte_crypto_rsa_padding_type padding;
	int pt_len;
	uint64_t operation;
};

struct asym_test_modex_vct {
	enum rte_crypto_asym_xform_type xform_type;
	char description[ASYM_DATA_SIZE];
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} base;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} exponent;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} modulus;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} reminder;
	uint16_t result_len;
};

struct asym_test_modinv_vct {
	enum rte_crypto_asym_xform_type xform_type;
	char description[ASYM_DATA_SIZE];
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} base;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} modulus;
	struct {
		uint8_t data[ASYM_DATA_SIZE];
		uint16_t len;
	} inverse;
	uint16_t result_len;
};

struct asym_test_modexp_rule
{
	int base_len;
	int modulus_len;
	int exponent_len;
};

struct asym_test_modinv_rule
{
	int base_len;
	int modulus_len;
};

#endif /* TEST_CRYPTODEV_ASYM_VECTORS_DEF_H__ */
