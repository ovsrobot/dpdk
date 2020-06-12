/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#ifndef _MP_CRYPTO_SAMPLE_APP_VECTORS_
#define _MP_CRYPTO_SAMPLE_APP_VECTORS_

#include <rte_cryptodev.h>

struct mp_crypto_session_vector {
	union {
		enum rte_crypto_aead_algorithm aead_algo;
		enum rte_crypto_auth_algorithm auth_algo;
		enum rte_crypto_cipher_algorithm cipher_algo;
	};
	enum rte_crypto_sym_xform_type x_type;
	union {
		enum rte_crypto_aead_operation aead_op;
		enum rte_crypto_cipher_operation cipher_op;
		enum rte_crypto_auth_operation auth_op;
	};
	struct {
		uint8_t data[64];
		uint16_t len;
	} crypto_key;
	struct {
		uint8_t data[64];
		uint16_t len;
	} auth_key;
	uint16_t aad_len;
	uint16_t iv_len;
	uint16_t digest_len;
	int chained;
};

struct mp_crypto_vector {
	int session;
	struct {
		uint8_t data[2048];
		int len;
	} ciphertext;
	struct {
		uint8_t data[2048];
		int len;
	} plaintext;
	struct {
		uint8_t data[2048];
		int len;
	} digest;
	struct {
		uint8_t data[64];
	} aad;
	uint8_t iv[16];
};

/* Predefinced vectors */
extern const struct mp_crypto_session_vector session_vectors[];
/* Sessions vectors for this device */
extern const uint64_t mp_app_numof_sessions;
/* Number of all sessions in array */

extern const struct mp_crypto_vector vectors[];
/* Operation vectors for this device */
const uint64_t mp_app_numof_ops;
/* Total number of operation types */

#endif