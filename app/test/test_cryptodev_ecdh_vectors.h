/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2022 Intel Corporation
 */

#ifndef __TEST_CRYPTODEV_ECDH_VECTORS_H__
#define __TEST_CRYPTODEV_ECDH_VECTORS_H__

#include "rte_crypto_asym.h"

/*
 * Elliptic Curve Diffie-Hellman test vector struct
 * Peers are named Alice and Bob
 * q - is a public key
 * d - is a private key
 * Z - is a shared secret
 */

struct ECDH_test_vector {
	enum rte_crypto_curve_id curve_id;
	int curve_bytesize;
	rte_crypto_uint alice_d;
	rte_crypto_uint bob_d;
	struct rte_crypto_ec_point alice_q;
	struct rte_crypto_ec_point bob_q;
	struct rte_crypto_ec_point Z;
};

/*
 * Elliptic Curve Diffie-Hellman test
 * It consist of three phases:
 * - Generation of public key based on private key
 * - Verification of peer's public key
 * - Generation of shared secret
 * Peers in tests are named Alice and Bob
 */

/* RFC 5114 256-bit Random ECP Group Data */

/*
 * Alice's parameters
 */
static uint8_t rfc5114_256b_dA[] = {
	0x81, 0x42, 0x64, 0x14, 0x5F, 0x2F, 0x56, 0xF2,
	0xE9, 0x6A, 0x8E, 0x33, 0x7A, 0x12, 0x84, 0x99,
	0x3F, 0xAF, 0x43, 0x2A, 0x5A, 0xBC, 0xE5, 0x9E,
	0x86, 0x7B, 0x72, 0x91, 0xD5, 0x07, 0xA3, 0xAF,
};

static uint8_t rfc5114_256b_x_qA[] = {
	0x2A, 0xF5, 0x02, 0xF3, 0xBE, 0x89, 0x52, 0xF2,
	0xC9, 0xB5, 0xA8, 0xD4, 0x16, 0x0D, 0x09, 0xE9,
	0x71, 0x65, 0xBE, 0x50, 0xBC, 0x42, 0xAE, 0x4A,
	0x5E, 0x8D, 0x3B, 0x4B, 0xA8, 0x3A, 0xEB, 0x15,
};

static uint8_t rfc5114_256b_y_qA[] = {
	0xEB, 0x0F, 0xAF, 0x4C, 0xA9, 0x86, 0xC4, 0xD3,
	0x86, 0x81, 0xA0, 0xF9, 0x87, 0x2D, 0x79, 0xD5,
	0x67, 0x95, 0xBD, 0x4B, 0xFF, 0x6E, 0x6D, 0xE3,
	0xC0, 0xF5, 0x01, 0x5E, 0xCE, 0x5E, 0xFD, 0x85,
};

/*
 * Bob's parameters
 */
static uint8_t rfc5114_256b_dB[] = {
	0x2C, 0xE1, 0x78, 0x8E, 0xC1, 0x97, 0xE0, 0x96,
	0xDB, 0x95, 0xA2, 0x00, 0xCC, 0x0A, 0xB2, 0x6A,
	0x19, 0xCE, 0x6B, 0xCC, 0xAD, 0x56, 0x2B, 0x8E,
	0xEE, 0x1B, 0x59, 0x37, 0x61, 0xCF, 0x7F, 0x41,
};

static uint8_t rfc5114_256b_x_qB[] = {
	0xB1, 0x20, 0xDE, 0x4A, 0xA3, 0x64, 0x92, 0x79,
	0x53, 0x46, 0xE8, 0xDE, 0x6C, 0x2C, 0x86, 0x46,
	0xAE, 0x06, 0xAA, 0xEA, 0x27, 0x9F, 0xA7, 0x75,
	0xB3, 0xAB, 0x07, 0x15, 0xF6, 0xCE, 0x51, 0xB0,
};

static uint8_t rfc5114_256b_y_qB[] = {
	0x9F, 0x1B, 0x7E, 0xEC, 0xE2, 0x0D, 0x7B, 0x5E,
	0xD8, 0xEC, 0x68, 0x5F, 0xA3, 0xF0, 0x71, 0xD8,
	0x37, 0x27, 0x02, 0x70, 0x92, 0xA8, 0x41, 0x13,
	0x85, 0xC3, 0x4D, 0xDE, 0x57, 0x08, 0xB2, 0xB6,
};

static uint8_t rfc5114_256b_x_Z[] = {
	0xDD, 0x0F, 0x53, 0x96, 0x21, 0x9D, 0x1E, 0xA3,
	0x93, 0x31, 0x04, 0x12, 0xD1, 0x9A, 0x08, 0xF1,
	0xF5, 0x81, 0x1E, 0x9D, 0xC8, 0xEC, 0x8E, 0xEA,
	0x7F, 0x80, 0xD2, 0x1C, 0x82, 0x0C, 0x27, 0x88,
};

static uint8_t rfc5114_256b_y_Z[] = {
	0x03, 0x57, 0xDC, 0xCD, 0x4C, 0x80, 0x4D, 0x0D,
	0x8D, 0x33, 0xAA, 0x42, 0xB8, 0x48, 0x83, 0x4A,
	0xA5, 0x60, 0x5F, 0x9A, 0xB0, 0xD3, 0x72, 0x39,
	0xA1, 0x15, 0xBB, 0xB6, 0x47, 0x93, 0x6F, 0x50,
};

static struct ECDH_test_vector rfc5114_secp256r1 = {
	.curve_id = RTE_CRYPTO_EC_GROUP_SECP256R1,
	.curve_bytesize = 32,
	.alice_d = {
		.data = rfc5114_256b_dA,
		.length = sizeof(rfc5114_256b_dA),
	},
	.alice_q = {
		.x = {
			.data = rfc5114_256b_x_qA,
			.length = sizeof(rfc5114_256b_x_qA),
		},
		.y = {
			.data = rfc5114_256b_y_qA,
			.length = sizeof(rfc5114_256b_y_qA),
		},
	},
	.bob_d = {
		.data = rfc5114_256b_dB,
		.length = sizeof(rfc5114_256b_dB)
	},
	.bob_q = {
		.x = {
			.data = rfc5114_256b_x_qB,
			.length = sizeof(rfc5114_256b_x_qB),
		},
		.y = {
			.data = rfc5114_256b_y_qB,
			.length = sizeof(rfc5114_256b_y_qB),
		},
	},
	.Z = {
		.x = {
			.data = rfc5114_256b_x_Z,
			.length = sizeof(rfc5114_256b_x_Z),
		},
		.y = {
			.data = rfc5114_256b_y_Z,
			.length = sizeof(rfc5114_256b_y_Z),
		}
	}
};

#endif