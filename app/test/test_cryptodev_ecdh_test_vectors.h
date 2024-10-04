/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2023 Marvell International Ltd.
 */

#ifndef __TEST_CRYPTODEV_ECDH_TEST_VECTORS_H__
#define __TEST_CRYPTODEV_ECDH_TEST_VECTORS_H__

#include "rte_crypto_asym.h"

struct crypto_testsuite_ecdh_params {
	rte_crypto_param pubkey_qA_x;
	rte_crypto_param pubkey_qA_y;
	rte_crypto_param pkey_A;
	rte_crypto_param pubkey_qB_x;
	rte_crypto_param pubkey_qB_y;
	rte_crypto_param pkey_B;
	rte_crypto_param secret_x;
	rte_crypto_param secret_y;
	int curve;
};

/*
 * Test vector reference:
 * https://datatracker.ietf.org/doc/html/rfc5114.html
 * Appendix A.
 */

/** SECP192R1 (P-192 NIST) test vector */

static uint8_t dA_secp192r1[] = {
	0x32, 0x3F, 0xA3, 0x16, 0x9D, 0x8E, 0x9C, 0x65,
	0x93, 0xF5, 0x94, 0x76, 0xBC, 0x14, 0x20, 0x00,
	0xAB, 0x5B, 0xE0, 0xE2, 0x49, 0xC4, 0x34, 0x26
};

static uint8_t x_qA_secp192r1[] = {
	0xCD, 0x46, 0x48, 0x9E, 0xCF, 0xD6, 0xC1, 0x05,
	0xE7, 0xB3, 0xD3, 0x25, 0x66, 0xE2, 0xB1, 0x22,
	0xE2, 0x49, 0xAB, 0xAA, 0xDD, 0x87, 0x06, 0x12
};

static uint8_t y_qA_secp192r1[] = {
	0x68, 0x88, 0x7B, 0x48, 0x77, 0xDF, 0x51, 0xDD,
	0x4D, 0xC3, 0xD6, 0xFD, 0x11, 0xF0, 0xA2, 0x6F,
	0x8F, 0xD3, 0x84, 0x43, 0x17, 0x91, 0x6E, 0x9A
};

static uint8_t dB_secp192r1[] = {
	0x63, 0x1F, 0x95, 0xBB, 0x4A, 0x67, 0x63, 0x2C,
	0x9C, 0x47, 0x6E, 0xEE, 0x9A, 0xB6, 0x95, 0xAB,
	0x24, 0x0A, 0x04, 0x99, 0x30, 0x7F, 0xCF, 0x62
};

static uint8_t x_qB_secp192r1[] = {
	0x51, 0x9A, 0x12, 0x16, 0x80, 0xE0, 0x04, 0x54,
	0x66, 0xBA, 0x21, 0xDF, 0x2E, 0xEE, 0x47, 0xF5,
	0x97, 0x3B, 0x50, 0x05, 0x77, 0xEF, 0x13, 0xD5
};

static uint8_t y_qB_secp192r1[] = {
	0xFF, 0x61, 0x3A, 0xB4, 0xD6, 0x4C, 0xEE, 0x3A,
	0x20, 0x87, 0x5B, 0xDB, 0x10, 0xF9, 0x53, 0xF6,
	0xB3, 0x0C, 0xA0, 0x72, 0xC6, 0x0A, 0xA5, 0x7F
};

static uint8_t x_Z_secp192r1[] = {
	0xAD, 0x42, 0x01, 0x82, 0x63, 0x3F, 0x85, 0x26,
	0xBF, 0xE9, 0x54, 0xAC, 0xDA, 0x37, 0x6F, 0x05,
	0xE5, 0xFF, 0x4F, 0x83, 0x7F, 0x54, 0xFE, 0xBE
};

static uint8_t y_Z_secp192r1[] = {
	0x43, 0x71, 0x54, 0x5E, 0xD7, 0x72, 0xA5, 0x97,
	0x41, 0xD0, 0xED, 0xA3, 0x2C, 0x67, 0x11, 0x12,
	0xB7, 0xFD, 0xDD, 0x51, 0x46, 0x1F, 0xCF, 0x32
};

/** ECDH SECP192R1 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_secp192r1 = {
	.pubkey_qA_x = {
		.data = x_qA_secp192r1,
		.length = sizeof(x_qA_secp192r1),
	},
	.pubkey_qA_y = {
		.data = y_qA_secp192r1,
		.length = sizeof(y_qA_secp192r1),
	},
	.pubkey_qB_x = {
		.data = x_qB_secp192r1,
		.length = sizeof(x_qB_secp192r1),
	},
	.pubkey_qB_y = {
		.data = y_qB_secp192r1,
		.length = sizeof(y_qB_secp192r1),
	},
	.pkey_A = {
		.data = dA_secp192r1,
		.length = sizeof(dA_secp192r1),
	},
	.pkey_B = {
		.data = dB_secp192r1,
		.length = sizeof(dB_secp192r1),
	},
	.secret_x = {
		.data = x_Z_secp192r1,
		.length = sizeof(x_Z_secp192r1),
	},
	.secret_y = {
		.data = y_Z_secp192r1,
		.length = sizeof(y_Z_secp192r1),
	},
	.curve = RTE_CRYPTO_EC_GROUP_SECP192R1
};

/** SECP224R1 (P-224 NIST) test vector */

static uint8_t dA_secp224r1[] = {
	0xB5, 0x58, 0xEB, 0x6C, 0x28, 0x8D, 0xA7, 0x07,
	0xBB, 0xB4, 0xF8, 0xFB, 0xAE, 0x2A, 0xB9, 0xE9,
	0xCB, 0x62, 0xE3, 0xBC, 0x5C, 0x75, 0x73, 0xE2,
	0x2E, 0x26, 0xD3, 0x7F
};

static uint8_t x_qA_secp224r1[] = {
	0x49, 0xDF, 0xEF, 0x30, 0x9F, 0x81, 0x48, 0x8C,
	0x30, 0x4C, 0xFF, 0x5A, 0xB3, 0xEE, 0x5A, 0x21,
	0x54, 0x36, 0x7D, 0xC7, 0x83, 0x31, 0x50, 0xE0,
	0xA5, 0x1F, 0x3E, 0xEB
};

static uint8_t y_qA_secp224r1[] = {
	0x4F, 0x2B, 0x5E, 0xE4, 0x57, 0x62, 0xC4, 0xF6,
	0x54, 0xC1, 0xA0, 0xC6, 0x7F, 0x54, 0xCF, 0x88,
	0xB0, 0x16, 0xB5, 0x1B, 0xCE, 0x3D, 0x7C, 0x22,
	0x8D, 0x57, 0xAD, 0xB4,
};

static uint8_t dB_secp224r1[] = {
	0xAC, 0x3B, 0x1A, 0xDD, 0x3D, 0x97, 0x70, 0xE6,
	0xF6, 0xA7, 0x08, 0xEE, 0x9F, 0x3B, 0x8E, 0x0A,
	0xB3, 0xB4, 0x80, 0xE9, 0xF2, 0x7F, 0x85, 0xC8,
	0x8B, 0x5E, 0x6D, 0x18,
};

static uint8_t x_qB_secp224r1[] = {
	0x6B, 0x3A, 0xC9, 0x6A, 0x8D, 0x0C, 0xDE, 0x6A,
	0x55, 0x99, 0xBE, 0x80, 0x32, 0xED, 0xF1, 0x0C,
	0x16, 0x2D, 0x0A, 0x8A, 0xD2, 0x19, 0x50, 0x6D,
	0xCD, 0x42, 0xA2, 0x07,
};

static uint8_t y_qB_secp224r1[] = {
	0xD4, 0x91, 0xBE, 0x99, 0xC2, 0x13, 0xA7, 0xD1,
	0xCA, 0x37, 0x06, 0xDE, 0xBF, 0xE3, 0x05, 0xF3,
	0x61, 0xAF, 0xCB, 0xB3, 0x3E, 0x26, 0x09, 0xC8,
	0xB1, 0x61, 0x8A, 0xD5
};

static uint8_t x_Z_secp224r1[] = {
	0x52, 0x27, 0x2F, 0x50, 0xF4, 0x6F, 0x4E, 0xDC,
	0x91, 0x51, 0x56, 0x90, 0x92, 0xF4, 0x6D, 0xF2,
	0xD9, 0x6E, 0xCC, 0x3B, 0x6D, 0xC1, 0x71, 0x4A,
	0x4E, 0xA9, 0x49, 0xFA
};

static uint8_t y_Z_secp224r1[] = {
	0x5F, 0x30, 0xC6, 0xAA, 0x36, 0xDD, 0xC4, 0x03,
	0xC0, 0xAC, 0xB7, 0x12, 0xBB, 0x88, 0xF1, 0x76,
	0x3C, 0x30, 0x46, 0xF6, 0xD9, 0x19, 0xBD, 0x9C,
	0x52, 0x43, 0x22, 0xBF
};

/** ECDH SECP224R1 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_secp224r1 = {
	.pubkey_qA_x = {
		.data = x_qA_secp224r1,
		.length = sizeof(x_qA_secp224r1),
	},
	.pubkey_qA_y = {
		.data = y_qA_secp224r1,
		.length = sizeof(y_qA_secp224r1),
	},
	.pubkey_qB_x = {
		.data = x_qB_secp224r1,
		.length = sizeof(x_qB_secp224r1),
	},
	.pubkey_qB_y = {
		.data = y_qB_secp224r1,
		.length = sizeof(y_qB_secp224r1),
	},
	.pkey_A = {
		.data = dA_secp224r1,
		.length = sizeof(dA_secp224r1),
	},
	.pkey_B = {
		.data = dB_secp224r1,
		.length = sizeof(dB_secp224r1),
	},
	.secret_x = {
		.data = x_Z_secp224r1,
		.length = sizeof(x_Z_secp224r1),
	},
	.secret_y = {
		.data = y_Z_secp224r1,
		.length = sizeof(y_Z_secp224r1),
	},
	.curve = RTE_CRYPTO_EC_GROUP_SECP224R1
};

/** SECP256R1 (P-256 NIST) test vector */

static uint8_t dA_secp256r1[] = {
	0x81, 0x42, 0x64, 0x14, 0x5F, 0x2F, 0x56, 0xF2,
	0xE9, 0x6A, 0x8E, 0x33, 0x7A, 0x12, 0x84, 0x99,
	0x3F, 0xAF, 0x43, 0x2A, 0x5A, 0xBC, 0xE5, 0x9E,
	0x86, 0x7B, 0x72, 0x91, 0xD5, 0x07, 0xA3, 0xAF
};

static uint8_t x_qA_secp256r1[] = {
	0x2A, 0xF5, 0x02, 0xF3, 0xBE, 0x89, 0x52, 0xF2,
	0xC9, 0xB5, 0xA8, 0xD4, 0x16, 0x0D, 0x09, 0xE9,
	0x71, 0x65, 0xBE, 0x50, 0xBC, 0x42, 0xAE, 0x4A,
	0x5E, 0x8D, 0x3B, 0x4B, 0xA8, 0x3A, 0xEB, 0x15
};

static uint8_t y_qA_secp256r1[] = {
	0xEB, 0x0F, 0xAF, 0x4C, 0xA9, 0x86, 0xC4, 0xD3,
	0x86, 0x81, 0xA0, 0xF9, 0x87, 0x2D, 0x79, 0xD5,
	0x67, 0x95, 0xBD, 0x4B, 0xFF, 0x6E, 0x6D, 0xE3,
	0xC0, 0xF5, 0x01, 0x5E, 0xCE, 0x5E, 0xFD, 0x85
};

static uint8_t dB_secp256r1[] = {
	0x2C, 0xE1, 0x78, 0x8E, 0xC1, 0x97, 0xE0, 0x96,
	0xDB, 0x95, 0xA2, 0x00, 0xCC, 0x0A, 0xB2, 0x6A,
	0x19, 0xCE, 0x6B, 0xCC, 0xAD, 0x56, 0x2B, 0x8E,
	0xEE, 0x1B, 0x59, 0x37, 0x61, 0xCF, 0x7F, 0x41
};

static uint8_t x_qB_secp256r1[] = {
	0xB1, 0x20, 0xDE, 0x4A, 0xA3, 0x64, 0x92, 0x79,
	0x53, 0x46, 0xE8, 0xDE, 0x6C, 0x2C, 0x86, 0x46,
	0xAE, 0x06, 0xAA, 0xEA, 0x27, 0x9F, 0xA7, 0x75,
	0xB3, 0xAB, 0x07, 0x15, 0xF6, 0xCE, 0x51, 0xB0
};

static uint8_t y_qB_secp256r1[] = {
	0x9F, 0x1B, 0x7E, 0xEC, 0xE2, 0x0D, 0x7B, 0x5E,
	0xD8, 0xEC, 0x68, 0x5F, 0xA3, 0xF0, 0x71, 0xD8,
	0x37, 0x27, 0x02, 0x70, 0x92, 0xA8, 0x41, 0x13,
	0x85, 0xC3, 0x4D, 0xDE, 0x57, 0x08, 0xB2, 0xB6
};

static uint8_t x_Z_secp256r1[] = {
	0xDD, 0x0F, 0x53, 0x96, 0x21, 0x9D, 0x1E, 0xA3,
	0x93, 0x31, 0x04, 0x12, 0xD1, 0x9A, 0x08, 0xF1,
	0xF5, 0x81, 0x1E, 0x9D, 0xC8, 0xEC, 0x8E, 0xEA,
	0x7F, 0x80, 0xD2, 0x1C, 0x82, 0x0C, 0x27, 0x88
};

static uint8_t y_Z_secp256r1[] = {
	0x03, 0x57, 0xDC, 0xCD, 0x4C, 0x80, 0x4D, 0x0D,
	0x8D, 0x33, 0xAA, 0x42, 0xB8, 0x48, 0x83, 0x4A,
	0xA5, 0x60, 0x5F, 0x9A, 0xB0, 0xD3, 0x72, 0x39,
	0xA1, 0x15, 0xBB, 0xB6, 0x47, 0x93, 0x6F, 0x50
};

/** ECDH SECP256R1 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_secp256r1 = {
	.pubkey_qA_x = {
		.data = x_qA_secp256r1,
		.length = sizeof(x_qA_secp256r1),
	},
	.pubkey_qA_y = {
		.data = y_qA_secp256r1,
		.length = sizeof(y_qA_secp256r1),
	},
	.pubkey_qB_x = {
		.data = x_qB_secp256r1,
		.length = sizeof(x_qB_secp256r1),
	},
	.pubkey_qB_y = {
		.data = y_qB_secp256r1,
		.length = sizeof(y_qB_secp256r1),
	},
	.pkey_A = {
		.data = dA_secp256r1,
		.length = sizeof(dA_secp256r1),
	},
	.pkey_B = {
		.data = dB_secp256r1,
		.length = sizeof(dB_secp256r1),
	},
	.secret_x = {
		.data = x_Z_secp256r1,
		.length = sizeof(x_Z_secp256r1),
	},
	.secret_y = {
		.data = y_Z_secp256r1,
		.length = sizeof(y_Z_secp256r1),
	},
	.curve = RTE_CRYPTO_EC_GROUP_SECP256R1
};

/** SECP384R1 (P-384 NIST) test vector */

static uint8_t dA_secp384r1[] = {
	0xD2, 0x73, 0x35, 0xEA, 0x71, 0x66, 0x4A, 0xF2,
	0x44, 0xDD, 0x14, 0xE9, 0xFD, 0x12, 0x60, 0x71,
	0x5D, 0xFD, 0x8A, 0x79, 0x65, 0x57, 0x1C, 0x48,
	0xD7, 0x09, 0xEE, 0x7A, 0x79, 0x62, 0xA1, 0x56,
	0xD7, 0x06, 0xA9, 0x0C, 0xBC, 0xB5, 0xDF, 0x29,
	0x86, 0xF0, 0x5F, 0xEA, 0xDB, 0x93, 0x76, 0xF1
};

static uint8_t x_qA_secp384r1[] = {
	0x79, 0x31, 0x48, 0xF1, 0x78, 0x76, 0x34, 0xD5,
	0xDA, 0x4C, 0x6D, 0x90, 0x74, 0x41, 0x7D, 0x05,
	0xE0, 0x57, 0xAB, 0x62, 0xF8, 0x20, 0x54, 0xD1,
	0x0E, 0xE6, 0xB0, 0x40, 0x3D, 0x62, 0x79, 0x54,
	0x7E, 0x6A, 0x8E, 0xA9, 0xD1, 0xFD, 0x77, 0x42,
	0x7D, 0x01, 0x6F, 0xE2, 0x7A, 0x8B, 0x8C, 0x66
};

static uint8_t y_qA_secp384r1[] = {
	0xC6, 0xC4, 0x12, 0x94, 0x33, 0x1D, 0x23, 0xE6,
	0xF4, 0x80, 0xF4, 0xFB, 0x4C, 0xD4, 0x05, 0x04,
	0xC9, 0x47, 0x39, 0x2E, 0x94, 0xF4, 0xC3, 0xF0,
	0x6B, 0x8F, 0x39, 0x8B, 0xB2, 0x9E, 0x42, 0x36,
	0x8F, 0x7A, 0x68, 0x59, 0x23, 0xDE, 0x3B, 0x67,
	0xBA, 0xCE, 0xD2, 0x14, 0xA1, 0xA1, 0xD1, 0x28
};

static uint8_t dB_secp384r1[] = {
	0x52, 0xD1, 0x79, 0x1F, 0xDB, 0x4B, 0x70, 0xF8,
	0x9C, 0x0F, 0x00, 0xD4, 0x56, 0xC2, 0xF7, 0x02,
	0x3B, 0x61, 0x25, 0x26, 0x2C, 0x36, 0xA7, 0xDF,
	0x1F, 0x80, 0x23, 0x11, 0x21, 0xCC, 0xE3, 0xD3,
	0x9B, 0xE5, 0x2E, 0x00, 0xC1, 0x94, 0xA4, 0x13,
	0x2C, 0x4A, 0x6C, 0x76, 0x8B, 0xCD, 0x94, 0xD2
};

static uint8_t x_qB_secp384r1[] = {
	0x5C, 0xD4, 0x2A, 0xB9, 0xC4, 0x1B, 0x53, 0x47,
	0xF7, 0x4B, 0x8D, 0x4E, 0xFB, 0x70, 0x8B, 0x3D,
	0x5B, 0x36, 0xDB, 0x65, 0x91, 0x53, 0x59, 0xB4,
	0x4A, 0xBC, 0x17, 0x64, 0x7B, 0x6B, 0x99, 0x99,
	0x78, 0x9D, 0x72, 0xA8, 0x48, 0x65, 0xAE, 0x2F,
	0x22, 0x3F, 0x12, 0xB5, 0xA1, 0xAB, 0xC1, 0x20
};

static uint8_t y_qB_secp384r1[] = {
	0xE1, 0x71, 0x45, 0x8F, 0xEA, 0xA9, 0x39, 0xAA,
	0xA3, 0xA8, 0xBF, 0xAC, 0x46, 0xB4, 0x04, 0xBD,
	0x8F, 0x6D, 0x5B, 0x34, 0x8C, 0x0F, 0xA4, 0xD8,
	0x0C, 0xEC, 0xA1, 0x63, 0x56, 0xCA, 0x93, 0x32,
	0x40, 0xBD, 0xE8, 0x72, 0x34, 0x15, 0xA8, 0xEC,
	0xE0, 0x35, 0xB0, 0xED, 0xF3, 0x67, 0x55, 0xDE
};

static uint8_t x_Z_secp384r1[] = {
	0x5E, 0xA1, 0xFC, 0x4A, 0xF7, 0x25, 0x6D, 0x20,
	0x55, 0x98, 0x1B, 0x11, 0x05, 0x75, 0xE0, 0xA8,
	0xCA, 0xE5, 0x31, 0x60, 0x13, 0x7D, 0x90, 0x4C,
	0x59, 0xD9, 0x26, 0xEB, 0x1B, 0x84, 0x56, 0xE4,
	0x27, 0xAA, 0x8A, 0x45, 0x40, 0x88, 0x4C, 0x37,
	0xDE, 0x15, 0x9A, 0x58, 0x02, 0x8A, 0xBC, 0x0E
};

static uint8_t y_Z_secp384r1[] = {
	0x0C, 0xC5, 0x9E, 0x4B, 0x04, 0x64, 0x14, 0xA8,
	0x1C, 0x8A, 0x3B, 0xDF, 0xDC, 0xA9, 0x25, 0x26,
	0xC4, 0x87, 0x69, 0xDD, 0x8D, 0x31, 0x27, 0xCA,
	0xA9, 0x9B, 0x36, 0x32, 0xD1, 0x91, 0x39, 0x42,
	0xDE, 0x36, 0x2E, 0xAF, 0xAA, 0x96, 0x23, 0x79,
	0x37, 0x4D, 0x9F, 0x3F, 0x06, 0x68, 0x41, 0xCA
};

/** ECDH SECP384R1 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_secp384r1 = {
	.pubkey_qA_x = {
		.data = x_qA_secp384r1,
		.length = sizeof(x_qA_secp384r1),
	},
	.pubkey_qA_y = {
		.data = y_qA_secp384r1,
		.length = sizeof(y_qA_secp384r1),
	},
	.pubkey_qB_x = {
		.data = x_qB_secp384r1,
		.length = sizeof(x_qB_secp384r1),
	},
	.pubkey_qB_y = {
		.data = y_qB_secp384r1,
		.length = sizeof(y_qB_secp384r1),
	},
	.pkey_A = {
		.data = dA_secp384r1,
		.length = sizeof(dA_secp384r1),
	},
	.pkey_B = {
		.data = dB_secp384r1,
		.length = sizeof(dB_secp384r1),
	},
	.secret_x = {
		.data = x_Z_secp384r1,
		.length = sizeof(x_Z_secp384r1),
	},
	.secret_y = {
		.data = y_Z_secp384r1,
		.length = sizeof(y_Z_secp384r1),
	},
	.curve = RTE_CRYPTO_EC_GROUP_SECP384R1
};

/** SECP521R1 (P-521 NIST) test vector */

static uint8_t dA_secp521r1[] = {
	0x01, 0x13, 0xF8, 0x2D, 0xA8, 0x25, 0x73, 0x5E,
	0x3D, 0x97, 0x27, 0x66, 0x83, 0xB2, 0xB7, 0x42,
	0x77, 0xBA, 0xD2, 0x73, 0x35, 0xEA, 0x71, 0x66,
	0x4A, 0xF2, 0x43, 0x0C, 0xC4, 0xF3, 0x34, 0x59,
	0xB9, 0x66, 0x9E, 0xE7, 0x8B, 0x3F, 0xFB, 0x9B,
	0x86, 0x83, 0x01, 0x5D, 0x34, 0x4D, 0xCB, 0xFE,
	0xF6, 0xFB, 0x9A, 0xF4, 0xC6, 0xC4, 0x70, 0xBE,
	0x25, 0x45, 0x16, 0xCD, 0x3C, 0x1A, 0x1F, 0xB4,
	0x73, 0x62
};

static uint8_t x_qA_secp521r1[] = {
	0x01, 0xEB, 0xB3, 0x4D, 0xD7, 0x57, 0x21, 0xAB,
	0xF8, 0xAD, 0xC9, 0xDB, 0xED, 0x17, 0x88, 0x9C,
	0xBB, 0x97, 0x65, 0xD9, 0x0A, 0x7C, 0x60, 0xF2,
	0xCE, 0xF0, 0x07, 0xBB, 0x0F, 0x2B, 0x26, 0xE1,
	0x48, 0x81, 0xFD, 0x44, 0x42, 0xE6, 0x89, 0xD6,
	0x1C, 0xB2, 0xDD, 0x04, 0x6E, 0xE3, 0x0E, 0x3F,
	0xFD, 0x20, 0xF9, 0xA4, 0x5B, 0xBD, 0xF6, 0x41,
	0x3D, 0x58, 0x3A, 0x2D, 0xBF, 0x59, 0x92, 0x4F,
	0xD3, 0x5C
};

static uint8_t y_qA_secp521r1[] = {
	0x00, 0xF6, 0xB6, 0x32, 0xD1, 0x94, 0xC0, 0x38,
	0x8E, 0x22, 0xD8, 0x43, 0x7E, 0x55, 0x8C, 0x55,
	0x2A, 0xE1, 0x95, 0xAD, 0xFD, 0x15, 0x3F, 0x92,
	0xD7, 0x49, 0x08, 0x35, 0x1B, 0x2F, 0x8C, 0x4E,
	0xDA, 0x94, 0xED, 0xB0, 0x91, 0x6D, 0x1B, 0x53,
	0xC0, 0x20, 0xB5, 0xEE, 0xCA, 0xED, 0x1A, 0x5F,
	0xC3, 0x8A, 0x23, 0x3E, 0x48, 0x30, 0x58, 0x7B,
	0xB2, 0xEE, 0x34, 0x89, 0xB3, 0xB4, 0x2A, 0x5A,
	0x86, 0xA4
};

static uint8_t dB_secp521r1[] = {
	0x00, 0xCE, 0xE3, 0x48, 0x0D, 0x86, 0x45, 0xA1,
	0x7D, 0x24, 0x9F, 0x27, 0x76, 0xD2, 0x8B, 0xAE,
	0x61, 0x69, 0x52, 0xD1, 0x79, 0x1F, 0xDB, 0x4B,
	0x70, 0xF7, 0xC3, 0x37, 0x87, 0x32, 0xAA, 0x1B,
	0x22, 0x92, 0x84, 0x48, 0xBC, 0xD1, 0xDC, 0x24,
	0x96, 0xD4, 0x35, 0xB0, 0x10, 0x48, 0x06, 0x6E,
	0xBE, 0x4F, 0x72, 0x90, 0x3C, 0x36, 0x1B, 0x1A,
	0x9D, 0xC1, 0x19, 0x3D, 0xC2, 0xC9, 0xD0, 0x89,
	0x1B, 0x96
};

static uint8_t x_qB_secp521r1[] = {
	0x01, 0x0E, 0xBF, 0xAF, 0xC6, 0xE8, 0x5E, 0x08,
	0xD2, 0x4B, 0xFF, 0xFC, 0xC1, 0xA4, 0x51, 0x1D,
	0xB0, 0xE6, 0x34, 0xBE, 0xEB, 0x1B, 0x6D, 0xEC,
	0x8C, 0x59, 0x39, 0xAE, 0x44, 0x76, 0x62, 0x01,
	0xAF, 0x62, 0x00, 0x43, 0x0B, 0xA9, 0x7C, 0x8A,
	0xC6, 0xA0, 0xE9, 0xF0, 0x8B, 0x33, 0xCE, 0x7E,
	0x9F, 0xEE, 0xB5, 0xBA, 0x4E, 0xE5, 0xE0, 0xD8,
	0x15, 0x10, 0xC2, 0x42, 0x95, 0xB8, 0xA0, 0x8D,
	0x02, 0x35
};

static uint8_t y_qB_secp521r1[] = {
	0x00, 0xA4, 0xA6, 0xEC, 0x30, 0x0D, 0xF9, 0xE2,
	0x57, 0xB0, 0x37, 0x2B, 0x5E, 0x7A, 0xBF, 0xEF,
	0x09, 0x34, 0x36, 0x71, 0x9A, 0x77, 0x88, 0x7E,
	0xBB, 0x0B, 0x18, 0xCF, 0x80, 0x99, 0xB9, 0xF4,
	0x21, 0x2B, 0x6E, 0x30, 0xA1, 0x41, 0x9C, 0x18,
	0xE0, 0x29, 0xD3, 0x68, 0x63, 0xCC, 0x9D, 0x44,
	0x8F, 0x4D, 0xBA, 0x4D, 0x2A, 0x0E, 0x60, 0x71,
	0x1B, 0xE5, 0x72, 0x91, 0x5F, 0xBD, 0x4F, 0xEF,
	0x26, 0x95
};

static uint8_t x_Z_secp521r1[] = {
	0x00, 0xCD, 0xEA, 0x89, 0x62, 0x1C, 0xFA, 0x46,
	0xB1, 0x32, 0xF9, 0xE4, 0xCF, 0xE2, 0x26, 0x1C,
	0xDE, 0x2D, 0x43, 0x68, 0xEB, 0x56, 0x56, 0x63,
	0x4C, 0x7C, 0xC9, 0x8C, 0x7A, 0x00, 0xCD, 0xE5,
	0x4E, 0xD1, 0x86, 0x6A, 0x0D, 0xD3, 0xE6, 0x12,
	0x6C, 0x9D, 0x2F, 0x84, 0x5D, 0xAF, 0xF8, 0x2C,
	0xEB, 0x1D, 0xA0, 0x8F, 0x5D, 0x87, 0x52, 0x1B,
	0xB0, 0xEB, 0xEC, 0xA7, 0x79, 0x11, 0x16, 0x9C,
	0x20, 0xCC
};

static uint8_t y_Z_secp521r1[] = {
	0x00, 0xF9, 0xA7, 0x16, 0x41, 0x02, 0x9B, 0x7F,
	0xC1, 0xA8, 0x08, 0xAD, 0x07, 0xCD, 0x48, 0x61,
	0xE8, 0x68, 0x61, 0x4B, 0x86, 0x5A, 0xFB, 0xEC,
	0xAB, 0x1F, 0x2B, 0xD4, 0xD8, 0xB5, 0x5E, 0xBC,
	0xB5, 0xE3, 0xA5, 0x31, 0x43, 0xCE, 0xB2, 0xC5,
	0x11, 0xB1, 0xAE, 0x0A, 0xF5, 0xAC, 0x82, 0x7F,
	0x60, 0xF2, 0xFD, 0x87, 0x25, 0x65, 0xAC, 0x5C,
	0xA0, 0xA1, 0x64, 0x03, 0x8F, 0xE9, 0x80, 0xA7,
	0xE4, 0xBD
};

/** ECDH SECP521R1 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_secp521r1 = {
	.pubkey_qA_x = {
		.data = x_qA_secp521r1,
		.length = sizeof(x_qA_secp521r1),
	},
	.pubkey_qA_y = {
		.data = y_qA_secp521r1,
		.length = sizeof(y_qA_secp521r1),
	},
	.pubkey_qB_x = {
		.data = x_qB_secp521r1,
		.length = sizeof(x_qB_secp521r1),
	},
	.pubkey_qB_y = {
		.data = y_qB_secp521r1,
		.length = sizeof(y_qB_secp521r1),
	},
	.pkey_A = {
		.data = dA_secp521r1,
		.length = sizeof(dA_secp521r1),
	},
	.pkey_B = {
		.data = dB_secp521r1,
		.length = sizeof(dB_secp521r1),
	},
	.secret_x = {
		.data = x_Z_secp521r1,
		.length = sizeof(x_Z_secp521r1),
	},
	.secret_y = {
		.data = y_Z_secp521r1,
		.length = sizeof(y_Z_secp521r1),
	},
	.curve = RTE_CRYPTO_EC_GROUP_SECP521R1
};

/** ED25519 test vector */

static uint8_t privkey_ed25519[] = {
	0x83, 0x3f, 0xe6, 0x24, 0x09, 0x23, 0x7b, 0x9d,
	0x62, 0xec, 0x77, 0x58, 0x75, 0x20, 0x91, 0x1e,
	0x9a, 0x75, 0x9c, 0xec, 0x1d, 0x19, 0x75, 0x5b,
	0x7d, 0xa9, 0x01, 0xb9, 0x6d, 0xca, 0x3d, 0x42
};

static uint8_t pubkey_ed25519[] = {
	0xec, 0x17, 0x2b, 0x93, 0xad, 0x5e, 0x56, 0x3b,
	0xf4, 0x93, 0x2c, 0x70, 0xe1, 0x24, 0x50, 0x34,
	0xc3, 0x54, 0x67, 0xef, 0x2e, 0xfd, 0x4d, 0x64,
	0xeb, 0xf8, 0x19, 0x68, 0x34, 0x67, 0xe2, 0xbf
};

/** ECDH ED25519 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_ed25519 = {
	.pubkey_qA_x = {
		.data = pubkey_ed25519,
		.length = sizeof(pubkey_ed25519),
	},
	.pubkey_qA_y = {
	},
	.pubkey_qB_x = {
	},
	.pubkey_qB_y = {
	},
	.pkey_A = {
		.data = privkey_ed25519,
		.length = sizeof(privkey_ed25519),
	},
	.pkey_B = {
	},
	.secret_x = {
	},
	.secret_y = {
	},
	.curve = RTE_CRYPTO_EC_GROUP_ED25519
};

/** ED448 test vector */

static uint8_t privkey_ed448[] = {
	0xd6, 0x5d, 0xf3, 0x41, 0xad, 0x13, 0xe0, 0x08,
	0x56, 0x76, 0x88, 0xba, 0xed, 0xda, 0x8e, 0x9d,
	0xcd, 0xc1, 0x7d, 0xc0, 0x24, 0x97, 0x4e, 0xa5,
	0xb4, 0x22, 0x7b, 0x65, 0x30, 0xe3, 0x39, 0xbf,
	0xf2, 0x1f, 0x99, 0xe6, 0x8c, 0xa6, 0x96, 0x8f,
	0x3c, 0xca, 0x6d, 0xfe, 0x0f, 0xb9, 0xf4, 0xfa,
	0xb4, 0xfa, 0x13, 0x5d, 0x55, 0x42, 0xea, 0x3f,
	0x01
};

static uint8_t pubkey_ed448[] = {
	0xdf, 0x97, 0x05, 0xf5, 0x8e, 0xdb, 0xab, 0x80,
	0x2c, 0x7f, 0x83, 0x63, 0xcf, 0xe5, 0x56, 0x0a,
	0xb1, 0xc6, 0x13, 0x2c, 0x20, 0xa9, 0xf1, 0xdd,
	0x16, 0x34, 0x83, 0xa2, 0x6f, 0x8a, 0xc5, 0x3a,
	0x39, 0xd6, 0x80, 0x8b, 0xf4, 0xa1, 0xdf, 0xbd,
	0x26, 0x1b, 0x09, 0x9b, 0xb0, 0x3b, 0x3f, 0xb5,
	0x09, 0x06, 0xcb, 0x28, 0xbd, 0x8a, 0x08, 0x1f,
	0x00
};

/** ECDH ED448 elliptic curve param */

struct crypto_testsuite_ecdh_params ecdh_param_ed448 = {
	.pubkey_qA_x = {
		.data = pubkey_ed448,
		.length = sizeof(pubkey_ed448),
	},
	.pubkey_qA_y = {
	},
	.pubkey_qB_x = {
	},
	.pubkey_qB_y = {
	},
	.pkey_A = {
		.data = privkey_ed448,
		.length = sizeof(privkey_ed448),
	},
	.pkey_B = {
	},
	.secret_x = {
	},
	.secret_y = {
	},
	.curve = RTE_CRYPTO_EC_GROUP_ED448
};

#endif /* __TEST_CRYPTODEV_ECDH_TEST_VECTORS_H__ */
