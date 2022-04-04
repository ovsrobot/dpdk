/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021-2022 Intel Corporation
 */

#ifndef _QAT_EC_H_
#define _QAT_EC_H_

#define EC_MAX_SIZE	571

#include <rte_crypto_asym.h>

typedef struct {
	uint8_t data[(EC_MAX_SIZE >> 3) + 1];
} buffer;

enum EC_NAME {
	SECP256R1	= 1,
	SECP384R1,
	SECP521R1,
};

struct elliptic_curve {
	const char *name;
	uint32_t bytesize;
	buffer x;
	buffer y;
	buffer n;
	buffer p;
	buffer a;
	buffer b;
	buffer h;
};

static struct elliptic_curve curve[] = {
	[SECP256R1] = {
		.name = "secp256r1",
		.bytesize = 32,
		.x = {
			.data = {
				0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
				0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
				0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
				0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
				},
		},
		.y = {
			.data = {
				0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B,
				0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
				0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE,
				0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
				},
		},
		.n = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
				0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
				},
		},
		.p = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				},
		},
		.a = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
				},
		},
		.b = {
			.data = {
				0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
				0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
				0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
				0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
				},
		},
		.h = {
			.data = {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
		},
	},
	[SECP384R1] = {
		.name = "secp384r1",
		.bytesize = 48,
		.x = {
			.data = {
				0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
				0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
				0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
				0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
				0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
				0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7
				},
		},
		.y = {
			.data = {
				0x36, 0x17, 0xDE, 0x4A, 0x96, 0x26, 0x2C, 0x6F,
				0x5D, 0x9E, 0x98, 0xBF, 0x92, 0x92, 0xDC, 0x29,
				0xF8, 0xF4, 0x1D, 0xBD, 0x28, 0x9A, 0x14, 0x7C,
				0xE9, 0xDA, 0x31, 0x13, 0xB5, 0xF0, 0xB8, 0xC0,
				0x0A, 0x60, 0xB1, 0xCE, 0x1D, 0x7E, 0x81, 0x9D,
				0x7A, 0x43, 0x1D, 0x7C, 0x90, 0xEA, 0x0E, 0x5F
				},
		},
		.n = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
				0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
				0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
				},
		},
		.p = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
				0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
				},
		},
		.a = {
			.data = {
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
				0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,
				},
		},
		.b = {
			.data = {
				0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
				0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
				0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
				0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
				0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
				0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,
				},
		},
		.h = {
			.data = {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				},
		},
	},
	[SECP521R1] = {
		.name = "secp521r1",
		.bytesize = 66,
		.x = {
			.data = {
				0x00, 0xC6, 0x85, 0x8E, 0x06, 0xB7, 0x04, 0x04,
				0xE9, 0xCD, 0x9E, 0x3E, 0xCB, 0x66, 0x23, 0x95,
				0xB4, 0x42, 0x9C, 0x64, 0x81, 0x39, 0x05, 0x3F,
				0xB5, 0x21, 0xF8, 0x28, 0xAF, 0x60, 0x6B, 0x4D,
				0x3D, 0xBA, 0xA1, 0x4B, 0x5E, 0x77, 0xEF, 0xE7,
				0x59, 0x28, 0xFE, 0x1D, 0xC1, 0x27, 0xA2, 0xFF,
				0xA8, 0xDE, 0x33, 0x48, 0xB3, 0xC1, 0x85, 0x6A,
				0x42, 0x9B, 0xF9, 0x7E, 0x7E, 0x31, 0xC2, 0xE5,
				0xBD, 0x66,
				},
		},
		.y = {
			.data = {
				0x01, 0x18, 0x39, 0x29, 0x6A, 0x78, 0x9A, 0x3B,
				0xC0, 0x04, 0x5C, 0x8A, 0x5F, 0xB4, 0x2C, 0x7D,
				0x1B, 0xD9, 0x98, 0xF5, 0x44, 0x49, 0x57, 0x9B,
				0x44, 0x68, 0x17, 0xAF, 0xBD, 0x17, 0x27, 0x3E,
				0x66, 0x2C, 0x97, 0xEE, 0x72, 0x99, 0x5E, 0xF4,
				0x26, 0x40, 0xC5, 0x50, 0xB9, 0x01, 0x3F, 0xAD,
				0x07, 0x61, 0x35, 0x3C, 0x70, 0x86, 0xA2, 0x72,
				0xC2, 0x40, 0x88, 0xBE, 0x94, 0x76, 0x9F, 0xD1,
				0x66, 0x50,
				},
		},
		.n = {
			.data = {
				0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFA, 0x51, 0x86, 0x87, 0x83, 0xBF, 0x2F,
				0x96, 0x6B, 0x7F, 0xCC, 0x01, 0x48, 0xF7, 0x09,
				0xA5, 0xD0, 0x3B, 0xB5, 0xC9, 0xB8, 0x89, 0x9C,
				0x47, 0xAE, 0xBB, 0x6F, 0xB7, 0x1E, 0x91, 0x38,
				0x64, 0x09,
				},
		},
		.p = {
			.data = {
				0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF,
				},
		},
		.a = {
			.data = {
				0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
				0xFF, 0xFC,
				},
		},
		.b = {
			.data = {
				0x00, 0x51, 0x95, 0x3E, 0xB9, 0x61, 0x8E, 0x1C,
				0x9A, 0x1F, 0x92, 0x9A, 0x21, 0xA0, 0xB6, 0x85,
				0x40, 0xEE, 0xA2, 0xDA, 0x72, 0x5B, 0x99, 0xB3,
				0x15, 0xF3, 0xB8, 0xB4, 0x89, 0x91, 0x8E, 0xF1,
				0x09, 0xE1, 0x56, 0x19, 0x39, 0x51, 0xEC, 0x7E,
				0x93, 0x7B, 0x16, 0x52, 0xC0, 0xBD, 0x3B, 0xB1,
				0xBF, 0x07, 0x35, 0x73, 0xDF, 0x88, 0x3D, 0x2C,
				0x34, 0xF1, 0xEF, 0x45, 0x1F, 0xD4, 0x6B, 0x50,
				0x3F, 0x00,
				},
		},
		.h = {
			.data = {
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x01,
				},
		},
	}
};

static int
pick_curve(struct rte_crypto_asym_xform *xform)
{
	switch (xform->ec.curve_id) {
	case RTE_CRYPTO_EC_GROUP_SECP256R1:
		return SECP256R1;
	case RTE_CRYPTO_EC_GROUP_SECP384R1:
		return SECP384R1;
	case RTE_CRYPTO_EC_GROUP_SECP521R1:
		return SECP521R1;
	default:
		return -1;
	}
}

#endif
