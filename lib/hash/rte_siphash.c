/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Based on code reference code licensed as CC0 and MIT.
 * Copyright (c) 2012-2022 Jean-Philippe Aumasson <jeanphilippe.aumasson@gmail.com>
 * Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>
 */

#include <stdint.h>
#include <string.h>

#include <rte_byteorder.h>
#include <rte_common.h>

#include "rte_siphash.h"

static __rte_always_inline uint64_t
rol64(uint64_t x,  unsigned int b)
{
	return (x << b) | (x >> (64 - b));
}

static __rte_always_inline uint64_t u8to64_le(const uint8_t *p)
{
	uint64_t w;

	memcpy(&w, p, sizeof(w));
	return rte_cpu_to_le_64(w);
}

static __rte_always_inline uint32_t u8to32_le(const uint8_t *p)
{
	uint32_t w;

	memcpy(&w, p, sizeof(w));
	return rte_cpu_to_le_32(w);
}

static __rte_always_inline uint16_t u8to16_le(const uint8_t *p)
{
	uint16_t w;

	memcpy(&w, p, sizeof(w));
	return rte_cpu_to_le_16(w);
}


/*
 * Use a 64bit version of SipHash for both full and
 * half versions, The difference is the number of rounds.
 */
#define PREAMBLE(len, key0, key1)			\
	uint64_t v0 = UINT64_C(0x736f6d6570736575);	\
	uint64_t v1 = UINT64_C(0x646f72616e646f6d);	\
	uint64_t v2 = UINT64_C(0x6c7967656e657261);	\
	uint64_t v3 = UINT64_C(0x7465646279746573);	\
	uint64_t b = (uint64_t)len << 56;		\
	v3 ^= key1; \
	v2 ^= key0; \
	v1 ^= key1; \
	v0 ^= key0

#define SIPROUND do {				\
	v0 += v1;			\
	v1 = rol64(v1, 13);		\
	v1 ^= v0;			\
	v0 = rol64(v0, 32);		\
	v2 += v3;			\
	v3 = rol64(v3, 16);		\
	v3 ^= v2;			\
	v0 += v3;			\
	v3 = rol64(v3, 21);		\
	v3 ^= v0;			\
	v2 += v1;			\
	v1 = rol64(v1, 17);		\
	v1 ^= v2;			\
	v2 = rol64(v2, 32);		\
} while (0)

uint64_t
rte_siphash(const void *key, uint32_t len, const uint64_t init[2])
{
	const uint8_t *data = key;
	const uint32_t left = len & 7;
	const uint8_t *end = data + (len - left);

	PREAMBLE(len, init[0], init[1]);

	for (; data != end; data += 8) {
		uint64_t m = u8to64_le(data);
		v3 ^= m;
		SIPROUND;
		SIPROUND;
		v0 ^= m;
	}

	switch (left) {
	case 7:
		b |= ((uint64_t)end[6]) << 48;	/* fallthrough */
	case 6:
		b |= ((uint64_t)end[5]) << 40;	/* fallthrough */
	case 5:
		b |= ((uint64_t)end[4]) << 32;	/* fallthrough */
	case 4:
		b |= u8to32_le(data);
		break;
	case 3:
		b |= ((uint64_t)end[2]) << 16;	/* fallthrough */
	case 2:
		b |= u8to16_le(data);
		break;
	case 1:
		b |= data[0];
	}

	v3 ^= b;
	SIPROUND;
	SIPROUND;

	v0 ^= b;
	v2 ^= 0xff;

	SIPROUND;
	SIPROUND;
	SIPROUND;
	SIPROUND;

	return (v0 ^ v1) ^ (v2 ^ v3);
}

uint32_t
rte_hsiphash(const void *key, uint32_t len, uint32_t init_val)
{
	const uint8_t *data = key;
	const uint32_t left = len & 7;
	const uint8_t *end = data + (len - left);

	PREAMBLE(len, init_val, 0);

	for (; data != end; data += 8) {
		uint64_t m = u8to64_le(data);
		v3 ^= m;
		SIPROUND;
		v0 ^= m;
	}

	switch (left) {
	case 7:
		b |= ((uint64_t)end[6]) << 48;	/* fallthrough */
	case 6:
		b |= ((uint64_t)end[5]) << 40;	/* fallthrough */
	case 5:
		b |= ((uint64_t)end[4]) << 32;	/* fallthrough */
	case 4:
		b |= u8to32_le(data);
		break;
	case 3:
		b |= ((uint64_t)end[2]) << 16;	/* fallthrough */
	case 2:
		b |= u8to16_le(data);
		break;
	case 1:
		b |= data[0];
	}

	v3 ^= b;
	SIPROUND;

	v0 ^= b;
	v2 ^= 0xff;

	SIPROUND;
	SIPROUND;
	SIPROUND;

	return (v0 ^ v1) ^ (v2 ^ v3);
}
