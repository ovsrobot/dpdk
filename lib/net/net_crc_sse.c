/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2020 Intel Corporation
 */

#include <stdalign.h>
#include <string.h>

#include <rte_common.h>
#include <rte_vect.h>
#include <rte_branch_prediction.h>

#include "net_crc.h"

/** PCLMULQDQ CRC computation context structure */
struct __rte_aligned(XMM_SIZE) crc_pclmulqdq_ctx {
	/**
	 * The constants are derived as below:
	 * P is assumed to be degree 64 polynomial. If the degree is less,
	 * then P = (poly << (64 - deg)) to have a 64-bit polynomial.
	 * rk1 = bitreverse64(x^575 MOD P)
	 * rk2 = bitreverse64(x^511 MOD P)
	 * rk3 = bitreverse64(x^191 MOD P)
	 * rk4 = bitreverse64(x^127 MOD P)
	 * rk5 = (bitreverse64(floor(x^128 / P) - x^64) << 1) | 1
	 * rk6 = (bitreverse64(P - x^64) << 1)
	 */
	rte_xmm_t rk1_rk2;
	rte_xmm_t rk3_rk4;
	rte_xmm_t rk5_rk6;
};

/**
 * @brief Performs one folding round
 *
 * Logically function operates as follows:
 *     DATA = READ_NEXT_16BYTES();
 *     F1 = LSB8(FOLD)
 *     F2 = MSB8(FOLD)
 *     T1 = CLMUL(F1, RK1)
 *     T2 = CLMUL(F2, RK2)
 *     FOLD = XOR(T1, T2, DATA)
 *
 * @param data_block
 *   16 byte data block
 * @param precomp
 *   Precomputed rk1 constant
 * @param fold
 *   Current16 byte folded data
 *
 * @return
 *   New 16 byte folded data
 */
static __rte_always_inline __m128i
crcr32_folding_round(__m128i data_block,
		__m128i precomp,
		__m128i fold)
{
	__m128i tmp0 = _mm_clmulepi64_si128(fold, precomp, 0x00);
	__m128i tmp1 = _mm_clmulepi64_si128(fold, precomp, 0x11);

	return _mm_xor_si128(tmp1, _mm_xor_si128(data_block, tmp0));
}

/**
 * Fold the low qword (upper 64 coefficients) with rk4 = x^127 mod P
 * and XOR into the high qword.
 *
 * @param data128
 *   128 bits data to be reduced
 * @param precomp
 *   precomputed constants rk3, rk4
 *
 * @return
 *  128 bits reduced data
 */

static __rte_always_inline __m128i
crcr32_reduce_to_128(__m128i data128, __m128i precomp)
{
	__m128i tmp0, tmp1;

	tmp0 = _mm_clmulepi64_si128(data128, precomp, 0x10);
	tmp1 = _mm_srli_si128(data128, 8);
	return _mm_xor_si128(tmp1, tmp0);
}

/**
 * Performs Barret's reduction from 128 bits to 32 bits.
 *
 * @param data128
 *   128 bits data to be reduced
 * @param precomp
 *   rk5, rk6 precomputed constant
 *
 * @return
 *   reduced 32 bits data
 */

static __rte_always_inline uint32_t
crcr32_reduce_128_to_32(__m128i data128, __m128i precomp)
{
	__m128i tmp0, tmp1, tmp2;

	tmp0 = _mm_clmulepi64_si128(data128, precomp, 0x00);
	tmp1 = _mm_clmulepi64_si128(tmp0, precomp, 0x10);

	tmp2 = _mm_xor_si128(tmp1, data128);

	return _mm_extract_epi32(tmp2, 2);
}

static const alignas(16) uint8_t crc_xmm_shift_tab[32] = {
	0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
	0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

/**
 * Shifts left 128 bit register by specified number of bytes
 *
 * @param reg
 *   128 bit value
 * @param num
 *   number of bytes to shift left reg by (0-16)
 *
 * @return
 *   reg << (num * 8)
 */

static __rte_always_inline __m128i
xmm_shift_left(__m128i reg, const unsigned int num)
{
	const __m128i *p = (const __m128i *)(crc_xmm_shift_tab + 16 - num);

	return _mm_shuffle_epi8(reg, _mm_loadu_si128(p));
}

static __rte_always_inline uint32_t
crc32_eth_calc_pclmulqdq(
	const uint8_t *data,
	uint32_t data_len,
	uint32_t crc,
	const struct crc_pclmulqdq_ctx *params)
{
	__m128i temp, fold, k;
	uint32_t n;

	/* Get CRC init value */
	temp = _mm_insert_epi32(_mm_setzero_si128(), crc, 0);

	/**
	 * Folding all data into 4 parallel 16 byte data block
	 * Later folds 4 parallel blocks into single fold block
	 */
	if (likely(data_len >= 64)) {
		__m128i fold1, fold2, fold3, fold4;
		__m128i temp1, temp2, temp3, temp4;
		fold1 = _mm_loadu_si128((const __m128i *)(data +  0));
		fold2 = _mm_loadu_si128((const __m128i *)(data + 16));
		fold3 = _mm_loadu_si128((const __m128i *)(data + 32));
		fold4 = _mm_loadu_si128((const __m128i *)(data + 48));
		fold1 = _mm_xor_si128(fold1, temp);
		k = params->rk1_rk2.x;

		for (n = 64; (n + 64) <= data_len; n += 64) {
			temp1 = _mm_loadu_si128((const __m128i *)&data[n]);
			temp2 = _mm_loadu_si128((const __m128i *)&data[n + 16]);
			temp3 = _mm_loadu_si128((const __m128i *)&data[n + 32]);
			temp4 = _mm_loadu_si128((const __m128i *)&data[n + 48]);
			fold1 = crcr32_folding_round(temp1, k, fold1);
			fold2 = crcr32_folding_round(temp2, k, fold2);
			fold3 = crcr32_folding_round(temp3, k, fold3);
			fold4 = crcr32_folding_round(temp4, k, fold4);
		}

		k = params->rk3_rk4.x;
		fold1 = crcr32_folding_round(fold2, k, fold1);
		fold1 = crcr32_folding_round(fold3, k, fold1);
		fold = crcr32_folding_round(fold4, k, fold1);
		goto single_fold_loop;
	}

	if (unlikely(data_len < 16)) {
		/* 0 to 15 bytes */
		alignas(16) uint8_t buffer[16];

		memset(buffer, 0, sizeof(buffer));
		memcpy(buffer, data, data_len);

		fold = _mm_load_si128((const __m128i *)buffer);
		fold = _mm_xor_si128(fold, temp);
		if (unlikely(data_len < 4)) {
			fold = xmm_shift_left(fold, 8 - data_len);
			goto barret_reduction;
		}
		fold = xmm_shift_left(fold, 16 - data_len);
		k = params->rk3_rk4.x;
		goto reduction_128;
	}

	/** At least 16 bytes in the buffer */
	/** Apply CRC initial value */
	fold = _mm_loadu_si128((const __m128i *)data);
	fold = _mm_xor_si128(fold, temp);

	/** Single folding loop - the last 16 bytes is processed separately */
	k = params->rk3_rk4.x;
	n = 16;

single_fold_loop:
	for (; (n + 16) <= data_len; n += 16) {
		temp = _mm_loadu_si128((const __m128i *)&data[n]);
		fold = crcr32_folding_round(temp, k, fold);
	}

	/** Partial bytes - process last <16 bytes */
	if (likely(n < data_len)) {

		__m128i last16, a, b;

		last16 = _mm_loadu_si128((const __m128i *)&data[data_len - 16]);

		temp = _mm_loadu_si128((const __m128i *)
			&crc_xmm_shift_tab[data_len & 15]);
		a = _mm_shuffle_epi8(fold, temp);

		temp = _mm_xor_si128(temp, _mm_set1_epi8(0xff));
		b = _mm_shuffle_epi8(fold, temp);
		b = _mm_blendv_epi8(b, last16, temp);

		/* k = rk3 & rk4 */
		fold = crcr32_folding_round(b, k, a);
	}

	/** Reduction 128 -> 32 Assumes: fold holds 128bit folded data */
reduction_128:
	fold = crcr32_reduce_to_128(fold, k);

barret_reduction:
	k = params->rk5_rk6.x;
	n = crcr32_reduce_128_to_32(fold, k);

	return n;
}

uint32_t
rte_crc16_ccitt_sse42_handler(const uint8_t *data, uint32_t data_len)
{
	static const struct crc_pclmulqdq_ctx crc16_ccitt_pclmulqdq = {
		.rk1_rk2 = { .u64 = { 0x922dULL, 0x47e3ULL } },
		.rk3_rk4 = { .u64 = { 0x8e10ULL, 0x81bfULL } },
		.rk5_rk6 = { .u64 = { 0x859b040b1c581911ULL, 0x10810ULL } },
	};

	/** return 16-bit CRC value */
	return (uint16_t)~crc32_eth_calc_pclmulqdq(data,
		data_len,
		0xffff,
		&crc16_ccitt_pclmulqdq);
}

uint32_t
rte_crc32_eth_sse42_handler(const uint8_t *data, uint32_t data_len)
{
	static const struct crc_pclmulqdq_ctx crc32_eth_pclmulqdq = {
		.rk1_rk2 = { .u64 = { 0x8f352d95ULL, 0x1d9513d7ULL } },
		.rk3_rk4 = { .u64 = { 0xae689191ULL, 0xccaa009eULL } },
		.rk5_rk6 = { .u64 = { 0xb4e5b025f7011641ULL, 0x1db710640ULL } },
	};

	return ~crc32_eth_calc_pclmulqdq(data,
		data_len,
		0xffffffffUL,
		&crc32_eth_pclmulqdq);
}
