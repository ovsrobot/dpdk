/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_NET_CRC_AVX_H_
#define _RTE_NET_CRC_AVX_H_

#include <rte_branch_prediction.h>

#include <rte_vect.h>
#include <immintrin.h>
#include <x86intrin.h>
#include <cpuid.h>

#ifdef __cplusplus
extern "C" {
#endif

/** PCLMULQDQ CRC computation context structure */
struct crc_pclmulqdq512_ctx {
	__m512i rk1_rk2;
	__m512i rk3_rk4;
	__m512i rk5_rk6;
	__m512i rk7_rk8;
};

static struct crc_pclmulqdq512_ctx crc32_eth_pclmulqdq __rte_aligned(16);

/**
 * @brief Performs one folding round
 *
 * Logically function operates as follows:
 *     DATA = READ_NEXT_64BYTES();
 *     F1 = LSB8(FOLD)
 *     F2 = MSB8(FOLD)
 *     T1 = CLMUL(F1, RK1)
 *     T2 = CLMUL(F2, RK2)
 *     FOLD = XOR(T1, T2, DATA)
 *
 * @param data_block
 *   64 byte data block
 * @param precomp
 *   Precomputed rk1 constant
 * @param fold
 *   Current16 byte folded data
 *
 * @return
 *   New 16 byte folded data
 */
static __rte_always_inline __m512i
crcr32_folding_round(__m512i data_block,
		__m512i precomp,
		__m512i fold)
{
	__m512i tmp0 = _mm512_clmulepi64_epi128(fold, precomp, 0x01);
	__m512i tmp1 = _mm512_clmulepi64_epi128(fold, precomp, 0x10);

	return _mm512_xor_si512(tmp1, _mm512_xor_si512(data_block, tmp0));
}

/**
 * Performs reduction from 128 bits to 64 bits
 *
 * @param data128
 *   128 bits data to be reduced
 * @param precomp
 *   precomputed constants rk5, rk6
 *
 * @return
 *  64 bits reduced data
 */

static __rte_always_inline __m128i
crcr32_reduce_128_to_64(__m128i data128, __m128i precomp)
{
	__m128i tmp0, tmp1, tmp2;

	/* 64b fold */
	tmp0 = _mm_clmulepi64_si128(data128, precomp, 0x00);
	tmp1 = _mm_srli_si128(data128, 8);
	tmp0 = _mm_xor_si128(tmp0, tmp1);

	/* 32b fold */
	tmp2 = _mm_slli_si128(tmp0, 4);
	tmp1 = _mm_clmulepi64_si128(tmp2, precomp, 0x10);

	return _mm_xor_si128(tmp1, tmp0);
}

/**
 * Performs Barret's reduction from 64 bits to 32 bits
 *
 * @param data64
 *   64 bits data to be reduced
 * @param precomp
 *   rk7 precomputed constant
 *
 * @return
 *   reduced 32 bits data
 */

static __rte_always_inline uint32_t
crcr32_reduce_64_to_32(__m512i data64, __m512i precomp)
{
	static const uint32_t mask1[4] __rte_aligned(64) = {
		0xffffffff, 0xffffffff, 0x00000000, 0x00000000
	};

	static const uint32_t mask2[4] __rte_aligned(64) = {
		0x00000000, 0xffffffff, 0xffffffff, 0xffffffff
	};
	__m512i tmp0, tmp1, tmp2;

	tmp0 = _mm512_and_si512(data64, _mm512_load_si512(
		(const __m512i *)mask2));

	tmp1 = _mm512_clmulepi64_epi128(tmp0, precomp, 0x00);
	tmp1 = _mm512_xor_si512(tmp1, tmp0);
	tmp1 = _mm512_and_si512(tmp1, _mm512_load_si512(
		(const __m128i *)mask1));

	tmp2 = _mm512_clmulepi64_epi128(tmp1, precomp, 0x10);
	tmp2 = _mm512_xor_si512(tmp2, tmp1);
	tmp2 = _mm512_xor_si512(tmp2, tmp0);

	return 0;
}

static const uint8_t crc_xmm_shift_tab[48] __rte_aligned(64) = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
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

static __rte_always_inline __m512i
xmm_shift_left(__m512i reg, const unsigned int num)
{
	const __m512i *p = (const __m512i *)(crc_xmm_shift_tab + 16 - num);

	/* TODO: Check unaligned load*/
	return _mm512_shuffle_epi8(reg, _mm512_load_si512(p));
}

static __rte_always_inline uint32_t
crc32_eth_calc_pclmulqdq(
	const uint8_t *data,
	uint32_t data_len,
	uint32_t crc,
	const struct crc_pclmulqdq512_ctx *params)
{
	__m256i b;
	__m512i temp, k;
	__m512i qw0 = _mm512_set1_epi64(0);
	__m512i fold0;
	uint32_t n;

	/* Get CRC init value */
	b = _mm256_insert_epi32(_mm256_setzero_si256(), crc, 0);
	temp = _mm512_inserti32x8(_mm512_setzero_si512(), b, 0);

	/* align data to 16B*/
	if (unlikely(data_len < 64)) {
		if (unlikely(data_len == 16)) {
			/* 16 bytes */
			/* TODO: Unaligned load not working */
			fold0 = _mm512_load_epi64((const __m512i *)data);
			fold0 = _mm512_xor_si512(fold0, temp);
			goto reduction_128_64;
		}

		if (unlikely(data_len < 16)) {
			/* 0 to 15 bytes */
			uint8_t buffer[16] __rte_aligned(16);

			memset(buffer, 0, sizeof(buffer));
			memcpy(buffer, data, data_len);

			fold0 = _mm512_load_si512((const __m128i *)buffer);
			fold0 = _mm512_xor_si512(fold0, temp);
			if (unlikely(data_len < 4)) {
				fold0 = xmm_shift_left(fold0, 8 - data_len);
				goto barret_reduction;
			}
			fold0 = xmm_shift_left(fold0, 16 - data_len);
			goto reduction_128_64;
		}
		/* 17 to 31 bytes */
		fold0 = _mm512_loadu_si512((const __m512i *)data);
		fold0 = _mm512_xor_si512(fold0, temp);
		n = 16;
		k = params->rk1_rk2;
		goto partial_bytes;
	}

	/*Loop of folds*/
	/** At least 32 bytes in the buffer */
	/** Apply CRC initial value */
	fold0 = _mm512_loadu_si512((const __m512i *)data);
	fold0 = _mm512_xor_si512(fold0, temp);

	/** Main folding loop - the last 32 bytes is processed separately */
	k = params->rk1_rk2;
	for (n = 64; (n + 64) <= data_len; n += 64) {
		qw0 = _mm512_loadu_si512((const __m512i *)&data[n]);
		fold0 = crcr32_folding_round(qw0, k, fold0);
	}

	/* 256 to 128 fold */
	/* Check this */
	k = params->rk3_rk4;
	fold0 = crcr32_folding_round(temp, k, fold0);
	n += 64;

	/* Remainder */
partial_bytes:
	if (likely(n < data_len)) {

		const uint32_t mask3[4] __rte_aligned(16) = {
			0x80808080, 0x80808080, 0x80808080, 0x80808080
		};

		const uint8_t shf_table[32] __rte_aligned(16) = {
			0x00, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
			0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
		};

		__m128i last16;
		__m512i a, b;

		last16 = _mm_loadu_si128((const __m128i *)&data[data_len - 16]);

		RTE_SET_USED(last16);

		temp = _mm512_loadu_si512((const __m512i *)
			&shf_table[data_len & 15]);
		a = _mm512_shuffle_epi8(fold0, temp);

		temp = _mm512_xor_si512(temp,
			_mm512_load_si512((const __m512i *)mask3));
		b = _mm512_shuffle_epi8(fold0, temp);

		/* k = rk1 & rk2 */
		temp = _mm512_clmulepi64_epi128(a, k, 0x01);
		fold0 = _mm512_clmulepi64_epi128(a, k, 0x10);

		fold0 = _mm512_xor_si512(fold0, temp);
		fold0 = _mm512_xor_si512(fold0, b);
	}

	/** Reduction 128 -> 32 Assumes: fold holds 128bit folded data */
reduction_128_64:
	k = params->rk5_rk6;

barret_reduction:
	k = params->rk7_rk8;
	n = crcr32_reduce_64_to_32(fold0, k);

	return n;
}


static inline void
rte_net_crc_avx512_init(void)
{
	__m128i a;
	uint64_t k1, k2, k3, k4, k5, k6;
	uint64_t p = 0, q = 0;

	/** Initialize CRC32 data */
	/* 256 fold constants*/
	k1 = 0xe95c1271LLU;
	k2 = 0xce3371cbLLU;

	/*256 - 128 fold constants */
	k3 = 0x910eeec1LLU;
	k4 = 0x33fff533LLU;

	k5 = 0xccaa009eLLU;
	k6 = 0x163cd6124LLU;
	q =  0x1f7011640LLU;
	p =  0x1db710641LLU;

	/** Save the params in context structure */
	a = _mm_set_epi64x(k2, k1);
	crc32_eth_pclmulqdq.rk1_rk2 = _mm512_broadcast_i32x4(a);
	crc32_eth_pclmulqdq.rk3_rk4 = _mm512_setr_epi64(
		k3, k4, 0, 0, 0, 0, 0, 0);
	crc32_eth_pclmulqdq.rk5_rk6 = _mm512_setr_epi64(
		k5, k6, 0, 0, 0, 0, 0, 0);
	crc32_eth_pclmulqdq.rk7_rk8 = _mm512_setr_epi64(
		q, p, 0, 0, 0, 0, 0, 0);
	/**
	 * Reset the register as following calculation may
	 * use other data types such as float, double, etc.
	 */
	_mm_empty();

}

static inline uint32_t
rte_crc32_eth_avx512_handler(const uint8_t *data,
	uint32_t data_len)
{
	return ~crc32_eth_calc_pclmulqdq(data,
		data_len,
		0xffffffffUL,
		&crc32_eth_pclmulqdq);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_NET_CRC_AVX_H_ */
