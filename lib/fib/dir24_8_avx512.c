/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <rte_vect.h>
#include <rte_fib.h>
#include <rte_debug.h>

#include "dir24_8.h"
#include "dir24_8_avx512.h"

enum vrf_scale {
	VRF_SCALE_SINGLE = 0,
	VRF_SCALE_SMALL = 1,
	VRF_SCALE_LARGE = 2,
};

static __rte_always_inline void
dir24_8_vec_lookup_x8_64b_path(struct dir24_8_tbl *dp, __m256i ip_vec_256,
	__m256i vrf32_256, uint64_t *next_hops, int size)
{
	const __m512i zero_64 = _mm512_set1_epi64(0);
	const __m512i lsb_64 = _mm512_set1_epi64(1);
	const __m512i lsbyte_msk_64 = _mm512_set1_epi64(0xff);
	__m512i res_msk_64, vrf64, idxes_64, res, bytes_64;
	__mmask8 msk_ext_64;

	if (size == sizeof(uint8_t))
		res_msk_64 = _mm512_set1_epi64(UINT8_MAX);
	else if (size == sizeof(uint16_t))
		res_msk_64 = _mm512_set1_epi64(UINT16_MAX);
	else if (size == sizeof(uint32_t))
		res_msk_64 = _mm512_set1_epi64(UINT32_MAX);

	vrf64 = _mm512_cvtepu32_epi64(vrf32_256);

	/* Compute index: (vrf_id << 24) + (ip >> 8) using 64-bit shift */
	idxes_64 = _mm512_slli_epi64(vrf64, 24);
	idxes_64 = _mm512_add_epi64(idxes_64, _mm512_cvtepu32_epi64(
		_mm256_srli_epi32(ip_vec_256, 8)));

	/* lookup in tbl24 */
	if (size == sizeof(uint8_t)) {
		res = _mm512_i64gather_epi64(idxes_64, (const void *)dp->tbl24, 1);
		res = _mm512_and_epi64(res, res_msk_64);
	} else if (size == sizeof(uint16_t)) {
		res = _mm512_i64gather_epi64(idxes_64, (const void *)dp->tbl24, 2);
		res = _mm512_and_epi64(res, res_msk_64);
	} else {
		res = _mm512_i64gather_epi64(idxes_64, (const void *)dp->tbl24, 4);
		res = _mm512_and_epi64(res, res_msk_64);
	}

	/* get extended entries indexes */
	msk_ext_64 = _mm512_test_epi64_mask(res, lsb_64);

	if (msk_ext_64 != 0) {
		bytes_64 = _mm512_cvtepu32_epi64(ip_vec_256);
		idxes_64 = _mm512_srli_epi64(res, 1);
		idxes_64 = _mm512_slli_epi64(idxes_64, 8);
		bytes_64 = _mm512_and_epi64(bytes_64, lsbyte_msk_64);
		idxes_64 = _mm512_maskz_add_epi64(msk_ext_64, idxes_64, bytes_64);

		if (size == sizeof(uint8_t))
			idxes_64 = _mm512_mask_i64gather_epi64(zero_64, msk_ext_64,
				idxes_64, (const void *)dp->tbl8, 1);
		else if (size == sizeof(uint16_t))
			idxes_64 = _mm512_mask_i64gather_epi64(zero_64, msk_ext_64,
				idxes_64, (const void *)dp->tbl8, 2);
		else
			idxes_64 = _mm512_mask_i64gather_epi64(zero_64, msk_ext_64,
				idxes_64, (const void *)dp->tbl8, 4);

		res = _mm512_mask_blend_epi64(msk_ext_64, res, idxes_64);
	}

	res = _mm512_srli_epi64(res, 1);
	_mm512_storeu_si512(next_hops, res);
}

static __rte_always_inline void
dir24_8_vec_lookup_x16_32b_path(struct dir24_8_tbl *dp, __m512i ip_vec,
	__m512i idxes, uint64_t *next_hops, int size)
{
	__mmask16 msk_ext;
	const __mmask16 exp_msk = 0x5555;
	const __m512i zero_32 = _mm512_set1_epi32(0);
	const __m512i lsb_32 = _mm512_set1_epi32(1);
	const __m512i lsbyte_msk_32 = _mm512_set1_epi32(0xff);
	__m512i res, bytes, tmp1, tmp2;
	__m256i tmp256;
	__m512i res_msk_32;

	if (size == sizeof(uint8_t))
		res_msk_32 = _mm512_set1_epi32(UINT8_MAX);
	else if (size == sizeof(uint16_t))
		res_msk_32 = _mm512_set1_epi32(UINT16_MAX);

	/*
	 * lookup in tbl24
	 * Put it inside branch to make compiler happy with -O0
	 */
	if (size == sizeof(uint8_t)) {
		res = _mm512_i32gather_epi32(idxes, (const int *)dp->tbl24, 1);
		res = _mm512_and_epi32(res, res_msk_32);
	} else if (size == sizeof(uint16_t)) {
		res = _mm512_i32gather_epi32(idxes, (const int *)dp->tbl24, 2);
		res = _mm512_and_epi32(res, res_msk_32);
	} else {
		res = _mm512_i32gather_epi32(idxes, (const int *)dp->tbl24, 4);
	}

	/* get extended entries indexes */
	msk_ext = _mm512_test_epi32_mask(res, lsb_32);

	if (msk_ext != 0) {
		idxes = _mm512_srli_epi32(res, 1);
		idxes = _mm512_slli_epi32(idxes, 8);
		bytes = _mm512_and_epi32(ip_vec, lsbyte_msk_32);
		idxes = _mm512_maskz_add_epi32(msk_ext, idxes, bytes);
		if (size == sizeof(uint8_t)) {
			idxes = _mm512_mask_i32gather_epi32(zero_32, msk_ext,
				idxes, (const int *)dp->tbl8, 1);
			idxes = _mm512_and_epi32(idxes, res_msk_32);
		} else if (size == sizeof(uint16_t)) {
			idxes = _mm512_mask_i32gather_epi32(zero_32, msk_ext,
				idxes, (const int *)dp->tbl8, 2);
			idxes = _mm512_and_epi32(idxes, res_msk_32);
		} else {
			idxes = _mm512_mask_i32gather_epi32(zero_32, msk_ext,
				idxes, (const int *)dp->tbl8, 4);
		}

		res = _mm512_mask_blend_epi32(msk_ext, res, idxes);
	}

	res = _mm512_srli_epi32(res, 1);
	tmp1 = _mm512_maskz_expand_epi32(exp_msk, res);
	tmp256 = _mm512_extracti32x8_epi32(res, 1);
	tmp2 = _mm512_maskz_expand_epi32(exp_msk,
		_mm512_castsi256_si512(tmp256));
	_mm512_storeu_si512(next_hops, tmp1);
	_mm512_storeu_si512(next_hops + 8, tmp2);
}

/* Unified function with vrf_scale parameter similar to be_addr */
static __rte_always_inline void
dir24_8_vec_lookup_x16(void *p, const uint16_t *vrf_ids, const uint32_t *ips,
	uint64_t *next_hops, int size, bool be_addr, enum vrf_scale vrf_scale)
{
	struct dir24_8_tbl *dp = (struct dir24_8_tbl *)p;
	__m512i ip_vec, idxes;
	__m256i ip_vec_256, vrf32_256;

	ip_vec = _mm512_loadu_si512(ips);
	if (be_addr) {
		const __m512i bswap32 = _mm512_set_epi32(
			0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203,
			0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203,
			0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203,
			0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203
		);
		ip_vec = _mm512_shuffle_epi8(ip_vec, bswap32);
	}

	if (vrf_scale == VRF_SCALE_SINGLE) {
		/* mask 24 most significant bits */
		idxes = _mm512_srli_epi32(ip_vec, 8);
		dir24_8_vec_lookup_x16_32b_path(dp, ip_vec, idxes, next_hops, size);
	} else if (vrf_scale == VRF_SCALE_SMALL) {
		/* For < 256 VRFs: use 32-bit indices with 32-bit shift */
		__m512i vrf32;
		uint32_t i;

		for (i = 0; i < 16; i++)
			RTE_ASSERT(vrf_ids[i] < dp->num_vrfs);

		vrf32 = _mm512_cvtepu16_epi32(_mm256_loadu_si256((const void *)vrf_ids));

		/* mask 24 most significant bits */
		idxes = _mm512_srli_epi32(ip_vec, 8);
		idxes = _mm512_add_epi32(idxes, _mm512_slli_epi32(vrf32, 24));
		dir24_8_vec_lookup_x16_32b_path(dp, ip_vec, idxes, next_hops, size);
	} else {
		/* For >= 256 VRFs: use 64-bit indices to avoid overflow */
		uint32_t i;

		for (i = 0; i < 16; i++)
			RTE_ASSERT(vrf_ids[i] < dp->num_vrfs);

		/* Extract first 8 IPs and VRF IDs */
		ip_vec_256 = _mm512_castsi512_si256(ip_vec);
		vrf32_256 = _mm256_cvtepu16_epi32(_mm_loadu_si128((const void *)vrf_ids));
		dir24_8_vec_lookup_x8_64b_path(dp, ip_vec_256, vrf32_256, next_hops, size);

		/* Process next 8 IPs from the second half of the vector */
		ip_vec_256 = _mm512_extracti32x8_epi32(ip_vec, 1);
		vrf32_256 = _mm256_cvtepu16_epi32(_mm_loadu_si128((const void *)(vrf_ids + 8)));
		dir24_8_vec_lookup_x8_64b_path(dp, ip_vec_256, vrf32_256, next_hops + 8, size);
	}
}

/* Unified function with vrf_scale parameter */
static __rte_always_inline void
dir24_8_vec_lookup_x8_8b(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, bool be_addr, enum vrf_scale vrf_scale)
{
	struct dir24_8_tbl *dp = (struct dir24_8_tbl *)p;
	const __m512i zero_64 = _mm512_set1_epi64(0);
	const __m512i lsbyte_msk_64 = _mm512_set1_epi64(0xff);
	const __m512i lsb_64 = _mm512_set1_epi64(1);
	__m512i res, idxes, bytes;
	__m256i ip_vec, vrf32_256;
	__mmask8 msk_ext;

	ip_vec = _mm256_loadu_si256((const void *)ips);
	if (be_addr) {
		const __m256i bswap32 = _mm256_set_epi8(
			12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3,
			12, 13, 14, 15, 8, 9, 10, 11, 4, 5, 6, 7, 0, 1, 2, 3
		);
		ip_vec = _mm256_shuffle_epi8(ip_vec, bswap32);
	}

	if (vrf_scale == VRF_SCALE_SINGLE) {
		/* For single VRF: use 32-bit indices without vrf_ids */
		__m256i idxes_256;

		/* mask 24 most significant bits */
		idxes_256 = _mm256_srli_epi32(ip_vec, 8);

		/* lookup in tbl24 */
		res = _mm512_i32gather_epi64(idxes_256, (const void *)dp->tbl24, 8);

		/* get extended entries indexes */
		msk_ext = _mm512_test_epi64_mask(res, lsb_64);

		if (msk_ext != 0) {
			bytes = _mm512_cvtepu32_epi64(ip_vec);
			idxes = _mm512_srli_epi64(res, 1);
			idxes = _mm512_slli_epi64(idxes, 8);
			bytes = _mm512_and_epi64(bytes, lsbyte_msk_64);
			idxes = _mm512_maskz_add_epi64(msk_ext, idxes, bytes);
			idxes = _mm512_mask_i64gather_epi64(zero_64, msk_ext, idxes,
				(const void *)dp->tbl8, 8);

			res = _mm512_mask_blend_epi64(msk_ext, res, idxes);
		}

		res = _mm512_srli_epi64(res, 1);
		_mm512_storeu_si512(next_hops, res);
	} else if (vrf_scale == VRF_SCALE_SMALL) {
		/* For < 256 VRFs: use 32-bit indices with 32-bit shift */
		__m256i idxes_256;
		uint32_t i;

		for (i = 0; i < 8; i++)
			RTE_ASSERT(vrf_ids[i] < dp->num_vrfs);

		/* mask 24 most significant bits */
		idxes_256 = _mm256_srli_epi32(ip_vec, 8);
		vrf32_256 = _mm256_cvtepu16_epi32(_mm_loadu_si128((const void *)vrf_ids));
		idxes_256 = _mm256_add_epi32(idxes_256, _mm256_slli_epi32(vrf32_256, 24));

		/* lookup in tbl24 */
		res = _mm512_i32gather_epi64(idxes_256, (const void *)dp->tbl24, 8);

		/* get extended entries indexes */
		msk_ext = _mm512_test_epi64_mask(res, lsb_64);

		if (msk_ext != 0) {
			bytes = _mm512_cvtepu32_epi64(ip_vec);
			idxes = _mm512_srli_epi64(res, 1);
			idxes = _mm512_slli_epi64(idxes, 8);
			bytes = _mm512_and_epi64(bytes, lsbyte_msk_64);
			idxes = _mm512_maskz_add_epi64(msk_ext, idxes, bytes);
			idxes = _mm512_mask_i64gather_epi64(zero_64, msk_ext, idxes,
				(const void *)dp->tbl8, 8);

			res = _mm512_mask_blend_epi64(msk_ext, res, idxes);
		}

		res = _mm512_srli_epi64(res, 1);
		_mm512_storeu_si512(next_hops, res);
	} else {
		/* For >= 256 VRFs: use 64-bit indices to avoid overflow */
		uint32_t i;

		for (i = 0; i < 8; i++)
			RTE_ASSERT(vrf_ids[i] < dp->num_vrfs);

		vrf32_256 = _mm256_cvtepu16_epi32(_mm_loadu_si128((const void *)vrf_ids));
		__m512i vrf64 = _mm512_cvtepu32_epi64(vrf32_256);

		/* Compute index: (vrf_id << 24) + (ip >> 8) using 64-bit arithmetic */
		idxes = _mm512_slli_epi64(vrf64, 24);
		idxes = _mm512_add_epi64(idxes, _mm512_cvtepu32_epi64(
			_mm256_srli_epi32(ip_vec, 8)));

		/* lookup in tbl24 with 64-bit gather */
		res = _mm512_i64gather_epi64(idxes, (const void *)dp->tbl24, 8);

		/* get extended entries indexes */
		msk_ext = _mm512_test_epi64_mask(res, lsb_64);

		if (msk_ext != 0) {
			bytes = _mm512_cvtepu32_epi64(ip_vec);
			idxes = _mm512_srli_epi64(res, 1);
			idxes = _mm512_slli_epi64(idxes, 8);
			bytes = _mm512_and_epi64(bytes, lsbyte_msk_64);
			idxes = _mm512_maskz_add_epi64(msk_ext, idxes, bytes);
			idxes = _mm512_mask_i64gather_epi64(zero_64, msk_ext, idxes,
				(const void *)dp->tbl8, 8);

			res = _mm512_mask_blend_epi64(msk_ext, res, idxes);
		}

		res = _mm512_srli_epi64(res, 1);
		_mm512_storeu_si512(next_hops, res);
	}
}

#define DECLARE_VECTOR_FN(suffix, scalar_suffix, nh_type, be_addr, vrf_scale) \
void \
rte_dir24_8_vec_lookup_bulk_##suffix(void *p, const uint16_t *vrf_ids, \
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n) \
{ \
	uint32_t i; \
	for (i = 0; i < (n / 16); i++) \
		dir24_8_vec_lookup_x16(p, vrf_ids + i * 16, ips + i * 16, \
			next_hops + i * 16, sizeof(nh_type), be_addr, vrf_scale); \
	dir24_8_lookup_bulk_##scalar_suffix(p, vrf_ids + i * 16, ips + i * 16, \
		next_hops + i * 16, n - i * 16); \
}

DECLARE_VECTOR_FN(1b, 1b, uint8_t, false, VRF_SCALE_SINGLE)
DECLARE_VECTOR_FN(1b_be, 1b_be, uint8_t, true, VRF_SCALE_SINGLE)
DECLARE_VECTOR_FN(2b, 2b, uint16_t, false, VRF_SCALE_SINGLE)
DECLARE_VECTOR_FN(2b_be, 2b_be, uint16_t, true, VRF_SCALE_SINGLE)
DECLARE_VECTOR_FN(4b, 4b, uint32_t, false, VRF_SCALE_SINGLE)
DECLARE_VECTOR_FN(4b_be, 4b_be, uint32_t, true, VRF_SCALE_SINGLE)

DECLARE_VECTOR_FN(vrf_1b, vrf_1b, uint8_t, false, VRF_SCALE_SMALL)
DECLARE_VECTOR_FN(vrf_1b_be, vrf_1b_be, uint8_t, true, VRF_SCALE_SMALL)
DECLARE_VECTOR_FN(vrf_2b, vrf_2b, uint16_t, false, VRF_SCALE_SMALL)
DECLARE_VECTOR_FN(vrf_2b_be, vrf_2b_be, uint16_t, true, VRF_SCALE_SMALL)
DECLARE_VECTOR_FN(vrf_4b, vrf_4b, uint32_t, false, VRF_SCALE_SMALL)
DECLARE_VECTOR_FN(vrf_4b_be, vrf_4b_be, uint32_t, true, VRF_SCALE_SMALL)

DECLARE_VECTOR_FN(vrf_1b_large, vrf_1b, uint8_t, false, VRF_SCALE_LARGE)
DECLARE_VECTOR_FN(vrf_1b_be_large, vrf_1b_be, uint8_t, true, VRF_SCALE_LARGE)
DECLARE_VECTOR_FN(vrf_2b_large, vrf_2b, uint16_t, false, VRF_SCALE_LARGE)
DECLARE_VECTOR_FN(vrf_2b_be_large, vrf_2b_be, uint16_t, true, VRF_SCALE_LARGE)
DECLARE_VECTOR_FN(vrf_4b_large, vrf_4b, uint32_t, false, VRF_SCALE_LARGE)
DECLARE_VECTOR_FN(vrf_4b_be_large, vrf_4b_be, uint32_t, true, VRF_SCALE_LARGE)

void
rte_dir24_8_vec_lookup_bulk_8b(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, false, VRF_SCALE_SINGLE);
	dir24_8_lookup_bulk_8b(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}

void
rte_dir24_8_vec_lookup_bulk_8b_be(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, true, VRF_SCALE_SINGLE);
	dir24_8_lookup_bulk_8b_be(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}

void
rte_dir24_8_vec_lookup_bulk_vrf_8b(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, false, VRF_SCALE_SMALL);
	dir24_8_lookup_bulk_vrf_8b(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}

void
rte_dir24_8_vec_lookup_bulk_vrf_8b_be(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, true, VRF_SCALE_SMALL);
	dir24_8_lookup_bulk_vrf_8b_be(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}

void
rte_dir24_8_vec_lookup_bulk_vrf_8b_large(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, false, VRF_SCALE_LARGE);
	dir24_8_lookup_bulk_vrf_8b(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}

void
rte_dir24_8_vec_lookup_bulk_vrf_8b_be_large(void *p, const uint16_t *vrf_ids,
	const uint32_t *ips, uint64_t *next_hops, const unsigned int n)
{
	uint32_t i;
	for (i = 0; i < (n / 8); i++)
		dir24_8_vec_lookup_x8_8b(p, vrf_ids + i * 8, ips + i * 8,
			next_hops + i * 8, true, VRF_SCALE_LARGE);
	dir24_8_lookup_bulk_vrf_8b_be(p, vrf_ids + i * 8, ips + i * 8,
		next_hops + i * 8, n - i * 8);
}
