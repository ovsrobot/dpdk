/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2020 Intel Corporation
 */

#include <stddef.h>
#include <string.h>
#include <stdint.h>

#include <rte_cpuflags.h>
#include <rte_common.h>
#include <rte_net_crc.h>

#include "net_crc.h"

/** CRC polynomials */
#define CRC32_ETH_POLYNOMIAL 0x04c11db7UL
#define CRC16_CCITT_POLYNOMIAL 0x1021U

#define CRC_LUT_SIZE 256

/* crc tables */
static uint32_t crc32_eth_lut[CRC_LUT_SIZE];
static uint32_t crc16_ccitt_lut[CRC_LUT_SIZE];

static uint32_t
rte_crc16_ccitt_handler(const uint8_t *data, uint32_t data_len);

static uint32_t
rte_crc32_eth_handler(const uint8_t *data, uint32_t data_len);

typedef uint32_t
(*rte_net_crc_handler)(const uint8_t *data, uint32_t data_len);

static rte_net_crc_handler *handlers;

static rte_net_crc_handler handlers_scalar[] = {
	[RTE_NET_CRC16_CCITT] = rte_crc16_ccitt_handler,
	[RTE_NET_CRC32_ETH] = rte_crc32_eth_handler,
};
#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
static rte_net_crc_handler handlers_avx512[] = {
	[RTE_NET_CRC16_CCITT] = rte_crc16_ccitt_avx512_handler,
	[RTE_NET_CRC32_ETH] = rte_crc32_eth_avx512_handler,
};
#endif
#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
static rte_net_crc_handler handlers_sse42[] = {
	[RTE_NET_CRC16_CCITT] = rte_crc16_ccitt_sse42_handler,
	[RTE_NET_CRC32_ETH] = rte_crc32_eth_sse42_handler,
};
#endif
#ifdef CC_ARM64_NEON_PMULL_SUPPORT
static rte_net_crc_handler handlers_neon[] = {
	[RTE_NET_CRC16_CCITT] = rte_crc16_ccitt_neon_handler,
	[RTE_NET_CRC32_ETH] = rte_crc32_eth_neon_handler,
};
#endif

/**
 * Reflect the bits about the middle
 *
 * @param val
 *   value to be reflected
 *
 * @return
 *   reflected value
 */
static uint32_t
reflect_32bits(uint32_t val)
{
	uint32_t i, res = 0;

	for (i = 0; i < 32; i++)
		if ((val & (1U << i)) != 0)
			res |= (uint32_t)(1U << (31 - i));

	return res;
}

static void
crc32_eth_init_lut(uint32_t poly,
	uint32_t *lut)
{
	uint32_t i, j;

	for (i = 0; i < CRC_LUT_SIZE; i++) {
		uint32_t crc = reflect_32bits(i);

		for (j = 0; j < 8; j++) {
			if (crc & 0x80000000L)
				crc = (crc << 1) ^ poly;
			else
				crc <<= 1;
		}
		lut[i] = reflect_32bits(crc);
	}
}

static __rte_always_inline uint32_t
crc32_eth_calc_lut(const uint8_t *data,
	uint32_t data_len,
	uint32_t crc,
	const uint32_t *lut)
{
	while (data_len--)
		crc = lut[(crc ^ *data++) & 0xffL] ^ (crc >> 8);

	return crc;
}

static void
rte_net_crc_scalar_init(void)
{
	/* 32-bit crc init */
	crc32_eth_init_lut(CRC32_ETH_POLYNOMIAL, crc32_eth_lut);

	/* 16-bit CRC init */
	crc32_eth_init_lut(CRC16_CCITT_POLYNOMIAL << 16, crc16_ccitt_lut);
}

static inline uint32_t
rte_crc16_ccitt_handler(const uint8_t *data, uint32_t data_len)
{
	/* return 16-bit CRC value */
	return (uint16_t)~crc32_eth_calc_lut(data,
		data_len,
		0xffff,
		crc16_ccitt_lut);
}

static inline uint32_t
rte_crc32_eth_handler(const uint8_t *data, uint32_t data_len)
{
	/* return 32-bit CRC value */
	return ~crc32_eth_calc_lut(data,
		data_len,
		0xffffffffUL,
		crc32_eth_lut);
}

#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
static uint8_t
avx512_vpclmulqdq_cpu_supported(void)
{
	return rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) &&
		rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) &&
		rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512DQ) &&
		rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512VL) &&
		rte_cpu_get_flag_enabled(RTE_CPUFLAG_PCLMULQDQ) &&
		rte_cpu_get_flag_enabled(RTE_CPUFLAG_VPCLMULQDQ);
}
#endif

#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
static uint8_t
sse42_pclmulqdq_cpu_supported(void)
{
	return rte_cpu_get_flag_enabled(RTE_CPUFLAG_PCLMULQDQ);
}
#endif

#ifdef CC_ARM64_NEON_PMULL_SUPPORT
static uint8_t
neon_pmull_cpu_supported(void)
{
	return rte_cpu_get_flag_enabled(RTE_CPUFLAG_PMULL);
}
#endif

void
rte_net_crc_set_alg(enum rte_net_crc_alg alg)
{
	switch (alg) {
#ifdef RTE_ARCH_X86_64
	case RTE_NET_CRC_AVX512:
#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
		if (avx512_vpclmulqdq_cpu_supported()) {
			handlers = handlers_avx512;
			break;
		}
#endif
		/* fall-through */
	case RTE_NET_CRC_SSE42:
#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
		if (sse42_pclmulqdq_cpu_supported()) {
			handlers = handlers_sse42;
			break;
		}
#endif
#endif /* RTE_ARCH_X86_64 */
#ifdef RTE_ARCH_ARM64
	case RTE_NET_CRC_NEON:
#ifdef CC_ARM64_NEON_PMULL_SUPPORT
		if (neon_pmull_cpu_supported()) {
			handlers = handlers_neon;
			break;
		}
#endif
#endif /* RTE_ARCH_ARM64 */
		/* fall-through */
	case RTE_NET_CRC_SCALAR:
		/* fall-through */
	default:
		handlers = handlers_scalar;
		break;
	}
}

uint32_t
rte_net_crc_calc(const void *data,
	uint32_t data_len,
	enum rte_net_crc_type type)
{
	uint32_t ret;
	rte_net_crc_handler f_handle;

	f_handle = handlers[type];
	ret = f_handle(data, data_len);

	return ret;
}

/* Select highest available crc algorithm as default one */
RTE_INIT(rte_net_crc_init)
{
	enum rte_net_crc_alg alg = RTE_NET_CRC_SCALAR;

	rte_net_crc_scalar_init();

#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
	if (sse42_pclmulqdq_cpu_supported()) {
		alg = RTE_NET_CRC_SSE42;
		rte_net_crc_sse42_init();
	}
#endif
#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
	if (avx512_vpclmulqdq_cpu_supported()) {
		alg = RTE_NET_CRC_AVX512;
		rte_net_crc_avx512_init();
	}
#endif
#ifdef CC_ARM64_NEON_PMULL_SUPPORT
	if (neon_pmull_cpu_supported()) {
		alg = RTE_NET_CRC_NEON;
		rte_net_crc_neon_init();
	}
#endif

	rte_net_crc_set_alg(alg);
}
