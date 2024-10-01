/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017-2020 Intel Corporation
 */

#include <stdint.h>

#include <rte_cpuflags.h>
#include <rte_common.h>
#include <rte_net_crc.h>
#include <rte_log.h>
#include <rte_vect.h>

#include "net_crc.h"

RTE_LOG_REGISTER_DEFAULT(libnet_logtype, INFO);
#define RTE_LOGTYPE_NET libnet_logtype

#define NET_LOG(level, ...) \
	RTE_LOG_LINE_PREFIX(level, NET, "%s(): ", __func__, __VA_ARGS__)

#define CRC32_ETH_POLYNOMIAL 0x04c11db7UL
#define CRC16_CCITT_POLYNOMIAL 0x1021U
#define CRC_LUT_SIZE 256

static uint32_t crc32_eth_lut[CRC_LUT_SIZE];
static uint32_t crc16_ccitt_lut[CRC_LUT_SIZE];

static struct
{
	uint32_t (*f[RTE_NET_CRC_REQS])
		(const uint8_t *data, uint32_t data_len);
} handlers[RTE_NET_CRC_AVX512 + 1];

static inline uint32_t
reflect_32bits(uint32_t val)
{
	uint32_t i, res = 0;

	for (i = 0; i < 32; i++)
		if ((val & (1U << i)) != 0)
			res |= (uint32_t)(1U << (31 - i));

	return res;
}

static inline uint32_t
crc32_eth_calc_lut(const uint8_t *data,
	uint32_t data_len,
	uint32_t crc,
	const uint32_t *lut)
{
	while (data_len--)
		crc = lut[(crc ^ *data++) & 0xffL] ^ (crc >> 8);

	return crc;
}

static inline uint32_t
crc16_ccitt(const uint8_t *data, uint32_t data_len)
{
	return (uint16_t)~crc32_eth_calc_lut(data,
		data_len,
		0xffff,
		crc16_ccitt_lut);
}

static inline uint32_t
crc32_eth(const uint8_t *data, uint32_t data_len)
{
	return ~crc32_eth_calc_lut(data,
		data_len,
		0xffffffffUL,
		crc32_eth_lut);
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

static void
crc_scalar_init(void)
{
	crc32_eth_init_lut(CRC32_ETH_POLYNOMIAL, crc32_eth_lut);
	crc32_eth_init_lut(CRC16_CCITT_POLYNOMIAL << 16, crc16_ccitt_lut);

	handlers[RTE_NET_CRC_SCALAR].f[RTE_NET_CRC16_CCITT] = crc16_ccitt;
	handlers[RTE_NET_CRC_SCALAR].f[RTE_NET_CRC32_ETH] = crc32_eth;
}

#define AVX512_VPCLMULQDQ_CPU_SUPPORTED ( \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512F) && \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512BW) && \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512DQ) && \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_AVX512VL) && \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_PCLMULQDQ) && \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_VPCLMULQDQ) \
)

static void
avx512_vpclmulqdq_init(void)
{
#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
	if (AVX512_VPCLMULQDQ_CPU_SUPPORTED) {
		rte_net_crc_avx512_init();
		handlers[RTE_NET_CRC_AVX512].f[RTE_NET_CRC16_CCITT] =
			rte_crc16_ccitt_avx512_handler;
		handlers[RTE_NET_CRC_AVX512].f[RTE_NET_CRC32_ETH] =
			rte_crc32_eth_avx512_handler;
	}
#endif
}

#define SSE42_PCLMULQDQ_CPU_SUPPORTED \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_PCLMULQDQ)

static void
sse42_pclmulqdq_init(void)
{
#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
	if (SSE42_PCLMULQDQ_CPU_SUPPORTED) {
		rte_net_crc_sse42_init();
		handlers[RTE_NET_CRC_SSE42].f[RTE_NET_CRC16_CCITT] =
			rte_crc16_ccitt_sse42_handler;
		handlers[RTE_NET_CRC_SSE42].f[RTE_NET_CRC32_ETH] =
			rte_crc32_eth_sse42_handler;
	}
#endif
}

#define NEON_PMULL_CPU_SUPPORTED \
	rte_cpu_get_flag_enabled(RTE_CPUFLAG_PMULL)

static void
neon_pmull_init(void)
{
#ifdef CC_ARM64_NEON_PMULL_SUPPORT
	if (NEON_PMULL_CPU_SUPPORTED) {
		rte_net_crc_neon_init();
		handlers[RTE_NET_CRC_NEON].f[RTE_NET_CRC16_CCITT] =
			rte_crc16_ccitt_neon_handler;
		handlers[RTE_NET_CRC_NEON].f[RTE_NET_CRC32_ETH] =
			rte_crc32_eth_neon_handler;
	}
#endif
}

struct rte_net_crc rte_net_crc_set(enum rte_net_crc_alg alg,
	enum rte_net_crc_type type)
{
	uint16_t max_simd_bitwidth;

	max_simd_bitwidth = rte_vect_get_max_simd_bitwidth();

	switch (alg) {
	case RTE_NET_CRC_AVX512:
#ifdef CC_X86_64_AVX512_VPCLMULQDQ_SUPPORT
		if (AVX512_VPCLMULQDQ_CPU_SUPPORTED &&
				max_simd_bitwidth >= RTE_VECT_SIMD_512) {
			return (struct rte_net_crc){ RTE_NET_CRC_AVX512, type };
		}
#endif
		/* fall-through */
	case RTE_NET_CRC_SSE42:
#ifdef CC_X86_64_SSE42_PCLMULQDQ_SUPPORT
		if (SSE42_PCLMULQDQ_CPU_SUPPORTED &&
				max_simd_bitwidth >= RTE_VECT_SIMD_128) {
			return (struct rte_net_crc){ RTE_NET_CRC_SSE42, type };
		}
#endif
		break;
	case RTE_NET_CRC_NEON:
#ifdef CC_ARM64_NEON_PMULL_SUPPORT
		if (NEON_PMULL_CPU_SUPPORTED &&
				max_simd_bitwidth >= RTE_VECT_SIMD_128) {
			return (struct rte_net_crc){ RTE_NET_CRC_NEON, type };
		}
#endif
		break;
	default:
		break;
	}
	return (struct rte_net_crc){ RTE_NET_CRC_SCALAR, type };
}

uint32_t rte_net_crc(const struct rte_net_crc *ctx,
	const void *data, const uint32_t data_len)
{
	return handlers[ctx->alg].f[ctx->type](data, data_len);
}

RTE_INIT(rte_net_crc_init)
{
	crc_scalar_init();
	sse42_pclmulqdq_init();
	avx512_vpclmulqdq_init();
	neon_pmull_init();
}
