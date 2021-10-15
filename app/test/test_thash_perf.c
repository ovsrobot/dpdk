/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <math.h>

#include <rte_cycles.h>
#include <rte_malloc.h>
#include <rte_random.h>
#include <rte_thash.h>

#include "test.h"

#define ITERATIONS	(1 << 15)
#define	BATCH_SZ	(1 << 10)

#define IPV4_2_TUPLE_LEN	(8)
#define IPV4_4_TUPLE_LEN	(12)
#define IPV6_2_TUPLE_LEN	(32)
#define IPV6_4_TUPLE_LEN	(36)


static uint8_t default_rss_key[] = {
	0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
	0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
	0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
	0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
	0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

static void
run_thash_test(unsigned int tuple_len)
{
	uint32_t *tuples[BATCH_SZ];
	unsigned int i, j;
	uint64_t start_tsc, end_tsc;
	uint32_t len = RTE_ALIGN_CEIL(tuple_len, sizeof(uint32_t));
	volatile uint32_t hash = 0;
	uint32_t hash_1 = 0;
	uint32_t hash_2 = 0;

	for (i = 0; i < BATCH_SZ; i++) {
		tuples[i] = rte_zmalloc(NULL, len, 0);
		for (j = 0; j < len / sizeof(uint32_t); j++)
			tuples[i][j] = rte_rand();
	}

	start_tsc = rte_rdtsc_precise();
	for (i = 0; i < ITERATIONS; i++) {
		for (j = 0; j < BATCH_SZ; j++) {
			hash ^= rte_softrss(tuples[j], len / sizeof(uint32_t),
				default_rss_key);
		}
	}
	end_tsc = rte_rdtsc_precise();

	printf("Average rte_softrss() takes \t\t%.1f cycles for key len %d\n",
		(double)(end_tsc - start_tsc) / (double)(ITERATIONS *
		BATCH_SZ), len);

	start_tsc = rte_rdtsc_precise();
	for (i = 0; i < ITERATIONS; i++) {
		for (j = 0; j < BATCH_SZ; j++) {
			hash ^= rte_softrss_be(tuples[j], len /
				sizeof(uint32_t), default_rss_key);
		}
	}
	end_tsc = rte_rdtsc_precise();

	printf("Average rte_softrss_be() takes \t\t%.1f cycles for key len %d\n",
		(double)(end_tsc - start_tsc) / (double)(ITERATIONS *
		BATCH_SZ), len);

	if (!rte_thash_gfni_supported)
		return;

	uint64_t rss_key_matrixes[RTE_DIM(default_rss_key)];

	rte_thash_complete_matrix(rss_key_matrixes, default_rss_key,
		RTE_DIM(default_rss_key));

	start_tsc = rte_rdtsc_precise();
	for (i = 0; i < ITERATIONS; i++) {
		for (j = 0; j < BATCH_SZ; j++)
			hash ^= rte_thash_gfni(rss_key_matrixes,
				(uint8_t *)tuples[j], len);
	}
	end_tsc = rte_rdtsc_precise();

	printf("Average rte_thash_gfni takes \t\t%.1f cycles for key len %d\n",
		(double)(end_tsc - start_tsc) / (double)(ITERATIONS *
		BATCH_SZ), len);

	start_tsc = rte_rdtsc_precise();
	for (i = 0; i < ITERATIONS; i++) {
		for (j = 0; j < BATCH_SZ; j += 2) {
			rte_thash_gfni_x2(rss_key_matrixes,
				(uint8_t *)tuples[j], (uint8_t *)tuples[j + 1],
				len, &hash_1, &hash_2);

			hash ^= hash_1 ^ hash_2;
		}
	}
	end_tsc = rte_rdtsc_precise();

	printf("Average rte_thash_gfni_x2 takes \t%.1f cycles for key len %d\n",
		(double)(end_tsc - start_tsc) / (double)(ITERATIONS *
		BATCH_SZ), len);
}

static int
test_thash_perf(void)
{
	run_thash_test(IPV4_2_TUPLE_LEN);
	run_thash_test(IPV4_4_TUPLE_LEN);
	run_thash_test(IPV6_2_TUPLE_LEN);
	run_thash_test(IPV6_4_TUPLE_LEN);

	return 0;
}

REGISTER_TEST_COMMAND(thash_perf_autotest, test_thash_perf);
