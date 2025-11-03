/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2016-2025 Alex Kiselev BisonRouter.com
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_memory.h>
#include <rte_lpm6.h>
#include <rte_lpm6c.h>
#include <rte_fib6.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_prefetch.h>

#include "test.h"

#define TEST_LPM_ASSERT(cond) do { \
	if (!(cond)) { \
		printf("Error at line %d:\n", __LINE__); \
		return -1; \
	} \
} while (0)

static inline void
lpm6_test_addr_gen(uint64_t rnd, struct rte_ipv6_addr *ip, unsigned int offs)
{
	ip->a[offs] = (uint8_t)(rnd & 0xFF);
	ip->a[offs + 1] = (uint8_t)((rnd & 0xFF00) >> 8);
}

static void
lpm6_test_prefetch_test_data(unsigned int prefix_cnt, uint64_t *rand_ints)
{
	volatile uint64_t sum = 0;

	for (unsigned int i = 0; i < prefix_cnt; i++) {
		rte_prefetch0(&rand_ints[i]);
		sum += rand_ints[i];
	}
}

/*
 * Convert a string to an ipv6 address
 */
static inline bool
ipv6_str_to_addr(const char *ip6str, uint8_t *ip6)
{
	return inet_pton(AF_INET6, ip6str, ip6) == 1;
}

static __rte_noinline int
rte_lpm6c_lookup_bulk_noinline_(const struct rte_lpm6c *lpm,
		  const struct rte_ipv6_addr *ips,
		  int32_t *next_hops, const unsigned int n)
{
	return rte_lpm6c_lookup_bulk(lpm, ips, next_hops, n);
}

static __rte_noinline int
rte_lpm6c_lookup_noinline_(const struct rte_lpm6c *lpm,
		  const struct rte_ipv6_addr *ip,
		  uint32_t *next_hop)
{
	return rte_lpm6c_lookup(lpm, ip, next_hop);
}

static void
lpm6_prefix_test(unsigned int prefix_size)
{
	uint32_t max_rules = 524288;
	struct rte_lpm6_config lpm_config;
	struct rte_lpm6c_config lpmc_config;
	struct rte_lpm6 *lpm;
	struct rte_lpm6c *lpm_c;
	uint8_t depth;
	struct rte_ipv6_addr ip;

	#define LPM_LOOKUP_TEST_BULK_SIZE 32
	const unsigned int test_rounds = 10000;
	const unsigned int prefix_cnt = LPM_LOOKUP_TEST_BULK_SIZE * 2000;

	struct rte_ipv6_addr ip_vec[LPM_LOOKUP_TEST_BULK_SIZE];
	uint32_t next_hop_r, next_hop_cr;
	int32_t next_hop_arr[LPM_LOOKUP_TEST_BULK_SIZE];
	uint64_t rand_ints[prefix_cnt];

	uint64_t next_hop_fr;
	uint64_t next_hop_fr_arr[LPM_LOOKUP_TEST_BULK_SIZE];
	int ret, ret1, ret2, ret3;
	volatile uint64_t cnt1, cnt2, cnt3, cnt4, cnt5;
	uint64_t t1, t2, tsum1, tsum2, tsum3, tsum4, tsum5;
	struct rte_fib6 *fib6 = NULL;
	struct rte_fib6_conf config;
	unsigned int socket_id;
	unsigned int ip_offs;
	bool warmup_run = true;
	struct rte_hash *uniq_addr_ht;

	printf("LMP6 prefix /%u tests\n", prefix_size);

	ip_offs = prefix_size / 8 - 2;

	/*
	 * Initialize LPM structures
	 */
	config.type = RTE_FIB6_TRIE;
	config.max_routes = (1 << 16) - 1;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.trie.nh_sz = RTE_FIB6_TRIE_4B;
	config.trie.num_tbl8 = (1 << 22);

	socket_id = SOCKET_ID_ANY;
	fib6 = rte_fib6_create("fib6", socket_id, &config);
	assert(fib6 != NULL);

	lpm_config.flags = 0;
	lpm_config.max_rules = max_rules;
	lpm_config.number_tbl8s = 800000;

	lpmc_config.flags = 0;
	lpmc_config.max_rules = max_rules;
	lpmc_config.number_tbl8s = 800000;

	lpm = rte_lpm6_create("test", socket_id, &lpm_config);
	assert(lpm != NULL);

	lpm_c = rte_lpm6c_create("test_c", socket_id, &lpmc_config);
	assert(lpm_c != NULL);

	assert(prefix_cnt < UINT16_MAX);

	/*
	 * Init prefixes
	 */
	ipv6_str_to_addr("2001::", ip.a);
	for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++)
		ipv6_str_to_addr("2001::", ip_vec[i].a);
	depth = prefix_size;

	const struct rte_hash_parameters hash_params = {
		.entries = prefix_cnt * 1.3,
		.key_len = sizeof(struct rte_ipv6_addr),
		.hash_func = rte_jhash,
		.hash_func_init_val = 0,
		.name = "lpm6_test_uniq_add_tb",
		.reserved = 0,
		.socket_id = socket_id,
		.extra_flag = 0,
	};

	uniq_addr_ht = rte_hash_create(&hash_params);
	assert(uniq_addr_ht != NULL);

	/*
	 * Populate LPMs
	 */
	for (unsigned int i = 0; i < prefix_cnt; i++) {
		/* generate unique IPv6 addresses */
		do {
			rand_ints[i] = (uint64_t)rte_rand();
			lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
		} while (rte_hash_lookup(uniq_addr_ht, (const void *)ip.a) != -ENOENT);
		rte_hash_add_key(uniq_addr_ht, (const void *)ip.a);

		ret = rte_lpm6c_add(lpm_c, &ip, depth, i + 1);
		assert(ret == 0);
		ret = rte_lpm6_add(lpm, &ip, depth, i + 1);
		assert(ret == 0);
		ret = rte_fib6_add(fib6, &ip, depth, i + 1);
		assert(ret == 0);
	}

	/* Test correctness */
	for (unsigned int i = 0; i < prefix_cnt; i++) {
		lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);

		ret1 = rte_lpm6_lookup(lpm, &ip, &next_hop_r);
		ret2 = rte_lpm6c_lookup_noinline_(lpm_c, &ip, &next_hop_cr);
		ret3 = rte_fib6_lookup_bulk(fib6, &ip, &next_hop_fr, 1);

		assert(ret1 == ret2);
		if (ret1 == 0) {
			assert(next_hop_r == next_hop_cr);
			assert(next_hop_r == next_hop_fr);
		}
	}

	/*
	 * Lookup performance tests
	 */
	tsum1 = 0;
	tsum2 = 0;
	tsum3 = 0;
	tsum4 = 0;
	tsum5 = 0;

	for (unsigned int j = 0; j < test_rounds; j++) {
		/*
		 * LPM6
		 */
		lpm6_test_prefetch_test_data(prefix_cnt, rand_ints);
		cnt1 = 0;

		if (warmup_run) {
			for (unsigned int i = 0; i < prefix_cnt; i++) {
				lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
				next_hop_r = 0;
				rte_lpm6_lookup(lpm, &ip, &next_hop_r);
				cnt1 += next_hop_r;
			}
		}

		t1 = rte_rdtsc();
		for (unsigned int i = 0; i < prefix_cnt; i++) {
			lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
			next_hop_r = 0;
			rte_lpm6_lookup(lpm, &ip, &next_hop_r);
			cnt1 += next_hop_r;
		}
		t2 = rte_rdtsc();
		tsum1 += t2 - t1;

		/*
		 * LPM6 compressed
		 */
		lpm6_test_prefetch_test_data(prefix_cnt, rand_ints);
		cnt2 = 0;

		if (warmup_run) {
			for (unsigned int i = 0; i < prefix_cnt; i++) {
				lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
				next_hop_r = 0;
				rte_lpm6c_lookup_noinline_(lpm_c, &ip, &next_hop_r);
				cnt2 += next_hop_r;
			}
		}

		t1 = rte_rdtsc();
		for (unsigned int i = 0; i < prefix_cnt; i++) {
			lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
			next_hop_r = 0;
			rte_lpm6c_lookup_noinline_(lpm_c, &ip, &next_hop_r);
			cnt2 += next_hop_r;
		}
		t2 = rte_rdtsc();
		tsum2 += t2 - t1;

		/*
		 * LPM6 compressed bulk
		 */
		lpm6_test_prefetch_test_data(prefix_cnt, rand_ints);
		cnt5 = 0;

		if (warmup_run) {
			for (unsigned int k = 0; k < prefix_cnt / LPM_LOOKUP_TEST_BULK_SIZE;
					k++) {
				for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++) {
					unsigned int ind = k * LPM_LOOKUP_TEST_BULK_SIZE + i;
					lpm6_test_addr_gen(rand_ints[ind], &ip_vec[i], ip_offs);
				}

				rte_lpm6c_lookup_bulk_noinline_(lpm_c, ip_vec, next_hop_arr,
						  LPM_LOOKUP_TEST_BULK_SIZE);
				for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++)
					cnt5 += next_hop_arr[i];
			}
		}

		t1 = rte_rdtsc();
		for (unsigned int k = 0; k < prefix_cnt / LPM_LOOKUP_TEST_BULK_SIZE;
				k++) {
			for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++) {
				unsigned int ind = k * LPM_LOOKUP_TEST_BULK_SIZE + i;
				lpm6_test_addr_gen(rand_ints[ind], &ip_vec[i], ip_offs);
			}

			rte_lpm6c_lookup_bulk_noinline_(lpm_c, ip_vec, next_hop_arr,
					  LPM_LOOKUP_TEST_BULK_SIZE);
			for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++)
				cnt5 += next_hop_arr[i];
		}
		t2 = rte_rdtsc();
		tsum5 += t2 - t1;

		/*
		 * FIB
		 */
		lpm6_test_prefetch_test_data(prefix_cnt, rand_ints);
		cnt3 = 0;

		if (warmup_run) {
			for (unsigned int i = 0; i < prefix_cnt; i++) {
				lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
				next_hop_r = 0;
				rte_fib6_lookup_bulk(fib6, &ip, &next_hop_fr, 1);
				cnt3 += next_hop_fr;
			}
		}

		t1 = rte_rdtsc();
		for (unsigned int i = 0; i < prefix_cnt; i++) {
			lpm6_test_addr_gen(rand_ints[i], &ip, ip_offs);
			next_hop_r = 0;
			rte_fib6_lookup_bulk(fib6, &ip, &next_hop_fr, 1);
			cnt3 += next_hop_fr;
		}
		t2 = rte_rdtsc();
		tsum3 += t2 - t1;

		/*
		 * FIB bulk
		 */
		lpm6_test_prefetch_test_data(prefix_cnt, rand_ints);
		cnt4 = 0;

		if (warmup_run) {
			for (unsigned int k = 0; k < prefix_cnt / LPM_LOOKUP_TEST_BULK_SIZE;
					k++) {
				for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++) {
					unsigned int ind = k * LPM_LOOKUP_TEST_BULK_SIZE + i;
					lpm6_test_addr_gen(rand_ints[ind], &ip_vec[i], ip_offs);
				}

				ret3 = rte_fib6_lookup_bulk(fib6, ip_vec, next_hop_fr_arr,
						  LPM_LOOKUP_TEST_BULK_SIZE);
				for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++)
					cnt4 += next_hop_fr_arr[i];
				assert(ret3 == 0);
			}
		}

		t1 = rte_rdtsc();
		for (unsigned int k = 0; k < prefix_cnt / LPM_LOOKUP_TEST_BULK_SIZE;
				k++) {
			for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++) {
				unsigned int ind = k * LPM_LOOKUP_TEST_BULK_SIZE + i;
				lpm6_test_addr_gen(rand_ints[ind], &ip_vec[i], ip_offs);
			}

			ret3 = rte_fib6_lookup_bulk(fib6, ip_vec, next_hop_fr_arr,
					  LPM_LOOKUP_TEST_BULK_SIZE);
			for (unsigned int i = 0; i < LPM_LOOKUP_TEST_BULK_SIZE; i++)
				cnt4 += next_hop_fr_arr[i];
			assert(ret3 == 0);
		}
		t2 = rte_rdtsc();
		tsum4 += t2 - t1;
	}

	assert(cnt1 == cnt2);
	assert(cnt1 == cnt3);
	assert(cnt1 == cnt4);
	assert(cnt1 == cnt5);

	printf("Speedup vs LPM6: LPM6c %.3fx, LPM6c VEC %.3fx, FIB %.3fx, "
			  "FIB VEC %.3fx\n",
			  (double)tsum1 / tsum2,
			  (double)tsum1 / tsum5,
			  (double)tsum1 / tsum3,
			  (double)tsum1 / tsum4);

	rte_lpm6_free(lpm);
	rte_lpm6c_free(lpm_c);
	rte_fib6_free(fib6);
	rte_hash_free(uniq_addr_ht);
}

static int
test_lpm6c_perf_cmp(void)
{
	unsigned int cnt = 1;

	printf("Starting LPM6 performance comparison tests\n");

	for (unsigned int i = 1; i <= cnt; i++) {
		printf("=== run %u/32 ===\n", i);
		lpm6_prefix_test(32);
	}
	for (unsigned int i = 1; i <= cnt; i++) {
		printf("=== run %u/48 ===\n", i);
		lpm6_prefix_test(48);
	}
	for (unsigned int i = 1; i <= cnt; i++) {
		printf("=== run %u/64 ===\n", i);
		lpm6_prefix_test(64);
	}
	for (unsigned int i = 1; i <= cnt; i++) {
		printf("=== run %u/80 ===\n", i);
		lpm6_prefix_test(80);
	}
	for (unsigned int i = 1; i <= cnt; i++) {
		printf("=== run %u/128 ===\n", i);
		lpm6_prefix_test(128);
	}

	return 0;
}

REGISTER_PERF_TEST(lpm6c_perf_cmp_autotest, test_lpm6c_perf_cmp);
