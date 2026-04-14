/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 AMD Corporation
 */

#include <sched.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_thread.h>
#include <rte_topology.h>

#include "test.h"

#ifndef _POSIX_PRIORITY_SCHEDULING
/* sched_yield(2):
 * POSIX systems on which sched_yield() is available define
 * _POSIX_PRIORITY_SCHEDULING in <unistd.h>.
 */
#define sched_yield()
#endif

#ifdef RTE_LIBHWLOC_PROBE

static const unsigned int domain_types[] = {
	RTE_TOPO_DOMAIN_NUMA,
	RTE_TOPO_DOMAIN_L4,
	RTE_TOPO_DOMAIN_L3,
	RTE_TOPO_DOMAIN_L2,
	RTE_TOPO_DOMAIN_L1
};

static int
test_topology_macro(void)
{
	unsigned int total_lcores = 0;
	unsigned int total_wrkr_lcores = 0;

	unsigned int count_lcore = 0;
	unsigned int total_lcore = 0;
	unsigned int total_wrkr_lcore = 0;

	unsigned int lcore = 0, pos = 0, domain = 0;

	/* get topology core count */
	lcore = -1;
	RTE_LCORE_FOREACH(lcore)
		total_lcores += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER(lcore)
		total_wrkr_lcores += 1;

	RTE_TEST_ASSERT(((total_wrkr_lcores + 1) == total_lcores),
		"fail in MACRO for RTE_LCORE_FOREACH\n");

	RTE_LOG(DEBUG, USER1, "Lcore: %u, Lcore Worker: %u\n", total_lcores, total_wrkr_lcores);
	RTE_LOG(DEBUG, USER1, "| %10s | %10s | %10s | %10s |\n",
		"domain name", "count", "LCORE", "WORKER");
	RTE_LOG(DEBUG, USER1, "------------------------------------------------------\n");

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		count_lcore = 0;
		total_lcore = 0;
		total_wrkr_lcore = 0;
		domain = RTE_TOPO_DOMAIN_MAX;
		RTE_TOPO_FOREACH_DOMAIN(domain, domain_types[d]) {
			count_lcore +=
				rte_topo_get_lcore_count_from_domain(domain_types[d], domain);

			lcore = RTE_MAX_LCORE;
			pos = 0;
			RTE_TOPO_FOREACH_LCORE_IN_DOMAIN(lcore, domain, pos, domain_types[d])
				total_lcore += 1;

			/* skip domain */
			if (rte_topo_is_main_lcore_in_domain(domain, domain_types[d]))
				continue;

			lcore = RTE_MAX_LCORE;
			RTE_TOPO_FOREACH_WORKER_LCORE_IN_DOMAIN(lcore, domain, domain_types[d]) {
				total_wrkr_lcore += 1;
			}
		}

		if (count_lcore) {
			RTE_TEST_ASSERT((total_wrkr_lcore < total_lcore),
				"unexpected workers in %s domain!\n",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);

			RTE_LOG(DEBUG, USER1, "| %10s | %10u | %10u | %10u |\n",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
				rte_topo_get_domain_count(domain_types[d]),
				total_lcore, total_wrkr_lcore);
		}
	}
	RTE_LOG(DEBUG, USER1, "---------------------------------------------------------\n");

	printf("INFO: lcore DOMAIN macro: success!\n");
	return TEST_SUCCESS;
}

static int
test_lcore_count_from_domain(void)
{
	unsigned int total_lcores = 0;
	unsigned int total_domain_lcores = 0;
	unsigned int domain_count;
	unsigned int i;

	/* get topology core count */
	total_lcores = rte_lcore_count();

	RTE_LOG(DEBUG, USER1, "| %10s | %10s |\n", "domain", " LCORE");
	RTE_LOG(DEBUG, USER1, "---------------------------------------\n");
	RTE_LOG(DEBUG, USER1, "| %10s | %10u |\n", "rte_lcore", total_lcores);

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		total_domain_lcores = 0;
		domain_count = rte_topo_get_domain_count(domain_types[d]);
		for (i = 0; i < domain_count; i++)
			total_domain_lcores +=
				rte_topo_get_lcore_count_from_domain(domain_types[d], i);

		if (domain_count) {
			RTE_TEST_ASSERT((total_domain_lcores == total_lcores),
				"domain %s lcores does not match!\n",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);

			RTE_LOG(DEBUG, USER1, "| %10s | %10u |\n",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
				total_domain_lcores);
		}
	}
	RTE_LOG(DEBUG, USER1, "---------------------------------------\n");

	printf("INFO: lcore count domain API: success\n");
	return TEST_SUCCESS;
}

#ifdef RTE_HAS_CPUSET
static int
test_lcore_cpuset_from_domain(void)
{
	unsigned int domain_count;
	uint16_t dmn_idx;
	rte_cpuset_t cpu_set_list;

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		domain_count = rte_topo_get_domain_count(domain_types[d]);
		for (dmn_idx = 0; dmn_idx < domain_count; dmn_idx++) {
			cpu_set_list = rte_topo_get_lcore_cpuset_in_domain(domain_types[d],
				dmn_idx);

			for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
				if (CPU_ISSET(cpu_idx, &cpu_set_list))
					RTE_TEST_ASSERT(rte_lcore_is_enabled(cpu_idx), "%s domain at %u lcore %u not enabled!\n",
					(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
					dmn_idx, cpu_idx);

			}
		}
	}
	printf("INFO: topology cpuset: success!\n");

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		cpu_set_list = rte_topo_get_lcore_cpuset_in_domain(domain_types[d], UINT32_MAX);
		RTE_TEST_ASSERT((CPU_COUNT(&cpu_set_list) == 0),
			"lcore not expected for %s domain invalid index!\n",
			(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);
	}

	printf("INFO: cpuset_in_domain API: success!\n");
	return TEST_SUCCESS;
}
#endif

static int
test_main_lcore_in_domain(void)
{
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		bool main_lcore_found = false;
		unsigned int domain_count = rte_topo_get_domain_count(domain_types[d]);
		for (unsigned int dmn_idx = 0; dmn_idx < domain_count; dmn_idx++) {
			main_lcore_found = rte_topo_is_main_lcore_in_domain(RTE_TOPO_DOMAIN_NUMA,
				dmn_idx);
			if (main_lcore_found)
				break;
		}

		if (domain_count)
			RTE_TEST_ASSERT((main_lcore_found == true),
			"main lcore is not found in %s domain!\n",
			(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
			(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);
	}

	printf("INFO: is_main_lcore_in_domain API: success!\n");
	return TEST_SUCCESS;
}

static int
test_lcore_from_domain_negative(void)
{
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		const unsigned int domain_count = rte_topo_get_domain_count(domain_types[d]);
		if (domain_count)
			RTE_TEST_ASSERT(
				(rte_topo_get_lcore_count_from_domain(domain_types[d],
					domain_count) == 0),
				"domain %s API inconsistent for numa\n",
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);
	}

	printf("INFO: lcore domain API: success!\n");
	return TEST_SUCCESS;
}

static int
test_wrap_with_skip_main_edge_case(void)
{
	const unsigned int main_lcore = rte_get_main_lcore();

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		const unsigned int domain_count = rte_topo_get_domain_count(domain_types[d]);
		for (unsigned int domain_index = 0; domain_index < domain_count; domain_index++) {
			unsigned int lcores_in_domain_index =
				rte_topo_get_lcore_count_from_domain(domain_types[d],
					domain_index);

			if (lcores_in_domain_index &&
				(rte_topo_is_main_lcore_in_domain(domain_types[d],
					lcores_in_domain_index))) {

				if (lcores_in_domain_index == 1)
					continue;

				for (unsigned int i = 0; i < lcores_in_domain_index; i++) {
					const uint16_t next_lcore =
						rte_topo_get_nth_lcore_from_domain(domain_index,
							i, 0, domain_types[d]);

					RTE_TEST_ASSERT(next_lcore != main_lcore,
						"expected domain %s, main lcore %u, to be skipped!",
						(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
						(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
						(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
						(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
						(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" :
						NULL,
						main_lcore);
				}
			}
		}
	}

	printf("INFO: skip main lcore API: success!\n");
	return TEST_SUCCESS;
}

static int
test_invalid_domain_selector(void)
{
	unsigned int count;
	unsigned int lcore;
	rte_cpuset_t cpuset;

	/* Test with completely invalid domain selector */
	count = rte_topo_get_domain_count(0xDEADBEEF);
	RTE_TEST_ASSERT((count == 0), "Invalid domain selector should return 0 count\n");

	/* Test with 0 (no bits set) */
	count = rte_topo_get_domain_count(0);
	RTE_TEST_ASSERT((count == 0), "Zero domain selector should return 0 count\n");

	/* Test count_from_domain with invalid selector */
	count = rte_topo_get_lcore_count_from_domain(0xBADC0DE, 0);
	RTE_TEST_ASSERT((count == 0), "Invalid domain should return 0 cores\n");

	/* Test get_lcore_in_domain with invalid selector */
	lcore = rte_topo_get_nth_lcore_in_domain(0xBADC0DE, 0, 0);
	RTE_TEST_ASSERT((lcore == RTE_MAX_LCORE), "Invalid domain should return RTE_MAX_LCORE\n");

	/* Test cpuset with invalid selector */
	cpuset = rte_topo_get_lcore_cpuset_in_domain(0xBADC0DE, 0);
	RTE_TEST_ASSERT((CPU_COUNT(&cpuset) == 0), "Invalid domain should return empty cpuset\n");

	printf("INFO: Invalid domain selector test: success\n");
	return TEST_SUCCESS;
}

static int
test_multiple_invalid_inputs(void)
{
	if (rte_lcore_count() == 1) {
		printf("INFO: topology MACRO test requires more than 1 core, skipping!\n");
		return TEST_SKIPPED;
	}

	/* Test all APIs with multiple types of invalid inputs */
	unsigned int invalid_domains[] = {
		0,             /* No bits set */
		0xFFFFFFFF,    /* All bits set (not a single domain) */
		0x80000000,    /* Bit outside valid range */
		0x12345678,    /* Random invalid value */
	};

	for (int i = 0; i < 4; i++) {
		unsigned int domain = invalid_domains[i];

		/* All should return safe defaults */
		RTE_TEST_ASSERT((rte_topo_get_domain_count(domain) == 0),
			"Invalid domain 0x%x should have NO count\n", domain);
		RTE_TEST_ASSERT((rte_topo_get_lcore_count_from_domain(domain, 0) == 0),
			"Invalid domain 0x%x should have NO cores\n", domain);
		RTE_TEST_ASSERT((rte_topo_get_nth_lcore_in_domain(domain, 0, 0) == RTE_MAX_LCORE),
			"Invalid domain 0x%x should return MAX_LCORE\n", domain);
	}

	printf("INFO: Multiple invalid inputs test: success\n");
	return TEST_SUCCESS;
}

static int
test_large_index_values(void)
{
	if (rte_lcore_count() == 1) {
		printf("INFO: topology MACRO test requires more than 1 core, skipping!\n");
		return TEST_SKIPPED;
	}

	uint16_t test_lcore = 0;
	unsigned int large_indices[] = {
		RTE_MAX_LCORE,
		RTE_MAX_LCORE + 1,
		UINT32_MAX,
		0x7FFFFFFF,
	};

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		for (unsigned int i = 0; i < RTE_DIM(large_indices); i++) {
			unsigned int idx = large_indices[i];

			/* Should all handle gracefully and return safe defaults */
			test_lcore = rte_topo_get_lcore_count_from_domain(domain_types[d], idx);
			RTE_TEST_ASSERT(test_lcore == 0,
				"Large index %u in domain %s should return 0 cores\n",
				idx,
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);

			test_lcore = rte_topo_get_nth_lcore_in_domain(domain_types[d], idx, 0);
			RTE_TEST_ASSERT(test_lcore == RTE_MAX_LCORE,
				"Large index %u in domain %s should return MAX_LCORE\n",
				idx,
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);

#ifdef RTE_HAS_CPUSET
			rte_cpuset_t cpuset = rte_topo_get_lcore_cpuset_in_domain(domain_types[d],
				idx);
			RTE_TEST_ASSERT(CPU_COUNT(&cpuset) == 0,
				"Large index %u in domain %s should return empty cpuset",
				idx,
				(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
				(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL);
#endif
		}
	}

	printf("INFO: Large index values test: success\n");
	return TEST_SUCCESS;
}


static int
test_domain_next_lcore_no_wrap(void)
{
	if (rte_lcore_count() == 1) {
		printf("INFO: topology MACRO test requires more than 1 core, skipping!\n");
		return TEST_SKIPPED;
	}

	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		const unsigned int lcores_in_domain = rte_topo_get_domain_count(domain_types[d]);

		for (unsigned int domain_index = 0; domain_index < lcores_in_domain;
			domain_index++) {
			unsigned int lcores_in_domain_index =
				rte_topo_get_lcore_count_from_domain(domain_types[d],
					domain_index);

			for (unsigned int i = 0; i < lcores_in_domain_index; i++) {
				const uint16_t curr_lcore =
					rte_topo_get_nth_lcore_from_domain(domain_index,
						i, 0, domain_types[d]);

				const uint16_t wrap_lcore =
					rte_topo_get_nth_lcore_from_domain(domain_index,
						lcores_in_domain_index + i, 0, domain_types[d]);

				RTE_TEST_ASSERT(wrap_lcore == RTE_MAX_LCORE,
					"expected domain %s, lcore %u, wrapped lcore %u should be RTE_MAX_LCORE!",
					(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
					curr_lcore, wrap_lcore);
			}
		}
	}

	printf("INFO: next lcore in domain test: success\n");
	return TEST_SUCCESS;
}

static int
test_domain_next_lcore_wrap(void)
{
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		const unsigned int lcores_in_domain = rte_topo_get_domain_count(domain_types[d]);
		for (unsigned int domain_index = 0; domain_index < lcores_in_domain;
			domain_index++) {
			unsigned int lcores_in_domain_index =
				rte_topo_get_lcore_count_from_domain(domain_types[d],
					domain_index);

			for (unsigned int i = 0; i < lcores_in_domain_index; i++) {
				const uint16_t curr_lcore =
					rte_topo_get_nth_lcore_from_domain(domain_index, i, 0,
						domain_types[d]);
				const uint16_t wrap_lcore =
					rte_topo_get_nth_lcore_from_domain(domain_index,
						lcores_in_domain_index + i, 1, domain_types[d]);

				RTE_TEST_ASSERT(curr_lcore == wrap_lcore,
					"expected domain %s, lcore %u, wrapped lcore %u not same!",
					(domain_types[d] == RTE_TOPO_DOMAIN_NUMA) ? "NUMA" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L4) ? "L4" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L3) ? "L3" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L2) ? "L2" :
					(domain_types[d] == RTE_TOPO_DOMAIN_L1) ? "L1" : NULL,
					curr_lcore, wrap_lcore);
			}
		}
	}

	printf("INFO: wrap next lcore in domain test: success\n");
	return TEST_SUCCESS;
}


static int
test_multibit_domain_selector(void)
{
	const unsigned int bad_sel = RTE_TOPO_DOMAIN_L1 | RTE_TOPO_DOMAIN_L2;

	unsigned int count;
	unsigned int lcore;
	rte_cpuset_t cpuset;

	count = rte_topo_get_domain_count(bad_sel);
	RTE_TEST_ASSERT(count == 0,
		"Multi-bit selector should return 0 domains");

	count = rte_topo_get_lcore_count_from_domain(bad_sel, 0);
	RTE_TEST_ASSERT(count == 0,
		"Multi-bit selector should return 0 lcores");

	lcore = rte_topo_get_nth_lcore_in_domain(bad_sel, 0, 0);
	RTE_TEST_ASSERT(lcore == RTE_MAX_LCORE,
		"Multi-bit selector should return RTE_MAX_LCORE");

#ifdef RTE_HAS_CPUSET
	cpuset = rte_topo_get_lcore_cpuset_in_domain(bad_sel, 0);
	RTE_TEST_ASSERT(CPU_COUNT(&cpuset) == 0,
		"Multi-bit selector should return empty cpuset");
#endif

	printf("INFO: invalid domain select test: success\n");
	return TEST_SUCCESS;
}

static int
test_domain_lcore_round_trip(void)
{
	for (unsigned int d = 0; d < RTE_DIM(domain_types); d++) {
		unsigned int dom_cnt = rte_topo_get_domain_count(domain_types[d]);

		for (unsigned int i = 0; i < dom_cnt; i++) {
			unsigned int lcnt =
				rte_topo_get_lcore_count_from_domain(domain_types[d], i);

			for (unsigned int p = 0; p < lcnt; p++) {
				uint16_t lcore =
					rte_topo_get_nth_lcore_in_domain(domain_types[d], i, p);

				int idx =
					rte_topo_get_domain_index_from_lcore(domain_types[d],
						lcore);

				RTE_TEST_ASSERT(idx == (int)i,
					"Round-trip mismatch: domain %u lcore %u -> idx %d",
					i, lcore, idx);
			}
		}
	}

	printf("INFO: lcore domain cross test: success\n");
	return TEST_SUCCESS;
}

static int
test_domain_lcore_ordering(void)
{
	unsigned int domain = RTE_TOPO_DOMAIN_L1;
	if (rte_topo_get_domain_count(domain) == 0)
		return TEST_SKIPPED;

	unsigned int lcnt = rte_topo_get_lcore_count_from_domain(domain, 0);

	uint16_t prev = 0;
	bool first = true;

	for (unsigned int i = 0; i < lcnt; i++) {
		uint16_t cur = rte_topo_get_nth_lcore_in_domain(domain, 0, i);

		if (!first)
			RTE_TEST_ASSERT(cur > prev, "Lcore ordering not strictly increasing");
		first = false;
		prev = cur;
	}

	printf("INFO: lcores ascending domain test: success\n");
	return TEST_SUCCESS;
}

static int
test_cpuset_matches_lcore_list(void)
{
#ifdef RTE_HAS_CPUSET
	unsigned int domain = RTE_TOPO_DOMAIN_L1;
	if (rte_topo_get_domain_count(domain) == 0)
		return TEST_SKIPPED;

	rte_cpuset_t cpuset = rte_topo_get_lcore_cpuset_in_domain(domain, 0);

	unsigned int lcnt = rte_topo_get_lcore_count_from_domain(domain, 0);

	for (unsigned int i = 0; i < lcnt; i++) {
		int16_t lc = rte_topo_get_nth_lcore_in_domain(domain, 0, i);

	RTE_TEST_ASSERT(CPU_ISSET(lc, &cpuset),
		"Cpuset missing lcore %u", lc);
	}

	RTE_TEST_ASSERT(((unsigned int)CPU_COUNT(&cpuset) == lcnt), "Cpuset contains extra CPUs");

	printf("INFO: cpuset lcore cross test: success\n");
	return TEST_SUCCESS;
#else
	return TEST_SKIPPED;
#endif
}
#endif

static int
test_topology_lcores(void)
{
#ifdef RTE_LIBHWLOC_PROBE
	printf("\nTopology test\n");

	printf("\nLcore dump mapped to topology\n");
	rte_topo_dump(stdout);
	printf("\n\n");

	if (rte_lcore_count() == 1) {
		RTE_LOG(INFO, USER1, "topology MACRO test requires more than 1 core, skipping!\n");
		return TEST_SKIPPED;
	}

	if (test_topology_macro() < 0)
		return TEST_FAILED;

	if (test_lcore_count_from_domain() < 0)
		return TEST_FAILED;

	if (test_lcore_from_domain_negative() < 0)
		return TEST_FAILED;

#ifdef RTE_HAS_CPUSET
	if (test_lcore_cpuset_from_domain() < 0)
		return TEST_FAILED;
#endif

	if (test_main_lcore_in_domain() < 0)
		return TEST_FAILED;

	if (test_wrap_with_skip_main_edge_case() < 0)
		return TEST_FAILED;

	if (test_invalid_domain_selector() < 0)
		return TEST_FAILED;

	if (test_multiple_invalid_inputs() < 0)
		return TEST_FAILED;

	if (test_large_index_values() < 0)
		return TEST_FAILED;

	if (test_domain_next_lcore_no_wrap() < 0)
		return TEST_FAILED;

	if (test_domain_next_lcore_wrap() < 0)
		return TEST_FAILED;

	if (test_multibit_domain_selector() < 0)
		return TEST_FAILED;

	if (test_domain_lcore_round_trip() < 0)
		return TEST_FAILED;

	if (test_domain_lcore_ordering() < 0)
		return TEST_FAILED;

	if (test_cpuset_matches_lcore_list() < 0)
		return TEST_FAILED;
#endif

	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(topology_autotest, NOHUGE_OK, ASAN_OK, test_topology_lcores);
