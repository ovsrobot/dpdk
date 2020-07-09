/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Samsung Electronics Co., Ltd All Rights Reserved
 */

#include <stdio.h>
#include <sys/time.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_memory.h>

#include "test.h"

#define NB_MBUF                 1024
#define MEMPOOL_CACHE_SIZE	0
#define MBUF_DATA_SIZE		2048
#define MBUF_PRIV_SIZE		128
#define REPEAT			(1024*1024)

static int
case_mbuf_alloc_free(struct rte_mempool *pktmbuf_pool)
{
	unsigned int i;
	int ret = TEST_SUCCESS;
	int r;

	struct rte_mbuf *m[NB_MBUF];
	for (i = 0; i < NB_MBUF; i++)
		m[i] = NULL;

	for (r = 0; r < REPEAT; r++) {
		for (i = 0; i < NB_MBUF; i++) {
			m[i] = rte_pktmbuf_alloc(pktmbuf_pool);
			if (m[i] == NULL) {
				printf("rte_pktmbuf_alloc() failed (%u)"
					" at repetition %d\n", i, r);
				ret = TEST_FAILED;
				goto end;
			}
		}
		for (i = 0; i < NB_MBUF; i++) {
			if (m[i] != NULL) {
				rte_pktmbuf_free(m[i]);
				m[i] = NULL;
			}
		}
	}

end:
	for (i = 0; i < NB_MBUF; i++) {
		if (m[i] != NULL)
			rte_pktmbuf_free(m[i]);
	}
	return ret;
}

static int
case_mbuf_bulk_alloc_free(struct rte_mempool *pktmbuf_pool)
{
	int ret = TEST_SUCCESS;
	int r;
	struct rte_mbuf *m[NB_MBUF];

	for (r = 0; r < REPEAT; r++) {
		ret = rte_pktmbuf_alloc_bulk(pktmbuf_pool, m, NB_MBUF);
		if (ret != 0) {
			printf("rte_pktmbuf_alloc_bulk() failed"
				" at repetition %d\n", r);
			ret = TEST_FAILED;
			break;
		}
		rte_pktmbuf_free_bulk(m, NB_MBUF);
	}
	return ret;
}

static int
case_mbuf_data_manipulation(struct rte_mempool *pktmbuf_pool)
{
	unsigned int i;
	int ret = TEST_SUCCESS;
	int r;

	struct rte_mbuf *m[NB_MBUF];
	ret = rte_pktmbuf_alloc_bulk(pktmbuf_pool, m, NB_MBUF);
	if (ret != 0) {
		printf("rte_pktmbuf_alloc_bulk() failed\n");
		return TEST_FAILED;
	}

	for (r = 0; r < REPEAT; r++) {
		for (i = 0; i < NB_MBUF; i++) {
			if (!rte_pktmbuf_is_contiguous(m[i])) {
				printf("rte_pktmbuf_is_contiguous() failed"
					" (%u)\n", i);
				ret = TEST_FAILED;
				goto end;
			}
			if (rte_pktmbuf_append(m[i], 0) == NULL) {
				printf("rte_pktmbuf_append() failed"
					" (%u)\n", i);
				ret = TEST_FAILED;
				goto end;
			}
			if (rte_pktmbuf_trim(m[i], 0) < 0) {
				printf("rte_pktmbuf_trim() failed (%u)\n", i);
				ret = TEST_FAILED;
				goto end;
			}
			if (rte_pktmbuf_prepend(m[i], 0) == NULL) {
				printf("rte_pktmbuf_prepend() failed"
					" (%u)\n", i);
				ret = TEST_FAILED;
				goto end;
			}
			if (rte_pktmbuf_adj(m[i], 0) == NULL) {
				printf("rte_pktmbuf_adj() failed (%u)\n", i);
				ret = TEST_FAILED;
				goto end;
			}
		}
	}

end:
	rte_pktmbuf_free_bulk(m, NB_MBUF);
	return ret;
}

static int
case_mbuf_sanity_checks_without_header(struct rte_mempool *pktmbuf_pool)
{
	unsigned int i;
	int ret = TEST_SUCCESS;
	int r;

	struct rte_mbuf *m[NB_MBUF];
	ret = rte_pktmbuf_alloc_bulk(pktmbuf_pool, m, NB_MBUF);
	if (ret != 0) {
		printf("rte_pktmbuf_alloc_bulk() failed\n");
		return TEST_FAILED;
	}

	for (r = 0; r < REPEAT; r++)
		for (i = 0; i < NB_MBUF; i++)
			rte_mbuf_sanity_check(m[i], 0);

	rte_pktmbuf_free_bulk(m, NB_MBUF);
	return ret;
}

static int
case_mbuf_sanity_checks_with_header(struct rte_mempool *pktmbuf_pool)
{
	unsigned int i;
	int ret = TEST_SUCCESS;
	int r;

	struct rte_mbuf *m[NB_MBUF];
	ret = rte_pktmbuf_alloc_bulk(pktmbuf_pool, m, NB_MBUF);
	if (ret != 0) {
		printf("rte_pktmbuf_alloc_bulk() failed\n");
		return TEST_FAILED;
	}

	for (r = 0; r < REPEAT; r++)
		for (i = 0; i < NB_MBUF; i++)
			rte_mbuf_sanity_check(m[i], 1);

	rte_pktmbuf_free_bulk(m, NB_MBUF);
	return ret;
}

static int
case_mbuf_sanity_checks_with_header_in_chain(struct rte_mempool *pktmbuf_pool)
{
	unsigned int i;
	int ret = TEST_SUCCESS;
	int r;

	struct rte_mbuf *m[NB_MBUF];
	ret = rte_pktmbuf_alloc_bulk(pktmbuf_pool, m, NB_MBUF);
	if (ret != 0) {
		printf("rte_pktmbuf_alloc_bulk() failed\n");
		return TEST_FAILED;
	}

	for (i = 1; i < NB_MBUF; i++) {
		ret = rte_pktmbuf_chain(m[0], m[i]);
		if (ret != 0) {
			printf("rte_pktmbuf_chain() failed: %d\n", ret);
			goto end;
		}
		m[i] = NULL;
	}

	for (r = 0; r < REPEAT; r++)
		rte_mbuf_sanity_check(m[0], 1);

end:
	rte_pktmbuf_free_bulk(m, NB_MBUF);
	return ret;
}

struct testcase {
	int (*func)(struct rte_mempool *pktmbuf_pool);
	const char *name;
	double time;
	int ret;
};

#define TC(F) {.func = F, .name = RTE_STR(F), .time = 0.0, .ret = TEST_SKIPPED}

static int
test_mbuf_perf(void)
{
	int ret = TEST_SUCCESS;
	struct timeval tv_begin, tv_end;
	struct testcase cases[] = {
		TC(case_mbuf_alloc_free),
		TC(case_mbuf_bulk_alloc_free),
		TC(case_mbuf_data_manipulation),
		TC(case_mbuf_sanity_checks_without_header),
		TC(case_mbuf_sanity_checks_with_header),
		TC(case_mbuf_sanity_checks_with_header_in_chain),
	};
	int i, n = RTE_DIM(cases);
	const char *status_ok = "[ OK ]";
	const char *status_skip = "[SKIP]";
	const char *status_fail = "[FAIL]";
	const char *status;
	struct rte_mempool *pktmbuf_pool = NULL;

	pktmbuf_pool = rte_pktmbuf_pool_create("test_pktmbuf_pool",
			NB_MBUF, MEMPOOL_CACHE_SIZE, MBUF_PRIV_SIZE,
			MBUF_DATA_SIZE,	SOCKET_ID_ANY);
	if (pktmbuf_pool == NULL) {
		printf("cannot allocate mbuf pool\n");
		ret = TEST_FAILED;
		goto end;
	}

	for (i = 0; i < n; i++) {
		printf("=== running %s ===\n", cases[i].name);
		gettimeofday(&tv_begin, NULL);
		cases[i].ret = cases[i].func(pktmbuf_pool);
		gettimeofday(&tv_end, NULL);
		cases[i].time = (double)(tv_end.tv_sec - tv_begin.tv_sec)
			+ ((double)tv_end.tv_usec - tv_begin.tv_usec)/1000000;
	}

	printf("%-50s %-10s %s:\n", "TestName", "Status", "Time(seconds)");
	for (i = 0; i < n; i++) {
		if (cases[i].ret == TEST_SKIPPED)
			status = status_skip;
		else if (cases[i].ret == TEST_SUCCESS)
			status = status_ok;
		else {
			status = status_fail;
			ret = TEST_FAILED;
		}
		printf("%-50s %-10s %8.3f\n", cases[i].name, status,
			cases[i].time);
	}

end:
	if (pktmbuf_pool != NULL)
		rte_mempool_free(pktmbuf_pool);

	return ret;
}

REGISTER_TEST_COMMAND(mbuf_perf_autotest, test_mbuf_perf);

