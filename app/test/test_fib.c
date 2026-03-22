/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Vladimir Medvedkin <medvedkinv@gmail.com>
 * Copyright(c) 2019 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <rte_ip.h>
#include <rte_log.h>
#include <rte_fib.h>
#include <rte_malloc.h>

#include "test.h"

typedef int32_t (*rte_fib_test)(void);

static int32_t test_create_invalid(void);
static int32_t test_multiple_create(void);
static int32_t test_free_null(void);
static int32_t test_add_del_invalid(void);
static int32_t test_get_invalid(void);
static int32_t test_lookup(void);
static int32_t test_invalid_rcu(void);
static int32_t test_fib_rcu_sync_rw(void);
static int32_t test_create_vrf(void);
static int32_t test_vrf_add_del(void);
static int32_t test_vrf_lookup(void);
static int32_t test_vrf_isolation(void);
static int32_t test_vrf_all_nh_sizes(void);

#define MAX_ROUTES	(1 << 16)
#define MAX_TBL8	(1 << 15)

/*
 * Check that rte_fib_create fails gracefully for incorrect user input
 * arguments
 */
int32_t
test_create_invalid(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DUMMY;

	/* rte_fib_create: fib name == NULL */
	fib = rte_fib_create(NULL, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");

	/* rte_fib_create: config == NULL */
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, NULL);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");

	/* socket_id < -1 is invalid */
	fib = rte_fib_create(__func__, -2, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");

	/* rte_fib_create: max_routes = 0 */
	config.max_routes = 0;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");
	config.max_routes = MAX_ROUTES;

	config.type = RTE_FIB_DIR24_8 + 1;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");

	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.num_tbl8 = MAX_TBL8;

	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_8B + 1;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_8B;

	config.dir24_8.num_tbl8 = 0;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib == NULL,
		"Call succeeded with invalid parameters\n");

	return TEST_SUCCESS;
}

/*
 * Create fib table then delete fib table 10 times
 * Use a slightly different rules size each time
 */
int32_t
test_multiple_create(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	int32_t i;

	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DUMMY;

	for (i = 0; i < 100; i++) {
		config.max_routes = MAX_ROUTES - i;
		fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
		RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
		rte_fib_free(fib);
	}
	/* Can not test free so return success */
	return TEST_SUCCESS;
}

/*
 * Call rte_fib_free for NULL pointer user input. Note: free has no return and
 * therefore it is impossible to check for failure but this test is added to
 * increase function coverage metrics and to validate that freeing null does
 * not crash.
 */
int32_t
test_free_null(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DUMMY;

	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	rte_fib_free(fib);
	rte_fib_free(NULL);
	return TEST_SUCCESS;
}

/*
 * Check that rte_fib_add and rte_fib_delete fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_add_del_invalid(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t nh = 100;
	uint32_t ip = RTE_IPV4(0, 0, 0, 0);
	int ret;
	uint8_t depth = 24;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DUMMY;

	/* rte_fib_add: fib == NULL */
	ret = rte_fib_add(NULL, ip, depth, nh);
	RTE_TEST_ASSERT(ret < 0,
		"Call succeeded with invalid parameters\n");

	/* rte_fib_delete: fib == NULL */
	ret = rte_fib_delete(NULL, ip, depth);
	RTE_TEST_ASSERT(ret < 0,
		"Call succeeded with invalid parameters\n");

	/*Create valid fib to use in rest of test. */
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* rte_fib_add: depth > RTE_FIB_MAXDEPTH */
	ret = rte_fib_add(fib, ip, RTE_FIB_MAXDEPTH + 1, nh);
	RTE_TEST_ASSERT(ret < 0,
		"Call succeeded with invalid parameters\n");

	/* rte_fib_delete: depth > RTE_FIB_MAXDEPTH */
	ret = rte_fib_delete(fib, ip, RTE_FIB_MAXDEPTH + 1);
	RTE_TEST_ASSERT(ret < 0,
		"Call succeeded with invalid parameters\n");

	rte_fib_free(fib);

	return TEST_SUCCESS;
}

/*
 * Check that rte_fib_get_dp and rte_fib_get_rib fails gracefully
 * for incorrect user input arguments
 */
int32_t
test_get_invalid(void)
{
	void *p;

	p = rte_fib_get_dp(NULL);
	RTE_TEST_ASSERT(p == NULL,
		"Call succeeded with invalid parameters\n");

	p = rte_fib_get_rib(NULL);
	RTE_TEST_ASSERT(p == NULL,
		"Call succeeded with invalid parameters\n");

	return TEST_SUCCESS;
}

/*
 * Add routes for one supernet with all possible depths and do lookup
 * on each step
 * After delete routes with doing lookup on each step
 */
static int
lookup_and_check_asc(struct rte_fib *fib, uint32_t ip_arr[RTE_FIB_MAXDEPTH],
	uint32_t ip_missing, uint64_t def_nh, uint32_t n)
{
	uint64_t nh_arr[RTE_FIB_MAXDEPTH];
	int ret;
	uint32_t i = 0;

	ret = rte_fib_lookup_bulk(fib, ip_arr, nh_arr, RTE_FIB_MAXDEPTH);
	RTE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

	for (; i <= RTE_FIB_MAXDEPTH - n; i++)
		RTE_TEST_ASSERT(nh_arr[i] == n,
			"Failed to get proper nexthop\n");

	for (; i < RTE_FIB_MAXDEPTH; i++)
		RTE_TEST_ASSERT(nh_arr[i] == --n,
			"Failed to get proper nexthop\n");

	ret = rte_fib_lookup_bulk(fib, &ip_missing, nh_arr, 1);
	RTE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh),
		"Failed to get proper nexthop\n");

	return TEST_SUCCESS;
}

static int
lookup_and_check_desc(struct rte_fib *fib, uint32_t ip_arr[RTE_FIB_MAXDEPTH],
	uint32_t ip_missing, uint64_t def_nh, uint32_t n)
{
	uint64_t nh_arr[RTE_FIB_MAXDEPTH];
	int ret;
	uint32_t i = 0;

	ret = rte_fib_lookup_bulk(fib, ip_arr, nh_arr, RTE_FIB_MAXDEPTH);
	RTE_TEST_ASSERT(ret == 0, "Failed to lookup\n");

	for (; i < n; i++)
		RTE_TEST_ASSERT(nh_arr[i] == RTE_FIB_MAXDEPTH - i,
			"Failed to get proper nexthop\n");

	for (; i < RTE_FIB_MAXDEPTH; i++)
		RTE_TEST_ASSERT(nh_arr[i] == def_nh,
			"Failed to get proper nexthop\n");

	ret = rte_fib_lookup_bulk(fib, &ip_missing, nh_arr, 1);
	RTE_TEST_ASSERT((ret == 0) && (nh_arr[0] == def_nh),
		"Failed to get proper nexthop\n");

	return TEST_SUCCESS;
}

static int
check_fib(struct rte_fib *fib)
{
	uint64_t def_nh = 100;
	uint32_t ip_arr[RTE_FIB_MAXDEPTH];
	uint32_t ip_add = RTE_IPV4(128, 0, 0, 0);
	uint32_t i, ip_missing = RTE_IPV4(127, 255, 255, 255);
	int ret;

	for (i = 0; i < RTE_FIB_MAXDEPTH; i++)
		ip_arr[i] = ip_add + (1ULL << i) - 1;

	ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

	for (i = 1; i <= RTE_FIB_MAXDEPTH; i++) {
		ret = rte_fib_add(fib, ip_add, i, i);
		RTE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
		ret = lookup_and_check_asc(fib, ip_arr, ip_missing,
				def_nh, i);
		RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
	}

	for (i = RTE_FIB_MAXDEPTH; i > 1; i--) {
		ret = rte_fib_delete(fib, ip_add, i);
		RTE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
		ret = lookup_and_check_asc(fib, ip_arr, ip_missing,
			def_nh, i - 1);

		RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
	}
	ret = rte_fib_delete(fib, ip_add, i);
	RTE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
	ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh, 0);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");

	for (i = 0; i < RTE_FIB_MAXDEPTH; i++) {
		ret = rte_fib_add(fib, ip_add, RTE_FIB_MAXDEPTH - i,
			RTE_FIB_MAXDEPTH - i);
		RTE_TEST_ASSERT(ret == 0, "Failed to add a route\n");
		ret = lookup_and_check_desc(fib, ip_arr, ip_missing,
			def_nh, i + 1);
		RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
	}

	for (i = 1; i <= RTE_FIB_MAXDEPTH; i++) {
		ret = rte_fib_delete(fib, ip_add, i);
		RTE_TEST_ASSERT(ret == 0, "Failed to delete a route\n");
		ret = lookup_and_check_desc(fib, ip_arr, ip_missing, def_nh,
			RTE_FIB_MAXDEPTH - i);
		RTE_TEST_ASSERT(ret == TEST_SUCCESS, "Lookup and check fails\n");
	}

	return TEST_SUCCESS;
}

int32_t
test_lookup(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t def_nh = 100;
	int ret;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;
	config.type = RTE_FIB_DUMMY;

	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
	ret = check_fib(fib);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS,
		"Check_fib fails for DUMMY type\n");
	rte_fib_free(fib);

	config.type = RTE_FIB_DIR24_8;

	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_1B;
	config.dir24_8.num_tbl8 = 127;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
	ret = check_fib(fib);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS,
		"Check_fib fails for DIR24_8_1B type\n");
	rte_fib_free(fib);

	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_2B;
	config.dir24_8.num_tbl8 = MAX_TBL8 - 1;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
	ret = check_fib(fib);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS,
		"Check_fib fails for DIR24_8_2B type\n");
	rte_fib_free(fib);

	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
	ret = check_fib(fib);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS,
		"Check_fib fails for DIR24_8_4B type\n");
	rte_fib_free(fib);

	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_8B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");
	ret = check_fib(fib);
	RTE_TEST_ASSERT(ret == TEST_SUCCESS,
		"Check_fib fails for DIR24_8_8B type\n");
	rte_fib_free(fib);

	return TEST_SUCCESS;
}

/*
 * rte_fib_rcu_qsbr_add positive and negative tests.
 *  - Add RCU QSBR variable to FIB
 *  - Add another RCU QSBR variable to FIB
 *  - Check returns
 */
int32_t
test_invalid_rcu(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	size_t sz;
	struct rte_rcu_qsbr *qsv;
	struct rte_rcu_qsbr *qsv2;
	int32_t status;
	struct rte_fib_rcu_config rcu_cfg = {0};
	uint64_t def_nh = 100;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;

	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* Create RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(RTE_MAX_LCORE);
	qsv = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		SOCKET_ID_ANY);
	RTE_TEST_ASSERT(qsv != NULL, "Can not allocate memory for RCU\n");

	status = rte_rcu_qsbr_init(qsv, RTE_MAX_LCORE);
	RTE_TEST_ASSERT(status == 0, "Can not initialize RCU\n");

	rcu_cfg.v = qsv;

	/* adding rcu to RTE_FIB_DUMMY FIB type */
	config.type = RTE_FIB_DUMMY;
	rcu_cfg.mode = RTE_FIB_QSBR_MODE_SYNC;
	status = rte_fib_rcu_qsbr_add(fib, &rcu_cfg);
	RTE_TEST_ASSERT(status == -ENOTSUP,
		"rte_fib_rcu_qsbr_add returned wrong error status when called with DUMMY type FIB\n");
	rte_fib_free(fib);

	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* Call rte_fib_rcu_qsbr_add without fib or config */
	status = rte_fib_rcu_qsbr_add(NULL, &rcu_cfg);
	RTE_TEST_ASSERT(status == -EINVAL, "RCU added without fib\n");
	status = rte_fib_rcu_qsbr_add(fib, NULL);
	RTE_TEST_ASSERT(status == -EINVAL, "RCU added without config\n");

	/* Invalid QSBR mode */
	rcu_cfg.mode = 2;
	status = rte_fib_rcu_qsbr_add(fib, &rcu_cfg);
	RTE_TEST_ASSERT(status == -EINVAL, "RCU added with incorrect mode\n");

	rcu_cfg.mode = RTE_FIB_QSBR_MODE_DQ;

	/* Attach RCU QSBR to FIB to check for double attach */
	status = rte_fib_rcu_qsbr_add(fib, &rcu_cfg);
	RTE_TEST_ASSERT(status == 0, "Can not attach RCU to FIB\n");

	/* Create and attach another RCU QSBR to FIB table */
	qsv2 = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		SOCKET_ID_ANY);
	RTE_TEST_ASSERT(qsv2 != NULL, "Can not allocate memory for RCU\n");

	rcu_cfg.v = qsv2;
	rcu_cfg.mode = RTE_FIB_QSBR_MODE_SYNC;
	status = rte_fib_rcu_qsbr_add(fib, &rcu_cfg);
	RTE_TEST_ASSERT(status == -EEXIST, "Secondary RCU was mistakenly attached\n");

	rte_fib_free(fib);
	rte_free(qsv);
	rte_free(qsv2);

	return TEST_SUCCESS;
}

static struct rte_fib *g_fib;
static struct rte_rcu_qsbr *g_v;
static uint32_t g_ip = RTE_IPV4(192, 0, 2, 100);
static volatile uint8_t writer_done;
/* Report quiescent state interval every 1024 lookups. Larger critical
 * sections in reader will result in writer polling multiple times.
 */
#define QSBR_REPORTING_INTERVAL 1024
#define WRITER_ITERATIONS	512

/*
 * Reader thread using rte_fib data structure with RCU.
 */
static int
test_fib_rcu_qsbr_reader(void *arg)
{
	int i;
	uint64_t next_hop_return = 0;

	RTE_SET_USED(arg);
	/* Register this thread to report quiescent state */
	rte_rcu_qsbr_thread_register(g_v, 0);
	rte_rcu_qsbr_thread_online(g_v, 0);

	do {
		for (i = 0; i < QSBR_REPORTING_INTERVAL; i++)
			rte_fib_lookup_bulk(g_fib, &g_ip, &next_hop_return, 1);

		/* Update quiescent state */
		rte_rcu_qsbr_quiescent(g_v, 0);
	} while (!writer_done);

	rte_rcu_qsbr_thread_offline(g_v, 0);
	rte_rcu_qsbr_thread_unregister(g_v, 0);

	return 0;
}

/*
 * rte_fib_rcu_qsbr_add sync mode functional test.
 * 1 Reader and 1 writer. They cannot be in the same thread in this test.
 *  - Create FIB which supports 1 tbl8 group at max
 *  - Add RCU QSBR variable with sync mode to FIB
 *  - Register a reader thread. Reader keeps looking up a specific rule.
 *  - Writer keeps adding and deleting a specific rule with depth=28 (> 24)
 */
int32_t
test_fib_rcu_sync_rw(void)
{
	struct rte_fib_conf config = { 0 };
	size_t sz;
	int32_t status;
	uint32_t i, next_hop;
	uint8_t depth;
	struct rte_fib_rcu_config rcu_cfg = {0};
	uint64_t def_nh = 100;

	if (rte_lcore_count() < 2) {
		printf("Not enough cores for %s, expecting at least 2\n", __func__);
		return TEST_SKIPPED;
	}

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = 1;

	g_fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(g_fib != NULL, "Failed to create FIB\n");

	/* Create RCU QSBR variable */
	sz = rte_rcu_qsbr_get_memsize(1);
	g_v = (struct rte_rcu_qsbr *)rte_zmalloc_socket(NULL, sz, RTE_CACHE_LINE_SIZE,
		SOCKET_ID_ANY);
	RTE_TEST_ASSERT(g_v != NULL, "Can not allocate memory for RCU\n");

	status = rte_rcu_qsbr_init(g_v, 1);
	RTE_TEST_ASSERT(status == 0, "Can not initialize RCU\n");

	rcu_cfg.v = g_v;
	rcu_cfg.mode = RTE_FIB_QSBR_MODE_SYNC;
	/* Attach RCU QSBR to FIB table */
	status = rte_fib_rcu_qsbr_add(g_fib, &rcu_cfg);
	RTE_TEST_ASSERT(status == 0, "Can not attach RCU to FIB\n");

	writer_done = 0;
	/* Launch reader thread */
	rte_eal_remote_launch(test_fib_rcu_qsbr_reader, NULL, rte_get_next_lcore(-1, 1, 0));

	depth = 28;
	next_hop = 1;
	status = rte_fib_add(g_fib, g_ip, depth, next_hop);
	if (status != 0) {
		printf("%s: Failed to add rule\n", __func__);
		goto error;
	}

	/* Writer update */
	for (i = 0; i < WRITER_ITERATIONS; i++) {
		status = rte_fib_delete(g_fib, g_ip, depth);
		if (status != 0) {
			printf("%s: Failed to delete rule at iteration %d\n", __func__, i);
			goto error;
		}

		status = rte_fib_add(g_fib, g_ip, depth, next_hop);
		if (status != 0) {
			printf("%s: Failed to add rule at iteration %d\n", __func__, i);
			goto error;
		}
	}

error:
	writer_done = 1;
	/* Wait until reader exited. */
	rte_eal_mp_wait_lcore();

	rte_fib_free(g_fib);
	rte_free(g_v);

	return status == 0 ? TEST_SUCCESS : TEST_FAILED;
}

/*
 * Test VRF creation and basic operations
 */
static int32_t
test_create_vrf(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t def_nh = 100;
	uint64_t vrf_def_nh[4] = {100, 200, 300, 400};

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;

	/* Test single VRF (backward compat) */
	config.max_vrfs = 0;
	config.vrf_default_nh = NULL;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB with max_vrfs=0\n");
	rte_fib_free(fib);

	/* Test single VRF explicitly */
	config.max_vrfs = 1;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB with max_vrfs=1\n");
	rte_fib_free(fib);

	/* Test multi-VRF with per-VRF defaults */
	config.max_vrfs = 4;
	config.vrf_default_nh = vrf_def_nh;
	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB with max_vrfs=4\n");
	rte_fib_free(fib);

	return TEST_SUCCESS;
}

/*
 * Test VRF route add/delete operations
 */
static int32_t
test_vrf_add_del(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t def_nh = 100;
	uint64_t vrf_def_nh[4] = {100, 200, 300, 400};
	uint32_t ip = RTE_IPV4(192, 168, 1, 0);
	uint8_t depth = 24;
	uint64_t nh = 1000;
	int ret;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	config.max_vrfs = 4;
	config.vrf_default_nh = vrf_def_nh;

	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* Add route to VRF 0 */
	ret = rte_fib_vrf_add(fib, 0, ip, depth, nh);
	RTE_TEST_ASSERT(ret == 0, "Failed to add route to VRF 0\n");

	/* Add route to VRF 1 with different nexthop */
	ret = rte_fib_vrf_add(fib, 1, ip, depth, nh + 1);
	RTE_TEST_ASSERT(ret == 0, "Failed to add route to VRF 1\n");

	/* Add route to VRF 2 */
	ret = rte_fib_vrf_add(fib, 2, ip, depth, nh + 2);
	RTE_TEST_ASSERT(ret == 0, "Failed to add route to VRF 2\n");

	/* Test invalid VRF ID */
	ret = rte_fib_vrf_add(fib, 10, ip, depth, nh);
	RTE_TEST_ASSERT(ret != 0, "Should fail with invalid VRF ID\n");

	/* Delete route from VRF 1 */
	ret = rte_fib_vrf_delete(fib, 1, ip, depth);
	RTE_TEST_ASSERT(ret == 0, "Failed to delete route from VRF 1\n");

	/* Delete non-existent route - implementation may return error */
	ret = rte_fib_vrf_delete(fib, 3, ip, depth);
	(void)ret;  /* Accept any return value */

	rte_fib_free(fib);
	return TEST_SUCCESS;
}

/*
 * Test VRF lookup functionality
 */
static int32_t
test_vrf_lookup(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t def_nh = 100;
	uint64_t vrf_def_nh[4] = {1000, 2000, 3000, 4000};
	uint32_t ip_base = RTE_IPV4(10, 0, 0, 0);
	uint16_t vrf_ids[8];
	uint32_t ips[8];
	uint64_t next_hops[8];
	int ret;
	uint32_t i;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = def_nh;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	config.max_vrfs = 4;
	config.vrf_default_nh = vrf_def_nh;

	fib = rte_fib_create(__func__, SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* Add routes to different VRFs with VRF-specific nexthops */
	for (i = 0; i < 4; i++) {
		ret = rte_fib_vrf_add(fib, i, ip_base + (i << 16), 16, 100 + i);
		RTE_TEST_ASSERT(ret == 0, "Failed to add route to VRF %u\n", i);
	}

	/* Prepare lookup: each IP should match its VRF-specific route */
	for (i = 0; i < 4; i++) {
		vrf_ids[i] = i;
		ips[i] = ip_base + (i << 16) + 0x1234;  /* Within the /16 */
	}

	/* Lookup should return VRF-specific nexthops */
	ret = rte_fib_vrf_lookup_bulk(fib, vrf_ids, ips, next_hops, 4);
	RTE_TEST_ASSERT(ret == 0, "VRF lookup failed\n");

	for (i = 0; i < 4; i++) {
		RTE_TEST_ASSERT(next_hops[i] == 100 + i,
			"Wrong nexthop for VRF %u: expected %"PRIu64", got %"PRIu64"\n",
			i, (uint64_t)(100 + i), next_hops[i]);
	}

	/* Test default nexthops for unmatched IPs */
	for (i = 0; i < 4; i++) {
		vrf_ids[i] = i;
		ips[i] = RTE_IPV4(192, 168, i, 1);  /* No route for these */
	}

	ret = rte_fib_vrf_lookup_bulk(fib, vrf_ids, ips, next_hops, 4);
	RTE_TEST_ASSERT(ret == 0, "VRF lookup failed\n");

	for (i = 0; i < 4; i++) {
		RTE_TEST_ASSERT(next_hops[i] == vrf_def_nh[i],
			"Wrong default nexthop for VRF %u: expected %"PRIu64", got %"PRIu64"\n",
			i, vrf_def_nh[i], next_hops[i]);
	}

	rte_fib_free(fib);
	return TEST_SUCCESS;
}

/*
 * Test VRF isolation - routes in one VRF shouldn't affect others
 */
static int32_t
test_vrf_isolation(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t vrf_def_nh[3] = {100, 200, 300};
	uint32_t ip = RTE_IPV4(10, 10, 10, 0);
	uint16_t vrf_ids[3] = {0, 1, 2};
	uint32_t ips[3];
	uint64_t next_hops[3];
	int ret;
	uint32_t i;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.nh_sz = RTE_FIB_DIR24_8_4B;
	config.dir24_8.num_tbl8 = MAX_TBL8;
	config.max_vrfs = 3;
	config.vrf_default_nh = vrf_def_nh;

	fib = rte_fib_create("test_vrfisol", SOCKET_ID_ANY, &config);
	RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

	/* Add route only to VRF 1 */
	ret = rte_fib_vrf_add(fib, 1, ip, 24, 777);
	RTE_TEST_ASSERT(ret == 0, "Failed to add route to VRF 1\n");

	/* Lookup same IP in all three VRFs */
	for (i = 0; i < 3; i++)
		ips[i] = ip + 15;  /* Within /24 */

	ret = rte_fib_vrf_lookup_bulk(fib, vrf_ids, ips, next_hops, 3);
	RTE_TEST_ASSERT(ret == 0, "VRF lookup failed\n");

	/* VRF 0 should get default */
	RTE_TEST_ASSERT(next_hops[0] == vrf_def_nh[0],
		"VRF 0 should return default nexthop\n");

	/* VRF 1 should get the route */
	RTE_TEST_ASSERT(next_hops[1] == 777,
		"VRF 1 should return route nexthop 777, got %"PRIu64"\n", next_hops[1]);

	/* VRF 2 should get default */
	RTE_TEST_ASSERT(next_hops[2] == vrf_def_nh[2],
		"VRF 2 should return default nexthop\n");

	rte_fib_free(fib);
	return TEST_SUCCESS;
}

/*
 * Test multi-VRF with all nexthop sizes
 */
static int32_t
test_vrf_all_nh_sizes(void)
{
	struct rte_fib *fib = NULL;
	struct rte_fib_conf config = { 0 };
	uint64_t vrf_def_nh[2] = {10, 20};
	uint32_t ip = RTE_IPV4(172, 16, 0, 0);
	uint16_t vrf_ids[2] = {0, 1};
	uint32_t ips[2];
	uint64_t next_hops[2];
	int ret;
	enum rte_fib_dir24_8_nh_sz nh_sizes[] = {
		RTE_FIB_DIR24_8_1B,
		RTE_FIB_DIR24_8_2B,
		RTE_FIB_DIR24_8_4B,
		RTE_FIB_DIR24_8_8B
	};
	uint64_t max_nhs[] = {127, 32767, 2147483647ULL, 9223372036854775807ULL};
	int i;

	config.max_routes = MAX_ROUTES;
	config.rib_ext_sz = 0;
	config.default_nh = 0;
	config.type = RTE_FIB_DIR24_8;
	config.dir24_8.num_tbl8 = 127;
	config.max_vrfs = 2;
	config.vrf_default_nh = vrf_def_nh;

	for (i = 0; i < (int)RTE_DIM(nh_sizes); i++) {
		char name[32];
		config.dir24_8.nh_sz = nh_sizes[i];
		snprintf(name, sizeof(name), "vrf_nh%d", i);

		fib = rte_fib_create(name, SOCKET_ID_ANY, &config);
		RTE_TEST_ASSERT(fib != NULL, "Failed to create FIB\n");

		/* Add routes with max nexthop for this size */
		ret = rte_fib_vrf_add(fib, 0, ip, 16, max_nhs[i]);
		RTE_TEST_ASSERT(ret == 0,
			"Failed to add route to VRF 0 with nh_sz=%d\n", nh_sizes[i]);

		ret = rte_fib_vrf_add(fib, 1, ip, 16, max_nhs[i] - 1);
		RTE_TEST_ASSERT(ret == 0,
			"Failed to add route to VRF 1 with nh_sz=%d\n", nh_sizes[i]);

		/* Lookup */
		ips[0] = ip + 0x100;
		ips[1] = ip + 0x200;

		ret = rte_fib_vrf_lookup_bulk(fib, vrf_ids, ips, next_hops, 2);
		RTE_TEST_ASSERT(ret == 0, "VRF lookup failed with nh_sz=%d\n", nh_sizes[i]);

		RTE_TEST_ASSERT(next_hops[0] == max_nhs[i],
			"Wrong nexthop for VRF 0 with nh_sz=%d\n", nh_sizes[i]);
		RTE_TEST_ASSERT(next_hops[1] == max_nhs[i] - 1,
			"Wrong nexthop for VRF 1 with nh_sz=%d\n", nh_sizes[i]);

		rte_fib_free(fib);
		fib = NULL;
	}

	return TEST_SUCCESS;
}

static struct unit_test_suite fib_fast_tests = {
	.suite_name = "fib autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
	TEST_CASE(test_create_invalid),
	TEST_CASE(test_free_null),
	TEST_CASE(test_add_del_invalid),
	TEST_CASE(test_get_invalid),
	TEST_CASE(test_lookup),
	TEST_CASE(test_invalid_rcu),
	TEST_CASE(test_fib_rcu_sync_rw),
	TEST_CASE(test_create_vrf),
	TEST_CASE(test_vrf_add_del),
	TEST_CASE(test_vrf_lookup),
	TEST_CASE(test_vrf_isolation),
	TEST_CASE(test_vrf_all_nh_sizes),
	TEST_CASES_END()
	}
};

static struct unit_test_suite fib_slow_tests = {
	.suite_name = "fib slow autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
	TEST_CASE(test_multiple_create),
	TEST_CASES_END()
	}
};

/*
 * Do all unit tests.
 */
static int
test_fib(void)
{
	return unit_test_suite_runner(&fib_fast_tests);
}

static int
test_slow_fib(void)
{
	return unit_test_suite_runner(&fib_slow_tests);
}

REGISTER_FAST_TEST(fib_autotest, NOHUGE_OK, ASAN_OK, test_fib);
REGISTER_PERF_TEST(fib_slow_autotest, test_slow_fib);
