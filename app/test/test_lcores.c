/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2020 Red Hat, Inc.
 */

#include <sched.h>
#include <string.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_thread.h>
#include <rte_stdatomic.h>

#include "test.h"

#ifndef _POSIX_PRIORITY_SCHEDULING
/* sched_yield(2):
 * POSIX systems on which sched_yield() is available define
 * _POSIX_PRIORITY_SCHEDULING in <unistd.h>.
 */
#define sched_yield()
#endif

struct thread_context {
	enum { Thread_INIT, Thread_ERROR, Thread_DONE } state;
	bool lcore_id_any;
	rte_thread_t id;
	RTE_ATOMIC(unsigned int) *registered_count;
};

static uint32_t thread_loop(void *arg)
{
	struct thread_context *t = arg;
	unsigned int lcore_id;

	lcore_id = rte_lcore_id();
	if (lcore_id != LCORE_ID_ANY) {
		printf("Error: incorrect lcore id for new thread %u\n", lcore_id);
		t->state = Thread_ERROR;
	}
	if (rte_thread_register() < 0)
		printf("Warning: could not register new thread (this might be expected during this test), reason %s\n",
			rte_strerror(rte_errno));
	lcore_id = rte_lcore_id();
	if ((t->lcore_id_any && lcore_id != LCORE_ID_ANY) ||
			(!t->lcore_id_any && lcore_id == LCORE_ID_ANY)) {
		printf("Error: could not register new thread, got %u while %sexpecting %u\n",
			lcore_id, t->lcore_id_any ? "" : "not ", LCORE_ID_ANY);
		t->state = Thread_ERROR;
	}
	/* Report register happened to the control thread. */
	rte_atomic_fetch_add_explicit(t->registered_count, 1, rte_memory_order_release);

	/* Wait for release from the control thread. */
	while (rte_atomic_load_explicit(t->registered_count, rte_memory_order_acquire) != 0)
		sched_yield();
	rte_thread_unregister();
	lcore_id = rte_lcore_id();
	if (lcore_id != LCORE_ID_ANY) {
		printf("Error: could not unregister new thread, %u still assigned\n",
			lcore_id);
		t->state = Thread_ERROR;
	}

	if (t->state != Thread_ERROR)
		t->state = Thread_DONE;

	return 0;
}

static int
test_non_eal_lcores(unsigned int eal_threads_count)
{
	struct thread_context thread_contexts[RTE_MAX_LCORE];
	unsigned int non_eal_threads_count;
	RTE_ATOMIC(unsigned int) registered_count;
	struct thread_context *t;
	unsigned int i;
	int ret;

	non_eal_threads_count = 0;
	registered_count = 0;

	/* Try to create as many threads as possible. */
	for (i = 0; i < RTE_MAX_LCORE - eal_threads_count; i++) {
		t = &thread_contexts[i];
		t->state = Thread_INIT;
		t->registered_count = &registered_count;
		t->lcore_id_any = false;
		if (rte_thread_create(&t->id, NULL, thread_loop, t) != 0)
			break;
		non_eal_threads_count++;
	}
	printf("non-EAL threads count: %u\n", non_eal_threads_count);
	/* Wait all non-EAL threads to register. */
	while (rte_atomic_load_explicit(&registered_count, rte_memory_order_acquire) !=
			non_eal_threads_count)
		sched_yield();

	/* We managed to create the max number of threads, let's try to create
	 * one more. This will allow one more check.
	 */
	if (eal_threads_count + non_eal_threads_count < RTE_MAX_LCORE)
		goto skip_lcore_any;
	t = &thread_contexts[non_eal_threads_count];
	t->state = Thread_INIT;
	t->registered_count = &registered_count;
	t->lcore_id_any = true;
	if (rte_thread_create(&t->id, NULL, thread_loop, t) == 0) {
		non_eal_threads_count++;
		printf("non-EAL threads count: %u\n", non_eal_threads_count);
		while (rte_atomic_load_explicit(&registered_count, rte_memory_order_acquire) !=
				non_eal_threads_count)
			sched_yield();
	}

skip_lcore_any:
	/* Release all threads, and check their states. */
	rte_atomic_store_explicit(&registered_count, 0, rte_memory_order_release);
	ret = 0;
	for (i = 0; i < non_eal_threads_count; i++) {
		t = &thread_contexts[i];
		rte_thread_join(t->id, NULL);
		if (t->state != Thread_DONE)
			ret = -1;
	}

	return ret;
}

struct limit_lcore_context {
	unsigned int init;
	unsigned int max;
	unsigned int uninit;
};

static int
limit_lcores_init(unsigned int lcore_id __rte_unused, void *arg)
{
	struct limit_lcore_context *l = arg;

	l->init++;
	if (l->init > l->max)
		return -1;
	return 0;
}

static void
limit_lcores_uninit(unsigned int lcore_id __rte_unused, void *arg)
{
	struct limit_lcore_context *l = arg;

	l->uninit++;
}

static int
test_lcores_callback(unsigned int eal_threads_count)
{
	struct limit_lcore_context l;
	void *handle;

	/* Refuse last lcore => callback register error. */
	memset(&l, 0, sizeof(l));
	l.max = eal_threads_count - 1;
	handle = rte_lcore_callback_register("limit", limit_lcores_init,
		limit_lcores_uninit, &l);
	if (handle != NULL) {
		printf("Error: lcore callback register should have failed\n");
		goto error;
	}
	/* Refusal happens at the n th call to the init callback.
	 * Besides, n - 1 were accepted, so we expect as many uninit calls when
	 * the rollback happens.
	 */
	if (l.init != eal_threads_count) {
		printf("Error: lcore callback register failed but incorrect init calls, expected %u, got %u\n",
			eal_threads_count, l.init);
		goto error;
	}
	if (l.uninit != eal_threads_count - 1) {
		printf("Error: lcore callback register failed but incorrect uninit calls, expected %u, got %u\n",
			eal_threads_count - 1, l.uninit);
		goto error;
	}

	/* Accept all lcore and unregister. */
	memset(&l, 0, sizeof(l));
	l.max = eal_threads_count;
	handle = rte_lcore_callback_register("limit", limit_lcores_init,
		limit_lcores_uninit, &l);
	if (handle == NULL) {
		printf("Error: lcore callback register failed\n");
		goto error;
	}
	if (l.uninit != 0) {
		printf("Error: lcore callback register succeeded but incorrect uninit calls, expected 0, got %u\n",
			l.uninit);
		goto error;
	}
	rte_lcore_callback_unregister(handle);
	handle = NULL;
	if (l.init != eal_threads_count) {
		printf("Error: lcore callback unregister done but incorrect init calls, expected %u, got %u\n",
			eal_threads_count, l.init);
		goto error;
	}
	if (l.uninit != eal_threads_count) {
		printf("Error: lcore callback unregister done but incorrect uninit calls, expected %u, got %u\n",
			eal_threads_count, l.uninit);
		goto error;
	}

	return 0;

error:
	if (handle != NULL)
		rte_lcore_callback_unregister(handle);

	return -1;
}

static int
test_non_eal_lcores_callback(unsigned int eal_threads_count)
{
	struct thread_context thread_contexts[2];
	unsigned int non_eal_threads_count = 0;
	struct limit_lcore_context l[2] = {};
	RTE_ATOMIC(unsigned int) registered_count = 0;
	struct thread_context *t;
	void *handle[2] = {};
	unsigned int i;
	int ret;

	/* This test requires two empty slots to be sure lcore init refusal is
	 * because of callback execution.
	 */
	if (eal_threads_count + 2 >= RTE_MAX_LCORE)
		return 0;

	/* Register two callbacks:
	 * - first one accepts any lcore,
	 * - second one accepts all EAL lcore + one more for the first non-EAL
	 *   thread, then refuses the next lcore.
	 */
	l[0].max = UINT_MAX;
	handle[0] = rte_lcore_callback_register("no_limit", limit_lcores_init,
		limit_lcores_uninit, &l[0]);
	if (handle[0] == NULL) {
		printf("Error: lcore callback [0] register failed\n");
		goto error;
	}
	l[1].max = eal_threads_count + 1;
	handle[1] = rte_lcore_callback_register("limit", limit_lcores_init,
		limit_lcores_uninit, &l[1]);
	if (handle[1] == NULL) {
		printf("Error: lcore callback [1] register failed\n");
		goto error;
	}
	if (l[0].init != eal_threads_count || l[1].init != eal_threads_count) {
		printf("Error: lcore callbacks register succeeded but incorrect init calls, expected %u, %u, got %u, %u\n",
			eal_threads_count, eal_threads_count,
			l[0].init, l[1].init);
		goto error;
	}
	if (l[0].uninit != 0 || l[1].uninit != 0) {
		printf("Error: lcore callbacks register succeeded but incorrect uninit calls, expected 0, 1, got %u, %u\n",
			l[0].uninit, l[1].uninit);
		goto error;
	}
	/* First thread that expects a valid lcore id. */
	t = &thread_contexts[0];
	t->state = Thread_INIT;
	t->registered_count = &registered_count;
	t->lcore_id_any = false;
	if (rte_thread_create(&t->id, NULL, thread_loop, t) != 0)
		goto cleanup_threads;
	non_eal_threads_count++;
	while (rte_atomic_load_explicit(&registered_count, rte_memory_order_acquire) !=
			non_eal_threads_count)
		sched_yield();
	if (l[0].init != eal_threads_count + 1 ||
			l[1].init != eal_threads_count + 1) {
		printf("Error: incorrect init calls, expected %u, %u, got %u, %u\n",
			eal_threads_count + 1, eal_threads_count + 1,
			l[0].init, l[1].init);
		goto cleanup_threads;
	}
	if (l[0].uninit != 0 || l[1].uninit != 0) {
		printf("Error: incorrect uninit calls, expected 0, 0, got %u, %u\n",
			l[0].uninit, l[1].uninit);
		goto cleanup_threads;
	}
	/* Second thread, that expects LCORE_ID_ANY because of init refusal. */
	t = &thread_contexts[1];
	t->state = Thread_INIT;
	t->registered_count = &registered_count;
	t->lcore_id_any = true;
	if (rte_thread_create(&t->id, NULL, thread_loop, t) != 0)
		goto cleanup_threads;
	non_eal_threads_count++;
	while (rte_atomic_load_explicit(&registered_count, rte_memory_order_acquire) !=
			non_eal_threads_count)
		sched_yield();
	if (l[0].init != eal_threads_count + 2 ||
			l[1].init != eal_threads_count + 2) {
		printf("Error: incorrect init calls, expected %u, %u, got %u, %u\n",
			eal_threads_count + 2, eal_threads_count + 2,
			l[0].init, l[1].init);
		goto cleanup_threads;
	}
	if (l[0].uninit != 1 || l[1].uninit != 0) {
		printf("Error: incorrect uninit calls, expected 1, 0, got %u, %u\n",
			l[0].uninit, l[1].uninit);
		goto cleanup_threads;
	}
	rte_lcore_dump(stdout);
	/* Release all threads, and check their states. */
	rte_atomic_store_explicit(&registered_count, 0, rte_memory_order_release);
	ret = 0;
	for (i = 0; i < non_eal_threads_count; i++) {
		t = &thread_contexts[i];
		rte_thread_join(t->id, NULL);
		if (t->state != Thread_DONE)
			ret = -1;
	}
	if (ret < 0)
		goto error;
	rte_lcore_dump(stdout);
	if (l[0].uninit != 2 || l[1].uninit != 1) {
		printf("Error: threads reported having successfully registered and unregistered, but incorrect uninit calls, expected 2, 1, got %u, %u\n",
			l[0].uninit, l[1].uninit);
		goto error;
	}
	rte_lcore_callback_unregister(handle[0]);
	rte_lcore_callback_unregister(handle[1]);
	return 0;

cleanup_threads:
	/* Release all threads */
	rte_atomic_store_explicit(&registered_count, 0, rte_memory_order_release);
	for (i = 0; i < non_eal_threads_count; i++) {
		t = &thread_contexts[i];
		rte_thread_join(t->id, NULL);
	}
error:
	if (handle[1] != NULL)
		rte_lcore_callback_unregister(handle[1]);
	if (handle[0] != NULL)
		rte_lcore_callback_unregister(handle[0]);
	return -1;
}

static uint32_t ctrl_thread_loop(void *arg)
{
	struct thread_context *t = arg;

	printf("Control thread running successfully\n");

	/* Set the thread state to DONE */
	t->state = Thread_DONE;

	return 0;
}

static int
test_ctrl_thread(void)
{
	struct thread_context ctrl_thread_context;
	struct thread_context *t;

	/* Create one control thread */
	t = &ctrl_thread_context;
	t->state = Thread_INIT;
	if (rte_thread_create_control(&t->id, "dpdk-test-ctrlt",
				ctrl_thread_loop, t) != 0)
		return -1;

	/* Wait till the control thread exits.
	 * This also acts as the barrier such that the memory operations
	 * in control thread are visible to this thread.
	 */
	rte_thread_join(t->id, NULL);

	/* Check if the control thread set the correct state */
	if (t->state != Thread_DONE)
		return -1;

	return 0;
}

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
static int
test_topology_macro(void)
{
	unsigned int total_lcores = 0;
	unsigned int total_wrkr_lcores = 0;

	unsigned int total_lcore_io = 0;
	unsigned int total_lcore_l4 = 0;
	unsigned int total_lcore_l3 = 0;
	unsigned int total_lcore_l2 = 0;
	unsigned int total_lcore_l1 = 0;

	unsigned int total_wrkr_lcore_io = 0;
	unsigned int total_wrkr_lcore_l4 = 0;
	unsigned int total_wrkr_lcore_l3 = 0;
	unsigned int total_wrkr_lcore_l2 = 0;
	unsigned int total_wrkr_lcore_l1 = 0;

	unsigned int lcore;

	/* get topology core count */
	lcore = -1;
	RTE_LCORE_FOREACH(lcore)
		total_lcores += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER(lcore)
		total_wrkr_lcores += 1;

	if ((total_wrkr_lcores + 1) != total_lcores) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH\n");
		return -2;
	}

	lcore = -1;
	RTE_LCORE_FOREACH_DOMAIN(lcore, RTE_LCORE_DOMAIN_IO)
		total_lcore_io += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_DOMAIN(lcore, RTE_LCORE_DOMAIN_L4)
		total_lcore_l4 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_DOMAIN(lcore, RTE_LCORE_DOMAIN_L3)
		total_lcore_l3 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_DOMAIN(lcore, RTE_LCORE_DOMAIN_L2)
		total_lcore_l2 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_DOMAIN(lcore, RTE_LCORE_DOMAIN_L1)
		total_lcore_l1 += 1;

	printf("DBG: lcore count: default (%u), io (%u), l4 (%u), l3 (%u), l2 (%u), l1 (%u).\n",
		total_lcores, total_lcore_io,
		total_lcore_l4, total_lcore_l3, total_lcore_l2, total_lcore_l1);


	lcore = -1;
	RTE_LCORE_FOREACH_WORKER_DOMAIN(lcore, RTE_LCORE_DOMAIN_IO)
		total_wrkr_lcore_io += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER_DOMAIN(lcore, RTE_LCORE_DOMAIN_L4)
		total_wrkr_lcore_l4 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER_DOMAIN(lcore, RTE_LCORE_DOMAIN_L3)
		total_wrkr_lcore_l3 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER_DOMAIN(lcore, RTE_LCORE_DOMAIN_L2)
		total_wrkr_lcore_l2 += 1;

	lcore = -1;
	RTE_LCORE_FOREACH_WORKER_DOMAIN(lcore, RTE_LCORE_DOMAIN_L1)
		total_wrkr_lcore_l1 += 1;

	printf("DBG: worker lcore count: default (%u), io (%u), l4 (%u), l3 (%u), l2 (%u), l1 (%u).\n",
		total_wrkr_lcores, total_wrkr_lcore_io,
		total_wrkr_lcore_l4, total_wrkr_lcore_l3,
		total_wrkr_lcore_l2, total_wrkr_lcore_l1);


	if ((total_wrkr_lcore_io) > total_lcore_io) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH_DOMAIN for IO\n");
		return -2;
	}

	if ((total_wrkr_lcore_l4) > total_lcore_l4) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH_DOMAIN for L4\n");
		return -2;
	}

	if ((total_wrkr_lcore_l3) > total_lcore_l3) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH_DOMAIN for L3\n");
		return -2;
	}

	if ((total_wrkr_lcore_l2) > total_lcore_l2) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH_DOMAIN for L2\n");
		return -2;
	}

	if ((total_wrkr_lcore_l1) > total_lcore_l1) {
		printf("ERR: failed in MACRO for RTE_LCORE_FOREACH_DOMAIN for L1\n");
		return -2;
	}

	total_lcore_io = 0;
	total_lcore_l4 = 0;
	total_lcore_l3 = 0;
	total_lcore_l2 = 0;
	total_lcore_l1 = 0;

	lcore = -1;
	RTE_LCORE_FORN_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_IO, 0)
		total_lcore_io += 1;

	lcore = -1;
	RTE_LCORE_FORN_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L4, 0)
		total_lcore_l4 += 1;

	lcore = -1;
	RTE_LCORE_FORN_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L3, 0)
		total_lcore_l3 += 1;

	lcore = -1;
	RTE_LCORE_FORN_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L2, 0)
		total_lcore_l2 += 1;

	lcore = -1;
	RTE_LCORE_FORN_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L1, 0)
		total_lcore_l1 += 1;

	printf("DBG: macro domain lcore: default (%u), io (%u), l4 (%u), l3 (%u), l2 (%u), l1 (%u).\n",
		total_lcores, total_lcore_io,
		total_lcore_l4, total_lcore_l3, total_lcore_l2, total_lcore_l1);

	total_wrkr_lcore_io = 0;
	total_wrkr_lcore_l4 = 0;
	total_wrkr_lcore_l3 = 0;
	total_wrkr_lcore_l2 = 0;
	total_wrkr_lcore_l1 = 0;

	lcore = -1;
	RTE_LCORE_FORN_WORKER_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_IO, 0)
		total_wrkr_lcore_io += 1;

	lcore = -1;
	RTE_LCORE_FORN_WORKER_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L4, 0)
		total_wrkr_lcore_l4 += 1;

	lcore = -1;
	RTE_LCORE_FORN_WORKER_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L3, 0)
		total_wrkr_lcore_l3 += 1;

	lcore = -1;
	RTE_LCORE_FORN_WORKER_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L2, 0)
		total_wrkr_lcore_l2 += 1;

	lcore = -1;
	RTE_LCORE_FORN_WORKER_NEXT_DOMAIN(lcore, RTE_LCORE_DOMAIN_L1, 0)
		total_wrkr_lcore_l1 += 1;

	printf("DBG: macro next domain worker count: default (%u), io (%u), l4 (%u), l3 (%u), l2 (%u), l1 (%u).\n",
		total_wrkr_lcores, total_wrkr_lcore_io,
		total_wrkr_lcore_l4, total_wrkr_lcore_l3,
		total_wrkr_lcore_l2, total_wrkr_lcore_l1);

	if ((total_wrkr_lcore_io) > total_lcore_io) {
		printf("ERR: failed in MACRO for RTE_LCORE_FORN_NEXT_DOMAIN for IO\n");
		return -2;
	}

	if ((total_wrkr_lcore_l4) > total_lcore_l4) {
		printf("ERR: failed in MACRO for RTE_LCORE_FORN_NEXT_DOMAIN for L4\n");
		return -2;
	}

	if ((total_wrkr_lcore_l3) > total_lcore_l3) {
		printf("ERR: failed in MACRO for RTE_LCORE_FORN_NEXT_DOMAIN for L3\n");
		return -2;
	}

	if ((total_wrkr_lcore_l2) > total_lcore_l2) {
		printf("ERR: failed in MACRO for RTE_LCORE_FORN_NEXT_DOMAIN for L2\n");
		return -2;
	}

	if ((total_wrkr_lcore_l1) > total_lcore_l1) {
		printf("ERR: failed in MACRO for RTE_LCORE_FORN_NEXT_DOMAIN for L1\n");
		return -2;
	}
	printf("INFO: lcore DOMAIN macro: success!\n");
	return 0;
}

static int
test_lcore_count_from_domain(void)
{
	unsigned int total_lcores = 0;
	unsigned int total_lcore_io = 0;
	unsigned int total_lcore_l4 = 0;
	unsigned int total_lcore_l3 = 0;
	unsigned int total_lcore_l2 = 0;
	unsigned int total_lcore_l1 = 0;

	unsigned int domain_count;
	unsigned int i;

	/* get topology core count */
	total_lcores = rte_lcore_count();

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_IO);
	for (i = 0; i < domain_count; i++)
		total_lcore_io += rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_IO, i);

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L4);
	for (i = 0; i < domain_count; i++)
		total_lcore_l4 += rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L4, i);

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L3);
	for (i = 0; i < domain_count; i++)
		total_lcore_l3 += rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L3, i);

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L2);
	for (i = 0; i < domain_count; i++)
		total_lcore_l2 += rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L2, i);

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L1);
	for (i = 0; i < domain_count; i++)
		total_lcore_l1 += rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L1, i);

	printf("DBG: lcore count: default (%u), io (%u), l4 (%u), l3 (%u), l2 (%u), l1 (%u).\n",
		total_lcores, total_lcore_io,
		total_lcore_l4, total_lcore_l3, total_lcore_l2, total_lcore_l1);

	if ((total_lcore_l1 && (total_lcores != total_lcore_l1)) ||
		(total_lcore_l2 && (total_lcores != total_lcore_l2)) ||
		(total_lcore_l3 && (total_lcores != total_lcore_l3)) ||
		(total_lcore_l4 && (total_lcores != total_lcore_l4)) ||
		(total_lcore_io && (total_lcores != total_lcore_io))) {
		printf("ERR: failed in domain API\n");
		return -2;
	}

	printf("INFO: lcore count domain API: success\n");

	return 0;
}

#ifdef RTE_HAS_CPUSET
static int
test_lcore_cpuset_from_domain(void)
{
	unsigned int domain_count;
	uint16_t dmn_idx;
	rte_cpuset_t cpu_set_list;

	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_IO);

	for (; dmn_idx < domain_count; dmn_idx++) {
		cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_IO, dmn_idx);

		for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
			if (CPU_ISSET(cpu_idx, &cpu_set_list)) {
				if (!rte_lcore_is_enabled(cpu_idx)) {
					printf("ERR: lcore id: %u, shared from IO (%u) domain is not enabled!\n",
						cpu_idx, dmn_idx);
					return -1;
				}
			}
		}
	}

	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L4);

	for (; dmn_idx < domain_count; dmn_idx++) {
		cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L4, dmn_idx);

		for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
			if (CPU_ISSET(cpu_idx, &cpu_set_list)) {
				if (!rte_lcore_is_enabled(cpu_idx)) {
					printf("ERR: lcore id: %u, shared from L4 (%u) domain is not enabled!\n",
						cpu_idx, dmn_idx);
					return -1;
				}
			}
		}
	}

	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L3);

	for (; dmn_idx < domain_count; dmn_idx++) {
		cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L3, dmn_idx);

		for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
			if (CPU_ISSET(cpu_idx, &cpu_set_list)) {
				if (!rte_lcore_is_enabled(cpu_idx)) {
					printf("ERR: lcore id: %u, shared from L3 (%u) domain is not enabled!\n",
						cpu_idx, dmn_idx);
					return -1;
				}
			}
		}
	}

	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L2);

	for (; dmn_idx < domain_count; dmn_idx++) {
		cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L2, dmn_idx);

		for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
			if (CPU_ISSET(cpu_idx, &cpu_set_list)) {
				if (!rte_lcore_is_enabled(cpu_idx)) {
					printf("ERR: lcore id: %u, shared from L2 (%u) domain is not enabled!\n",
						cpu_idx, dmn_idx);
					return -1;
				}
			}
		}
	}

	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L1);

	for (; dmn_idx < domain_count; dmn_idx++) {
		cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L1, dmn_idx);

		for (uint16_t cpu_idx = 0; cpu_idx < RTE_MAX_LCORE; cpu_idx++) {
			if (CPU_ISSET(cpu_idx, &cpu_set_list)) {
				if (!rte_lcore_is_enabled(cpu_idx)) {
					printf("ERR: lcore id: %u, shared from IO (%u) domain is not enabled!\n",
						cpu_idx, dmn_idx);
					return -1;
				}
			}
		}
	}

	cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L1, RTE_MAX_LCORE);
	if (CPU_COUNT(&cpu_set_list)) {
		printf("ERR: RTE_MAX_LCORE (%u) in L1 domain is enabled!\n", RTE_MAX_LCORE);
		return -2;
	}

	cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L2, RTE_MAX_LCORE);
	if (CPU_COUNT(&cpu_set_list)) {
		printf("ERR: RTE_MAX_LCORE (%u) in L2 domain is enabled!\n", RTE_MAX_LCORE);
		return -2;
	}

	cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_L3, RTE_MAX_LCORE);
	if (CPU_COUNT(&cpu_set_list)) {
		printf("ERR: RTE_MAX_LCORE (%u) in L3 domain is enabled!\n", RTE_MAX_LCORE);
		return -2;
	}

	cpu_set_list = rte_lcore_cpuset_in_domain(RTE_LCORE_DOMAIN_IO, RTE_MAX_LCORE);
	if (CPU_COUNT(&cpu_set_list)) {
		printf("ERR: RTE_MAX_LCORE (%u) in IO domain is enabled!\n", RTE_MAX_LCORE);
		return -2;
	}

	printf("INFO: cpuset_in_domain API: success!\n");
	return 0;
}
#endif

static int
test_main_lcore_in_domain(void)
{
	bool main_lcore_found;
	unsigned int domain_count;
	uint16_t dmn_idx;

	main_lcore_found = false;
	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_IO);
	for (; dmn_idx < domain_count; dmn_idx++) {
		main_lcore_found = rte_lcore_is_main_in_domain(RTE_LCORE_DOMAIN_IO, dmn_idx);
		if (main_lcore_found) {
			printf("DBG: main lcore found in IO domain: %u\n", dmn_idx);
			break;
		}
	}

	if ((domain_count) && (main_lcore_found == false)) {
		printf("ERR: main lcore is not found in any of the IO domain!\n");
		return -1;
	}

	main_lcore_found = false;
	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L4);
	for (; dmn_idx  < domain_count; dmn_idx++) {
		main_lcore_found = rte_lcore_is_main_in_domain(RTE_LCORE_DOMAIN_L4, dmn_idx);
		if (main_lcore_found) {
			printf("DBG: main lcore found in L4 domain: %u\n", dmn_idx);
			break;
		}
	}

	if ((domain_count) && (main_lcore_found == false)) {
		printf("ERR: main lcore is not found in any of the L4 domain!\n");
		return -1;
	}

	main_lcore_found = false;
	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L3);
	for (; dmn_idx  < domain_count; dmn_idx++) {
		main_lcore_found = rte_lcore_is_main_in_domain(RTE_LCORE_DOMAIN_L3, dmn_idx);
		if (main_lcore_found) {
			printf("DBG: main lcore found in L3 domain: %u\n", dmn_idx);
			break;
		}
	}

	if ((domain_count) && (main_lcore_found == false)) {
		printf("ERR: main lcore is not found in any of the L3 domain!\n");
		return -1;
	}

	main_lcore_found = false;
	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L2);
	for (; dmn_idx  < domain_count; dmn_idx++) {
		main_lcore_found = rte_lcore_is_main_in_domain(RTE_LCORE_DOMAIN_L2, dmn_idx);
		if (main_lcore_found) {
			printf("DBG: main lcore is found on the L2 domain: %u\n", dmn_idx);
			break;
		}
	}

	if ((domain_count) && (main_lcore_found == false)) {
		printf("ERR: main lcore is not found in any of the L2 domain!\n");
		return -1;
	}

	main_lcore_found = false;
	dmn_idx = 0;
	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L1);
	for (; dmn_idx  < domain_count; dmn_idx++) {
		main_lcore_found = rte_lcore_is_main_in_domain(RTE_LCORE_DOMAIN_L1, dmn_idx);
		if (main_lcore_found) {
			printf("DBG: main lcore is found on the L1 domain: %u\n", dmn_idx);
			break;
		}
	}

	if ((domain_count) && (main_lcore_found == false)) {
		printf("ERR: main lcore is not found in any of the L1 domain!\n");
		return -1;
	}

	printf("INFO: is_main_lcore_in_domain API: success!\n");
	return 0;
}

static int
test_lcore_from_domain_negative(void)
{
	unsigned int domain_count;

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_IO);
	if ((domain_count) && (rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_IO, domain_count))) {
		printf("ERR: domain API inconsistent for IO\n");
		return -1;
	}

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L4);
	if ((domain_count) && (rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L4, domain_count))) {
		printf("ERR: domain API inconsistent for L4\n");
		return -1;
	}

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L3);
	if ((domain_count) && (rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L3, domain_count))) {
		printf("ERR: domain API inconsistent for L3\n");
		return -1;
	}

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L2);
	if ((domain_count) && (rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L2, domain_count))) {
		printf("ERR: domain API inconsistent for L2\n");
		return -1;
	}

	domain_count = rte_get_domain_count(RTE_LCORE_DOMAIN_L1);
	if ((domain_count) && (rte_lcore_count_from_domain(RTE_LCORE_DOMAIN_L1, domain_count))) {
		printf("ERR: domain API inconsistent for L1\n");
		return -1;
	}

	printf("INFO: lcore domain API: success!\n");
	return 0;
}
#endif

static int
test_lcores(void)
{
	unsigned int eal_threads_count = 0;
	unsigned int i;

	for (i = 0; i < RTE_MAX_LCORE; i++) {
		if (!rte_lcore_has_role(i, ROLE_OFF))
			eal_threads_count++;
	}
	if (eal_threads_count == 0) {
		printf("Error: something is broken, no EAL thread detected.\n");
		return TEST_FAILED;
	}
	printf("EAL threads count: %u, RTE_MAX_LCORE=%u\n", eal_threads_count,
		RTE_MAX_LCORE);
	rte_lcore_dump(stdout);

	if (test_non_eal_lcores(eal_threads_count) < 0)
		return TEST_FAILED;

	if (test_lcores_callback(eal_threads_count) < 0)
		return TEST_FAILED;

	if (test_non_eal_lcores_callback(eal_threads_count) < 0)
		return TEST_FAILED;

	if (test_ctrl_thread() < 0)
		return TEST_FAILED;

#ifdef RTE_EAL_HWLOC_TOPOLOGY_PROBE
	printf("\nTopology test\n");

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
#endif

	return TEST_SUCCESS;
}

REGISTER_FAST_TEST(lcores_autotest, true, true, test_lcores);
