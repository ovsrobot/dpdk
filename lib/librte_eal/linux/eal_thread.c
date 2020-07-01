/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/queue.h>
#include <sys/syscall.h>

#include <rte_debug.h>
#include <rte_atomic.h>
#include <rte_launch.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_eal_trace.h>

#include "eal_private.h"
#include "eal_thread.h"

RTE_DEFINE_PER_LCORE(unsigned, _lcore_id) = LCORE_ID_ANY;
RTE_DEFINE_PER_LCORE(unsigned, _socket_id) = (unsigned)SOCKET_ID_ANY;
RTE_DEFINE_PER_LCORE(rte_cpuset_t, _cpuset);

/*
 * Send a message to a worker lcore identified by worker_id to call a
 * function f with argument arg. Once the execution is done, the
 * remote lcore switch in FINISHED state.
 */
int
rte_eal_remote_launch(int (*f)(void *), void *arg, unsigned worker_id)
{
	int n;
	char c = 0;
	int i2w = lcore_config[worker_id].pipe_init2worker[1];
	int w2i = lcore_config[worker_id].pipe_worker2init[0];
	int rc = -EBUSY;

	if (lcore_config[worker_id].state != WAIT)
		goto finish;

	lcore_config[worker_id].f = f;
	lcore_config[worker_id].arg = arg;

	/* send message */
	n = 0;
	while (n == 0 || (n < 0 && errno == EINTR))
		n = write(i2w, &c, 1);
	if (n < 0)
		rte_panic("cannot write on configuration pipe\n");

	/* wait ack */
	do {
		n = read(w2i, &c, 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0)
		rte_panic("cannot read on configuration pipe\n");

	rc = 0;
finish:
	rte_eal_trace_thread_remote_launch(f, arg, worker_id, rc);
	return rc;
}

/* set affinity for current EAL thread */
static int
eal_thread_set_affinity(void)
{
	unsigned lcore_id = rte_lcore_id();

	/* acquire system unique id  */
	rte_gettid();

	/* update EAL thread core affinity */
	return rte_thread_set_affinity(&lcore_config[lcore_id].cpuset);
}

void eal_thread_initial_lcore(unsigned lcore_id)
{
	/* set the lcore ID in per-lcore memory area */
	RTE_PER_LCORE(_lcore_id) = lcore_id;

	/* set CPU affinity */
	if (eal_thread_set_affinity() < 0)
		rte_panic("cannot set affinity\n");
}

/* main loop of threads */
__rte_noreturn void *
eal_thread_loop(__rte_unused void *arg)
{
	char c;
	int n, ret;
	unsigned lcore_id;
	pthread_t thread_id;
	int i2w, w2i;
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];

	thread_id = pthread_self();

	/* retrieve our lcore_id from the configuration structure */
	RTE_LCORE_FOREACH_WORKER(lcore_id) {
		if (thread_id == lcore_config[lcore_id].thread_id)
			break;
	}
	if (lcore_id == RTE_MAX_LCORE)
		rte_panic("cannot retrieve lcore id\n");

	i2w = lcore_config[lcore_id].pipe_init2worker[0];
	w2i = lcore_config[lcore_id].pipe_worker2init[1];

	/* set the lcore ID in per-lcore memory area */
	RTE_PER_LCORE(_lcore_id) = lcore_id;

	/* set CPU affinity */
	if (eal_thread_set_affinity() < 0)
		rte_panic("cannot set affinity\n");

	ret = eal_thread_dump_affinity(cpuset, sizeof(cpuset));

	RTE_LOG(DEBUG, EAL, "lcore %u is ready (tid=%zx;cpuset=[%s%s])\n",
		lcore_id, (uintptr_t)thread_id, cpuset, ret == 0 ? "" : "...");

	__rte_trace_mem_per_thread_alloc();
	rte_eal_trace_thread_lcore_ready(lcore_id, cpuset);

	/* read on our pipe to get commands */
	while (1) {
		void *fct_arg;

		/* wait command */
		do {
			n = read(i2w, &c, 1);
		} while (n < 0 && errno == EINTR);

		if (n <= 0)
			rte_panic("cannot read on configuration pipe\n");

		lcore_config[lcore_id].state = RUNNING;

		/* send ack */
		n = 0;
		while (n == 0 || (n < 0 && errno == EINTR))
			n = write(w2i, &c, 1);
		if (n < 0)
			rte_panic("cannot write on configuration pipe\n");

		if (lcore_config[lcore_id].f == NULL)
			rte_panic("NULL function pointer\n");

		/* call the function and store the return value */
		fct_arg = lcore_config[lcore_id].arg;
		ret = lcore_config[lcore_id].f(fct_arg);
		lcore_config[lcore_id].ret = ret;
		rte_wmb();

		/* when a service core returns, it should go directly to WAIT
		 * state, because the application will not lcore_wait() for it.
		 */
		if (lcore_config[lcore_id].core_role == ROLE_SERVICE)
			lcore_config[lcore_id].state = WAIT;
		else
			lcore_config[lcore_id].state = FINISHED;
	}

	/* never reached */
	/* pthread_exit(NULL); */
	/* return NULL; */
}

/* require calling thread tid by gettid() */
int rte_sys_gettid(void)
{
	return (int)syscall(SYS_gettid);
}

int rte_thread_setname(pthread_t id, const char *name)
{
	int ret = ENOSYS;
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 12)
	ret = pthread_setname_np(id, name);
#endif
#endif
	RTE_SET_USED(id);
	RTE_SET_USED(name);
	return -ret;
}

int rte_thread_getname(pthread_t id, char *name, size_t len)
{
	int ret = ENOSYS;
#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 12)
	ret = pthread_getname_np(id, name, len);
#endif
#endif
	RTE_SET_USED(id);
	RTE_SET_USED(name);
	RTE_SET_USED(len);
	return -ret;

}
