/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include <io.h>

#include <rte_atomic.h>
#include <rte_debug.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_common.h>
#include <rte_memory.h>
#include <eal_thread.h>

#include "eal_private.h"
#include "eal_windows.h"

RTE_DEFINE_PER_LCORE(unsigned int, _lcore_id) = LCORE_ID_ANY;
RTE_DEFINE_PER_LCORE(unsigned int, _socket_id) = (unsigned int)SOCKET_ID_ANY;
RTE_DEFINE_PER_LCORE(rte_cpuset_t, _cpuset);

/*
 * Send a message to a worker lcore identified by worker_id to call a
 * function f with argument arg. Once the execution is done, the
 * remote lcore switch in FINISHED state.
 */
int
rte_eal_remote_launch(lcore_function_t *f, void *arg, unsigned int worker_id)
{
	int n;
	char c = 0;
	int i2w = lcore_config[worker_id].pipe_init2worker[1];
	int w2i = lcore_config[worker_id].pipe_worker2init[0];

	if (lcore_config[worker_id].state != WAIT)
		return -EBUSY;

	lcore_config[worker_id].f = f;
	lcore_config[worker_id].arg = arg;

	/* send message */
	n = 0;
	while (n == 0 || (n < 0 && errno == EINTR))
		n = _write(i2w, &c, 1);
	if (n < 0)
		rte_panic("cannot write on configuration pipe\n");

	/* wait ack */
	do {
		n = _read(w2i, &c, 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0)
		rte_panic("cannot read on configuration pipe\n");

	return 0;
}

void
eal_thread_set_initial_lcore(unsigned int lcore_id)
{
	/* set the lcore ID in per-lcore memory area */
	RTE_PER_LCORE(_lcore_id) = lcore_id;
}

/* main loop of threads */
void *
eal_thread_loop(void *arg __rte_unused)
{
	char c;
	int n, ret;
	unsigned int lcore_id;
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

	RTE_LOG(DEBUG, EAL, "lcore %u is ready (tid=%zx;cpuset=[%s])\n",
		lcore_id, (uintptr_t)thread_id, cpuset);

	/* read on our pipe to get commands */
	while (1) {
		void *fct_arg;

		/* wait command */
		do {
			n = _read(i2w, &c, 1);
		} while (n < 0 && errno == EINTR);

		if (n <= 0)
			rte_panic("cannot read on configuration pipe\n");

		lcore_config[lcore_id].state = RUNNING;

		/* send ack */
		n = 0;
		while (n == 0 || (n < 0 && errno == EINTR))
			n = _write(w2i, &c, 1);
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
}

/* function to create threads */
int
eal_thread_create(pthread_t *thread)
{
	HANDLE th;

	th = CreateThread(NULL, 0,
		(LPTHREAD_START_ROUTINE)(ULONG_PTR)eal_thread_loop,
						NULL, 0, (LPDWORD)thread);
	if (!th)
		return -1;

	SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
	SetThreadPriority(th, THREAD_PRIORITY_TIME_CRITICAL);

	return 0;
}

/* get current thread ID */
int
rte_sys_gettid(void)
{
	return GetCurrentThreadId();
}

int
rte_thread_setname(__rte_unused pthread_t id, __rte_unused const char *name)
{
	/* TODO */
	/* This is a stub, not the expected result */
	return 0;
}
