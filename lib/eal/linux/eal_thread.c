/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>

#include <rte_debug.h>
#include <rte_launch.h>
#include <rte_log.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_eal_trace.h>

#include "eal_private.h"
#include "eal_thread.h"

/*
 * Send a message to a worker lcore identified by worker_id to call a
 * function f with argument arg. Once the execution is done, the
 * remote lcore switches to WAIT state.
 */
int
rte_eal_remote_launch(int (*f)(void *), void *arg, unsigned int worker_id)
{
	int n;
	char c = 0;
	int m2w = lcore_config[worker_id].pipe_main2worker[1];
	int w2m = lcore_config[worker_id].pipe_worker2main[0];
	int rc = -EBUSY;

	/* Check if the worker is in 'WAIT' state. Use acquire order
	 * since 'state' variable is used as the guard variable.
	 */
	if (__atomic_load_n(&lcore_config[worker_id].state,
					__ATOMIC_ACQUIRE) != WAIT)
		goto finish;

	lcore_config[worker_id].arg = arg;
	/* Ensure that all the memory operations are completed
	 * before the worker thread starts running the function.
	 * Use worker thread function pointer as the guard variable.
	 */
	__atomic_store_n(&lcore_config[worker_id].f, f, __ATOMIC_RELEASE);

	/* send message */
	n = 0;
	while (n == 0 || (n < 0 && errno == EINTR))
		n = write(m2w, &c, 1);
	if (n < 0)
		rte_panic("cannot write on configuration pipe\n");

	/* wait ack */
	do {
		n = read(w2m, &c, 1);
	} while (n < 0 && errno == EINTR);

	if (n <= 0)
		rte_panic("cannot read on configuration pipe\n");

	rc = 0;
finish:
	rte_eal_trace_thread_remote_launch(f, arg, worker_id, rc);
	return rc;
}

/* main loop of threads */
__rte_noreturn void *
eal_thread_loop(void *arg)
{
	unsigned int lcore_id = (uintptr_t)arg;
	char c;
	int n, ret;
	int m2w, w2m;
	char cpuset[RTE_CPU_AFFINITY_STR_LEN];


	m2w = lcore_config[lcore_id].pipe_main2worker[0];
	w2m = lcore_config[lcore_id].pipe_worker2main[1];

	__rte_thread_init(lcore_id, &lcore_config[lcore_id].cpuset);

	ret = eal_thread_dump_current_affinity(cpuset, sizeof(cpuset));
	RTE_LOG(DEBUG, EAL, "lcore %u is ready (tid=%zx;cpuset=[%s%s])\n",
		lcore_id, (uintptr_t)pthread_self(), cpuset,
		ret == 0 ? "" : "...");

	rte_eal_trace_thread_lcore_ready(lcore_id, cpuset);

	/* read on our pipe to get commands */
	while (1) {
		lcore_function_t *f;
		void *fct_arg;

		/* wait command */
		do {
			n = read(m2w, &c, 1);
		} while (n < 0 && errno == EINTR);

		if (n <= 0)
			rte_panic("cannot read on configuration pipe\n");

		/* Set the state to 'RUNNING'. Use release order
		 * since 'state' variable is used as the guard variable.
		 */
		__atomic_store_n(&lcore_config[lcore_id].state, RUNNING,
					__ATOMIC_RELEASE);

		/* send ack */
		n = 0;
		while (n == 0 || (n < 0 && errno == EINTR))
			n = write(w2m, &c, 1);
		if (n < 0)
			rte_panic("cannot write on configuration pipe\n");

		/* Load 'f' with acquire order to ensure that
		 * the memory operations from the main thread
		 * are accessed only after update to 'f' is visible.
		 * Wait till the update to 'f' is visible to the worker.
		 */
		while ((f = __atomic_load_n(&lcore_config[lcore_id].f,
			__ATOMIC_ACQUIRE)) == NULL)
			rte_pause();

		/* call the function and store the return value */
		fct_arg = lcore_config[lcore_id].arg;
		ret = f(fct_arg);
		lcore_config[lcore_id].ret = ret;
		lcore_config[lcore_id].f = NULL;
		lcore_config[lcore_id].arg = NULL;

		/* Store the state with release order to ensure that
		 * the memory operations from the worker thread
		 * are completed before the state is updated.
		 * Use 'state' as the guard variable.
		 */
		__atomic_store_n(&lcore_config[lcore_id].state, WAIT,
					__ATOMIC_RELEASE);
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
	char truncated[16];

	strlcpy(truncated, name, sizeof(truncated));
	ret = pthread_setname_np(id, truncated);
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
