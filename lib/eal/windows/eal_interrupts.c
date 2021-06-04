/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <inttypes.h>

#include <rte_interrupts.h>

#include "eal_private.h"
#include "eal_windows.h"

static rte_thread_t intr_thread;

static HANDLE intr_iocp;

static void
eal_intr_process(const OVERLAPPED_ENTRY *event)
{
	RTE_SET_USED(event);
}

static void *
eal_intr_thread_main(LPVOID arg __rte_unused)
{
	while (1) {
		OVERLAPPED_ENTRY events[16];
		ULONG event_count, i;
		BOOL result;

		result = GetQueuedCompletionStatusEx(
			intr_iocp, events, RTE_DIM(events), &event_count,
			INFINITE, /* no timeout */
			TRUE);    /* alertable wait for alarm APCs */

		if (!result) {
			DWORD error = GetLastError();
			if (error != WAIT_IO_COMPLETION) {
				RTE_LOG_WIN32_ERR("GetQueuedCompletionStatusEx()");
				RTE_LOG(ERR, EAL, "Failed waiting for interrupts\n");
				break;
			}

			/* No I/O events, all work is done in completed APCs. */
			continue;
		}

		for (i = 0; i < event_count; i++)
			eal_intr_process(&events[i]);
	}

	CloseHandle(intr_iocp);
	intr_iocp = NULL;
	return NULL;
}

int
rte_eal_intr_init(void)
{
	int ret = 0;

	intr_iocp = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 1);
	if (intr_iocp == NULL) {
		RTE_LOG_WIN32_ERR("CreateIoCompletionPort()");
		RTE_LOG(ERR, EAL, "Cannot create interrupt IOCP\n");
		return -1;
	}

	ret = rte_ctrl_thread_create(&intr_thread, "eal-intr-thread", NULL,
			eal_intr_thread_main, NULL);
	if (ret != 0) {
		rte_errno = -ret;
		RTE_LOG(ERR, EAL, "Cannot create interrupt thread\n");
	}

	return ret;
}

int
rte_thread_is_intr(void)
{
	return rte_thread_equal(intr_thread, rte_thread_self());
}

int
rte_intr_rx_ctl(__rte_unused struct rte_intr_handle *intr_handle,
		__rte_unused int epfd, __rte_unused int op,
		__rte_unused unsigned int vec, __rte_unused void *data)
{
	return -ENOTSUP;
}

int
eal_intr_thread_schedule(void (*func)(void *arg), void *arg)
{
	HANDLE handle;

	handle = OpenThread(THREAD_ALL_ACCESS, FALSE, intr_thread.opaque_id);
	if (handle == NULL) {
		RTE_LOG_WIN32_ERR("OpenThread (%" PRIuPTR ")", intr_thread.opaque_id);
		return -ENOENT;
	}

	if (!QueueUserAPC((PAPCFUNC)(ULONG_PTR)func, handle, (ULONG_PTR)arg)) {
		RTE_LOG_WIN32_ERR("QueueUserAPC()");
		return -EINVAL;
	}

	return 0;
}

int
rte_intr_callback_register(
	__rte_unused const struct rte_intr_handle *intr_handle,
	__rte_unused rte_intr_callback_fn cb, __rte_unused void *cb_arg)
{
	return -ENOTSUP;
}

int
rte_intr_callback_unregister_pending(
	__rte_unused const struct rte_intr_handle *intr_handle,
	__rte_unused rte_intr_callback_fn cb_fn, __rte_unused void *cb_arg,
	__rte_unused rte_intr_unregister_callback_fn ucb_fn)
{
	return -ENOTSUP;
}

int
rte_intr_callback_unregister(
	__rte_unused const struct rte_intr_handle *intr_handle,
	__rte_unused rte_intr_callback_fn cb_fn, __rte_unused void *cb_arg)
{
	return 0;
}

int
rte_intr_callback_unregister_sync(
	__rte_unused const struct rte_intr_handle *intr_handle,
	__rte_unused rte_intr_callback_fn cb_fn, __rte_unused void *cb_arg)
{
	return 0;
}

int
rte_intr_enable(__rte_unused const struct rte_intr_handle *intr_handle)
{
	return -ENOTSUP;
}

int
rte_intr_ack(__rte_unused const struct rte_intr_handle *intr_handle)
{
	return -ENOTSUP;
}

int
rte_intr_disable(__rte_unused const struct rte_intr_handle *intr_handle)
{
	return -ENOTSUP;
}

int
rte_intr_efd_enable(struct rte_intr_handle *intr_handle, uint32_t nb_efd)
{
	RTE_SET_USED(intr_handle);
	RTE_SET_USED(nb_efd);

	return 0;
}

void
rte_intr_efd_disable(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
}

int
rte_intr_dp_is_en(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);

	return 0;
}

int
rte_intr_allow_others(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);

	return 1;
}

int
rte_intr_cap_multiple(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);

	return 0;
}

int
rte_epoll_wait(int epfd, struct rte_epoll_event *events,
		int maxevents, int timeout)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(events);
	RTE_SET_USED(maxevents);
	RTE_SET_USED(timeout);

	return -ENOTSUP;
}

int
rte_epoll_wait_interruptible(int epfd, struct rte_epoll_event *events,
			     int maxevents, int timeout)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(events);
	RTE_SET_USED(maxevents);
	RTE_SET_USED(timeout);

	return -ENOTSUP;
}

int
rte_epoll_ctl(int epfd, int op, int fd, struct rte_epoll_event *event)
{
	RTE_SET_USED(epfd);
	RTE_SET_USED(op);
	RTE_SET_USED(fd);
	RTE_SET_USED(event);

	return -ENOTSUP;
}

int
rte_intr_tls_epfd(void)
{
	return -ENOTSUP;
}

void
rte_intr_free_epoll_fd(struct rte_intr_handle *intr_handle)
{
	RTE_SET_USED(intr_handle);
}
