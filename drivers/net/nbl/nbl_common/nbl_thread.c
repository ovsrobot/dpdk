/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#include "nbl_common.h"

static rte_spinlock_t nbl_work_list_lock = RTE_SPINLOCK_INITIALIZER;
TAILQ_HEAD(nbl_work_list_head, nbl_work);
rte_thread_t nbl_work_tid;
static bool thread_exit;

static struct nbl_work_list_head nbl_work_list = TAILQ_HEAD_INITIALIZER(nbl_work_list);

static uint32_t nbl_thread_polling_task(__rte_unused void *param)
{
	struct timespec time;
	struct nbl_work *work;
	struct nbl_work *work_tmp;
	int i = 0;

	time.tv_sec = 0;
	time.tv_nsec = 100000;

	while (true) {
		i++;
		rte_spinlock_lock(&nbl_work_list_lock);
		RTE_TAILQ_FOREACH_SAFE(work, &nbl_work_list, next, work_tmp) {
			if (work->no_run)
				continue;

			if (work->run_once) {
				work->handler(work->params);
				TAILQ_REMOVE(&nbl_work_list, work, next);
			} else {
				if (i % work->tick == work->random)
					work->handler(work->params);
			}
		}

		rte_spinlock_unlock(&nbl_work_list_lock);
		nanosleep(&time, 0);
	}

	return 0;
}

int nbl_thread_add_work(struct nbl_work *work)
{
	int ret = 0;

	work->random = rte_rand() % work->tick;
	rte_spinlock_lock(&nbl_work_list_lock);

	if (thread_exit) {
		rte_thread_join(nbl_work_tid, NULL);
		nbl_work_tid.opaque_id = 0;
		thread_exit = 0;
	}

	if (!nbl_work_tid.opaque_id) {
		ret = rte_thread_create_internal_control(&nbl_work_tid, "nbl_thread",
						nbl_thread_polling_task, NULL);

		if (ret) {
			NBL_LOG(ERR, "create thread failed, ret %d", ret);
			rte_spinlock_unlock(&nbl_work_list_lock);
			return ret;
		}
	}

	NBL_ASSERT(nbl_work_tid.opaque_id);
	TAILQ_INSERT_HEAD(&nbl_work_list, work, next);
	rte_spinlock_unlock(&nbl_work_list_lock);

	return 0;
}

void nbl_thread_del_work(struct nbl_work *work)
{
	rte_spinlock_lock(&nbl_work_list_lock);
	TAILQ_REMOVE(&nbl_work_list, work, next);
	if (TAILQ_EMPTY(&nbl_work_list)) {
		pthread_cancel((pthread_t)nbl_work_tid.opaque_id);
		thread_exit = 1;
	}

	rte_spinlock_unlock(&nbl_work_list_lock);
}
