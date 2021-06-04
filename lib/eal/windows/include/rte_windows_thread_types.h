/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <rte_windows.h>

#define WINDOWS_MUTEX_INITIALIZER               (void*)-1
#define RTE_THREAD_MUTEX_INITIALIZER            {WINDOWS_MUTEX_INITIALIZER}

struct thread_mutex_t {
	void* mutex_id;
};

typedef struct thread_mutex_t rte_thread_mutex_t;

#endif /* _RTE_THREAD_TYPES_H_ */
