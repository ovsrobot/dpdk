/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <pthread.h>

#define RTE_THREAD_MUTEX_INITIALIZER     PTHREAD_MUTEX_INITIALIZER

typedef pthread_mutex_t                 rte_thread_mutex_t;

#endif /* _RTE_THREAD_TYPES_H_ */
