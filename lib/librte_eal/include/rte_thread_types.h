/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <pthread.h>

#define RTE_THREAD_BARRIER_SERIAL_THREAD PTHREAD_BARRIER_SERIAL_THREAD
#define RTE_THREAD_MUTEX_INITIALIZER     PTHREAD_MUTEX_INITIALIZER

#define EAL_THREAD_PRIORITY_NORMAL               0
#define EAL_THREAD_PRIORITY_REALTIME_CIRTICAL    99

typedef pthread_t                       rte_thread_t;
typedef pthread_mutex_t                 rte_thread_mutex_t;
typedef pthread_barrier_t               rte_thread_barrier_t;

#endif /* _RTE_THREAD_TYPES_H_ */
