/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <rte_windows.h>

#define RTE_THREAD_BARRIER_SERIAL_THREAD TRUE

#define EAL_THREAD_PRIORITY_NORMAL             THREAD_PRIORITY_NORMAL
#define EAL_THREAD_PRIORITY_REALTIME_CIRTICAL  THREAD_PRIORITY_TIME_CRITICAL

typedef DWORD                       rte_thread_t;
typedef CRITICAL_SECTION            rte_thread_mutex_t;
typedef SYNCHRONIZATION_BARRIER     rte_thread_barrier_t;

#endif /* _RTE_THREAD_TYPES_H_ */
