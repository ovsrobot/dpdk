/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <rte_windows.h>

#define EAL_THREAD_PRIORITY_NORMAL             THREAD_PRIORITY_NORMAL
#define EAL_THREAD_PRIORITY_REALTIME_CIRTICAL  THREAD_PRIORITY_TIME_CRITICAL

typedef DWORD                       rte_thread_t;

#endif /* _RTE_THREAD_TYPES_H_ */
