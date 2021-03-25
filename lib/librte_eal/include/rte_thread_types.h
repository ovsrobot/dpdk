/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Microsoft Corporation
 */

#ifndef _RTE_THREAD_TYPES_H_
#define _RTE_THREAD_TYPES_H_

#include <pthread.h>

#define EAL_THREAD_PRIORITY_NORMAL               0
#define EAL_THREAD_PRIORITY_REALTIME_CIRTICAL    99

typedef pthread_t                       rte_thread_t;

#endif /* _RTE_THREAD_TYPES_H_ */
