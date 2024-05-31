/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTDRV_4GA_H__
#define __NTDRV_4GA_H__

#include <rte_version.h>
#include <rte_thread.h>
#include "nthw_drv.h"
#include "nt4ga_adapter.h"
#include "nthw_platform_drv.h"

typedef struct ntdrv_4ga_s {
	uint32_t pciident;
	struct adapter_info_s adapter_info;
	char *p_drv_name;

	volatile bool b_shutdown;
	pthread_mutex_t stat_lck;
#if RTE_VERSION_NUM(23, 11, 0, 0) < RTE_VERSION
	rte_thread_t stat_thread;
	rte_thread_t flm_thread;
	rte_thread_t port_event_thread;
#else
	pthread_t stat_thread;
	pthread_t flm_thread;
	pthread_t port_event_thread;
#endif
} ntdrv_4ga_t;

#endif	/* __NTDRV_4GA_H__ */
