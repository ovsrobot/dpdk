/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTDRV_4GA_H__
#define __NTDRV_4GA_H__

#include "nthw_drv.h"
#include "nt4ga_adapter.h"
#include "nthw_platform_drv.h"

typedef struct ntdrv_4ga_s {
	uint32_t pciident;
	struct adapter_info_s adapter_info;
	char *p_drv_name;

	volatile bool b_shutdown;
	pthread_mutex_t stat_lck;
	pthread_t stat_thread;
	pthread_t flm_thread;
} ntdrv_4ga_t;

#endif /* __NTDRV_4GA_H__ */
