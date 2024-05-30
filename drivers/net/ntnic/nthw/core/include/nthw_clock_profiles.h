/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef _NTHW_CLOCK_PROFILES_H_
#define _NTHW_CLOCK_PROFILES_H_

/* TODO: figure out why static_assert(sizeof(x)...) does not work in plain C */
#ifndef __cplusplus
#ifndef __KERNEL__
#include <assert.h>	/* static_assert */
#endif	/* __KERNEL__ */
#endif	/* __cplusplus */

#include "nthw_helper.h"

#include "clock_profiles_structs.h"

#endif	/* _NTHW_CLOCK_PROFILES_H_ */
