/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#ifndef __NTHW_HELPER_H__
#define __NTHW_HELPER_H__

#include <unistd.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>

#ifndef PRIXPTR
#define PRIXPTR "llX"
#endif

#ifndef UINT8_MAX
#define UINT8_MAX (U8_MAX)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

#endif	/* __NTHW_HELPER_H__ */
