/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_DPDK_TYPES_H__
#define __SXE_DPDK_TYPES_H__

#include <sys/time.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>

#include <rte_common.h>

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef uint64_t	u64;

typedef char		s8;
typedef int16_t		s16;
typedef int32_t		s32;
typedef int64_t		s64;

typedef s8		S8;
typedef s16		S16;
typedef s32		S32;

#define __le16  u16
#define __le32  u32
#define __le64  u64

#define __be16  u16
#define __be32  u32
#define __be64  u64

#endif
