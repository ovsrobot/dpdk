/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_TYPES_H__
#define __SXE2_TYPES_H__

#include <sys/time.h>

#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#if defined __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#endif
#elif defined __BYTE_ORDER
#if __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#endif
#elif defined __BIG_ENDIAN__
#define __BIG_ENDIAN_BITFIELD
#elif defined __LITTLE_ENDIAN__
#define __LITTLE_ENDIAN_BITFIELD
#elif defined RTE_TOOLCHAIN_MSVC
#define __LITTLE_ENDIAN_BITFIELD
#else
#error  "Unknown endianness."
#endif
typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef int8_t     s8;
typedef int16_t    s16;
typedef int32_t    s32;
typedef int64_t    s64;

#define __le16    u16
#define __le32    u32
#define __le64    u64

#define __be16    u16
#define __be32    u32
#define __be64    u64

#define STATIC static

#define ETH_ALEN    6

#endif /* __SXE2_TYPES_H__ */
