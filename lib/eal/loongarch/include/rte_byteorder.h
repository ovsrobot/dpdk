/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Loongson Technology Corporation Limited
 */

#ifndef _RTE_BYTEORDER_LOONGARCH_H_
#define _RTE_BYTEORDER_LOONGARCH_H_

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_byteorder.h"

#ifndef RTE_FORCE_INTRINSICS
#define rte_bswap16(x) rte_constant_bswap16(x)
#define rte_bswap32(x) rte_constant_bswap32(x)
#define rte_bswap64(x) rte_constant_bswap64(x)
#endif

#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN

#define rte_cpu_to_le_16(x) (x)
#define rte_cpu_to_le_32(x) (x)
#define rte_cpu_to_le_64(x) (x)

#define rte_cpu_to_be_16(x) rte_bswap16(x)
#define rte_cpu_to_be_32(x) rte_bswap32(x)
#define rte_cpu_to_be_64(x) rte_bswap64(x)

#define rte_le_to_cpu_16(x) (x)
#define rte_le_to_cpu_32(x) (x)
#define rte_le_to_cpu_64(x) (x)

#define rte_be_to_cpu_16(x) rte_bswap16(x)
#define rte_be_to_cpu_32(x) rte_bswap32(x)
#define rte_be_to_cpu_64(x) rte_bswap64(x)

#else /* RTE_BIG_ENDIAN */
#error "LoongArch not support big endian!"
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_BYTEORDER_LOONGARCH_H_ */
