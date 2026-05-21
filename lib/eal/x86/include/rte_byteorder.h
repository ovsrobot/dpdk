/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_BYTEORDER_X86_H_
#define _RTE_BYTEORDER_X86_H_

#include <stdint.h>
#include <rte_common.h>
#include <rte_config.h>
#include "generic/rte_byteorder.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef RTE_BYTE_ORDER
#define RTE_BYTE_ORDER RTE_LITTLE_ENDIAN
#endif


#ifdef __cplusplus
}
#endif

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

#endif /* _RTE_BYTEORDER_X86_H_ */
