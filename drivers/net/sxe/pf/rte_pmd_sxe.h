/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __PMD_SXE_H__
#define __PMD_SXE_H__

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef int32_t		s32;

s32 rte_pmd_sxe_tx_loopback_set(u16 port, u8 on);
#endif
