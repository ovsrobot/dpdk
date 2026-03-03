/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __PMD_SXE_H__
#define __PMD_SXE_H__

#include <rte_compat.h>

typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint32_t	u32;
typedef int32_t		s32;

s32 rte_pmd_sxe_tx_loopback_set(u16 port, u8 on);
__rte_experimental
s32 rte_pmd_sxe_tc_bw_set(u8 port, u8 tc_num, u8 *bw_weight);
int rte_pmd_sxe_set_vf_rxmode(u16 port, u16 vf, u16 rx_mask, u8 on);
#endif
