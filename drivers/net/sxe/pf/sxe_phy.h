/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_PHY_H__
#define __SXE_PHY_H__

#include <rte_ethdev.h>
#include "drv_msg.h"
#include "sxe_msg.h"

#define SXE_SFF_BASE_ADDR			0x0
#define SXE_SFF_IDENTIFIER			0x0
#define SXE_SFF_10GBE_COMP_CODES		0x3
#define SXE_SFF_1GBE_COMP_CODES			0x6
#define SXE_SFF_CABLE_TECHNOLOGY		0x8
#define SXE_SFF_8472_DIAG_MONITOR_TYPE		0x5C
#define SXE_SFF_8472_COMPLIANCE			0x5E

#define SXE_SFF_IDENTIFIER_SFP			0x3
#define SXE_SFF_ADDRESSING_MODE			0x4
#define SXE_SFF_8472_UNSUP			0x0
#define SXE_SFF_DDM_IMPLEMENTED			0x40
#define SXE_SFF_DA_PASSIVE_CABLE		0x4
#define SXE_SFF_DA_ACTIVE_CABLE			0x8
#define SXE_SFF_DA_SPEC_ACTIVE_LIMITING		0x4
#define SXE_SFF_1GBASESX_CAPABLE		0x1
#define SXE_SFF_1GBASELX_CAPABLE		0x2
#define SXE_SFF_1GBASET_CAPABLE			0x8
#define SXE_SFF_10GBASESR_CAPABLE		0x10
#define SXE_SFF_10GBASELR_CAPABLE		0x20

#define SXE_SFP_COMP_CODE_SIZE			10
#define SXE_SFP_EEPROM_SIZE_MAX			512

#define SXE_IRQ_LINK_UPDATE	  ((u32)(1 << 0))
#define SXE_IRQ_LINK_CONFIG	  ((u32)(1 << 3))

#endif
