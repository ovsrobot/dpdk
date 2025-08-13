/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_PHY_H_
#define _NBL_PHY_H_

#include "nbl_ethdev.h"

#define NBL_NOTIFY_ADDR			(0x00000000)
#define NBL_BYTES_IN_REG		(4)
#define NBL_TAIL_PTR_OFT		(16)
#define NBL_LO_DWORD(x)			((u32)((x) & 0xFFFFFFFF))
#define NBL_HI_DWORD(x)			((u32)(((x) >> 32) & 0xFFFFFFFF))

struct nbl_phy_mgt {
	u8 *hw_addr;
	u64 memory_bar_pa;
	u8 *mailbox_bar_hw_addr;
	u64 notify_addr;
	u32 version;
};

struct nbl_phy_mgt_leonis_snic {
	struct nbl_phy_mgt phy_mgt;
};

#endif
