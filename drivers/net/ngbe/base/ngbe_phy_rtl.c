/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020 Beijing WangXun Technology Co., Ltd.
 */

#include "ngbe_phy_rtl.h"

s32 ngbe_read_phy_reg_rtl(struct ngbe_hw *hw,
		u32 reg_addr, u32 device_type, u16 *phy_data)
{
	mdi_reg_t reg;
	mdi_reg_22_t reg22;

	reg.device_type = device_type;
	reg.addr = reg_addr;
	ngbe_mdi_map_register(&reg, &reg22);

	wr32(hw, NGBE_PHY_CONFIG(RTL_PAGE_SELECT), reg22.page);
	*phy_data = 0xFFFF & rd32(hw, NGBE_PHY_CONFIG(reg22.addr));

	return 0;
}

s32 ngbe_write_phy_reg_rtl(struct ngbe_hw *hw,
		u32 reg_addr, u32 device_type, u16 phy_data)
{
	mdi_reg_t reg;
	mdi_reg_22_t reg22;

	reg.device_type = device_type;
	reg.addr = reg_addr;
	ngbe_mdi_map_register(&reg, &reg22);

	wr32(hw, NGBE_PHY_CONFIG(RTL_PAGE_SELECT), reg22.page);
	wr32(hw, NGBE_PHY_CONFIG(reg22.addr), phy_data);

	return 0;
}

s32 ngbe_reset_phy_rtl(struct ngbe_hw *hw)
{
	UNREFERENCED_PARAMETER(hw);
	return 0;
}

