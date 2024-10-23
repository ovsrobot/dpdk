/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#include "../r8169_ethdev.h"
#include "../r8169_hw.h"
#include "../r8169_phy.h"
#include "rtl8125d_mcu.h"

/* For RTL8125D, CFG_METHOD_56,57 */

/* ------------------------------------MAC 8125D------------------------------------- */

void
rtl_set_mac_mcu_8125d_1(struct rtl_hw *hw)
{
	static const u16 mcu_patch_code_8125d_1[] = {
		0xE002, 0xE006, 0x4166, 0x9CF6, 0xC002, 0xB800, 0x14A4, 0xC102, 0xB900,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
		0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x6938,
		0x0A18, 0x0217, 0x0D2A
	};
	rtl_hw_disable_mac_mcu_bps(hw);
	rtl_write_mac_mcu_ram_code(hw, mcu_patch_code_8125d_1,
				   ARRAY_SIZE(mcu_patch_code_8125d_1));
	rtl_mac_ocp_write(hw, 0xFC26, 0x8000);
	rtl_mac_ocp_write(hw, 0xFC28, 0x14A2);
	rtl_mac_ocp_write(hw, 0xFC48, 0x0001);
}

void
rtl_set_mac_mcu_8125d_2(struct rtl_hw *hw)
{
	rtl_hw_disable_mac_mcu_bps(hw);
}

/* ------------------------------------PHY 8125D--------------------------------------- */

static const u16 phy_mcu_ram_code_8125d_1_1[] = {
	0xa436, 0x8023, 0xa438, 0x3800, 0xa436, 0xB82E, 0xa438, 0x0001,
	0xb820, 0x0090, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
	0xa438, 0x0000, 0xa436, 0xA014, 0xa438, 0x1800, 0xa438, 0x8010,
	0xa438, 0x1800, 0xa438, 0x8018, 0xa438, 0x1800, 0xa438, 0x8021,
	0xa438, 0x1800, 0xa438, 0x8029, 0xa438, 0x1800, 0xa438, 0x8031,
	0xa438, 0x1800, 0xa438, 0x8035, 0xa438, 0x1800, 0xa438, 0x8035,
	0xa438, 0x1800, 0xa438, 0x8035, 0xa438, 0xd711, 0xa438, 0x6081,
	0xa438, 0x8904, 0xa438, 0x1800, 0xa438, 0x2021, 0xa438, 0xa904,
	0xa438, 0x1800, 0xa438, 0x2021, 0xa438, 0xd75f, 0xa438, 0x4083,
	0xa438, 0xd503, 0xa438, 0xa908, 0xa438, 0x87f0, 0xa438, 0x1000,
	0xa438, 0x17e0, 0xa438, 0x1800, 0xa438, 0x13c3, 0xa438, 0xd707,
	0xa438, 0x2005, 0xa438, 0x8027, 0xa438, 0xd75e, 0xa438, 0x1800,
	0xa438, 0x1434, 0xa438, 0x1800, 0xa438, 0x14a5, 0xa438, 0xc504,
	0xa438, 0xce20, 0xa438, 0xcf01, 0xa438, 0xd70a, 0xa438, 0x4005,
	0xa438, 0xcf02, 0xa438, 0x1800, 0xa438, 0x1c50, 0xa438, 0xa980,
	0xa438, 0xd500, 0xa438, 0x1800, 0xa438, 0x14f3, 0xa436, 0xA026,
	0xa438, 0xffff, 0xa436, 0xA024, 0xa438, 0xffff, 0xa436, 0xA022,
	0xa438, 0xffff, 0xa436, 0xA020, 0xa438, 0x14f2, 0xa436, 0xA006,
	0xa438, 0x1c4f, 0xa436, 0xA004, 0xa438, 0x1433, 0xa436, 0xA002,
	0xa438, 0x13c1, 0xa436, 0xA000, 0xa438, 0x2020, 0xa436, 0xA008,
	0xa438, 0x1f00, 0xa436, 0xA016, 0xa438, 0x0000, 0xa436, 0xA012,
	0xa438, 0x07f8, 0xa436, 0xA014, 0xa438, 0xd04d, 0xa438, 0x8904,
	0xa438, 0x813C, 0xa438, 0xA13D, 0xa438, 0x0000, 0xa438, 0x0000,
	0xa438, 0x0000, 0xa438, 0x0000, 0xa436, 0xA152, 0xa438, 0x1384,
	0xa436, 0xA154, 0xa438, 0x1fa8, 0xa436, 0xA156, 0xa438, 0x218B,
	0xa436, 0xA158, 0xa438, 0x21B8, 0xa436, 0xA15A, 0xa438, 0x3fff,
	0xa436, 0xA15C, 0xa438, 0x3fff, 0xa436, 0xA15E, 0xa438, 0x3fff,
	0xa436, 0xA160, 0xa438, 0x3fff, 0xa436, 0xA150, 0xa438, 0x000f,
	0xa436, 0xA016, 0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x1ff8,
	0xa436, 0xA014, 0xa438, 0x001c, 0xa438, 0xce15, 0xa438, 0xd105,
	0xa438, 0xa410, 0xa438, 0x8320, 0xa438, 0xFFD7, 0xa438, 0x0000,
	0xa438, 0x0000, 0xa436, 0xA164, 0xa438, 0x0260, 0xa436, 0xA166,
	0xa438, 0x0add, 0xa436, 0xA168, 0xa438, 0x05CC, 0xa436, 0xA16A,
	0xa438, 0x05C5, 0xa436, 0xA16C, 0xa438, 0x0429, 0xa436, 0xA16E,
	0xa438, 0x07B6, 0xa436, 0xA170, 0xa438, 0x0259, 0xa436, 0xA172,
	0xa438, 0x3fff, 0xa436, 0xA162, 0xa438, 0x003f, 0xa436, 0xA016,
	0xa438, 0x0020, 0xa436, 0xA012, 0xa438, 0x0000, 0xa436, 0xA014,
	0xa438, 0x1800, 0xa438, 0x8010, 0xa438, 0x1800, 0xa438, 0x8023,
	0xa438, 0x1800, 0xa438, 0x80e6, 0xa438, 0x1800, 0xa438, 0x80f0,
	0xa438, 0x1800, 0xa438, 0x80f8, 0xa438, 0x1800, 0xa438, 0x816c,
	0xa438, 0x1800, 0xa438, 0x817d, 0xa438, 0x1800, 0xa438, 0x818b,
	0xa438, 0xa801, 0xa438, 0x9308, 0xa438, 0xb201, 0xa438, 0xb301,
	0xa438, 0xd701, 0xa438, 0x4000, 0xa438, 0xd2ff, 0xa438, 0xb302,
	0xa438, 0xd200, 0xa438, 0xb201, 0xa438, 0xb309, 0xa438, 0xd701,
	0xa438, 0x4000, 0xa438, 0xd2ff, 0xa438, 0xb302, 0xa438, 0xd200,
	0xa438, 0xa800, 0xa438, 0x1800, 0xa438, 0x0031, 0xa438, 0xd700,
	0xa438, 0x4543, 0xa438, 0xd71f, 0xa438, 0x40fe, 0xa438, 0xd1b7,
	0xa438, 0xd049, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700,
	0xa438, 0x5fbb, 0xa438, 0xa220, 0xa438, 0x8501, 0xa438, 0x0c03,
	0xa438, 0x1502, 0xa438, 0x0c70, 0xa438, 0x0b00, 0xa438, 0x0c07,
	0xa438, 0x0604, 0xa438, 0x9503, 0xa438, 0xa510, 0xa438, 0xce49,
	0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0x8520, 0xa438, 0xa520,
	0xa438, 0xa501, 0xa438, 0xd105, 0xa438, 0xd047, 0xa438, 0x1000,
	0xa438, 0x109e, 0xa438, 0xd707, 0xa438, 0x6087, 0xa438, 0xd700,
	0xa438, 0x5f7b, 0xa438, 0xffe9, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0x8501, 0xa438, 0xd707, 0xa438, 0x5e08, 0xa438, 0x8530,
	0xa438, 0xba20, 0xa438, 0xf00c, 0xa438, 0xd700, 0xa438, 0x4098,
	0xa438, 0xd1ef, 0xa438, 0xd047, 0xa438, 0xf003, 0xa438, 0xd1db,
	0xa438, 0xd040, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700,
	0xa438, 0x5fbb, 0xa438, 0x8980, 0xa438, 0xd704, 0xa438, 0x40a3,
	0xa438, 0xd702, 0xa438, 0x4060, 0xa438, 0x8410, 0xa438, 0xf002,
	0xa438, 0xa410, 0xa438, 0xce02, 0xa438, 0x1000, 0xa438, 0x10be,
	0xa438, 0xcd81, 0xa438, 0xd412, 0xa438, 0x1000, 0xa438, 0x1069,
	0xa438, 0xcd82, 0xa438, 0xd40e, 0xa438, 0x1000, 0xa438, 0x1069,
	0xa438, 0xcd83, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd71f,
	0xa438, 0x5fb4, 0xa438, 0xa00a, 0xa438, 0xa340, 0xa438, 0x0c06,
	0xa438, 0x0102, 0xa438, 0xa240, 0xa438, 0xa290, 0xa438, 0xa324,
	0xa438, 0xab02, 0xa438, 0xd13e, 0xa438, 0xd05a, 0xa438, 0xd13e,
	0xa438, 0xd06b, 0xa438, 0xcd84, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0xd706, 0xa438, 0x6079, 0xa438, 0xd700, 0xa438, 0x5f5c,
	0xa438, 0xcd8a, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd706,
	0xa438, 0x6079, 0xa438, 0xd700, 0xa438, 0x5f5d, 0xa438, 0xcd8b,
	0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xcd8c, 0xa438, 0xd700,
	0xa438, 0x6050, 0xa438, 0xab04, 0xa438, 0xd700, 0xa438, 0x4083,
	0xa438, 0xd160, 0xa438, 0xd04b, 0xa438, 0xf003, 0xa438, 0xd193,
	0xa438, 0xd047, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700,
	0xa438, 0x5fbb, 0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x8410,
	0xa438, 0xd71f, 0xa438, 0x5f94, 0xa438, 0xb920, 0xa438, 0x1000,
	0xa438, 0x109e, 0xa438, 0xd71f, 0xa438, 0x7fb4, 0xa438, 0x9920,
	0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd71f, 0xa438, 0x6105,
	0xa438, 0x6054, 0xa438, 0xfffb, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0xd706, 0xa438, 0x5fb9, 0xa438, 0xfff0, 0xa438, 0xa410,
	0xa438, 0xb820, 0xa438, 0xcd85, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0xd71f, 0xa438, 0x7fa5, 0xa438, 0x9820, 0xa438, 0xbb20,
	0xa438, 0xd105, 0xa438, 0xd042, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0xd706, 0xa438, 0x5fbb, 0xa438, 0x5f85, 0xa438, 0xd700,
	0xa438, 0x5f5b, 0xa438, 0xd700, 0xa438, 0x6090, 0xa438, 0xd700,
	0xa438, 0x4043, 0xa438, 0xaa20, 0xa438, 0xcd86, 0xa438, 0xd700,
	0xa438, 0x6083, 0xa438, 0xd1c7, 0xa438, 0xd045, 0xa438, 0xf003,
	0xa438, 0xd17a, 0xa438, 0xd04b, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0xd700, 0xa438, 0x5fbb, 0xa438, 0x0c18, 0xa438, 0x0108,
	0xa438, 0x0c3f, 0xa438, 0x0609, 0xa438, 0x0cfb, 0xa438, 0x0729,
	0xa438, 0xa308, 0xa438, 0x8320, 0xa438, 0xd105, 0xa438, 0xd042,
	0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd700, 0xa438, 0x5fbb,
	0xa438, 0x1800, 0xa438, 0x08f7, 0xa438, 0x1000, 0xa438, 0x109e,
	0xa438, 0x1000, 0xa438, 0x10a3, 0xa438, 0xd700, 0xa438, 0x607b,
	0xa438, 0xd700, 0xa438, 0x5f2b, 0xa438, 0x1800, 0xa438, 0x0a81,
	0xa438, 0xd700, 0xa438, 0x40bd, 0xa438, 0xd707, 0xa438, 0x4065,
	0xa438, 0x1800, 0xa438, 0x1121, 0xa438, 0x1800, 0xa438, 0x1124,
	0xa438, 0xd705, 0xa438, 0x627d, 0xa438, 0xd704, 0xa438, 0x6192,
	0xa438, 0xa00a, 0xa438, 0xd704, 0xa438, 0x41c7, 0xa438, 0xd700,
	0xa438, 0x3691, 0xa438, 0x810c, 0xa438, 0x0c03, 0xa438, 0x1502,
	0xa438, 0xa570, 0xa438, 0x9503, 0xa438, 0xf006, 0xa438, 0x800a,
	0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503,
	0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x1108,
	0xa438, 0xcd64, 0xa438, 0xd704, 0xa438, 0x3398, 0xa438, 0x8166,
	0xa438, 0xd71f, 0xa438, 0x620e, 0xa438, 0xd704, 0xa438, 0x6096,
	0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf004, 0xa438, 0xd705,
	0xa438, 0x605d, 0xa438, 0xf008, 0xa438, 0xd706, 0xa438, 0x609d,
	0xa438, 0xd705, 0xa438, 0x405f, 0xa438, 0xf003, 0xa438, 0xd700,
	0xa438, 0x5a9b, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0xc7aa,
	0xa438, 0x9503, 0xa438, 0xd71f, 0xa438, 0x674e, 0xa438, 0xd704,
	0xa438, 0x6096, 0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf005,
	0xa438, 0xd705, 0xa438, 0x607d, 0xa438, 0x1800, 0xa438, 0x0cc7,
	0xa438, 0xd706, 0xa438, 0x60bd, 0xa438, 0xd705, 0xa438, 0x407f,
	0xa438, 0x1800, 0xa438, 0x0e42, 0xa438, 0xce04, 0xa438, 0x1000,
	0xa438, 0x10be, 0xa438, 0xd702, 0xa438, 0x40a4, 0xa438, 0x0c03,
	0xa438, 0x1502, 0xa438, 0x8e20, 0xa438, 0x9503, 0xa438, 0xd702,
	0xa438, 0x40a5, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8e40,
	0xa438, 0x9503, 0xa438, 0x1000, 0xa438, 0x11a4, 0xa438, 0x1000,
	0xa438, 0x109e, 0xa438, 0x1000, 0xa438, 0x1108, 0xa438, 0xcd61,
	0xa438, 0xd704, 0xa438, 0x3398, 0xa438, 0x8166, 0xa438, 0xd704,
	0xa438, 0x6096, 0xa438, 0xd705, 0xa438, 0x6051, 0xa438, 0xf005,
	0xa438, 0xd705, 0xa438, 0x607d, 0xa438, 0x1800, 0xa438, 0x0cc7,
	0xa438, 0xd71f, 0xa438, 0x60ee, 0xa438, 0xd706, 0xa438, 0x7bdd,
	0xa438, 0xd705, 0xa438, 0x5b9f, 0xa438, 0x1800, 0xa438, 0x0e42,
	0xa438, 0x1800, 0xa438, 0x0b5f, 0xa438, 0x0c03, 0xa438, 0x1502,
	0xa438, 0xae40, 0xa438, 0x9503, 0xa438, 0x1800, 0xa438, 0x0c47,
	0xa438, 0x607c, 0xa438, 0x1800, 0xa438, 0x027a, 0xa438, 0x0c03,
	0xa438, 0x1502, 0xa438, 0xae01, 0xa438, 0x9503, 0xa438, 0x1000,
	0xa438, 0x109e, 0xa438, 0xd702, 0xa438, 0x5fa3, 0xa438, 0x0c03,
	0xa438, 0x1502, 0xa438, 0x8e01, 0xa438, 0x9503, 0xa438, 0x1800,
	0xa438, 0x027d, 0xa438, 0x1000, 0xa438, 0x10be, 0xa438, 0xd702,
	0xa438, 0x40a5, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8e40,
	0xa438, 0x9503, 0xa438, 0xd73e, 0xa438, 0x6065, 0xa438, 0x1800,
	0xa438, 0x0cea, 0xa438, 0x1800, 0xa438, 0x0cf4, 0xa438, 0xa290,
	0xa438, 0xa304, 0xa438, 0xab02, 0xa438, 0xd700, 0xa438, 0x6050,
	0xa438, 0xab04, 0xa438, 0x0c38, 0xa438, 0x0608, 0xa438, 0xaa0b,
	0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8d01, 0xa438, 0x0c03,
	0xa438, 0x1502, 0xa438, 0xae40, 0xa438, 0x9503, 0xa438, 0xd702,
	0xa438, 0x40a4, 0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8e20,
	0xa438, 0x9503, 0xa438, 0xd700, 0xa438, 0x6078, 0xa438, 0xd700,
	0xa438, 0x609a, 0xa438, 0xd109, 0xa438, 0xd074, 0xa438, 0xf003,
	0xa438, 0xd109, 0xa438, 0xd075, 0xa438, 0xd704, 0xa438, 0x6192,
	0xa438, 0xa00a, 0xa438, 0xd704, 0xa438, 0x41c7, 0xa438, 0xd700,
	0xa438, 0x3691, 0xa438, 0x81bc, 0xa438, 0x0c03, 0xa438, 0x1502,
	0xa438, 0xa570, 0xa438, 0x9503, 0xa438, 0xf006, 0xa438, 0x800a,
	0xa438, 0x0c03, 0xa438, 0x1502, 0xa438, 0x8570, 0xa438, 0x9503,
	0xa438, 0x1000, 0xa438, 0x109e, 0xa438, 0xd704, 0xa438, 0x60f3,
	0xa438, 0xd71f, 0xa438, 0x60ee, 0xa438, 0xd700, 0xa438, 0x5cfe,
	0xa438, 0x1800, 0xa438, 0x0deb, 0xa438, 0x1800, 0xa438, 0x0c47,
	0xa438, 0x1800, 0xa438, 0x0df8, 0xa436, 0xA10E, 0xa438, 0x0dc5,
	0xa436, 0xA10C, 0xa438, 0x0ce8, 0xa436, 0xA10A, 0xa438, 0x0279,
	0xa436, 0xA108, 0xa438, 0x0b19, 0xa436, 0xA106, 0xa438, 0x111f,
	0xa436, 0xA104, 0xa438, 0x0a7b, 0xa436, 0xA102, 0xa438, 0x0ba3,
	0xa436, 0xA100, 0xa438, 0x0022, 0xa436, 0xA110, 0xa438, 0x00ff,
	0xa436, 0xb87c, 0xa438, 0x859b, 0xa436, 0xb87e, 0xa438, 0xaf85,
	0xa438, 0xb3af, 0xa438, 0x863b, 0xa438, 0xaf86, 0xa438, 0x4caf,
	0xa438, 0x8688, 0xa438, 0xaf86, 0xa438, 0xceaf, 0xa438, 0x8744,
	0xa438, 0xaf87, 0xa438, 0x68af, 0xa438, 0x8781, 0xa438, 0xbf5e,
	0xa438, 0x7202, 0xa438, 0x5f7e, 0xa438, 0xac28, 0xa438, 0x68e1,
	0xa438, 0x84e6, 0xa438, 0xad28, 0xa438, 0x09bf, 0xa438, 0x5e75,
	0xa438, 0x025f, 0xa438, 0x7eac, 0xa438, 0x2d59, 0xa438, 0xe18f,
	0xa438, 0xebad, 0xa438, 0x2809, 0xa438, 0xbf5e, 0xa438, 0x7502,
	0xa438, 0x5f7e, 0xa438, 0xac2e, 0xa438, 0x50e1, 0xa438, 0x84e6,
	0xa438, 0xac28, 0xa438, 0x08bf, 0xa438, 0x873e, 0xa438, 0x025f,
	0xa438, 0x3cae, 0xa438, 0x06bf, 0xa438, 0x873e, 0xa438, 0x025f,
	0xa438, 0x33bf, 0xa438, 0x8741, 0xa438, 0x025f, 0xa438, 0x33ee,
	0xa438, 0x8fea, 0xa438, 0x02e1, 0xa438, 0x84e4, 0xa438, 0xad28,
	0xa438, 0x14e1, 0xa438, 0x8fe8, 0xa438, 0xad28, 0xa438, 0x17e1,
	0xa438, 0x84e5, 0xa438, 0x11e5, 0xa438, 0x84e5, 0xa438, 0xa10c,
	0xa438, 0x04ee, 0xa438, 0x84e5, 0xa438, 0x0002, 0xa438, 0x4977,
	0xa438, 0xee84, 0xa438, 0xdc03, 0xa438, 0xae1d, 0xa438, 0xe18f,
	0xa438, 0xe811, 0xa438, 0xe58f, 0xa438, 0xe8ae, 0xa438, 0x14bf,
	0xa438, 0x873e, 0xa438, 0x025f, 0xa438, 0x3cbf, 0xa438, 0x8741,
	0xa438, 0x025f, 0xa438, 0x3cee, 0xa438, 0x8fea, 0xa438, 0x01ee,
	0xa438, 0x84e4, 0xa438, 0x00af, 0xa438, 0x50c1, 0xa438, 0x1f00,
	0xa438, 0xbf5a, 0xa438, 0x6102, 0xa438, 0x5f5f, 0xa438, 0xbf5a,
	0xa438, 0x5e02, 0xa438, 0x5f3c, 0xa438, 0xaf45, 0xa438, 0x7be0,
	0xa438, 0x8012, 0xa438, 0xad23, 0xa438, 0x141f, 0xa438, 0x001f,
	0xa438, 0x22d1, 0xa438, 0x00bf, 0xa438, 0x3fcf, 0xa438, 0x0261,
	0xa438, 0x3412, 0xa438, 0xa204, 0xa438, 0xf6ee, 0xa438, 0x8317,
	0xa438, 0x00e0, 0xa438, 0x8012, 0xa438, 0xad24, 0xa438, 0x141f,
	0xa438, 0x001f, 0xa438, 0x22d1, 0xa438, 0x00bf, 0xa438, 0x3fd7,
	0xa438, 0x0261, 0xa438, 0x3412, 0xa438, 0xa204, 0xa438, 0xf6ee,
	0xa438, 0x8317, 0xa438, 0x00ef, 0xa438, 0x96fe, 0xa438, 0xfdfc,
	0xa438, 0xaf42, 0xa438, 0x9802, 0xa438, 0x56ec, 0xa438, 0xf70b,
	0xa438, 0xac13, 0xa438, 0x0fbf, 0xa438, 0x5e75, 0xa438, 0x025f,
	0xa438, 0x7eac, 0xa438, 0x280c, 0xa438, 0xe2ff, 0xa438, 0xcfad,
	0xa438, 0x32ee, 0xa438, 0x0257, 0xa438, 0x05af, 0xa438, 0x00a4,
	0xa438, 0x0286, 0xa438, 0xaaae, 0xa438, 0xeff8, 0xa438, 0xf9ef,
	0xa438, 0x5902, 0xa438, 0x1fe1, 0xa438, 0xbf59, 0xa438, 0x4d02,
	0xa438, 0x5f3c, 0xa438, 0xac13, 0xa438, 0x09bf, 0xa438, 0x5e75,
	0xa438, 0x025f, 0xa438, 0x7ea1, 0xa438, 0x00f4, 0xa438, 0xbf59,
	0xa438, 0x4d02, 0xa438, 0x5f33, 0xa438, 0xef95, 0xa438, 0xfdfc,
	0xa438, 0x04bf, 0xa438, 0x5e72, 0xa438, 0x025f, 0xa438, 0x7eac,
	0xa438, 0x284a, 0xa438, 0xe184, 0xa438, 0xe6ad, 0xa438, 0x2809,
	0xa438, 0xbf5e, 0xa438, 0x7502, 0xa438, 0x5f7e, 0xa438, 0xac2d,
	0xa438, 0x3be1, 0xa438, 0x8feb, 0xa438, 0xad28, 0xa438, 0x09bf,
	0xa438, 0x5e75, 0xa438, 0x025f, 0xa438, 0x7eac, 0xa438, 0x2e32,
	0xa438, 0xe184, 0xa438, 0xe6ac, 0xa438, 0x2808, 0xa438, 0xbf87,
	0xa438, 0x3e02, 0xa438, 0x5f3c, 0xa438, 0xae06, 0xa438, 0xbf87,
	0xa438, 0x3e02, 0xa438, 0x5f33, 0xa438, 0xbf87, 0xa438, 0x4102,
	0xa438, 0x5f33, 0xa438, 0xee8f, 0xa438, 0xea04, 0xa438, 0xbf5e,
	0xa438, 0x4e02, 0xa438, 0x5f7e, 0xa438, 0xad28, 0xa438, 0x1f02,
	0xa438, 0x4b12, 0xa438, 0xae1a, 0xa438, 0xbf87, 0xa438, 0x3e02,
	0xa438, 0x5f3c, 0xa438, 0xbf87, 0xa438, 0x4102, 0xa438, 0x5f3c,
	0xa438, 0xee8f, 0xa438, 0xea03, 0xa438, 0xbf5e, 0xa438, 0x2a02,
	0xa438, 0x5f33, 0xa438, 0xee84, 0xa438, 0xe701, 0xa438, 0xaf4a,
	0xa438, 0x7444, 0xa438, 0xac0e, 0xa438, 0x55ac, 0xa438, 0x0ebf,
	0xa438, 0x5e75, 0xa438, 0x025f, 0xa438, 0x7ead, 0xa438, 0x2d0b,
	0xa438, 0xbf5e, 0xa438, 0x36e1, 0xa438, 0x8fe9, 0xa438, 0x025f,
	0xa438, 0x5fae, 0xa438, 0x09bf, 0xa438, 0x5e36, 0xa438, 0xe184,
	0xa438, 0xe102, 0xa438, 0x5f5f, 0xa438, 0xee8f, 0xa438, 0xe800,
	0xa438, 0xaf49, 0xa438, 0xcdbf, 0xa438, 0x595c, 0xa438, 0x025f,
	0xa438, 0x7ea1, 0xa438, 0x0203, 0xa438, 0xaf87, 0xa438, 0x79d1,
	0xa438, 0x00af, 0xa438, 0x877c, 0xa438, 0xe181, 0xa438, 0x941f,
	0xa438, 0x00af, 0xa438, 0x3ff7, 0xa438, 0xac4e, 0xa438, 0x06ac,
	0xa438, 0x4003, 0xa438, 0xaf24, 0xa438, 0x97af, 0xa438, 0x2467,
	0xa436, 0xb85e, 0xa438, 0x5082, 0xa436, 0xb860, 0xa438, 0x4575,
	0xa436, 0xb862, 0xa438, 0x425F, 0xa436, 0xb864, 0xa438, 0x0096,
	0xa436, 0xb886, 0xa438, 0x4A44, 0xa436, 0xb888, 0xa438, 0x49c4,
	0xa436, 0xb88a, 0xa438, 0x3FF2, 0xa436, 0xb88c, 0xa438, 0x245C,
	0xa436, 0xb838, 0xa438, 0x00ff, 0xb820, 0x0010, 0xa466, 0x0001,
	0xa436, 0x836a, 0xa438, 0x0001, 0xa436, 0x843d, 0xa438, 0xaf84,
	0xa438, 0xa6af, 0xa438, 0x8540, 0xa438, 0xaf85, 0xa438, 0xaeaf,
	0xa438, 0x85b5, 0xa438, 0xaf87, 0xa438, 0x7daf, 0xa438, 0x8784,
	0xa438, 0xaf87, 0xa438, 0x87af, 0xa438, 0x87e5, 0xa438, 0x0066,
	0xa438, 0x0a03, 0xa438, 0x6607, 0xa438, 0x2666, 0xa438, 0x1c00,
	0xa438, 0x660d, 0xa438, 0x0166, 0xa438, 0x1004, 0xa438, 0x6616,
	0xa438, 0x0566, 0xa438, 0x1f06, 0xa438, 0x6a5d, 0xa438, 0x2766,
	0xa438, 0x1900, 0xa438, 0x6625, 0xa438, 0x2466, 0xa438, 0x2820,
	0xa438, 0x662b, 0xa438, 0x2466, 0xa438, 0x4600, 0xa438, 0x664c,
	0xa438, 0x0166, 0xa438, 0x4902, 0xa438, 0x8861, 0xa438, 0x0388,
	0xa438, 0x5e05, 0xa438, 0x886d, 0xa438, 0x0588, 0xa438, 0x7005,
	0xa438, 0x8873, 0xa438, 0x0588, 0xa438, 0x7605, 0xa438, 0x8879,
	0xa438, 0x0588, 0xa438, 0x7c05, 0xa438, 0x887f, 0xa438, 0x0588,
	0xa438, 0x8205, 0xa438, 0x8885, 0xa438, 0x0588, 0xa438, 0x881e,
	0xa438, 0x13ad, 0xa438, 0x2841, 0xa438, 0xbf64, 0xa438, 0xf102,
	0xa438, 0x6b9d, 0xa438, 0xad28, 0xa438, 0x03af, 0xa438, 0x15fc,
	0xa438, 0xbf65, 0xa438, 0xcb02, 0xa438, 0x6b9d, 0xa438, 0x0d11,
	0xa438, 0xf62f, 0xa438, 0xef31, 0xa438, 0xd202, 0xa438, 0xbf88,
	0xa438, 0x6402, 0xa438, 0x6b52, 0xa438, 0xe082, 0xa438, 0x020d,
	0xa438, 0x01f6, 0xa438, 0x271b, 0xa438, 0x03aa, 0xa438, 0x0182,
	0xa438, 0xe082, 0xa438, 0x010d, 0xa438, 0x01f6, 0xa438, 0x271b,
	0xa438, 0x03aa, 0xa438, 0x0782, 0xa438, 0xbf88, 0xa438, 0x6402,
	0xa438, 0x6b5b, 0xa438, 0xaf15, 0xa438, 0xf9bf, 0xa438, 0x65cb,
	0xa438, 0x026b, 0xa438, 0x9d0d, 0xa438, 0x11f6, 0xa438, 0x2fef,
	0xa438, 0x31e0, 0xa438, 0x8ff7, 0xa438, 0x0d01, 0xa438, 0xf627,
	0xa438, 0x1b03, 0xa438, 0xaa20, 0xa438, 0xe18f, 0xa438, 0xf4d0,
	0xa438, 0x00bf, 0xa438, 0x6587, 0xa438, 0x026b, 0xa438, 0x7ee1,
	0xa438, 0x8ff5, 0xa438, 0xbf65, 0xa438, 0x8a02, 0xa438, 0x6b7e,
	0xa438, 0xe18f, 0xa438, 0xf6bf, 0xa438, 0x6584, 0xa438, 0x026b,
	0xa438, 0x7eaf, 0xa438, 0x15fc, 0xa438, 0xe18f, 0xa438, 0xf1d0,
	0xa438, 0x00bf, 0xa438, 0x6587, 0xa438, 0x026b, 0xa438, 0x7ee1,
	0xa438, 0x8ff2, 0xa438, 0xbf65, 0xa438, 0x8a02, 0xa438, 0x6b7e,
	0xa438, 0xe18f, 0xa438, 0xf3bf, 0xa438, 0x6584, 0xa438, 0xaf15,
	0xa438, 0xfcd1, 0xa438, 0x07bf, 0xa438, 0x65ce, 0xa438, 0x026b,
	0xa438, 0x7ed1, 0xa438, 0x0cbf, 0xa438, 0x65d1, 0xa438, 0x026b,
	0xa438, 0x7ed1, 0xa438, 0x03bf, 0xa438, 0x885e, 0xa438, 0x026b,
	0xa438, 0x7ed1, 0xa438, 0x05bf, 0xa438, 0x8867, 0xa438, 0x026b,
	0xa438, 0x7ed1, 0xa438, 0x07bf, 0xa438, 0x886a, 0xa438, 0x026b,
	0xa438, 0x7ebf, 0xa438, 0x6a6c, 0xa438, 0x026b, 0xa438, 0x5b02,
	0xa438, 0x62b5, 0xa438, 0xbf6a, 0xa438, 0x0002, 0xa438, 0x6b5b,
	0xa438, 0xbf64, 0xa438, 0x4e02, 0xa438, 0x6b9d, 0xa438, 0xac28,
	0xa438, 0x0bbf, 0xa438, 0x6412, 0xa438, 0x026b, 0xa438, 0x9da1,
	0xa438, 0x0502, 0xa438, 0xaeec, 0xa438, 0xd104, 0xa438, 0xbf65,
	0xa438, 0xce02, 0xa438, 0x6b7e, 0xa438, 0xd104, 0xa438, 0xbf65,
	0xa438, 0xd102, 0xa438, 0x6b7e, 0xa438, 0xd102, 0xa438, 0xbf88,
	0xa438, 0x6702, 0xa438, 0x6b7e, 0xa438, 0xd104, 0xa438, 0xbf88,
	0xa438, 0x6a02, 0xa438, 0x6b7e, 0xa438, 0xaf62, 0xa438, 0x72f6,
	0xa438, 0x0af6, 0xa438, 0x09af, 0xa438, 0x34e3, 0xa438, 0x0285,
	0xa438, 0xbe02, 0xa438, 0x106c, 0xa438, 0xaf10, 0xa438, 0x6bf8,
	0xa438, 0xfaef, 0xa438, 0x69e0, 0xa438, 0x804c, 0xa438, 0xac25,
	0xa438, 0x17e0, 0xa438, 0x8040, 0xa438, 0xad25, 0xa438, 0x1a02,
	0xa438, 0x85ed, 0xa438, 0xe080, 0xa438, 0x40ac, 0xa438, 0x2511,
	0xa438, 0xbf87, 0xa438, 0x6502, 0xa438, 0x6b5b, 0xa438, 0xae09,
	0xa438, 0x0287, 0xa438, 0x2402, 0xa438, 0x875a, 0xa438, 0x0287,
	0xa438, 0x4fef, 0xa438, 0x96fe, 0xa438, 0xfc04, 0xa438, 0xf8e0,
	0xa438, 0x8019, 0xa438, 0xad20, 0xa438, 0x11e0, 0xa438, 0x8fe3,
	0xa438, 0xac20, 0xa438, 0x0502, 0xa438, 0x860a, 0xa438, 0xae03,
	0xa438, 0x0286, 0xa438, 0x7802, 0xa438, 0x86c1, 0xa438, 0x0287,
	0xa438, 0x4ffc, 0xa438, 0x04f8, 0xa438, 0xf9ef, 0xa438, 0x79fb,
	0xa438, 0xbf87, 0xa438, 0x6802, 0xa438, 0x6b9d, 0xa438, 0x5c20,
	0xa438, 0x000d, 0xa438, 0x4da1, 0xa438, 0x0151, 0xa438, 0xbf87,
	0xa438, 0x6802, 0xa438, 0x6b9d, 0xa438, 0x5c07, 0xa438, 0xffe3,
	0xa438, 0x8fe4, 0xa438, 0x1b31, 0xa438, 0x9f41, 0xa438, 0x0d48,
	0xa438, 0xe38f, 0xa438, 0xe51b, 0xa438, 0x319f, 0xa438, 0x38bf,
	0xa438, 0x876b, 0xa438, 0x026b, 0xa438, 0x9d5c, 0xa438, 0x07ff,
	0xa438, 0xe38f, 0xa438, 0xe61b, 0xa438, 0x319f, 0xa438, 0x280d,
	0xa438, 0x48e3, 0xa438, 0x8fe7, 0xa438, 0x1b31, 0xa438, 0x9f1f,
	0xa438, 0xbf87, 0xa438, 0x6e02, 0xa438, 0x6b9d, 0xa438, 0x5c07,
	0xa438, 0xffe3, 0xa438, 0x8fe8, 0xa438, 0x1b31, 0xa438, 0x9f0f,
	0xa438, 0x0d48, 0xa438, 0xe38f, 0xa438, 0xe91b, 0xa438, 0x319f,
	0xa438, 0x06ee, 0xa438, 0x8fe3, 0xa438, 0x01ae, 0xa438, 0x04ee,
	0xa438, 0x8fe3, 0xa438, 0x00ff, 0xa438, 0xef97, 0xa438, 0xfdfc,
	0xa438, 0x04f8, 0xa438, 0xf9ef, 0xa438, 0x79fb, 0xa438, 0xbf87,
	0xa438, 0x6802, 0xa438, 0x6b9d, 0xa438, 0x5c20, 0xa438, 0x000d,
	0xa438, 0x4da1, 0xa438, 0x0020, 0xa438, 0xbf87, 0xa438, 0x6802,
	0xa438, 0x6b9d, 0xa438, 0x5c06, 0xa438, 0x000d, 0xa438, 0x49e3,
	0xa438, 0x8fea, 0xa438, 0x1b31, 0xa438, 0x9f0e, 0xa438, 0xbf87,
	0xa438, 0x7102, 0xa438, 0x6b5b, 0xa438, 0xbf87, 0xa438, 0x7702,
	0xa438, 0x6b5b, 0xa438, 0xae0c, 0xa438, 0xbf87, 0xa438, 0x7102,
	0xa438, 0x6b52, 0xa438, 0xbf87, 0xa438, 0x7702, 0xa438, 0x6b52,
	0xa438, 0xee8f, 0xa438, 0xe300, 0xa438, 0xffef, 0xa438, 0x97fd,
	0xa438, 0xfc04, 0xa438, 0xf8f9, 0xa438, 0xef79, 0xa438, 0xfbbf,
	0xa438, 0x8768, 0xa438, 0x026b, 0xa438, 0x9d5c, 0xa438, 0x2000,
	0xa438, 0x0d4d, 0xa438, 0xa101, 0xa438, 0x4abf, 0xa438, 0x8768,
	0xa438, 0x026b, 0xa438, 0x9d5c, 0xa438, 0x07ff, 0xa438, 0xe38f,
	0xa438, 0xeb1b, 0xa438, 0x319f, 0xa438, 0x3a0d, 0xa438, 0x48e3,
	0xa438, 0x8fec, 0xa438, 0x1b31, 0xa438, 0x9f31, 0xa438, 0xbf87,
	0xa438, 0x6b02, 0xa438, 0x6b9d, 0xa438, 0xe38f, 0xa438, 0xed1b,
	0xa438, 0x319f, 0xa438, 0x240d, 0xa438, 0x48e3, 0xa438, 0x8fee,
	0xa438, 0x1b31, 0xa438, 0x9f1b, 0xa438, 0xbf87, 0xa438, 0x6e02,
	0xa438, 0x6b9d, 0xa438, 0xe38f, 0xa438, 0xef1b, 0xa438, 0x319f,
	0xa438, 0x0ebf, 0xa438, 0x8774, 0xa438, 0x026b, 0xa438, 0x5bbf,
	0xa438, 0x877a, 0xa438, 0x026b, 0xa438, 0x5bae, 0xa438, 0x00ff,
	0xa438, 0xef97, 0xa438, 0xfdfc, 0xa438, 0x04f8, 0xa438, 0xef79,
	0xa438, 0xfbe0, 0xa438, 0x8019, 0xa438, 0xad20, 0xa438, 0x1cee,
	0xa438, 0x8fe3, 0xa438, 0x00bf, 0xa438, 0x8771, 0xa438, 0x026b,
	0xa438, 0x52bf, 0xa438, 0x8777, 0xa438, 0x026b, 0xa438, 0x52bf,
	0xa438, 0x8774, 0xa438, 0x026b, 0xa438, 0x52bf, 0xa438, 0x877a,
	0xa438, 0x026b, 0xa438, 0x52ff, 0xa438, 0xef97, 0xa438, 0xfc04,
	0xa438, 0xf8e0, 0xa438, 0x8040, 0xa438, 0xf625, 0xa438, 0xe480,
	0xa438, 0x40fc, 0xa438, 0x04f8, 0xa438, 0xe080, 0xa438, 0x4cf6,
	0xa438, 0x25e4, 0xa438, 0x804c, 0xa438, 0xfc04, 0xa438, 0x55a4,
	0xa438, 0xbaf0, 0xa438, 0xa64a, 0xa438, 0xf0a6, 0xa438, 0x4cf0,
	0xa438, 0xa64e, 0xa438, 0x66a4, 0xa438, 0xb655, 0xa438, 0xa4b6,
	0xa438, 0x00ac, 0xa438, 0x0e11, 0xa438, 0xac0e, 0xa438, 0xee80,
	0xa438, 0x4c3a, 0xa438, 0xaf07, 0xa438, 0xd0af, 0xa438, 0x26d0,
	0xa438, 0xa201, 0xa438, 0x0ebf, 0xa438, 0x663d, 0xa438, 0x026b,
	0xa438, 0x52bf, 0xa438, 0x6643, 0xa438, 0x026b, 0xa438, 0x52ae,
	0xa438, 0x11bf, 0xa438, 0x6643, 0xa438, 0x026b, 0xa438, 0x5bd4,
	0xa438, 0x0054, 0xa438, 0xb4fe, 0xa438, 0xbf66, 0xa438, 0x3d02,
	0xa438, 0x6b5b, 0xa438, 0xd300, 0xa438, 0x020d, 0xa438, 0xf6a2,
	0xa438, 0x0405, 0xa438, 0xe081, 0xa438, 0x47ae, 0xa438, 0x03e0,
	0xa438, 0x8148, 0xa438, 0xac23, 0xa438, 0x02ae, 0xa438, 0x0268,
	0xa438, 0xf01a, 0xa438, 0x10ad, 0xa438, 0x2f04, 0xa438, 0xd100,
	0xa438, 0xae05, 0xa438, 0xad2c, 0xa438, 0x02d1, 0xa438, 0x0f1f,
	0xa438, 0x00a2, 0xa438, 0x0407, 0xa438, 0x3908, 0xa438, 0xad2f,
	0xa438, 0x02d1, 0xa438, 0x0002, 0xa438, 0x0e1c, 0xa438, 0x2b01,
	0xa438, 0xad3a, 0xa438, 0xc9af, 0xa438, 0x0dee, 0xa438, 0xa000,
	0xa438, 0x2702, 0xa438, 0x1beb, 0xa438, 0xe18f, 0xa438, 0xe1ac,
	0xa438, 0x2819, 0xa438, 0xee8f, 0xa438, 0xe101, 0xa438, 0x1f44,
	0xa438, 0xbf65, 0xa438, 0x9302, 0xa438, 0x6b9d, 0xa438, 0xe58f,
	0xa438, 0xe21f, 0xa438, 0x44d1, 0xa438, 0x02bf, 0xa438, 0x6593,
	0xa438, 0x026b, 0xa438, 0x7ee0, 0xa438, 0x82b1, 0xa438, 0xae49,
	0xa438, 0xa001, 0xa438, 0x0502, 0xa438, 0x1c4d, 0xa438, 0xae41,
	0xa438, 0xa002, 0xa438, 0x0502, 0xa438, 0x1c90, 0xa438, 0xae39,
	0xa438, 0xa003, 0xa438, 0x0502, 0xa438, 0x1c9d, 0xa438, 0xae31,
	0xa438, 0xa004, 0xa438, 0x0502, 0xa438, 0x1cbc, 0xa438, 0xae29,
	0xa438, 0xa005, 0xa438, 0x1e02, 0xa438, 0x1cc9, 0xa438, 0xe080,
	0xa438, 0xdfac, 0xa438, 0x2013, 0xa438, 0xac21, 0xa438, 0x10ac,
	0xa438, 0x220d, 0xa438, 0xe18f, 0xa438, 0xe2bf, 0xa438, 0x6593,
	0xa438, 0x026b, 0xa438, 0x7eee, 0xa438, 0x8fe1, 0xa438, 0x00ae,
	0xa438, 0x08a0, 0xa438, 0x0605, 0xa438, 0x021d, 0xa438, 0x07ae,
	0xa438, 0x00e0, 0xa438, 0x82b1, 0xa438, 0xaf1b, 0xa438, 0xe910,
	0xa438, 0xbf4a, 0xa438, 0x99bf, 0xa438, 0x4a00, 0xa438, 0xa86a,
	0xa438, 0xfdad, 0xa438, 0x5eca, 0xa438, 0xad5e, 0xa438, 0x88bd,
	0xa438, 0x2c99, 0xa438, 0xbd2c, 0xa438, 0x33bd, 0xa438, 0x3222,
	0xa438, 0xbd32, 0xa438, 0x11bd, 0xa438, 0x3200, 0xa438, 0xbd32,
	0xa438, 0x77bd, 0xa438, 0x3266, 0xa438, 0xbd32, 0xa438, 0x55bd,
	0xa438, 0x3244, 0xa438, 0xbd32, 0xa436, 0xb818, 0xa438, 0x15c5,
	0xa436, 0xb81a, 0xa438, 0x6255, 0xa436, 0xb81c, 0xa438, 0x34e1,
	0xa436, 0xb81e, 0xa438, 0x1068, 0xa436, 0xb850, 0xa438, 0x07cc,
	0xa436, 0xb852, 0xa438, 0x26ca, 0xa436, 0xb878, 0xa438, 0x0dbf,
	0xa436, 0xb884, 0xa438, 0x1BB1, 0xa436, 0xb832, 0xa438, 0x00ff,
	0xa436, 0x0000, 0xa438, 0x0000, 0xB82E, 0x0000, 0xa436, 0x8023,
	0xa438, 0x0000, 0xa436, 0x801E, 0xa438, 0x0023, 0xB820, 0x0000,
	0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125d_1_2[] = {
	0xb892, 0x0000, 0xB88E, 0xC28F, 0xB890, 0x252D, 0xB88E, 0xC290,
	0xB890, 0xC924, 0xB88E, 0xC291, 0xB890, 0xC92E, 0xB88E, 0xC292,
	0xB890, 0xF626, 0xB88E, 0xC293, 0xB890, 0xF630, 0xB88E, 0xC294,
	0xB890, 0xA328, 0xB88E, 0xC295, 0xB890, 0xA332, 0xB88E, 0xC296,
	0xB890, 0xD72B, 0xB88E, 0xC297, 0xB890, 0xD735, 0xB88E, 0xC298,
	0xB890, 0x8A2E, 0xB88E, 0xC299, 0xB890, 0x8A38, 0xB88E, 0xC29A,
	0xB890, 0xBE32, 0xB88E, 0xC29B, 0xB890, 0xBE3C, 0xB88E, 0xC29C,
	0xB890, 0x7436, 0xB88E, 0xC29D, 0xB890, 0x7440, 0xB88E, 0xC29E,
	0xB890, 0xAD3B, 0xB88E, 0xC29F, 0xB890, 0xAD45, 0xB88E, 0xC2A0,
	0xB890, 0x6640, 0xB88E, 0xC2A1, 0xB890, 0x664A, 0xB88E, 0xC2A2,
	0xB890, 0xA646, 0xB88E, 0xC2A3, 0xB890, 0xA650, 0xB88E, 0xC2A4,
	0xB890, 0x624C, 0xB88E, 0xC2A5, 0xB890, 0x6256, 0xB88E, 0xC2A6,
	0xB890, 0xA453, 0xB88E, 0xC2A7, 0xB890, 0xA45D, 0xB88E, 0xC2A8,
	0xB890, 0x665A, 0xB88E, 0xC2A9, 0xB890, 0x6664, 0xB88E, 0xC2AA,
	0xB890, 0xAC62, 0xB88E, 0xC2AB, 0xB890, 0xAC6C, 0xB88E, 0xC2AC,
	0xB890, 0x746A, 0xB88E, 0xC2AD, 0xB890, 0x7474, 0xB88E, 0xC2AE,
	0xB890, 0xBCFA, 0xB88E, 0xC2AF, 0xB890, 0xBCFD, 0xB88E, 0xC2B0,
	0xB890, 0x79FF, 0xB88E, 0xC2B1, 0xB890, 0x7901, 0xB88E, 0xC2B2,
	0xB890, 0xF703, 0xB88E, 0xC2B3, 0xB890, 0xF706, 0xB88E, 0xC2B4,
	0xB890, 0x7408, 0xB88E, 0xC2B5, 0xB890, 0x740A, 0xB88E, 0xC2B6,
	0xB890, 0xF10C, 0xB88E, 0xC2B7, 0xB890, 0xF10F, 0xB88E, 0xC2B8,
	0xB890, 0x6F10, 0xB88E, 0xC2B9, 0xB890, 0x6F13, 0xB88E, 0xC2BA,
	0xB890, 0xEC15, 0xB88E, 0xC2BB, 0xB890, 0xEC18, 0xB88E, 0xC2BC,
	0xB890, 0x6A1A, 0xB88E, 0xC2BD, 0xB890, 0x6A1C, 0xB88E, 0xC2BE,
	0xB890, 0xE71E, 0xB88E, 0xC2BF, 0xB890, 0xE721, 0xB88E, 0xC2C0,
	0xB890, 0x6424, 0xB88E, 0xC2C1, 0xB890, 0x6425, 0xB88E, 0xC2C2,
	0xB890, 0xE228, 0xB88E, 0xC2C3, 0xB890, 0xE22A, 0xB88E, 0xC2C4,
	0xB890, 0x5F2B, 0xB88E, 0xC2C5, 0xB890, 0x5F2E, 0xB88E, 0xC2C6,
	0xB890, 0xDC31, 0xB88E, 0xC2C7, 0xB890, 0xDC33, 0xB88E, 0xC2C8,
	0xB890, 0x2035, 0xB88E, 0xC2C9, 0xB890, 0x2036, 0xB88E, 0xC2CA,
	0xB890, 0x9F3A, 0xB88E, 0xC2CB, 0xB890, 0x9F3A, 0xB88E, 0xC2CC,
	0xB890, 0x4430, 0xFFFF, 0xFFFF
};

static const u16 phy_mcu_ram_code_8125d_1_3[] = {
	0xa436, 0xacca, 0xa438, 0x0104, 0xa436, 0xaccc, 0xa438, 0x8000,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x0fff,
	0xa436, 0xacce, 0xa438, 0xfff8, 0xa436, 0xacd0, 0xa438, 0x0fff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xffff, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xfb47, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xfb4f, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0x6087, 0xa436, 0xacd0, 0xa438, 0x0180,
	0xa436, 0xacce, 0xa438, 0x600f, 0xa436, 0xacd0, 0xa438, 0x0108,
	0xa436, 0xacce, 0xa438, 0x6807, 0xa436, 0xacd0, 0xa438, 0x0100,
	0xa436, 0xacce, 0xa438, 0x688f, 0xa436, 0xacd0, 0xa438, 0x0188,
	0xa436, 0xacce, 0xa438, 0x7027, 0xa436, 0xacd0, 0xa438, 0x0120,
	0xa436, 0xacce, 0xa438, 0x702f, 0xa436, 0xacd0, 0xa438, 0x0128,
	0xa436, 0xacce, 0xa438, 0x7847, 0xa436, 0xacd0, 0xa438, 0x0140,
	0xa436, 0xacce, 0xa438, 0x784f, 0xa436, 0xacd0, 0xa438, 0x0148,
	0xa436, 0xacce, 0xa438, 0x80a7, 0xa436, 0xacd0, 0xa438, 0x01a0,
	0xa436, 0xacce, 0xa438, 0x88af, 0xa436, 0xacd0, 0xa438, 0x01a8,
	0xa436, 0xacce, 0xa438, 0x8067, 0xa436, 0xacd0, 0xa438, 0x0161,
	0xa436, 0xacce, 0xa438, 0x886f, 0xa436, 0xacd0, 0xa438, 0x0169,
	0xa436, 0xacce, 0xa438, 0xfb57, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0xfb5f, 0xa436, 0xacd0, 0xa438, 0x07ff,
	0xa436, 0xacce, 0xa438, 0x6017, 0xa436, 0xacd0, 0xa438, 0x0110,
	0xa436, 0xacce, 0xa438, 0x601f, 0xa436, 0xacd0, 0xa438, 0x0118,
	0xa436, 0xacce, 0xa438, 0x6837, 0xa436, 0xacd0, 0xa438, 0x0130,
	0xa436, 0xacce, 0xa438, 0x683f, 0xa436, 0xacd0, 0xa438, 0x0138,
	0xa436, 0xacce, 0xa438, 0x7097, 0xa436, 0xacd0, 0xa438, 0x0190,
	0xa436, 0xacce, 0xa438, 0x705f, 0xa436, 0xacd0, 0xa438, 0x0158,
	0xa436, 0xacce, 0xa438, 0x7857, 0xa436, 0xacd0, 0xa438, 0x0150,
	0xa436, 0xacce, 0xa438, 0x789f, 0xa436, 0xacd0, 0xa438, 0x0198,
	0xa436, 0xacce, 0xa438, 0x90b7, 0xa436, 0xacd0, 0xa438, 0x01b0,
	0xa436, 0xacce, 0xa438, 0x98bf, 0xa436, 0xacd0, 0xa438, 0x01b8,
	0xa436, 0xacce, 0xa438, 0x9077, 0xa436, 0xacd0, 0xa438, 0x1171,
	0xa436, 0xacce, 0xa438, 0x987f, 0xa436, 0xacd0, 0xa438, 0x1179,
	0xa436, 0xacca, 0xa438, 0x0004, 0xa436, 0xacc6, 0xa438, 0x0015,
	0xa436, 0xacc8, 0xa438, 0xc000, 0xa436, 0xacc8, 0xa438, 0x0000,
	0xFFFF, 0xFFFF
};

static void
rtl_real_set_phy_mcu_8125d_1_1(struct rtl_hw *hw)
{
	rtl_set_phy_mcu_ram_code(hw, phy_mcu_ram_code_8125d_1_1,
				 ARRAY_SIZE(phy_mcu_ram_code_8125d_1_1));
}

static void
rtl_real_set_phy_mcu_8125d_1_2(struct rtl_hw *hw)
{
	rtl_set_phy_mcu_ram_code(hw, phy_mcu_ram_code_8125d_1_2,
				 ARRAY_SIZE(phy_mcu_ram_code_8125d_1_2));
}

static void
rtl_real_set_phy_mcu_8125d_1_3(struct rtl_hw *hw)
{
	rtl_set_phy_mcu_ram_code(hw, phy_mcu_ram_code_8125d_1_3,
				 ARRAY_SIZE(phy_mcu_ram_code_8125d_1_3));
}

void
rtl_set_phy_mcu_8125d_1(struct rtl_hw *hw)
{
	rtl_set_phy_mcu_patch_request(hw);

	rtl_real_set_phy_mcu_8125d_1_1(hw);

	rtl_clear_phy_mcu_patch_request(hw);

	rtl_set_phy_mcu_patch_request(hw);

	rtl_real_set_phy_mcu_8125d_1_2(hw);

	rtl_clear_phy_mcu_patch_request(hw);

	rtl_set_phy_mcu_patch_request(hw);

	rtl_real_set_phy_mcu_8125d_1_3(hw);

	rtl_clear_phy_mcu_patch_request(hw);
}

