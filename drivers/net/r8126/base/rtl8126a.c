/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#include "../r8126_ethdev.h"
#include "../r8126_hw.h"
#include "../r8126_phy.h"
#include "rtl8126a_mcu.h"

/* For RTL8126A, CFG_METHOD_1,2,3 */

static void
hw_init_rxcfg_8126a(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1:
		RTL_W32(hw, RxConfig, Rx_Fetch_Number_8 | RxCfg_pause_slot_en |
		        (RX_DMA_BURST_512 << RxCfgDMAShift));
		break;
	case CFG_METHOD_2:
	case CFG_METHOD_3:
		RTL_W32(hw, RxConfig, Rx_Fetch_Number_8 | Rx_Close_Multiple |
		        RxCfg_pause_slot_en | (RX_DMA_BURST_512 << RxCfgDMAShift));
		break;
	}
}

static void
hw_ephy_config_8126a(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1 ... CFG_METHOD_3:
		/* nothing to do */
		break;
	}
}

static void
rtl8126_hw_phy_config_8126a_1(struct rtl8126_hw *hw)
{
	rtl8126_set_eth_phy_ocp_bit(hw, 0xA442, BIT_11);

	RTL_W16(hw, EEE_TXIDLE_TIMER_8125, hw->mtu + ETH_HLEN + 0x20);
}

static void
rtl8126_hw_phy_config_8126a_2(struct rtl8126_hw *hw)
{
	rtl8126_set_eth_phy_ocp_bit(hw, 0xA442, BIT_11);

	RTL_W16(hw, EEE_TXIDLE_TIMER_8125, hw->mtu + ETH_HLEN + 0x20);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80BF);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0xED00);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80CD);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x1000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80D1);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0xC800);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80D4);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0xC800);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80E1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x10CC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x80E5);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x4F0C);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8387);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x4700);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA80C, (BIT_7 | BIT_6), BIT_7);

	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAC90, BIT_4);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAD2C, BIT_15);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8321);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1100);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xACF8, (BIT_3 | BIT_2));
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8183);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x5900);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD94, BIT_5);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xA654, BIT_11);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xB648, BIT_14);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x839E);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x2F00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83F2);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0800);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xADA0, BIT_1);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x80F3);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x9900);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8126);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0xC100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x893A);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x8080);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8647);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0xE600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x862C);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1200);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x864A);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0xE600);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x80A0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0xBCBC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x805E);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0xBCBC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8056);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x3077);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8058);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x5A00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8098);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x3077);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x809A);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x5A00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8052);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x3733);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8094);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x3733);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x807F);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x7C75);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x803D);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x7C75);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8036);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8078);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8031);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3300);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8073);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3300);

	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xAE06, 0xFC00, 0x7C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x89D1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0004);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8FBD);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x0A00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8FBE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0D09);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x89CD);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0F0F);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x89CF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0F0F);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83A4);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83A6);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6601);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83C0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83C2);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6601);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8414);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8416);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6601);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83F8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x83FA);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x6601);

	rtl8126_set_phy_mcu_patch_request(hw);

	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xBD96, 0x1F00, 0x1000);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xBF1C, 0x0007, 0x0007);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xBFBE, BIT_15);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xBF40, 0x0380, 0x0280);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xBF90, BIT_7, (BIT_6 | BIT_5));
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xBF90, BIT_4, (BIT_3 | BIT_2));
	rtl8126_clear_phy_mcu_patch_request(hw);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x843B);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x2000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x843D);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x2000);

	rtl8126_clear_eth_phy_ocp_bit(hw, 0xB516, 0x7F);

	rtl8126_clear_eth_phy_ocp_bit(hw, 0xBF80, (BIT_5 | BIT_4));

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8188);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0044);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00A8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00D6);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00EC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00F6);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00FC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00BC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0058);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x002A);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8015);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0800);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFD);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFF);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x7F00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFB);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FE9);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0002);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FEF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x00A5);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FF1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0106);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FE1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0102);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FE3);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0400);

	rtl8126_set_eth_phy_ocp_bit(hw, 0xA654, BIT_11);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0XA65A, (BIT_1 | BIT_0));

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xAC3A, 0x5851);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0XAC3C, (BIT_15 | BIT_14 | BIT_12),
	                                      BIT_13);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xAC42, BIT_9,
	                                      (BIT_8 | BIT_7 | BIT_6));
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAC3E, (BIT_15 | BIT_14 | BIT_13));
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAC42, (BIT_5 | BIT_4 | BIT_3));
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xAC42, BIT_1, (BIT_2 | BIT_0));

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xAC1A, 0x00DB);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xADE4, 0x01B5);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAD9C, (BIT_11 | BIT_10));

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814B);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814D);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814F);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0B00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8142);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8144);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8150);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8118);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0700);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811A);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0700);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811C);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0500);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x810F);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8111);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811D);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);

	rtl8126_set_eth_phy_ocp_bit(hw, 0xAC36, BIT_12);
	rtl8126_clear_eth_phy_ocp_bit(hw, 0xAD1C, BIT_8);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xADE8, 0xFFC0, 0x1400);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x864B);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x9D00);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8F97);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x003F);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x3F02);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x023C);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x3B0A);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x1C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);


	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD9C, BIT_5);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8122);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0C00);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x82C8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0009);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000B);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0021);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F7);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03B8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0049);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0049);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03B8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F7);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0021);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000B);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0009);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x80EF);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x82A0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000E);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0006);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x001A);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03D8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0023);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0054);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0322);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x00DD);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03AB);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03DC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0027);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000E);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E5);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F9);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0012);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0001);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F1);


	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8018);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xA438, BIT_13);


	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FE4);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0000);

	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB54C, 0xFFC0, 0x3700);
}

static void
rtl8126_hw_phy_config_8126a_3(struct rtl8126_hw *hw)
{
	rtl8126_set_eth_phy_ocp_bit(hw, 0xA442, BIT_11);

	RTL_W16(hw, EEE_TXIDLE_TIMER_8125, hw->mtu + ETH_HLEN + 0x20);


	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8183);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x5900);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xA654, BIT_11);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xB648, BIT_14);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD2C, BIT_15);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD94, BIT_5);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xADA0, BIT_1);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xAE06,
	                                      (BIT_15 | BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10),
	                                      (BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10));

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8647);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0xE600);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8036);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8078);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x3000);


	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x89E9);
	rtl8126_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFD);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFE);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0200);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8FFF);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0400);


	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8018);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x7700);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8F9C);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0005);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x00ED);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0502);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0B00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0xD401);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8FA8);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xA438, 0xFF00, 0x2900);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814B);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814D);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x814F);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0B00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8142);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8144);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8150);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8118);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0700);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811A);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0700);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811C);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0500);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x810F);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8111);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x811D);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0100);


	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD1C, BIT_8);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xADE8,
	                                      (BIT_15 | BIT_14 | BIT_13 | BIT_12 | BIT_11 | BIT_10 | BIT_9 | BIT_8 | BIT_7 |
	                                       BIT_6), (BIT_12 | BIT_10));
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x864B);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x9D00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x862C);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x1200);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA436, 0x8566);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x003F);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x3F02);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x023C);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x3B0A);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x1C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xA438, 0x0000);


	rtl8126_set_eth_phy_ocp_bit(hw, 0xAD9C, BIT_5);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x8122);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x82C8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0009);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000B);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0021);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F7);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03B8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0049);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0049);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03B8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F7);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0021);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000B);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0009);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FF);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);

	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x80EF);
	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB87E, 0xFF00, 0x0C00);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87C, 0x82A0);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000E);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03FE);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03ED);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0006);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x001A);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F1);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03D8);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0023);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0054);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0322);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x00DD);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03AB);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03DC);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0027);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x000E);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03E5);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F9);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0012);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x0001);
	rtl8126_mdio_direct_write_phy_ocp(hw, 0xB87E, 0x03F1);


	rtl8126_set_eth_phy_ocp_bit(hw, 0xA430, (BIT_1 | BIT_0));


	rtl8126_clear_and_set_eth_phy_ocp_bit(hw, 0xB54C, 0xFFC0, 0x3700);
}

static void
hw_phy_config_8126a(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1:
		rtl8126_hw_phy_config_8126a_1(hw);
		break;
	case CFG_METHOD_2:
		rtl8126_hw_phy_config_8126a_2(hw);
		break;
	case CFG_METHOD_3:
		rtl8126_hw_phy_config_8126a_3(hw);
		break;
	}
}

static void
hw_mac_mcu_config_8126a(struct rtl8126_hw *hw)
{
	if (hw->NotWrMcuPatchCode == TRUE)
		return;

	switch (hw->mcfg) {
	case CFG_METHOD_1:
		rtl8126_set_mac_mcu_8126a_1(hw);
		break;
	case CFG_METHOD_2:
		rtl8126_set_mac_mcu_8126a_2(hw);
		break;
	case CFG_METHOD_3:
		rtl8126_set_mac_mcu_8126a_3(hw);
		break;
	}
}

static void
hw_phy_mcu_config_8126a(struct rtl8126_hw *hw)
{
	switch (hw->mcfg) {
	case CFG_METHOD_1:
		rtl8126_set_phy_mcu_8126a_1(hw);
		break;
	case CFG_METHOD_2:
		rtl8126_set_phy_mcu_8126a_2(hw);
		break;
	case CFG_METHOD_3:
		rtl8126_set_phy_mcu_8126a_3(hw);
		break;
	}
}

const struct rtl8126_hw_ops rtl8126a_ops = {
	.hw_init_rxcfg     = hw_init_rxcfg_8126a,
	.hw_ephy_config    = hw_ephy_config_8126a,
	.hw_phy_config     = hw_phy_config_8126a,
	.hw_mac_mcu_config = hw_mac_mcu_config_8126a,
	.hw_phy_mcu_config = hw_phy_mcu_config_8126a,
};
