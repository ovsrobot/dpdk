#ifndef _MOTORCOMM_H
#define _MOTORCOMM_H

#include "generic_phy.h"

/* MOTORCOMM_PHY_H */
#define MOTORCOMM_PHY_ID_MASK           0xffffffff

#define PHY_ID_YT8010                   0x00000309
#define PHY_ID_YT8510                   0x00000109
#define PHY_ID_YT8511                   0x0000010a
#define PHY_ID_YT8512                   0x00000118
#define PHY_ID_YT8512B                  0x00000128
#define PHY_ID_YT8521                   0x0000011a
#define PHY_ID_YT8531S                  0x4f51e91a
#define PHY_ID_YT8531                   0x4f51e91b
#define PHY_ID_YT8614                   0x4F51E899
#define PHY_ID_YT8618                   0x0000e889
#define PHY_ID_YT8821                   0x4f51ea19

#define REG_PHY_SPEC_STATUS             0x11
#define REG_DEBUG_ADDR_OFFSET           0x1e
#define REG_DEBUG_DATA                  0x1f

#define YT8512_EXTREG_AFE_PLL           0x50
#define YT8512_EXTREG_EXTEND_COMBO      0x4000
#define YT8512_EXTREG_LED0              0x40c0
#define YT8512_EXTREG_LED1              0x40c3

#define YT8512_EXTREG_SLEEP_CONTROL1    0x2027

#define YT_SOFTWARE_RESET		0x8000

#define YT8512_CONFIG_PLL_REFCLK_SEL_EN	0x0040
#define YT8512_CONTROL1_RMII_EN		0x0001
#define YT8512_LED0_ACT_BLK_IND		0x1000
#define YT8512_LED0_DIS_LED_AN_TRY	0x0001
#define YT8512_LED0_BT_BLK_EN		0x0002
#define YT8512_LED0_HT_BLK_EN		0x0004
#define YT8512_LED0_COL_BLK_EN		0x0008
#define YT8512_LED0_BT_ON_EN		0x0010
#define YT8512_LED1_BT_ON_EN		0x0010
#define YT8512_LED1_TXACT_BLK_EN	0x0100
#define YT8512_LED1_RXACT_BLK_EN	0x0200
#define YT8512_SPEED_MODE		0xc000
#define YT8512_DUPLEX			0x2000
#define YT8512_SPEED_MODE_BIT		14
#define YT8512_DUPLEX_BIT		13
#define YT8512_EN_SLEEP_SW_BIT		15

#define YT8521_EXTREG_SLEEP_CONTROL1	0x27
#define YT8521_EN_SLEEP_SW_BIT		15
#define YT8521_SPEED_MODE        0xc000
#define YT8521_DUPLEX            0x2000
#define YT8521_SPEED_MODE_BIT    14
#define YT8521_DUPLEX_BIT        13
#define YT8521_LINK_STATUS_BIT   10

#define YT8821_EXTREG_SLEEP_CONTROL1	0x27
#define YT8821_EN_SLEEP_SW_BIT		15
#define YT8821_SPEED_MODE        0xc000
#define YT8821_SPEED_MODE_UPPER  9
#define YT8821_DUPLEX            0x2000
#define YT8821_SPEED_MODE_BIT    14
#define YT8821_DUPLEX_BIT        13
#define YT8821_LINK_STATUS_BIT   10
/*
 * ext reg 0xa001 contains hw strap configuration of 8521, it can be:
 * 3'b000: UTP_TO_RGMII;
 * 3'b001: FIBER_TO_RGMII;
 * 3'b010: UTP_FIBER_TO_RGMII;
 * 3'b011: UTP_TO_SGMII;
 * 3'b100: SGPHY_TO_RGMAC;
 * 3'b101: SGMAC_TO_RGPHY;
 * 3'b110: UTP_TO_FIBER_AUTO;
 * 3'b111: UTP_TO_FIBER_FORCE
 *
 */

/* YT8521 polling mode */
#define YT8521_PHY_MODE_FIBER           1 /* fiber mode only */
#define YT8521_PHY_MODE_UTP             2 /* utp mode only */
#define YT8521_PHY_MODE_POLL            3 /* fiber and utp, poll mode */

#endif /* _MOTORCOMM_H */
