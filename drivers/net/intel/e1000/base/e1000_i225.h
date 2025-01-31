/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#ifndef _E1000_I225_H_
#define _E1000_I225_H_

s32 e1000_id_led_init_i225(struct e1000_hw *hw);
s32 e1000_blink_led_i225(struct e1000_hw *hw);
s32 e1000_init_hw_i225(struct e1000_hw *hw);
s32 e1000_setup_copper_link_i225(struct e1000_hw *hw);
s32 e1000_set_d0_lplu_state_i225(struct e1000_hw *hw, bool active);
s32 e1000_set_d3_lplu_state_i225(struct e1000_hw *hw, bool active);

#define ID_LED_DEFAULT_I225		((ID_LED_OFF1_ON2  << 8) | \
					 (ID_LED_DEF1_DEF2 <<  4) | \
					 (ID_LED_OFF1_OFF2))
#define ID_LED_DEFAULT_I225_SERDES	((ID_LED_DEF1_DEF2 << 8) | \
					 (ID_LED_DEF1_DEF2 <<  4) | \
					 (ID_LED_OFF1_ON2))

/* LED Control */
#define E1000_GLOBAL_BLINK_MODE	0x00000020 /*Blink at 200 ms on and 200 ms off.*/
#define E1000_LED1_MODE_MASK	0x00000F00
#define E1000_LED1_BLINK	0x00008000
#define E1000_LED2_MODE_MASK	0x000F0000

#endif
