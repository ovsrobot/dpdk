/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#ifndef _E1000_I225_H_
#define _E1000_I225_H_

bool e1000_get_flash_presence_i225(struct e1000_hw *hw);
s32 e1000_update_flash_i225(struct e1000_hw *hw);
s32 e1000_update_nvm_checksum_i225(struct e1000_hw *hw);
s32 e1000_validate_nvm_checksum_i225(struct e1000_hw *hw);
s32 e1000_write_nvm_srwr_i225(struct e1000_hw *hw, u16 offset,
			      u16 words, u16 *data);
s32 e1000_read_nvm_srrd_i225(struct e1000_hw *hw, u16 offset,
			     u16 words, u16 *data);
s32 e1000_set_flsw_flash_burst_counter_i225(struct e1000_hw *hw,
					    u32 burst_counter);
s32 e1000_write_erase_flash_command_i225(struct e1000_hw *hw, u32 opcode,
					 u32 address);
s32 e1000_id_led_init_i225(struct e1000_hw *hw);
s32 e1000_blink_led_i225(struct e1000_hw *hw);
s32 e1000_acquire_swfw_sync_i225(struct e1000_hw *hw, u16 mask);
void e1000_release_swfw_sync_i225(struct e1000_hw *hw, u16 mask);
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

/* NVM offset defaults for I225 devices */
#define NVM_INIT_CTRL_2_DEFAULT_I225	0X7243
#define NVM_INIT_CTRL_4_DEFAULT_I225	0x00C1
#define NVM_LED_1_CFG_DEFAULT_I225	0x0184
#define NVM_LED_0_2_CFG_DEFAULT_I225	0x200C

#define E1000_I225_SHADOW_RAM_SIZE		4096
#define E1000_I225_ERASE_CMD_OPCODE		0x02000000
#define E1000_I225_WRITE_CMD_OPCODE		0x01000000
#define E1000_FLSWCTL_DONE			0x40000000
#define E1000_FLSWCTL_CMDV			0x10000000

/* LED Control */
#define E1000_GLOBAL_BLINK_MODE	0x00000020 /*Blink at 200 ms on and 200 ms off.*/
#define E1000_LED1_MODE_MASK	0x00000F00
#define E1000_LED1_BLINK	0x00008000
#define E1000_LED2_MODE_MASK	0x000F0000

#endif
