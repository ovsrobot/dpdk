/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#ifndef _E1000_I225_H_
#define _E1000_I225_H_

s32 e1000_init_hw_i225(struct e1000_hw *hw);
s32 e1000_setup_copper_link_i225(struct e1000_hw *hw);
s32 e1000_set_d0_lplu_state_i225(struct e1000_hw *hw, bool active);
s32 e1000_set_d3_lplu_state_i225(struct e1000_hw *hw, bool active);

#endif
