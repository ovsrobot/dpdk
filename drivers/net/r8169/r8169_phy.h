/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#ifndef _R8169_PHY_H_
#define _R8169_PHY_H_

#include <stdint.h>
#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

#include "r8169_base.h"
#include "r8169_ethdev.h"

void rtl_clear_mac_ocp_bit(struct rtl_hw *hw, u16 addr, u16 mask);
void rtl_set_mac_ocp_bit(struct rtl_hw *hw, u16 addr, u16 mask);

#endif
