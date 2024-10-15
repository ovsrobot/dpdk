/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#ifndef _R8169_HW_H_
#define _R8169_HW_H_

#include <stdint.h>

#include <bus_pci_driver.h>
#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

#include "r8169_base.h"
#include "r8169_ethdev.h"

u16 rtl_mac_ocp_read(struct rtl_hw *hw, u16 addr);
void rtl_mac_ocp_write(struct rtl_hw *hw, u16 addr, u16 value);

u32 rtl_csi_read(struct rtl_hw *hw, u32 addr);
void rtl_csi_write(struct rtl_hw *hw, u32 addr, u32 value);

/* Channel wait count */
#define RTL_CHANNEL_WAIT_COUNT      20000
#define RTL_CHANNEL_WAIT_TIME       1   /*  1 us */
#define RTL_CHANNEL_EXIT_DELAY_TIME 20  /* 20 us */

#endif

