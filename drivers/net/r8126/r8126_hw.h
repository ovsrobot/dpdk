/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Realtek Corporation. All rights reserved
 */

#ifndef _R8126_HW_H_
#define _R8126_HW_H_

#include <stdint.h>

#include <bus_pci_driver.h>
#include <rte_ethdev.h>
#include <rte_ethdev_core.h>

#include "r8126_base.h"
#include "r8126_ethdev.h"
#include "r8126_phy.h"

u16 rtl8126_mac_ocp_read(struct rtl8126_hw *hw, u16 addr);
void rtl8126_mac_ocp_write(struct rtl8126_hw *hw, u16 addr, u16 value);

u32 rtl8126_csi_read(struct rtl8126_hw *hw, u32 addr);
void rtl8126_csi_write(struct rtl8126_hw *hw, u32 addr, u32 value);

void rtl8126_get_mac_version(struct rtl8126_hw *hw);
int rtl8126_get_mac_address(struct rtl8126_hw *hw, struct rte_ether_addr *ea);

void rtl8126_enable_cfg9346_write(struct rtl8126_hw *hw);
void rtl8126_disable_cfg9346_write(struct rtl8126_hw *hw);

void rtl8126_rar_set(struct rtl8126_hw *hw, uint8_t *addr);

void rtl8126_hw_disable_mac_mcu_bps(struct rtl8126_hw *hw);

void rtl8126_disable_ups(struct rtl8126_hw *hw);

void rtl8126_disable_rxdvgate(struct rtl8126_hw *hw);

void rtl8126_init_software_variable(struct rtl8126_hw *hw);

void rtl8126_get_tally_stats(struct rtl8126_hw *hw,
                             struct rte_eth_stats *stats);
void rtl8126_clear_tally_stats(struct rtl8126_hw *hw);

void rtl8126_exit_oob(struct rtl8126_hw *hw);
void rtl8126_nic_reset(struct rtl8126_hw *hw);

int rtl8126_set_hw_ops(struct rtl8126_hw *hw);

void rtl8126_write_mac_mcu_ram_code(struct rtl8126_hw *hw, const u16 *entry,
                                    u16 entry_cnt);

void rtl8126_enable_force_clkreq(struct rtl8126_hw *hw, bool enable);
void rtl8126_enable_aspm_clkreq_lock(struct rtl8126_hw *hw, bool enable);

void rtl8126_disable_l1_timeout(struct rtl8126_hw *hw);

bool rtl8126_is_speed_mode_valid(u32 speed);

extern const struct rtl8126_hw_ops rtl8126a_ops;

#define RTL8126_MAC_MCU_PAGE_SIZE 256

#define ARRAY_SIZE(arr) RTE_DIM(arr)

#define HW_SUPPORT_CHECK_PHY_DISABLE_MODE(_M) ((_M)->HwSuppCheckPhyDisableModeVer > 0 )
#define HW_HAS_WRITE_PHY_MCU_RAM_CODE(_M)     (((_M)->HwHasWrRamCodeToMicroP == TRUE) ? 1 : 0)
#define HW_SUPPORT_D0_SPEED_UP(_M)            ((_M)->HwSuppD0SpeedUpVer > 0)
#define HW_SUPPORT_MAC_MCU(_M)                ((_M)->HwSuppMacMcuVer > 0)

#define HW_SUPP_PHY_LINK_SPEED_GIGA(_M)	      ((_M)->HwSuppMaxPhyLinkSpeed >= 1000)
#define HW_SUPP_PHY_LINK_SPEED_2500M(_M)      ((_M)->HwSuppMaxPhyLinkSpeed >= 2500)
#define HW_SUPP_PHY_LINK_SPEED_5000M(_M)      ((_M)->HwSuppMaxPhyLinkSpeed >= 5000)

#define NO_BASE_ADDRESS 0x00000000

/* Tx NO CLOSE */
#define MAX_TX_NO_CLOSE_DESC_PTR_V2            0x10000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V2       0xFFFF
#define MAX_TX_NO_CLOSE_DESC_PTR_V3            0x100000000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V3       0xFFFFFFFF
#define MAX_TX_NO_CLOSE_DESC_PTR_V4            0x80000000
#define MAX_TX_NO_CLOSE_DESC_PTR_MASK_V4       0x7FFFFFFF
#define TX_NO_CLOSE_SW_PTR_MASK_V2             0x1FFFF

/* Channel wait count */
#define R8126_CHANNEL_WAIT_COUNT      20000
#define R8126_CHANNEL_WAIT_TIME       1   /*  1 us */
#define R8126_CHANNEL_EXIT_DELAY_TIME 20  /* 20 us */

#endif