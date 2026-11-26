/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_HW_DRACO_SNIC_H_
#define _NBL_HW_DRACO_SNIC_H_

#include "../nbl_hw.h"

/* Function BAR0 BDF capture register. */
#define NBL_PCOMPLETER_BDF_CAPTURE_OFFSET		(0x1010)
#define NBL_PCOMPLETER_FID_SHIFT			(16)
#define NBL_PCOMPLETER_FID_MASK			(0xfff)
#define NBL_PCOMPLETER_PF_SHIFT			(28)

/* MAILBOX BAR2 */
#define NBL_MAILBOX_NOTIFY_ADDR			(0x00000000)
#define NBL_MAILBOX_QINFO_CFG_RX_TABLE_ADDR	(0x10)
#define NBL_MAILBOX_QINFO_CFG_TX_TABLE_ADDR	(0x20)
#define NBL_MAILBOX_QINFO_CFG_DBG_TABLE_ADDR	(0x30)

#define NBL_NOTIFY_DELAY_MIN_TIME_FOR_REGS	200

/* mailbox BAR qinfo_cfg_rx_table */
struct nbl_mailbox_qinfo_cfg_rx_table {
	u32 rx_queue_base_addr_l;
	u32 rx_queue_base_addr_h;
	u32 rx_queue_size_bwind:4;
	u32 rsv1:28;
	u32 rx_queue_rst:1;
	u32 rx_queue_en:1;
	u32 rx_rdif_err:1;
	u32 rx_ptr_err:1;
	u32 rsv2:28;
};

/* mailbox BAR qinfo_cfg_tx_table */
struct nbl_mailbox_qinfo_cfg_tx_table {
	u32 tx_queue_base_addr_l;
	u32 tx_queue_base_addr_h;
	u32 tx_queue_size_bwind:4;
	u32 rsv1:28;
	u32 tx_queue_rst:1;
	u32 tx_queue_en:1;
	u32 tx_rdif_err:1;
	u32 tx_ptr_err:1;
	u32 rsv2:28;
};

/* mailbox BAR qinfo_cfg_dbg_table */
struct nbl_mailbox_qinfo_cfg_dbg_tbl {
	u16 rx_drop;
	u16 rx_get;
	u16 tx_drop;
	u16 tx_out;
	u16 rx_hd_ptr;
	u16 tx_hd_ptr;
	u16 rx_tail_ptr;
	u16 tx_tail_ptr;
};

#endif
