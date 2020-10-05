/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015-2020
 */

#ifndef _TXGBE_DCB_HW_H_
#define _TXGBE_DCB_HW_H_

/* DCB PFC */
s32 txgbe_dcb_config_pfc_raptor(struct txgbe_hw *, u8, u8 *);

/* DCB stats */
s32 txgbe_dcb_config_tc_stats_raptor(struct txgbe_hw *,
				    struct txgbe_dcb_config *);

/* DCB config arbiters */
s32 txgbe_dcb_config_tx_desc_arbiter_raptor(struct txgbe_hw *, u16 *, u16 *,
					   u8 *, u8 *);
s32 txgbe_dcb_config_tx_data_arbiter_raptor(struct txgbe_hw *, u16 *, u16 *,
					   u8 *, u8 *, u8 *);
s32 txgbe_dcb_config_rx_arbiter_raptor(struct txgbe_hw *, u16 *, u16 *, u8 *,
				      u8 *, u8 *);

#endif /* _TXGBE_DCB_HW_H_ */
