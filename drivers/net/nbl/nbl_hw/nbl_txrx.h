/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Nebulamatrix Technology Co., Ltd.
 */

#ifndef _NBL_TXRX_H_
#define _NBL_TXRX_H_

#include "nbl_resource.h"

#define NBL_PACKED_DESC_F_NEXT			(0)
#define NBL_PACKED_DESC_F_WRITE			(1)
#define NBL_PACKED_DESC_F_AVAIL			(7)
#define NBL_PACKED_DESC_F_USED			(15)
#define NBL_PACKED_DESC_F_NEXT_BIT		(1 << NBL_PACKED_DESC_F_NEXT)
#define NBL_PACKED_DESC_F_WRITE_BIT		(1 << NBL_PACKED_DESC_F_WRITE)
#define NBL_PACKED_DESC_F_AVAIL_BIT		(1 << NBL_PACKED_DESC_F_AVAIL)
#define NBL_PACKED_DESC_F_USED_BIT		(1 << NBL_PACKED_DESC_F_USED)
#define NBL_PACKED_DESC_F_AVAIL_USED		(NBL_PACKED_DESC_F_AVAIL_BIT | \
						 NBL_PACKED_DESC_F_USED_BIT)

#define NBL_TX_HEADER_LEN			(32)
#define NBL_VQ_HDR_NAME_MAXSIZE			(32)

#define NBL_VRING_DESC_F_NEXT			RTE_BIT64(0)
#define NBL_VRING_DESC_F_WRITE			RTE_BIT64(1)
#define NBL_FREE_DESC_THRES			16
#define NBL_USED_DESC_THRES			32
#define NBL_TX_TOTAL_HEADERLEN_SHIFT		24
#define NBL_TX_FREE_THRESH			32
#define NBL_TX_RS_THRESH			32

#define NBL_RXQ_REARM_THRESH			32

#define NBL_DESC_PER_LOOP_VEC_MAX		(8)
#define NBL_BUF_LEN_16K				(16384)
#define NBL_BUF_LEN_8K				(8192)
#define NBL_BUF_LEN_4K				(4096)
#define NBL_BUF_LEN_2K				(2048)

union nbl_tx_extend_head {
	struct nbl_tx_ehdr_leonis {
		/* DW0 */
		u32 mac_len :5;
		u32 ip_len :5;
		u32 l4_len :4;
		u32 l4_type :2;
		u32 inner_ip_type :2;
		u32 external_ip_type :2;
		u32 external_ip_len :5;
		u32 l4_tunnel_type :2;
		u32 l4_tunnel_len :5;
		/* DW1 */
		u32 l4s_sid :10;
		u32 l4s_sync_ind :1;
		u32 l4s_redun_ind :1;
		u32 l4s_redun_head_ind :1;
		u32 l4s_hdl_ind :1;
		u32 l4s_pbrac_mode :1;
		u32 rsv0 :2;
		u32 mss :14;
		u32 tso :1;
		/* DW2 */
		/* if dport = NBL_TX_DPORT_ETH; dport_info = 0
		 * if dport = NBL_TX_DPORT_HOST; dport_info = host queue id
		 * if dport = NBL_TX_DPORT_ECPU; dport_info = ecpu queue_id
		 */
		u32 dport_info :11;
		/* if dport = NBL_TX_DPORT_ETH; dport_id[3:0] = eth port id, dport_id[9:4] = lag id
		 * if dport = NBL_TX_DPORT_HOST; dport_id[9:0] = host vsi_id
		 * if dport = NBL_TX_DPORT_ECPU; dport_id[9:0] = ecpu vsi_id
		 */
		u32 dport_id :10;
#define NBL_TX_DPORT_ID_LAG_OFT_LEONIS	(4)
		u32 dport :3;
#define NBL_TX_DPORT_ETH		(0)
#define NBL_TX_DPORT_HOST		(1)
#define NBL_TX_DPORT_ECPU		(2)
#define NBL_TX_DPORT_EMP		(3)
#define NBL_TX_DPORT_BMC		(4)
#define NBL_TX_DPORT_EMP_DRACO		(2)
#define NBL_TX_DPORT_BMC_DRACO		(3)
		u32 fwd :2;
#define NBL_TX_FWD_TYPE_DROP		(0)
#define NBL_TX_FWD_TYPE_NORMAL		(1)
#define NBL_TX_FWD_TYPE_RSV		(2)
#define NBL_TX_FWD_TYPE_CPU_ASSIGNED	(3)
		u32 rss_lag_en :1;
		u32 l4_csum_en :1;
		u32 l3_csum_en :1;
		u32 rsv1 :3;
	} leonis;
};

union nbl_rx_extend_head {
	struct nbl_rx_ehdr_leonis {
		/* DW0 */
		/* 0x0:eth, 0x1:host, 0x2:ecpu, 0x3:emp, 0x4:bcm */
		u32 sport :3;
		u32 dport_info :11;
		/* sport = 0, sport_id[3:0] = eth id,
		 * sport = 1, sport_id[9:0] = host vsi_id,
		 * sport = 2, sport_id[9:0] = ecpu vsi_id,
		 */
		u32 sport_id :10;
		/* 0x0:drop, 0x1:normal, 0x2:cpu upcall */
		u32 fwd :2;
		u32 rsv0 :6;
		/* DW1 */
		u32 error_code :6;
		u32 ptype :10;
		u32 profile_id :4;
		u32 checksum_status :1;
		u32 rsv1 :1;
		u32 l4s_sid :10;
		/* DW2 */
		u32 rsv3 :2;
		u32 l4s_hdl_ind :1;
		u32 l4s_tcp_offset :14;
		u32 l4s_resync_ind :1;
		u32 l4s_check_ind :1;
		u32 l4s_dec_ind :1;
		u32 rsv2 :4;
		u32 num_buffers :8;
		u32 hash_value;
	} leonis;

	struct nbl_rx_ehdr_common {
		u32 dw0;
		u32 dw1;
		u32 dw2:24;
		u32 num_buffers:8;
		u32 dw3;
	} common;
};

#endif
