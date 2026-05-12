/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __sxe2_VSI_H__
#define __sxe2_VSI_H__
#include <rte_os.h>
#include "sxe2_type.h"
#include "sxe2_drv_cmd.h"

#define SXE2_MAX_BOND_MEMBER_CNT   4

enum sxe2_drv_type {
	SXE2_MAX_DRV_TYPE_DPDK = 0,
	SXE2_MAX_DRV_TYPE_KERNEL,
	SXE2_MAX_DRV_TYPE_CNT,
};

#define SXE2_MAX_USER_PRIORITY        (8)

#define SXE2_DFLT_NUM_RX_DESC 512
#define SXE2_DFLT_NUM_TX_DESC 512

#define SXE2_DFLT_Q_NUM_OTHER_VSI 1
#define SXE2_INVALID_VSI_ID    0xFFFF

struct sxe2_adapter;
struct sxe2_drv_vsi_caps;
struct rte_eth_dev;

enum sxe2_vsi_type {
	SXE2_VSI_T_PF = 0,
	SXE2_VSI_T_VF,
	SXE2_VSI_T_CTRL,
	SXE2_VSI_T_LB,
	SXE2_VSI_T_MACVLAN,
	SXE2_VSI_T_ESW,
	SXE2_VSI_T_RDMA,
	SXE2_VSI_T_DPDK_PF,
	SXE2_VSI_T_DPDK_VF,
	SXE2_VSI_T_DPDK_ESW,
	SXE2_VSI_T_NR,
};

struct sxe2_queue_info {
	u16 base_idx_in_nic;
	u16 base_idx_in_func;
	u16 q_cnt;
	u16 depth;
	u16 rx_buf_len;
	u16 max_frame_len;
	struct sxe2_queue **queues;
};

struct sxe2_vsi_irqs {
	u16 avail_cnt;
	u16 used_cnt;
	u16 base_idx_in_pf;
};

enum {
	sxe2_VSI_DOWN = 0,
	sxe2_VSI_CLOSE,
	sxe2_VSI_DISABLE,
	sxe2_VSI_MAX,
};

struct sxe2_stats {
	u64 ipackets;

	u64 opackets;

	u64 ibytes;

	u64 obytes;

	u64 ierrors;

	u64 imissed;

	u64 rx_out_of_buffer;
	u64 rx_qblock_drop;

	u64 tx_frame_good;
	u64 rx_frame_good;
	u64 rx_crc_errors;
	u64 tx_bytes_good;
	u64 rx_bytes_good;
	u64 tx_multicast_good;
	u64 tx_broadcast_good;
	u64 rx_multicast_good;
	u64 rx_broadcast_good;
	u64 rx_len_errors;
	u64 rx_out_of_range_errors;
	u64 rx_oversize_pkts_phy;
	u64 rx_symbol_err;
	u64 rx_pause_frame;
	u64 tx_pause_frame;

	u64 rx_discards_phy;
	u64 rx_discards_ips_phy;

	u64 tx_dropped_link_down;
	u64 rx_undersize_good;
	u64 rx_runt_error;
	u64 tx_bytes_good_bad;
	u64 tx_frame_good_bad;
	u64 rx_jabbers;
	u64 rx_size_64;
	u64 rx_size_65_127;
	u64 rx_size_128_255;
	u64 rx_size_256_511;
	u64 rx_size_512_1023;
	u64 rx_size_1024_1522;
	u64 rx_size_1523_max;
	u64 rx_pcs_symbol_err_phy;
	u64 rx_corrected_bits_phy;
	u64 rx_err_lane_0_phy;
	u64 rx_err_lane_1_phy;
	u64 rx_err_lane_2_phy;
	u64 rx_err_lane_3_phy;

	u64 rx_prio_buf_discard[SXE2_MAX_USER_PRIORITY];
	u64 rx_illegal_bytes;
	u64 rx_oversize_good;
	u64 tx_unicast;
	u64 tx_broadcast;
	u64 tx_multicast;
	u64 tx_vlan_packet_good;
	u64 tx_size_64;
	u64 tx_size_65_127;
	u64 tx_size_128_255;
	u64 tx_size_256_511;
	u64 tx_size_512_1023;
	u64 tx_size_1024_1522;
	u64 tx_size_1523_max;
	u64 tx_underflow_error;
	u64 rx_byte_good_bad;
	u64 rx_frame_good_bad;
	u64 rx_unicast_good;
	u64 rx_vlan_packets;

	u64 prio_xoff_rx[SXE2_MAX_USER_PRIORITY];
	u64 prio_xon_rx[SXE2_MAX_USER_PRIORITY];
	u64 prio_xon_tx[SXE2_MAX_USER_PRIORITY];
	u64 prio_xoff_tx[SXE2_MAX_USER_PRIORITY];
	u64 prio_xon_2_xoff[SXE2_MAX_USER_PRIORITY];

	u64 rx_vsi_unicast_packets;
	u64 rx_vsi_bytes;
	u64 tx_vsi_unicast_packets;
	u64 tx_vsi_bytes;
	u64 rx_vsi_multicast_packets;
	u64 tx_vsi_multicast_packets;
	u64 rx_vsi_broadcast_packets;
	u64 tx_vsi_broadcast_packets;

	u64 rx_sw_unicast_packets;
	u64 rx_sw_broadcast_packets;
	u64 rx_sw_multicast_packets;
	u64 rx_sw_drop_packets;
	u64 rx_sw_drop_bytes;
};

struct sxe2_vsi_stats {
	struct sxe2_stats        vsi_sw_stats;
	struct sxe2_stats        vsi_sw_stats_prev;
	struct sxe2_stats        vsi_hw_stats;
	struct sxe2_stats        stats;
};

struct sxe2_vsi {
	TAILQ_ENTRY(sxe2_vsi) next;
	struct sxe2_adapter *adapter;
	u16 vsi_id;
	u16 vsi_type;
	struct sxe2_vsi_irqs irqs;
	struct sxe2_queue_info txqs;
	struct sxe2_queue_info rxqs;
	u16 budget;
	struct sxe2_vsi_stats vsi_stats;
};

TAILQ_HEAD(sxe2_vsi_list_head, sxe2_vsi);

struct sxe2_vsi_context {
	u16 func_id;
	u16 dpdk_vsi_id;
	u16 kernel_vsi_id;
	u16 vsi_type;

	u16 bond_member_kernel_vsi_id[SXE2_MAX_BOND_MEMBER_CNT];
	u16 bond_member_dpdk_vsi_id[SXE2_MAX_BOND_MEMBER_CNT];

	struct sxe2_vsi *main_vsi;
};

void sxe2_sw_vsi_ctx_hw_cap_set(struct sxe2_adapter *adapter,
		struct sxe2_drv_vsi_caps *vsi_caps);

s32 sxe2_vsi_init(struct rte_eth_dev *dev);

void sxe2_vsi_uninit(struct rte_eth_dev *dev);

#endif
