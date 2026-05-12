/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_DRV_CMD_H__
#define __SXE2_DRV_CMD_H__

#include "sxe2_type.h"
#define SXE2_DPDK_RESOURCE_INSUFFICIENT

#define SXE2_DRV_CMD_MODULE_S        (16)
#define SXE2_MK_DRV_CMD(module, cmd) (((module) << SXE2_DRV_CMD_MODULE_S) | ((cmd) & 0xFFFF))

#define SXE2_DEV_CAPS_OFFLOAD_L2    BIT(0)
#define SXE2_DEV_CAPS_OFFLOAD_VLAN  BIT(1)
#define SXE2_DEV_CAPS_OFFLOAD_RSS   BIT(2)
#define SXE2_DEV_CAPS_OFFLOAD_IPSEC BIT(3)
#define SXE2_DEV_CAPS_OFFLOAD_FNAV  BIT(4)
#define SXE2_DEV_CAPS_OFFLOAD_TM    BIT(5)
#define SXE2_DEV_CAPS_OFFLOAD_PTP   BIT(6)
#define SXE2_DEV_CAPS_OFFLOAD_Q_MAP BIT(7)
#define SXE2_DEV_CAPS_OFFLOAD_FC_STATE BIT(8)

#define SXE2_TXQ_STATS_MAP_MAX_NUM 16
#define SXE2_RXQ_STATS_MAP_MAX_NUM 4
#define SXE2_RXQ_MAP_Q_MAX_NUM 256

#define SXE2_STAT_MAP_INVALID_QID 0xFFFF

#define SXE2_SCHED_MODE_DEFAULT				0
#define SXE2_SCHED_MODE_TM					1
#define SXE2_SCHED_MODE_HIGH_PERFORMANCE	2
#define SXE2_SCHED_MODE_INVALID				3

#define SXE2_SRCVSI_PRUNE_MAX_NUM			2

#define SXE2_PTYPE_UNKNOWN                   BIT(0)
#define SXE2_PTYPE_L2_ETHER                  BIT(1)
#define SXE2_PTYPE_L3_IPV4                   BIT(2)
#define SXE2_PTYPE_L3_IPV6                   BIT(4)
#define SXE2_PTYPE_L4_TCP                    BIT(6)
#define SXE2_PTYPE_L4_UDP                    BIT(7)
#define SXE2_PTYPE_L4_SCTP                   BIT(8)
#define SXE2_PTYPE_INNER_L2_ETHER            BIT(9)
#define SXE2_PTYPE_INNER_L3_IPV4             BIT(10)
#define SXE2_PTYPE_INNER_L3_IPV6             BIT(12)
#define SXE2_PTYPE_INNER_L4_TCP              BIT(14)
#define SXE2_PTYPE_INNER_L4_UDP              BIT(15)
#define SXE2_PTYPE_INNER_L4_SCTP             BIT(16)
#define SXE2_PTYPE_TUNNEL_GRENAT             BIT(17)

#define SXE2_PTYPE_L2_MASK       (SXE2_PTYPE_L2_ETHER)
#define SXE2_PTYPE_L3_MASK       (SXE2_PTYPE_L3_IPV4 | SXE2_PTYPE_L3_IPV6)
#define SXE2_PTYPE_L4_MASK       (SXE2_PTYPE_L4_TCP | SXE2_PTYPE_L4_UDP | \
		SXE2_PTYPE_L4_SCTP)
#define SXE2_PTYPE_INNER_L2_MASK (SXE2_PTYPE_INNER_L2_ETHER)
#define SXE2_PTYPE_INNER_L3_MASK (SXE2_PTYPE_INNER_L3_IPV4 | \
		SXE2_PTYPE_INNER_L3_IPV6)
#define SXE2_PTYPE_INNER_L4_MASK (SXE2_PTYPE_INNER_L4_TCP | \
		SXE2_PTYPE_INNER_L4_UDP | \
		SXE2_PTYPE_INNER_L4_SCTP)
#define SXE2_PTYPE_TUNNEL_MASK   (SXE2_PTYPE_TUNNEL_GRENAT)

enum sxe2_dev_type {
	SXE2_DEV_T_PF = 0,
	SXE2_DEV_T_VF,
	SXE2_DEV_T_PF_BOND,
	SXE2_DEV_T_MAX,
};

struct sxe2_drv_queue_caps {
	__le16 queues_cnt;
	__le16 base_idx_in_pf;
};

struct sxe2_drv_msix_caps {
	__le16 msix_vectors_cnt;
	__le16 base_idx_in_func;
};

struct sxe2_drv_rss_hash_caps {
	__le16 hash_key_size;
	__le16 lut_key_size;
};

enum sxe2_vf_vsi_valid {
	SXE2_VF_VSI_BOTH = 0,
	SXE2_VF_VSI_ONLY_DPDK,
	SXE2_VF_VSI_ONLY_KERNEL,
	SXE2_VF_VSI_MAX,
};

struct sxe2_drv_vsi_caps {
	__le16 func_id;
	__le16 dpdk_vsi_id;
	__le16 kernel_vsi_id;
	__le16 vsi_type;
};

struct sxe2_drv_representor_caps {
	__le16 cnt_repr_vf;
	u8 rsv[2];
	struct sxe2_drv_vsi_caps repr_vf_id[256];
};

enum sxe2_phys_port_name_type {
	SXE2_PHYS_PORT_NAME_TYPE_NOTSET = 0,
	SXE2_PHYS_PORT_NAME_TYPE_LEGACY,
	SXE2_PHYS_PORT_NAME_TYPE_UPLINK,
	SXE2_PHYS_PORT_NAME_TYPE_PFVF,

	SXE2_PHYS_PORT_NAME_TYPE_UNKNOWN,
};

struct sxe2_switchdev_mode_info {
	u8 pf_id;
	u8 is_switchdev;
	u8 rsv[2];
};

struct sxe2_switchdev_cpvsi_info {
	__le16 cp_vsi_id;
	u8 rsv[2];
};

struct sxe2_txsch_caps {
	u8 layer_cap;
	u8 tm_mid_node_num;
	u8 prio_num;
	u8 rev;
};

struct sxe2_drv_dev_caps_resp {
	struct sxe2_drv_queue_caps queue_caps;
	struct sxe2_drv_msix_caps msix_caps;
	struct sxe2_drv_rss_hash_caps rss_hash_caps;
	struct sxe2_drv_vsi_caps vsi_caps;
	struct sxe2_txsch_caps   txsch_caps;
	struct sxe2_drv_representor_caps repr_caps;
	u8 port_idx;
	u8 pf_idx;
	u8 dev_type;
	u8 rev;
	__le32 cap_flags;
};

struct sxe2_drv_dev_info_resp {
	__le64 dsn;
	__le16 vsi_id;
	u8 rsv[2];
	u8 mac_addr[ETH_ALEN];
	u8 rsv2[2];
};

struct sxe2_drv_dev_fw_info_resp {
	u8 main_version_id;
	u8 sub_version_id;
	u8 fix_version_id;
	u8 build_id;
};

struct sxe2_drv_rxq_ctxt {
	__le64 dma_addr;
	__le32 max_lro_size;
	__le32 split_type_mask;
	__le16 hdr_len;
	__le16 buf_len;
	__le16 depth;
	__le16 queue_id;
	u8 lro_en;
	u8 keep_crc_en;
	u8 split_en;
	u8 desc_size;
};

struct sxe2_drv_rxq_cfg_req {
	__le16 q_cnt;
	__le16 vsi_id;
	__le16 max_frame_size;
	u8 rsv[2];
	struct sxe2_drv_rxq_ctxt cfg[];
};

struct sxe2_drv_txq_ctxt {
	__le64 dma_addr;
	__le32 sched_mode;
	__le16 queue_id;
	__le16 depth;
	__le16 vsi_id;
	u8 rsv[2];
};

struct sxe2_drv_txq_cfg_req {
	__le16 q_cnt;
	__le16 vsi_id;
	struct sxe2_drv_txq_ctxt cfg[];
};

struct sxe2_drv_q_switch_req {
	__le16 q_idx;
	__le16 vsi_id;
	u8 is_enable;
	u8 sched_mode;
	u8 rsv[2];
};

struct sxe2_drv_vsi_create_req_resp {
	__le16 vsi_id;
	__le16 vsi_type;
	struct sxe2_drv_queue_caps used_queues;
	struct sxe2_drv_msix_caps used_msix;
};

struct sxe2_drv_vsi_free_req {
	__le16 vsi_id;
	u8 rsv[2];
};

struct sxe2_drv_vsi_info_get_req {
	__le16 vsi_id;
	u8 rsv[2];
};

struct sxe2_drv_vsi_info_get_resp {
	__le16 vsi_id;
	__le16 vsi_type;
	struct sxe2_drv_queue_caps used_queues;
	struct sxe2_drv_msix_caps used_msix;
};

enum sxe2_drv_cmd_module {
	SXE2_DRV_CMD_MODULE_HANDSHAKE = 0,
	SXE2_DRV_CMD_MODULE_DEV = 1,
	SXE2_DRV_CMD_MODULE_VSI = 2,
	SXE2_DRV_CMD_MODULE_QUEUE = 3,
	SXE2_DRV_CMD_MODULE_STATS = 4,
	SXE2_DRV_CMD_MODULE_SUBSCRIBE = 5,
	SXE2_DRV_CMD_MODULE_RSS = 6,
	SXE2_DRV_CMD_MODULE_FLOW = 7,
	SXE2_DRV_CMD_MODULE_TM = 8,
	SXE2_DRV_CMD_MODULE_IPSEC = 9,
	SXE2_DRV_CMD_MODULE_PTP = 10,

	SXE2_DRV_CMD_MODULE_VLAN = 11,
	SXE2_DRV_CMD_MODULE_RDMA = 12,
	SXE2_DRV_CMD_MODULE_LINK = 13,
	SXE2_DRV_CMD_MODULE_MACADDR = 14,
	SXE2_DRV_CMD_MODULE_PROMISC = 15,

	SXE2_DRV_CMD_MODULE_LED = 16,
	SXE2_DEV_CMD_MODULE_OPT = 17,
	SXE2_DEV_CMD_MODULE_SWITCH = 18,
	SXE2_DRV_CMD_MODULE_ACL = 19,
	SXE2_DRV_CMD_MODULE_UDPTUNEEL = 20,
	SXE2_DRV_CMD_MODULE_QUEUE_MAP = 21,

	SXE2_DRV_CMD_MODULE_SCHED = 22,

	SXE2_DRV_CMD_MODULE_IRQ = 23,

	SXE2_DRV_CMD_MODULE_OPT = 24,
};

enum sxe2_drv_cmd_code {
	SXE2_DRV_CMD_HANDSHAKE_ENABLE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_HANDSHAKE, 1),
	SXE2_DRV_CMD_HANDSHAKE_DISABLE,

	SXE2_DRV_CMD_DEV_GET_CAPS =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_DEV, 1),
	SXE2_DRV_CMD_DEV_GET_INFO,
	SXE2_DRV_CMD_DEV_GET_FW_INFO,
	SXE2_DRV_CMD_DEV_RESET,
	SXE2_DRV_CMD_DEV_GET_SWITCHDEV_INFO,

	SXE2_DRV_CMD_VSI_CREATE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_VSI, 1),
	SXE2_DRV_CMD_VSI_FREE,
	SXE2_DRV_CMD_VSI_INFO_GET,
	SXE2_DRV_CMD_VSI_SRCVSI_PRUNE,
	SXE2_DRV_CMD_VSI_FC_GET,

	SXE2_DRV_CMD_RX_MAP_SET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_QUEUE_MAP, 1),
	SXE2_DRV_CMD_TX_MAP_SET,
	SXE2_DRV_CMD_TX_RX_MAP_GET,
	SXE2_DRV_CMD_TX_RX_MAP_RESET,
	SXE2_DRV_CMD_TX_RX_MAP_INFO_CLEAR,

	SXE2_DRV_CMD_SCHED_ROOT_TREE_ALLOC =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_SCHED, 1),
	SXE2_DRV_CMD_SCHED_ROOT_TREE_RELEASE,
	SXE2_DRV_CMD_SCHED_ROOT_CHILDREN_DELETE,
	SXE2_DRV_CMD_SCHED_TM_ADD_MID_NODE,
	SXE2_DRV_CMD_SCHED_TM_ADD_QUEUE_NODE,

	SXE2_DRV_CMD_RXQ_CFG_ENABLE =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_QUEUE, 1),
	SXE2_DRV_CMD_TXQ_CFG_ENABLE,
	SXE2_DRV_CMD_RXQ_DISABLE,
	SXE2_DRV_CMD_TXQ_DISABLE,

	SXE2_DRV_CMD_VSI_STATS_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_STATS, 1),
	SXE2_DRV_CMD_VSI_STATS_CLEAR,
	SXE2_DRV_CMD_MAC_STATS_GET,
	SXE2_DRV_CMD_MAC_STATS_CLEAR,

	SXE2_DRV_CMD_RSS_KEY_SET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_RSS, 1),
	SXE2_DRV_CMD_RSS_LUT_SET,
	SXE2_DRV_CMD_RSS_FUNC_SET,
	SXE2_DRV_CMD_RSS_HF_ADD,
	SXE2_DRV_CMD_RSS_HF_DEL,
	SXE2_DRV_CMD_RSS_HF_CLEAR,

	SXE2_DRV_CMD_FLOW_FILTER_ADD =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_FLOW, 1),
	SXE2_DRV_CMD_FLOW_FILTER_DEL,
	SXE2_DRV_CMD_FLOW_FILTER_CLEAR,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_ALLOC,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_FREE,
	SXE2_DRV_CMD_FLOW_FNAV_STAT_QUERY,

	SXE2_DRV_CMD_DEL_TM_ROOT =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_TM, 1),
	SXE2_DRV_CMD_ADD_TM_ROOT,
	SXE2_DRV_CMD_ADD_TM_NODE,
	SXE2_DRV_CMD_ADD_TM_QUEUE,

	SXE2_DRV_CMD_GET_PTP_CLOCK =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_PTP, 1),

	SXE2_DRV_CMD_VLAN_FILTER_ADD_DEL =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_VLAN, 1),
	SXE2_DRV_CMD_VLAN_FILTER_SWITCH,
	SXE2_DRV_CMD_VLAN_OFFLOAD_CFG,
	SXE2_DRV_CMD_VLAN_PORTVLAN_CFG,
	SXE2_DRV_CMD_VLAN_CFG_QUERY,

	SXE2_DRV_CMD_RDMA_DUMP_PCAP =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_RDMA, 1),

	SXE2_DRV_CMD_LINK_STATUS_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_LINK, 1),

	SXE2_DRV_CMD_MAC_ADDR_UC =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_MACADDR, 1),
	SXE2_DRV_CMD_MAC_ADDR_MC,

	SXE2_DRV_CMD_PROMISC_CFG =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_PROMISC, 1),
	SXE2_DRV_CMD_ALLMULTI_CFG,

	SXE2_DRV_CMD_LED_CTRL =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_LED, 1),

	SXE2_DRV_CMD_OPT_EEP =
		SXE2_MK_DRV_CMD(SXE2_DEV_CMD_MODULE_OPT, 1),

	SXE2_DRV_CMD_SWITCH =
		SXE2_MK_DRV_CMD(SXE2_DEV_CMD_MODULE_SWITCH, 1),
	SXE2_DRV_CMD_SWITCH_UPLINK,
	SXE2_DRV_CMD_SWITCH_REPR,
	SXE2_DRV_CMD_SWITCH_MODE,
	SXE2_DRV_CMD_SWITCH_CPVSI,

	SXE2_DRV_CMD_UDPTUNNEL_ADD =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_UDPTUNEEL, 1),
	SXE2_DRV_CMD_UDPTUNNEL_DEL,
	SXE2_DRV_CMD_UDPTUNNEL_GET,

	SXE2_DRV_CMD_IPSEC_CAP_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_IPSEC, 1),
	SXE2_DRV_CMD_IPSEC_TXSA_ADD,
	SXE2_DRV_CMD_IPSEC_RXSA_ADD,
	SXE2_DRV_CMD_IPSEC_TXSA_DEL,
	SXE2_DRV_CMD_IPSEC_RXSA_DEL,
	SXE2_DRV_CMD_IPSEC_RESOURCE_CLEAR,

	SXE2_DRV_CMD_EVT_IRQ_BAND_RXQ =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_IRQ, 1),

	SXE2_DRV_CMD_OPT_EEP_GET =
		SXE2_MK_DRV_CMD(SXE2_DRV_CMD_MODULE_OPT, 1),

};

#endif
