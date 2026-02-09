/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_VF_H__
#define __SXE_VF_H__

#include <rte_ethdev.h>
#include <bus_pci_driver.h>

#include "sxe_hw.h"

#define SXE_MIRROR_RULES_MAX   4

#define SXE_MSG_NUM(size)		 DIV_ROUND_UP(size, 4)

#define SXE_MSGTYPE_ACK	0x80000000
#define SXE_MSGTYPE_NACK   0x40000000

#define SXE_VFREQ_RESET			   0x01
#define SXE_VFREQ_MAC_ADDR_SET		0x02
#define SXE_VFREQ_MC_ADDR_SYNC		0x03
#define SXE_VFREQ_VLAN_SET			0x04
#define SXE_VFREQ_LPE_SET			 0x05

#define SXE_VFREQ_UC_ADDR_SYNC		0x06

#define SXE_VFREQ_API_NEGOTIATE	   0x08

#define SXE_VFREQ_RING_INFO_GET	   0x09
#define SXE_VFREQ_REDIR_TBL_GET	   0x0a
#define SXE_VFREQ_RSS_KEY_GET		 0x0b
#define SXE_VFREQ_CAST_MODE_SET	   0x0c
#define SXE_VFREQ_LINK_ENABLE_GET	 0X0d
#define SXE_VFREQ_IPSEC_ADD		   0x0e
#define SXE_VFREQ_IPSEC_DEL		   0x0f
#define SXE_VFREQ_RSS_CONF_GET		0x10

#define SXE_VFREQ_MASK				0xFF

#define SXE_MIRROR_TYPE_INVALID(mirror_type) \
	((mirror_type) & ~(u8)(ETH_MIRROR_VIRTUAL_POOL_UP | \
	ETH_MIRROR_UPLINK_PORT | ETH_MIRROR_DOWNLINK_PORT | ETH_MIRROR_VLAN))

#define SXE_ETH_MIRROR_TYPE_MASK \
			(ETH_MIRROR_VIRTUAL_POOL_UP | ETH_MIRROR_UPLINK_PORT \
			| ETH_MIRROR_DOWNLINK_PORT | ETH_MIRROR_VLAN)

static inline u16 sxe_vf_num_get(struct rte_eth_dev *eth_dev)
{
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);

	return pci_dev->max_vfs;
}

enum sxe_mbx_api_version {
	SXE_MBX_API_10 = 0,
	SXE_MBX_API_11,
	SXE_MBX_API_12,
	SXE_MBX_API_13,
	SXE_MBX_API_14,

	SXE_MBX_API_NR,
};

enum sxe_cast_mode {
	SXE_CAST_MODE_NONE = 0,
	SXE_CAST_MODE_MULTI,
	SXE_CAST_MODE_ALLMULTI,
	SXE_CAST_MODE_PROMISC,
};

struct sxe_vf_info {
	u8 mac_addr[RTE_ETHER_ADDR_LEN];
	u16 mc_hash[SXE_VF_MC_ENTRY_NUM_MAX];
	u8  mc_hash_used;
	u8 cast_mode;
	u8  trusted :1;
	u8  is_ready :1;
	u8  spoof_chk_enabled :1;
	u8  rss_query_enabled :1;
	u8  mac_from_pf :1;
	u8  reserved :3;
	u16 domain_id;
	u16 tx_rate;
	u32 mbx_version;
	u32 vlan_cnt;
	u32 uc_mac_cnt;
	u8 uc_mac_table[SXE_UC_ENTRY_NUM_MAX];
};

struct sxe_virtual_context {
	u8  pflink_fullchk;
	u8  promisc_cnt;
	u32 mbx_version;
	struct sxe_vf_info *vf_info;
};

struct sxe_msg_table {
	u32 msg_type;
	s32 (*msg_func)(struct rte_eth_dev *dev, u32 *msg, u32 vf_idx);
};

enum RTE_PMD_SXE_MB_event_rsp {
	RTE_PMD_SXE_MB_EVENT_NOOP_ACK,
	RTE_PMD_SXE_MB_EVENT_NOOP_NACK,
	RTE_PMD_SXE_MB_EVENT_PROCEED,
	RTE_PMD_SXE_MB_EVENT_MAX
};

struct rte_pmd_sxe_mb_event_param {
	u16 vf_idx;
	u16 msg_type;
	u16 ret;
	void *msg;
};

struct sxe_mbx_api_msg {
	u32 msg_type;
	u32 api_version;
};

struct sxe_uc_addr_msg {
	u32 msg_type;
	u8 uc_addr[RTE_ETHER_ADDR_LEN];
	u16 pad;
};

struct sxe_rst_rcv {
	u32 msg_type;
};

struct sxe_rst_reply {
	u32 msg_type;
	u32 mac_addr[2];
	u32 mc_filter_type;
};

struct sxe_rst_msg {
	union {
		struct sxe_rst_rcv rcv;
		struct sxe_rst_reply reply;
	};
};

struct sxe_ring_info_msg {
	u32 msg_type;
	u8  max_rx_num;
	u8  max_tx_num;
	u8  tc_num;
	u8  default_tc;
};

struct sxe_rss_hash_msg {
	u32 msg_type;
	u8  hash_key[SXE_RSS_KEY_SIZE];
	u64 rss_hf;
};

struct sxe_vlan_msg {
	u16 msg_type;
	u16 add;
	u32 vlan_id;
};

struct sxe_mc_sync_msg {
	u16 msg_type;
	u16 mc_cnt;
	u16 mc_addr_extract[SXE_VF_MC_ENTRY_NUM_MAX];
};

struct sxe_cast_mode_msg {
	u32 msg_type;
	u32 cast_mode;
};

struct sxe_uc_sync_msg {
	u16 msg_type;
	u16 index;
	u32 addr[2];
};

struct sxe_max_frame_msg {
	u32 msg_type;
	u32 max_frame;
};

s32 sxe_vt_init(struct rte_eth_dev *eth_dev);

void sxe_vt_configure(struct rte_eth_dev *eth_dev);

void sxe_vt_uninit(struct rte_eth_dev *eth_dev);

s32 sxe_vf_rss_configure(struct rte_eth_dev *dev);

s32 sxe_vf_default_mode_configure(struct rte_eth_dev *dev);

void sxe_mbx_irq_handler(struct rte_eth_dev *eth_dev);

#endif
