/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2023 Mucse IC Design Ltd.
 */
#ifndef __RNP_H__
#define __RNP_H__
#include <rte_log.h>

#include "base/rnp_hw.h"

#define PCI_VENDOR_ID_MUCSE	(0x8848)
#define RNP_DEV_ID_N10G		(0x1000)
#define RNP_DEV_ID_N400L_X4	(0x1021)
#define RNP_MAX_PORT_OF_PF	(4)
#define RNP_CFG_BAR		(4)
#define RNP_PF_INFO_BAR		(0)

/* Peer Port Own Independent Resource */
#define RNP_PORT_MAX_MACADDR         (32)
#define RNP_PORT_MAX_UC_MAC_SIZE     (256)
#define RNP_PORT_MAX_VLAN_HASH       (12)
#define RNP_PORT_MAX_UC_HASH_TB      (8)

/* Hardware Resource info */
#define RNP_MAX_RX_QUEUE_NUM         (128)
#define RNP_MAX_TX_QUEUE_NUM         (128)
#define RNP_N400_MAX_RX_QUEUE_NUM    (8)
#define RNP_N400_MAX_TX_QUEUE_NUM    (8)
#define RNP_MAX_HASH_KEY_SIZE        (10)
#define RNP_MAX_MAC_ADDRS            (128)
#define RNP_MAX_SUPPORT_VF_NUM       (64)
#define RNP_MAX_VFTA_SIZE            (128)
#define RNP_MAX_TC_SUPPORT           (4)

#define RNP_MAX_UC_MAC_SIZE          (4096) /* Max Num of Unicast MAC addr */
#define RNP_MAX_UC_HASH_TB           (128)
#define RNP_MAX_MC_MAC_SIZE          (4096) /* Max Num of Multicast MAC addr */
#define RNP_MAC_MC_HASH_TB           (128)
#define RNP_MAX_VLAN_HASH_TB_SIZE    (4096)

#define RNP_MAX_UC_HASH_TABLE        (128)
#define RNP_MAC_MC_HASH_TABLE        (128)
#define RNP_UTA_BIT_SHIFT            (5)

enum rnp_resource_share_m {
	RNP_SHARE_CORPORATE = 0,
	RNP_SHARE_INDEPENDENT,
};

/* media type */
enum rnp_media_type {
	RNP_MEDIA_TYPE_UNKNOWN,
	RNP_MEDIA_TYPE_FIBER,
	RNP_MEDIA_TYPE_COPPER,
	RNP_MEDIA_TYPE_BACKPLANE,
	RNP_MEDIA_TYPE_NONE,
};

struct rnp_phy_meta {
	uint16_t phy_type;
	uint32_t speed_cap;
	uint32_t supported_link;
	uint16_t link_duplex;
	uint16_t link_autoneg;
	uint8_t media_type;
	bool is_sgmii;
	bool is_backplane;
	bool fec;
	uint32_t phy_identifier;
};

struct rnp_port_attr {
	uint16_t max_mac_addrs;   /* Max Support Mac Address */
	uint16_t uc_hash_tb_size; /* Unicast Hash Table Size */
	uint16_t max_uc_mac_hash; /* Max Num of hash MAC addr for UC */
	uint16_t mc_hash_tb_size; /* Multicast Hash Table Size */
	uint16_t max_mc_mac_hash; /* Max Num Of Hash Mac addr For MC */
	uint16_t max_vlan_hash;   /* Max Num Of Hash For Vlan ID*/
	uint32_t hash_table_shift;
	uint16_t rte_pid;         /* Dpdk Manage Port Sequence Id */
	uint8_t max_rx_queues;    /* Belong To This Port Rxq Resource */
	uint8_t max_tx_queues;    /* Belong To This Port Rxq Resource */
	uint8_t queue_ring_base;
	uint8_t port_offset;      /* Use For Redir Table Dma Ring Offset Of Port */
	union {
		uint8_t nr_lane; /* phy lane of This PF:0~3 */
		uint8_t nr_port; /* phy lane of This PF:0~3 */
	};
	struct rnp_phy_meta phy_meta;
	bool link_ready;
	bool pre_link;
	uint32_t speed;
	uint16_t max_rx_pktlen;   /* Current Port Max Support Packet Len */
	uint16_t max_mtu;
};

/*
 * Structure to store private data for each driver instance (for each port).
 */
enum rnp_work_mode {
	RNP_SINGLE_40G = 0,
	RNP_SINGLE_10G = 1,
	RNP_DUAL_10G = 2,
	RNP_QUAD_10G = 3,
};

struct rnp_eth_port {
	struct rnp_eth_adapter *adapt;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
	struct rnp_hw *hw;
	uint8_t rx_func_sec; /* force set io rx_func */
	uint8_t tx_func_sec; /* force set io tx func */
	struct rte_eth_dev *eth_dev;
	struct rnp_port_attr attr;
	uint64_t state;
	rte_spinlock_t rx_mac_lock; /* Lock For Mac_cfg resource write */
	/* Recvice Mac Address Record Table */
	uint8_t mac_use_tb[RNP_MAX_MAC_ADDRS];
	uint8_t use_num_mac;
	bool port_stopped;
	bool port_closed;
	enum rnp_resource_share_m s_mode; /* Independent Port Resource */
} __rte_cache_aligned;

struct rnp_share_ops {
	const struct rnp_mbx_api *mbx_api;
	const struct rnp_mac_api *mac_api;
} __rte_cache_aligned;

enum {
	RNP_IO_FUNC_USE_NONE = 0,
	RNP_IO_FUNC_USE_VEC,
	RNP_IO_FUNC_USE_SIMPLE,
	RNP_IO_FUNC_USE_COMMON,
};

enum rnp_port_state {
	RNP_PORT_STATE_PAUSE = 0,
	RNP_PORT_STATE_FINISH,
	RNP_PORT_STATE_SETTING,
};

struct rnp_eth_adapter {
	enum rnp_work_mode mode;
	enum rnp_resource_share_m s_mode; /* Port Resource Share Policy */
	struct rnp_hw hw;
	uint16_t max_vfs;
	struct rte_pci_device *pdev;
	struct rte_eth_dev *eth_dev; /* primary eth_dev */
	struct rnp_eth_port *ports[RNP_MAX_PORT_OF_PF];
	struct rnp_share_ops *share_priv;

	int max_link_speed;
	uint8_t num_ports; /* Cur Pf Has physical Port Num */
	uint8_t lane_mask;

	uint8_t rx_func_sec; /* force set io rx_func */
	uint8_t tx_func_sec; /* force set io tx func*/
	/*fw-update*/
	bool  do_fw_update;
	char *fw_path;

	bool loopback_en;
	bool fw_sfp_10g_1g_auto_det;
	int fw_force_speed_1g;
#define FOCE_SPEED_1G_NOT_SET	(-1)
#define FOCE_SPEED_1G_DISABLED	(0)
#define FOCE_SPEED_1G_ENABLED	(1)
} __rte_cache_aligned;

#define RNP_DEV_TO_PORT(eth_dev) \
	(((struct rnp_eth_port *)((eth_dev)->data->dev_private)))
#define RNP_DEV_TO_ADAPTER(eth_dev) \
	((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT(eth_dev)->adapt))
#define RNP_DEV_TO_HW(eth_dev) \
	(&((struct rnp_eth_adapter *)(RNP_DEV_TO_PORT((eth_dev))->adapt))->hw)
#define RNP_HW_TO_ADAPTER(hw) \
	((struct rnp_eth_adapter *)((hw)->back))
#define RNP_PORT_TO_HW(port) \
	(&(((struct rnp_eth_adapter *)(port)->adapt)->hw))
#define RNP_PORT_TO_ADAPTER(port) \
	((struct rnp_eth_adapter *)((port)->adapt))
#define RNP_DEV_PP_PRIV_TO_MBX_OPS(dev) \
	(((struct rnp_share_ops *)(dev)->process_private)->mbx_api)
#define RNP_DEV_TO_MBX_OPS(dev)	RNP_DEV_PP_PRIV_TO_MBX_OPS(dev)
#define RNP_DEV_PP_PRIV_TO_MAC_OPS(dev) \
	(((struct rnp_share_ops *)(dev)->process_private)->mac_api)
#define RNP_DEV_TO_MAC_OPS(dev) RNP_DEV_PP_PRIV_TO_MAC_OPS(dev)

static inline void rnp_reg_offset_init(struct rnp_hw *hw)
{
	uint16_t i;

	if (hw->device_id == RNP_DEV_ID_N10G && hw->mbx.pf_num) {
		hw->iobar4 = (void *)((uint8_t *)hw->iobar4 + 0x100000);
		hw->msix_base = (void *)((uint8_t *)hw->iobar4 + 0xa4000);
		hw->msix_base = (void *)((uint8_t *)hw->msix_base + 0x200);
	} else {
		hw->msix_base = (void *)((uint8_t *)hw->iobar4 + 0xa4000);
	}
	/* === dma status/config====== */
	hw->dev_version = (void *)((uint8_t *)hw->iobar4 + 0x0000);
	hw->link_sync = (void *)((uint8_t *)hw->iobar4 + 0x000c);
	hw->dma_axi_en = (void *)((uint8_t *)hw->iobar4 + 0x0010);
	hw->dma_axi_st = (void *)((uint8_t *)hw->iobar4 + 0x0014);

	if (hw->mbx.pf_num)
		hw->msix_base = (void *)((uint8_t *)0x200);
	/* === queue registers === */
	hw->dma_base = (void *)((uint8_t *)hw->iobar4 + 0x08000);
	hw->veb_base = (void *)((uint8_t *)hw->iobar4 + 0x0);
	hw->eth_base = (void *)((uint8_t *)hw->iobar4 + 0x10000);
	/* mac */
	for (i = 0; i < RNP_MAX_HW_PORT_PERR_PF; i++)
		hw->mac_base[i] = (void *)((uint8_t *)hw->iobar4 + 0x60000 + 0x10000 * i);
	/* ===  top reg === */
	hw->comm_reg_base = (void *)((uint8_t *)hw->iobar4 + 0x30000);
}
#endif /* __RNP_H__ */
