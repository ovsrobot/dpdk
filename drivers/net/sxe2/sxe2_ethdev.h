/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */
#ifndef __SXE2_ETHDEV_H__
#define __SXE2_ETHDEV_H__
#include <rte_compat.h>
#include <rte_kvargs.h>
#include <rte_time.h>
#include <ethdev_driver.h>
#include <ethdev_pci.h>
#include <rte_tm_driver.h>
#include <rte_io.h>

#include "sxe2_common.h"
#include "sxe2_errno.h"
#include "sxe2_type.h"
#include "sxe2_vsi.h"
#include "sxe2_queue.h"
#include "sxe2_irq.h"
#include "sxe2_osal.h"

struct sxe2_link_msg {
	__le32 speed;
	u8 status;
};

enum sxe2_fnav_tunnel_flag_type {
	SXE2_FNAV_TUN_FLAG_NO_TUNNEL,
	SXE2_FNAV_TUN_FLAG_TUNNEL,
	SXE2_FNAV_TUN_FLAG_ANY,
};

#define SXE2_VF_MAX_NUM        256
#define SXE2_VSI_MAX_NUM       768
#define SXE2_FRAME_SIZE_MAX    9832
#define SXE2_VLAN_TAG_SIZE     4
#define SXE2_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + SXE2_VLAN_TAG_SIZE * 2)
#define SXE2_ETH_MAX_LEN (RTE_ETHER_MTU + SXE2_ETH_OVERHEAD)

#ifdef SXE2_TEST
#define SXE2_RESET_ACTIVE_WAIT_COUNT   (5)
#else
#define SXE2_RESET_ACTIVE_WAIT_COUNT   (10000)
#endif
#define SXE2_NO_ACTIVE_CNT           (10)

#define SXE2_WOKER_DELAY_5MS         (5)
#define SXE2_WOKER_DELAY_10MS        (10)
#define SXE2_WOKER_DELAY_20MS        (20)
#define SXE2_WOKER_DELAY_30MS        (30)

#define SXE2_RESET_DETEC_WAIT_COUNT    (100)
#define SXE2_RESET_DONE_WAIT_COUNT     (250)
#define SXE2_RESET_WAIT_MS             (10)

#define SXE2_RESET_WAIT_MIN   (10)
#define SXE2_RESET_WAIT_MAX   (20)
#define upper_32_bits(n) ((u32)(((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32)((n) & 0xffffffff))

#define SXE2_I2C_EEPROM_DEV_ADDR	0xA0
#define SXE2_I2C_EEPROM_DEV_ADDR2	0xA2
#define SXE2_MODULE_TYPE_SFP		0x03
#define SXE2_MODULE_TYPE_QSFP_PLUS	0x0D
#define SXE2_MODULE_TYPE_QSFP28	0x11
#define SXE2_MODULE_SFF_ADDR_MODE	0x04
#define SXE2_MODULE_SFF_DIAG_CAPAB	0x40
#define SXE2_MODULE_REVISION_ADDR	0x01
#define SXE2_MODULE_SFF_8472_COMP	0x5E
#define SXE2_MODULE_SFF_8472_SWAP	0x5C
#define SXE2_MODULE_QSFP_MAX_LEN	640
#define SXE2_MODULE_SFF_8472_UNSUP	0x0
#define SXE2_MODULE_SFF_DDM_IMPLEMENTED	0x40
#define SXE2_MODULE_SFF_SFP_TYPE   0x03
#define SXE2_MODULE_TYPE_QSFP_PLUS	0x0D
#define SXE2_MODULE_TYPE_QSFP28	0x11

#define SXE2_MODULE_SFF_8079		0x1
#define SXE2_MODULE_SFF_8079_LEN	256
#define SXE2_MODULE_SFF_8472		0x2
#define SXE2_MODULE_SFF_8472_LEN	512
#define SXE2_MODULE_SFF_8636		0x3
#define SXE2_MODULE_SFF_8636_LEN	256
#define SXE2_MODULE_SFF_8636_MAX_LEN     640
#define SXE2_MODULE_SFF_8436		0x4
#define SXE2_MODULE_SFF_8436_LEN	256
#define SXE2_MODULE_SFF_8436_MAX_LEN     640

enum sxe2_wk_type {
	SXE2_WK_MONITOR,
	SXE2_WK_MONITOR_IM,
	SXE2_WK_POST,
	SXE2_WK_MBX,
};

enum {
	SXE2_FLAG_LEGACY_RX_ENABLE   = 0,
	SXE2_FLAG_LRO_ENABLE = 1,
	SXE2_FLAG_RXQ_DISABLED = 2,
	SXE2_FLAG_TXQ_DISABLED = 3,
	SXE2_FLAG_DRV_REMOVING = 4,
	SXE2_FLAG_RESET_DETECTED = 5,
	SXE2_FLAG_CORE_RESET_DONE = 6,
	SXE2_FLAG_RESET_ACTIVED = 7,
	SXE2_FLAG_RESET_PENDING = 8,
	SXE2_FLAG_RESET_REQUEST = 9,
	SXE2_FLAGS_RESET_PROCESS_DONE = 10,
	SXE2_FLAG_RESET_FAILED = 11,
	SXE2_FLAG_DRV_PROBE_DONE = 12,
	SXE2_FLAG_NETDEV_REGISTED = 13,
	SXE2_FLAG_DRV_UP = 15,
	SXE2_FLAG_DCB_ENABLE = 16,
	SXE2_FLAG_FLTR_SYNC = 17,

	SXE2_FLAG_EVENT_IRQ_DISABLED = 18,
	SXE2_FLAG_SUSPEND = 19,
	SXE2_FLAG_FNAV_ENABLE = 20,

	SXE2_FLAGS_NBITS
};

struct sxe2_link_context {
	rte_spinlock_t link_lock;
	bool link_up;
	u32  speed;
};

struct sxe2_devargs {
	u8 flow_dup_pattern_mode;
	u8 func_flow_direct_en;
	u8 fnav_stat_type;
	u8 high_performance_mode;
	u8 sched_layer_mode;
	u8 sw_stats_en;
	u8 rx_low_latency;
};

#define SXE2_PCI_MAP_BAR_INVALID ((u8)0xff)
#define SXE2_PCI_MAP_INVALID_VAL ((u32)0xffffffff)

enum sxe2_pci_map_resource {
	SXE2_PCI_MAP_RES_INVALID = 0,
	SXE2_PCI_MAP_RES_DOORBELL_TX,
	SXE2_PCI_MAP_RES_DOORBELL_RX_TAIL,
	SXE2_PCI_MAP_RES_IRQ_DYN,
	SXE2_PCI_MAP_RES_IRQ_ITR,
	SXE2_PCI_MAP_RES_IRQ_MSIX,
	SXE2_PCI_MAP_RES_PTP,
	SXE2_PCI_MAP_RES_MAX_COUNT,
};

enum sxe2_udp_tunnel_protocol {
	SXE2_UDP_TUNNEL_PROTOCOL_VXLAN = 0,
	SXE2_UDP_TUNNEL_PROTOCOL_VXLAN_GPE,
	SXE2_UDP_TUNNEL_PROTOCOL_GENEVE,
	SXE2_UDP_TUNNEL_PROTOCOL_GTP_C = 4,
	SXE2_UDP_TUNNEL_PROTOCOL_GTP_U,
	SXE2_UDP_TUNNEL_PROTOCOL_PFCP,
	SXE2_UDP_TUNNEL_PROTOCOL_ECPRI,
	SXE2_UDP_TUNNEL_PROTOCOL_MPLS,
	SXE2_UDP_TUNNEL_PROTOCOL_NVGRE = 10,
	SXE2_UDP_TUNNEL_PROTOCOL_L2TP,
	SXE2_UDP_TUNNEL_PROTOCOL_TEREDO,
	SXE2_UDP_TUNNEL_MAX,
};

struct sxe2_pci_map_addr_info {
	u64 addr_base;
	u8 bar_idx;
	u8 reg_width;
};

struct sxe2_pci_map_segment_info {
	enum sxe2_pci_map_resource	type;
	void __iomem				*addr;
	resource_size_t				page_inner_offset;
	resource_size_t				len;
};

struct sxe2_pci_map_bar_info {
	u8    bar_idx;
	u8    map_cnt;
	struct sxe2_pci_map_segment_info    *seg_info;
};

struct sxe2_pci_map_context {
	u8    bar_cnt;
	struct sxe2_pci_map_bar_info *bar_info;
	struct sxe2_pci_map_addr_info *addr_info;
};

struct sxe2_dev_mac_info {
	u8 perm_addr[ETH_ALEN];
};

struct sxe2_pci_info {
	u64                     serial_number;
	u8                      bus_devid;
	u8                      bus_function;
	u16                     max_vfs;
};

struct sxe2_fw_info {
	u8                      main_version_id;
	u8                      sub_version_id;
	u8                      fix_version_id;
	u8                      build_id;
};

struct sxe2_dev_info {
	struct rte_eth_dev_data        *dev_data;
	struct sxe2_pci_info           pci;
	struct sxe2_fw_info            fw;
	struct sxe2_dev_mac_info       mac;
};

enum sxe2_udp_tunnel_status {
	SXE2_UDP_TUNNEL_DISABLE = 0x0,
	SXE2_UDP_TUNNEL_ENABLE,
};

struct sxe2_udp_tunnel_cfg {
	u8			protocol;
	u8			dev_status;
	u16			dev_port;
	u16			dev_ref_cnt;

	u16			fw_port;
	u8			fw_status;
	u8			fw_dst_en;
	u8			fw_src_en;
	u8			fw_used;
};

struct sxe2_udp_tunnel_ctx {
	struct sxe2_udp_tunnel_cfg   tunnel_conf[SXE2_UDP_TUNNEL_MAX];
	rte_spinlock_t                lock;
};

struct sxe2_repr_context {
	u16 nb_vf;
	u16 nb_repr_vf;
	struct rte_eth_dev **vf_rep_eth_dev;
	struct sxe2_drv_vsi_caps repr_vf_id[SXE2_VF_MAX_NUM];
};

struct sxe2_repr_private_data {
	struct rte_eth_dev *rep_eth_dev;
	struct sxe2_adapter *parent_adapter;

	struct sxe2_vsi *cp_vsi;
	u16 repr_q_id;

	u16 repr_id;
	u16 repr_pf_id;
	u16 repr_vf_id;
	u16 repr_vf_vsi_id;
	u16 repr_vf_k_vsi_id;
	u16 repr_vf_u_vsi_id;
};

struct sxe2_sched_hw_cap {
	u32 tm_layers;
	u8 root_max_children;
	u8 prio_max;
	u8 adj_lvl;
};

struct sxe2_adapter {
	struct sxe2_common_device      *cdev;
	struct sxe2_dev_info            dev_info;
	struct rte_pci_device            *pci_dev;
	struct sxe2_repr_private_data  *repr_priv_data;
	struct sxe2_pci_map_context   map_ctxt;
	struct sxe2_irq_context       irq_ctxt;
	struct sxe2_queue_context     q_ctxt;
	struct sxe2_vsi_context       vsi_ctxt;
	struct sxe2_devargs			  devargs;
	u16                           dev_port_id;
	u64                           cap_flags;
	enum sxe2_dev_type            dev_type;
	u32    ptype_tbl[SXE2_MAX_PTYPE_NUM];
	struct rte_ether_addr           mac_addr;
	u8                              port_idx;
	u8                              pf_idx;
	u32                             tx_mode_flags;
	u32                             rx_mode_flags;
	u8                              started;
};

#define SXE2_DEV_PRIVATE_TO_ADAPTER(dev) \
	((struct sxe2_adapter *)(dev)->data->dev_private)

#define SXE2_DEV_TO_PCI(eth_dev) \
		RTE_DEV_TO_PCI((eth_dev)->device)

void __iomem *sxe2_pci_map_addr_get(struct sxe2_adapter *adapter,
		enum sxe2_pci_map_resource res_type, u16 idx_in_func);

struct sxe2_pci_map_bar_info *sxe2_dev_get_bar_info(struct sxe2_adapter *adapter,
		enum sxe2_pci_map_resource res_type);

s32 sxe2_dev_pci_seg_map(struct sxe2_adapter *adapter,
		enum sxe2_pci_map_resource res_type, u64 org_len, u64 org_offset);

s32 sxe2_dev_pci_res_seg_map(struct sxe2_adapter *adapter, u32 res_type,
		u32 item_cnt, u32 item_base);

void sxe2_dev_pci_seg_unmap(struct sxe2_adapter *adapter, u32 res_type);

s32 sxe2_dev_pci_map_init(struct rte_eth_dev *dev);

void sxe2_dev_pci_map_uinit(struct rte_eth_dev *dev);

#endif
