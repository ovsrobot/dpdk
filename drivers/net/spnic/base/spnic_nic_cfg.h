/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_NIC_CFG_H_
#define _SPNIC_NIC_CFG_H_

#ifndef ETH_ALEN
#define ETH_ALEN			6
#endif

#define OS_VF_ID_TO_HW(os_vf_id) ((os_vf_id) + 1)
#define HW_VF_ID_TO_OS(hw_vf_id) ((hw_vf_id) - 1)

#define SPNIC_VLAN_PRIORITY_SHIFT	13

#define SPNIC_DCB_UP_MAX		0x8

#define SPNIC_MAX_NUM_RQ		256

#define SPNIC_MAX_MTU_SIZE		9600
#define SPNIC_MIN_MTU_SIZE		384

#define SPNIC_COS_NUM_MAX		8

#define SPNIC_VLAN_TAG_SIZE		4
#define SPNIC_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + SPNIC_VLAN_TAG_SIZE * 2)

#define SPNIC_MIN_FRAME_SIZE (SPNIC_MIN_MTU_SIZE + SPNIC_ETH_OVERHEAD)
#define SPNIC_MAX_JUMBO_FRAME_SIZE (SPNIC_MAX_MTU_SIZE + SPNIC_ETH_OVERHEAD)

#define SPNIC_MTU_TO_PKTLEN(mtu)	((mtu) + SPNIC_ETH_OVERHEAD)

#define SPNIC_PKTLEN_TO_MTU(pktlen)	((pktlen) - SPNIC_ETH_OVERHEAD)

#define SPNIC_PF_SET_VF_ALREADY		0x4
#define SPNIC_MGMT_STATUS_EXIST		0x6
#define CHECK_IPSU_15BIT		0x8000

#define SPNIC_MGMT_STATUS_TABLE_EMPTY	0xB
#define SPNIC_MGMT_STATUS_TABLE_FULL	0xC

#define SPNIC_MGMT_CMD_UNSUPPORTED	0xFF

#define SPNIC_MAX_UC_MAC_ADDRS		128
#define SPNIC_MAX_MC_MAC_ADDRS		128

/* Structures for RSS config */
#define SPNIC_RSS_INDIR_SIZE		256
#define SPNIC_RSS_INDIR_CMDQ_SIZE	128
#define SPNIC_RSS_KEY_SIZE		40
#define SPNIC_RSS_ENABLE		0x01
#define SPNIC_RSS_DISABLE		0x00

struct spnic_rss_type {
	u8 tcp_ipv6_ext;
	u8 ipv6_ext;
	u8 tcp_ipv6;
	u8 ipv6;
	u8 tcp_ipv4;
	u8 ipv4;
	u8 udp_ipv6;
	u8 udp_ipv4;
};

enum spnic_rss_hash_type {
	SPNIC_RSS_HASH_ENGINE_TYPE_XOR = 0,
	SPNIC_RSS_HASH_ENGINE_TYPE_TOEP,
	SPNIC_RSS_HASH_ENGINE_TYPE_MAX,
};

struct spnic_cmd_feature_nego {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;	/* 1: set, 0: get */
	u8 rsvd;
	u64 s_feature[MAX_FEATURE_QWORD];
};

/* Structures for port info */
struct nic_port_info {
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
};

enum spnic_link_status {
	SPNIC_LINK_DOWN = 0,
	SPNIC_LINK_UP
};

enum nic_media_type {
	MEDIA_UNKNOWN = -1,
	MEDIA_FIBRE = 0,
	MEDIA_COPPER,
	MEDIA_BACKPLANE
};

enum nic_speed_level {
	LINK_SPEED_10MB = 0,
	LINK_SPEED_100MB,
	LINK_SPEED_1GB,
	LINK_SPEED_10GB,
	LINK_SPEED_25GB,
	LINK_SPEED_40GB,
	LINK_SPEED_100GB,
	LINK_SPEED_LEVELS,
};

struct spnic_sq_attr {
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	u64 ci_dma_base;
};

struct spnic_cmd_cons_idx_attr {
	struct mgmt_msg_head msg_head;

	u16 func_idx;
	u8 dma_attr_off;
	u8 pending_limit;
	u8 coalescing_time;
	u8 intr_en;
	u16 intr_idx;
	u32 l2nic_sqn;
	u32 rsvd;
	u64 ci_addr;
};

struct spnic_port_mac_set {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 vlan_id;
	u16 rsvd1;
	u8 mac[ETH_ALEN];
};

struct spnic_port_mac_update {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 vlan_id;
	u16 rsvd1;
	u8 old_mac[ETH_ALEN];
	u16 rsvd2;
	u8 new_mac[ETH_ALEN];
};

#define SPNIC_CMD_OP_ADD	1
#define SPNIC_CMD_OP_DEL	0

struct spnic_cmd_vlan_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u16 vlan_id;
	u16 rsvd2;
};

struct spnic_cmd_set_vlan_filter {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 resvd[2];
	/* Bit0: vlan filter en; bit1: broadcast filter en */
	u32 vlan_filter_ctrl;
};

struct spnic_cmd_port_info {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 rsvd1[3];
	u8 port_type;
	u8 autoneg_cap;
	u8 autoneg_state;
	u8 duplex;
	u8 speed;
	u8 fec;
	u16 rsvd2;
	u32 rsvd3[4];
};

struct spnic_cmd_link_state {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 state;
	u16 rsvd1;
};

struct nic_pause_config {
	u8 auto_neg;
	u8 rx_pause;
	u8 tx_pause;
};

struct spnic_cmd_pause_config {
	struct mgmt_msg_head msg_head;

	u8 port_id;
	u8 opcode;
	u16 rsvd1;
	u8 auto_neg;
	u8 rx_pause;
	u8 tx_pause;
	u8 rsvd2[5];
};

struct spnic_vport_state {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 state;  /* 0--disable, 1--enable */
	u8 rsvd2[3];
};

#define MAG_CMD_PORT_DISABLE  0x0
#define MAG_CMD_TX_ENABLE     0x1
#define MAG_CMD_RX_ENABLE     0x2
/* the physical port is disable only when all pf of the port are set to down,
 * if any pf is enable, the port is enable
 */
struct mag_cmd_set_port_enable {
	struct mgmt_msg_head head;

	u16 function_id;
	u16 rsvd0;

	u8 state;  /* bitmap bit0:tx_en bit1:rx_en */
	u8 rsvd1[3];
};

struct mag_cmd_get_port_enable {
	struct mgmt_msg_head head;

	u8 port;
	u8 state; /* bitmap bit0:tx_en bit1:rx_en */
	u8 rsvd0[2];
};

struct spnic_cmd_clear_qp_resource {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
};


enum spnic_func_tbl_cfg_bitmap {
	FUNC_CFG_INIT,
	FUNC_CFG_RX_BUF_SIZE,
	FUNC_CFG_MTU,
};

struct spnic_func_tbl_cfg {
	u16 rx_wqe_buf_size;
	u16 mtu;
	u32 rsvd[9];
};

struct spnic_cmd_set_func_tbl {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd;

	u32 cfg_bitmap;
	struct spnic_func_tbl_cfg tbl_cfg;
};

struct spnic_rx_mode_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 rx_mode;
};

struct spnic_cmd_vlan_offload {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 vlan_offload;
	u8 rsvd1[5];
};

#define SPNIC_CMD_OP_GET	0
#define SPNIC_CMD_OP_SET	1

struct spnic_cmd_lro_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u8 lro_ipv4_en;
	u8 lro_ipv6_en;
	u8 lro_max_pkt_len; /* Unit size is 1K */
	u8 resv2[13];
};

struct spnic_cmd_lro_timer {
	struct mgmt_msg_head msg_head;

	u8 opcode; /* 1: set timer value, 0: get timer value */
	u8 rsvd1;
	u16 rsvd2;
	u32 timer;
};

struct spnic_rss_template_mgmt {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 cmd;
	u8 template_id;
	u8 rsvd1[4];
};

struct spnic_cmd_rss_hash_key {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 rsvd1;
	u8 key[SPNIC_RSS_KEY_SIZE];
};

struct spnic_rss_indir_table {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u8 indir[SPNIC_RSS_INDIR_SIZE];
};

struct nic_rss_indirect_tbl {
	u32 rsvd[4]; /* Make sure that 16B beyond entry[] */
	u16 entry[SPNIC_RSS_INDIR_SIZE];
};

struct nic_rss_context_tbl {
	u32 rsvd[4];
	u32 ctx;
};

struct spnic_rss_context_table {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u16 rsvd1;
	u32 context;
};

struct spnic_cmd_rss_engine_type {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 opcode;
	u8 hash_engine;
	u8 rsvd1[4];
};

struct spnic_cmd_rss_config {
	struct mgmt_msg_head msg_head;

	u16 func_id;
	u8 rss_en;
	u8 rq_priority_number;
	u8 prio_tc[SPNIC_DCB_UP_MAX];
	u32 rsvd1;
};

enum {
	SPNIC_IFLA_VF_LINK_STATE_AUTO,	/* Link state of the uplink */
	SPNIC_IFLA_VF_LINK_STATE_ENABLE, /* Link always up */
	SPNIC_IFLA_VF_LINK_STATE_DISABLE, /* Link always down */
};

struct spnic_dcb_state {
	u8 dcb_on;
	u8 default_cos;
	u16 rsvd1;
	u8 up_cos[SPNIC_DCB_UP_MAX];
	u32 rsvd2[7];
};

struct spnic_cmd_vf_dcb_state {
	struct mgmt_msg_head msg_head;

	struct spnic_dcb_state state;
};

struct spnic_cmd_register_vf {
	struct mgmt_msg_head msg_head;

	u8 op_register; /* 0 - unregister, 1 - register */
	u8 rsvd[39];
};


struct spnic_cmd_set_rq_flush {
	union {
		struct {
			u16 global_rq_id;
			u16 local_rq_id;
		};
		u32 value;
	};
};

int l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size);

int spnic_set_ci_table(void *hwdev, struct spnic_sq_attr *attr);

/**
 * Update MAC address to hardware
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] old_mac
 *   Old MAC addr to delete
 * @param[in] new_mac
 *   New MAC addr to update
 * @param[in] vlan_id
 *   Vlan id
 * @param func_id
 *   Function index
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_update_mac(void *hwdev, u8 *old_mac, u8 *new_mac, u16 vlan_id,
		     u16 func_id);

/**
 * Get the default mac address
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] mac_addr
 *   Mac address from hardware
 * @param[in] ether_len
 *   The length of mac address
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_get_default_mac(void *hwdev, u8 *mac_addr, int ether_len);

/**
 * Set mac address
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] mac_addr
 *   Mac address from hardware
 * @param[in] vlan_id
 *   Vlan id
 * @param[in] func_id
 *   Function index
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id);

/**
 * Delete MAC address
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] mac_addr
 *   MAC address from hardware
 * @param[in] vlan_id
 *   Vlan id
 * @param[in] func_id
 *   Function index
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id);

/**
 * Set function mtu
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] new_mtu
 *   MTU value
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_port_mtu(void *hwdev, u16 new_mtu);

/**
 * Set function valid status
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] enable
 *   0-disable, 1-enable
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_vport_enable(void *hwdev, bool enable);

/**
 * Set port status
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] enable
 *   0-disable, 1-enable
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_port_enable(void *hwdev, bool enable);

/**
 * Get link state
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] link_state
 *   Link state, 0-link down, 1-link up
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_get_link_state(void *hwdev, u8 *link_state);

/**
 * Flush queue pairs resource in hardware
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_flush_qps_res(void *hwdev);


/**
 * Init nic hwdev
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_init_nic_hwdev(void *hwdev);

/**
 * Free nic hwdev
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 */
void spnic_free_nic_hwdev(void *hwdev);

/**
 * Set function rx mode
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] enable
 *   Rx mode state, 0-disable, 1-enable
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_rx_mode(void *hwdev, u32 enable);

/**
 * Set function vlan offload valid state
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] enable
 *   Rx mode state, 0-disable, 1-enable
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_rx_vlan_offload(void *hwdev, u8 en);

/**
 * Set rx LRO configuration
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] lro_en
 *   LRO enable state, 0-disable, 1-enable
 * @param[in] lro_timer
 *   LRO aggregation timeout
 * @param[in] lro_max_pkt_len
 *   LRO coalesce packet size(unit size is 1K)
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_rx_lro_state(void *hwdev, u8 lro_en, u32 lro_timer,
			   u32 lro_max_pkt_len);

/**
 * Get port info
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] port_info
 *   Port info, including autoneg, port type, duplex, speed and fec mode
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_get_port_info(void *hwdev, struct nic_port_info *port_info);

int spnic_init_function_table(void *hwdev, u16 rx_buff_len);

/**
 * Alloc RSS template table
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_template_alloc(void *hwdev);

/**
 * Free RSS template table
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_template_free(void *hwdev);

/**
 * Set RSS indirect table
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] indir_table
 *   RSS indirect table
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_set_indir_tbl(void *hwdev, const u32 *indir_table);

/**
 * Get RSS indirect table
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] indir_table
 *   RSS indirect table
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_get_indir_tbl(void *hwdev, u32 *indir_table);

/**
 * Set RSS type
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] rss_type
 *   RSS type, including ipv4, tcpv4, ipv6, tcpv6 and etc.
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_rss_type(void *hwdev, struct spnic_rss_type rss_type);

/**
 * Get RSS type
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] rss_type
 *   RSS type, including ipv4, tcpv4, ipv6, tcpv6 and etc.
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_get_rss_type(void *hwdev, struct spnic_rss_type *rss_type);

/**
 * Get RSS hash engine
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] type
 *   RSS hash engine, pmd driver only supports Toeplitz
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_get_hash_engine(void *hwdev, u8 *type);

/**
 * Set RSS hash engine
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] type
 *   RSS hash engine, pmd driver only supports Toeplitz
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_set_hash_engine(void *hwdev, u8 type);

/**
 * Set RSS configuration
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] rss_en
 *   RSS enable lag, 0-disable, 1-enable
 * @param[in] tc_num
 *   Number of TC
 * @param[in] prio_tc
 *   Priority of TC
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_cfg(void *hwdev, u8 rss_en, u8 tc_num, u8 *prio_tc);

/**
 * Set RSS hash key
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] key
 *   RSS hash key
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_set_hash_key(void *hwdev, u8 *key);

/**
 * Get RSS hash key
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] key
 *   RSS hash key
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_rss_get_hash_key(void *hwdev, u8 *key);

/**
 * Add vlan to hardware
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] vlan_id
 *   Vlan id
 * @param[in] func_id
 *   Function id
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_add_vlan(void *hwdev, u16 vlan_id, u16 func_id);

/**
 * Delete vlan
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] vlan_id
 *   Vlan id
 * @param[in] func_id
 *   Function id
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_del_vlan(void *hwdev, u16 vlan_id, u16 func_id);

/**
 * Set vlan filter
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[in] vlan_filter_ctrl
 *   Vlan filter enable flag, 0-disable, 1-enable
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_set_vlan_fliter(void *hwdev, u32 vlan_filter_ctrl);

/**
 * Get VF function default cos
 *
 * @param[in] hwdev
 *   Device pointer to hwdev
 * @param[out] cos_id
 *   Cos id
 *
 * @retval zero : Success
 * @retval non-zero : Failure
 */
int spnic_vf_get_default_cos(void *hwdev, u8 *cos_id);

/**
 * Get service feature HW supported
 *
 * @param[in] dev
 *   Device pointer to hwdev
 * @param[in] size
 *   s_feature's array size
 * @param[out] s_feature
 *   s_feature HW supported
 * @retval zero: Success
 * @retval non-zero: Failure
 */
int spnic_get_feature_from_hw(void *hwdev, u64 *s_feature, u16 size);

/**
 * Set service feature driver supported to hardware
 *
 * @param[in] dev
 *   Device pointer to hwdev
 *
 * @retval zero: Success
 * @retval non-zero: Failure
 */
int spnic_set_feature_to_hw(void *hwdev, u64 *s_feature, u16 size);

#endif /* _SPNIC_NIC_CFG_H_ */
