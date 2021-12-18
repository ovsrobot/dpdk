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

int l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size);

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
#endif /* _SPNIC_NIC_CFG_H_ */
