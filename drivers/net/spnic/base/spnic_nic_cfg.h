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

int spnic_l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
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

#endif /* _SPNIC_NIC_CFG_H_ */
