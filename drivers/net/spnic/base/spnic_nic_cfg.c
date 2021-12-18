/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include <rte_ether.h>
#include "spnic_compat.h"
#include "spnic_cmd.h"
#include "spnic_mgmt.h"
#include "spnic_hwif.h"
#include "spnic_mbox.h"
#include "spnic_hwdev.h"
#include "spnic_wq.h"
#include "spnic_cmdq.h"
#include "spnic_nic_cfg.h"
#include "spnic_hw_cfg.h"

struct vf_msg_handler {
	u16 cmd;
};

const struct vf_msg_handler vf_cmd_handler[] = {
	{
		.cmd = SPNIC_CMD_VF_REGISTER,
	},

	{
		.cmd = SPNIC_CMD_GET_MAC,
	},

	{
		.cmd = SPNIC_CMD_SET_MAC,
	},

	{
		.cmd = SPNIC_CMD_DEL_MAC,
	},

	{
		.cmd = SPNIC_CMD_UPDATE_MAC,
	},

	{
		.cmd = SPNIC_CMD_VF_COS,
	},
};

static const struct vf_msg_handler vf_mag_cmd_handler[] = {
	{
		.cmd = MAG_CMD_GET_LINK_STATUS,
	},
};

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size);

int l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
			   void *buf_out, u16 *out_size)
{
	u32 i, cmd_cnt = ARRAY_LEN(vf_cmd_handler);
	bool cmd_to_pf = false;

	if (spnic_func_type(hwdev) == TYPE_VF) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == vf_cmd_handler[i].cmd)
				cmd_to_pf = true;
		}
	}

	if (cmd_to_pf) {
		return spnic_mbox_to_pf(hwdev, SPNIC_MOD_L2NIC, cmd, buf_in,
					in_size, buf_out, out_size, 0);
	}

	return spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_L2NIC, cmd, buf_in,
				      in_size, buf_out, out_size, 0);
}

static int spnic_check_mac_info(u8 status, u16 vlan_id)
{
	if ((status && status != SPNIC_MGMT_STATUS_EXIST &&
	     status != SPNIC_PF_SET_VF_ALREADY) ||
	    (vlan_id & CHECK_IPSU_15BIT &&
	     status == SPNIC_MGMT_STATUS_EXIST))
		return -EINVAL;

	return 0;
}

#define VLAN_N_VID		4096

int spnic_set_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));

	if (vlan_id >= VLAN_N_VID) {
		PMD_DRV_LOG(ERR, "Invalid VLAN number: %d", vlan_id);
		return -EINVAL;
	}

	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	memmove(mac_info.mac, mac_addr, ETH_ALEN);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_MAC, &mac_info,
				     sizeof(mac_info), &mac_info, &out_size);
	if (err || !out_size ||
	    spnic_check_mac_info(mac_info.msg_head.status, mac_info.vlan_id)) {
		PMD_DRV_LOG(ERR, "Update MAC failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		PMD_DRV_LOG(WARNING, "PF has already set VF mac, Ignore set operation");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == SPNIC_MGMT_STATUS_EXIST) {
		PMD_DRV_LOG(WARNING, "MAC is repeated. Ignore update operation");
		return 0;
	}

	return 0;
}

int spnic_del_mac(void *hwdev, const u8 *mac_addr, u16 vlan_id, u16 func_id)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	if (vlan_id >= VLAN_N_VID) {
		PMD_DRV_LOG(ERR, "Invalid VLAN number: %d", vlan_id);
		return -EINVAL;
	}

	memset(&mac_info, 0, sizeof(mac_info));
	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	memmove(mac_info.mac, mac_addr, ETH_ALEN);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_DEL_MAC, &mac_info,
				     sizeof(mac_info), &mac_info, &out_size);
	if (err || !out_size || (mac_info.msg_head.status &&
	    mac_info.msg_head.status != SPNIC_PF_SET_VF_ALREADY)) {
		PMD_DRV_LOG(ERR, "Delete MAC failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		PMD_DRV_LOG(WARNING, "PF has already set VF mac, Ignore delete operation");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	return 0;
}

int spnic_update_mac(void *hwdev, u8 *old_mac, u8 *new_mac, u16 vlan_id,
		     u16 func_id)
{
	struct spnic_port_mac_update mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (!hwdev || !old_mac || !new_mac)
		return -EINVAL;

	if (vlan_id >= VLAN_N_VID) {
		PMD_DRV_LOG(ERR, "Invalid VLAN number: %d", vlan_id);
		return -EINVAL;
	}

	memset(&mac_info, 0, sizeof(mac_info));
	mac_info.func_id = func_id;
	mac_info.vlan_id = vlan_id;
	memcpy(mac_info.old_mac, old_mac, ETH_ALEN);
	memcpy(mac_info.new_mac, new_mac, ETH_ALEN);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_UPDATE_MAC, &mac_info,
				     sizeof(mac_info), &mac_info, &out_size);
	if (err || !out_size ||
	    spnic_check_mac_info(mac_info.msg_head.status, mac_info.vlan_id)) {
		PMD_DRV_LOG(ERR, "Update MAC failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	if (mac_info.msg_head.status == SPNIC_PF_SET_VF_ALREADY) {
		PMD_DRV_LOG(WARNING, "PF has already set VF MAC. Ignore update operation");
		return SPNIC_PF_SET_VF_ALREADY;
	}

	if (mac_info.msg_head.status == SPNIC_MGMT_STATUS_EXIST) {
		PMD_DRV_LOG(INFO, "MAC is repeated. Ignore update operation");
		return 0;
	}

	return 0;
}

int spnic_get_default_mac(void *hwdev, u8 *mac_addr, int ether_len)
{
	struct spnic_port_mac_set mac_info;
	u16 out_size = sizeof(mac_info);
	int err;

	if (!hwdev || !mac_addr)
		return -EINVAL;

	memset(&mac_info, 0, sizeof(mac_info));
	mac_info.func_id = spnic_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_GET_MAC,
				     &mac_info, sizeof(mac_info),
		&mac_info, &out_size);
	if (err || !out_size || mac_info.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get MAC failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, mac_info.msg_head.status, out_size);
		return -EINVAL;
	}

	memmove(mac_addr, mac_info.mac, ether_len);

	return 0;
}

int spnic_get_port_info(void *hwdev, struct nic_port_info *port_info)
{
	struct spnic_cmd_port_info port_msg;
	u16 out_size = sizeof(port_msg);
	int err;

	if (!hwdev || !port_info)
		return -EINVAL;

	memset(&port_msg, 0, sizeof(port_msg));
	port_msg.port_id = spnic_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_PORT_INFO, &port_msg,
				   sizeof(port_msg), &port_msg, &out_size);
	if (err || !out_size || port_msg.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get port info failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, port_msg.msg_head.status, out_size);
		return -EINVAL;
	}

	port_info->autoneg_cap = port_msg.autoneg_cap;
	port_info->autoneg_state = port_msg.autoneg_state;
	port_info->duplex = port_msg.duplex;
	port_info->port_type = port_msg.port_type;
	port_info->speed = port_msg.speed;
	port_info->fec = port_msg.fec;

	return 0;
}

static int _mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in,
				 u16 in_size, void *buf_out, u16 *out_size)
{
	u32 i, cmd_cnt = ARRAY_LEN(vf_mag_cmd_handler);

	if (spnic_func_type(hwdev) == TYPE_VF) {
		for (i = 0; i < cmd_cnt; i++) {
			if (cmd == vf_mag_cmd_handler[i].cmd)
				return spnic_mbox_to_pf(hwdev, SPNIC_MOD_HILINK,
							cmd, buf_in, in_size,
							buf_out, out_size, 0);
		}
	}

	return spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_HILINK, cmd, buf_in,
				      in_size, buf_out, out_size, 0);
}

static int mag_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
				void *buf_out, u16 *out_size)
{
	return _mag_msg_to_mgmt_sync(hwdev, cmd, buf_in, in_size, buf_out,
				     out_size);
}
