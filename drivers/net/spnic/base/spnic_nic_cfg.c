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

int spnic_l2nic_msg_to_mgmt_sync(void *hwdev, u16 cmd, void *buf_in, u16 in_size,
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

int spnic_set_ci_table(void *hwdev, struct spnic_sq_attr *attr)
{
	struct spnic_cmd_cons_idx_attr cons_idx_attr;
	u16 out_size = sizeof(cons_idx_attr);
	int err;

	if (!hwdev || !attr)
		return -EINVAL;

	memset(&cons_idx_attr, 0, sizeof(cons_idx_attr));
	cons_idx_attr.func_idx = spnic_global_func_id(hwdev);
	cons_idx_attr.dma_attr_off  = attr->dma_attr_off;
	cons_idx_attr.pending_limit = attr->pending_limit;
	cons_idx_attr.coalescing_time  = attr->coalescing_time;

	if (attr->intr_en) {
		cons_idx_attr.intr_en = attr->intr_en;
		cons_idx_attr.intr_idx = attr->intr_idx;
	}

	cons_idx_attr.l2nic_sqn = attr->l2nic_sqn;
	cons_idx_attr.ci_addr = attr->ci_dma_base;

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SQ_CI_ATTR_SET,
				     &cons_idx_attr, sizeof(cons_idx_attr),
				     &cons_idx_attr, &out_size);
	if (err || !out_size || cons_idx_attr.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set ci attribute table failed, err: %d, "
			    "status: 0x%x, out_size: 0x%x",
			    err, cons_idx_attr.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
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

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_MAC, &mac_info,
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

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_DEL_MAC, &mac_info,
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

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_UPDATE_MAC, &mac_info,
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

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_GET_MAC,
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


int spnic_get_link_state(void *hwdev, u8 *link_state)
{
	struct spnic_cmd_link_state get_link;
	u16 out_size = sizeof(get_link);
	int err;

	if (!hwdev || !link_state)
		return -EINVAL;

	memset(&get_link, 0, sizeof(get_link));
	get_link.port_id = spnic_physical_port_id(hwdev);
	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_LINK_STATUS, &get_link,
				   sizeof(get_link), &get_link, &out_size);
	if (err || !out_size || get_link.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get link state failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, get_link.msg_head.status, out_size);
		return -EIO;
	}

	*link_state = get_link.state;

	return 0;
}

int spnic_set_vport_enable(void *hwdev, bool enable)
{
	struct spnic_vport_state en_state;
	u16 out_size = sizeof(en_state);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&en_state, 0, sizeof(en_state));
	en_state.func_id = spnic_global_func_id(hwdev);
	en_state.state = enable ? 1 : 0;

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_VPORT_ENABLE, &en_state,
				     sizeof(en_state), &en_state, &out_size);
	if (err || !out_size || en_state.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set vport state failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, en_state.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_set_port_enable(void *hwdev, bool enable)
{
	struct mag_cmd_set_port_enable en_state;
	u16 out_size = sizeof(en_state);
	int err;

	if (!hwdev)
		return -EINVAL;

	if (spnic_func_type(hwdev) == TYPE_VF)
		return 0;

	memset(&en_state, 0, sizeof(en_state));
	en_state.function_id = spnic_global_func_id(hwdev);
	en_state.state = enable ? MAG_CMD_TX_ENABLE | MAG_CMD_RX_ENABLE :
				MAG_CMD_PORT_DISABLE;

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_SET_PORT_ENABLE, &en_state,
				     sizeof(en_state), &en_state, &out_size);
	if (err || !out_size || en_state.head.status) {
		PMD_DRV_LOG(ERR, "Set port state failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, en_state.head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_flush_qps_res(void *hwdev)
{
	struct spnic_cmd_clear_qp_resource sq_res;
	u16 out_size = sizeof(sq_res);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&sq_res, 0, sizeof(sq_res));
	sq_res.func_id = spnic_global_func_id(hwdev);

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CLEAR_QP_RESOURCE, &sq_res,
				     sizeof(sq_res), &sq_res, &out_size);
	if (err || !out_size || sq_res.msg_head.status) {
		PMD_DRV_LOG(ERR, "Clear sq resources failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, sq_res.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

static int spnic_set_function_table(void *hwdev, u32 cfg_bitmap,
				     struct spnic_func_tbl_cfg *cfg)
{
	struct spnic_cmd_set_func_tbl cmd_func_tbl;
	u16 out_size = sizeof(cmd_func_tbl);
	int err;

	memset(&cmd_func_tbl, 0, sizeof(cmd_func_tbl));
	cmd_func_tbl.func_id = spnic_global_func_id(hwdev);
	cmd_func_tbl.cfg_bitmap = cfg_bitmap;
	cmd_func_tbl.tbl_cfg = *cfg;

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_FUNC_TBL,
				     &cmd_func_tbl, sizeof(cmd_func_tbl),
				     &cmd_func_tbl, &out_size);
	if (err || cmd_func_tbl.msg_head.status || !out_size) {
		PMD_DRV_LOG(ERR, "Set func table failed, bitmap: 0x%x, err: %d, "
			    "status: 0x%x, out size: 0x%x\n", cfg_bitmap, err,
			    cmd_func_tbl.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_init_function_table(void *hwdev, u16 rx_buff_len)
{
	struct spnic_func_tbl_cfg func_tbl_cfg;
	u32 cfg_bitmap = BIT(FUNC_CFG_INIT) | BIT(FUNC_CFG_MTU) |
			 BIT(FUNC_CFG_RX_BUF_SIZE);

	memset(&func_tbl_cfg, 0, sizeof(func_tbl_cfg));
	func_tbl_cfg.mtu = 0x3FFF; /* Default, max mtu */
	func_tbl_cfg.rx_wqe_buf_size = rx_buff_len;

	return spnic_set_function_table(hwdev, cfg_bitmap, &func_tbl_cfg);
}

int spnic_set_port_mtu(void *hwdev, u16 new_mtu)
{
	struct spnic_func_tbl_cfg func_tbl_cfg;

	if (!hwdev)
		return -EINVAL;

	if (new_mtu < SPNIC_MIN_MTU_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid mtu size: %ubytes, mtu size < %ubytes",
			    new_mtu, SPNIC_MIN_MTU_SIZE);
		return -EINVAL;
	}

	if (new_mtu > SPNIC_MAX_JUMBO_FRAME_SIZE) {
		PMD_DRV_LOG(ERR, "Invalid mtu size: %ubytes, mtu size > %ubytes",
			    new_mtu, SPNIC_MAX_JUMBO_FRAME_SIZE);
		return -EINVAL;
	}

	memset(&func_tbl_cfg, 0, sizeof(func_tbl_cfg));
	func_tbl_cfg.mtu = new_mtu;

	return spnic_set_function_table(hwdev, BIT(FUNC_CFG_MTU),
					&func_tbl_cfg);
}

static int nic_feature_nego(void *hwdev, u8 opcode, u64 *s_feature, u16 size)
{
	struct spnic_cmd_feature_nego feature_nego;
	u16 out_size = sizeof(feature_nego);
	int err;

	if (!hwdev || !s_feature || size > MAX_FEATURE_QWORD)
		return -EINVAL;

	memset(&feature_nego, 0, sizeof(feature_nego));
	feature_nego.func_id = spnic_global_func_id(hwdev);
	feature_nego.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET)
		memcpy(feature_nego.s_feature, s_feature, size * sizeof(u64));

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_FEATURE_NEGO,
				     &feature_nego, sizeof(feature_nego),
				     &feature_nego, &out_size);
	if (err || !out_size || feature_nego.msg_head.status) {
		PMD_DRV_LOG(ERR, "Failed to negotiate nic feature, err:%d, status: 0x%x, out_size: 0x%x\n",
			    err, feature_nego.msg_head.status, out_size);
		return -EFAULT;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		memcpy(s_feature, feature_nego.s_feature, size * sizeof(u64));

	return 0;
}

int spnic_get_feature_from_hw(void *hwdev, u64 *s_feature, u16 size)
{
	return nic_feature_nego(hwdev, SPNIC_CMD_OP_GET, s_feature, size);
}

int spnic_set_feature_to_hw(void *hwdev, u64 *s_feature, u16 size)
{
	return nic_feature_nego(hwdev, SPNIC_CMD_OP_SET, s_feature, size);
}

static int spnic_vf_func_init(void *hwdev)
{
	struct spnic_cmd_register_vf register_info;
	u16 out_size = sizeof(register_info);
	int err;

	if (spnic_func_type(hwdev) != TYPE_VF)
		return 0;

	memset(&register_info, 0, sizeof(register_info));
	register_info.op_register = 1;
	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_REGISTER,
				     &register_info, sizeof(register_info),
				     &register_info, &out_size);
	if (err || register_info.msg_head.status || !out_size) {
		PMD_DRV_LOG(ERR, "Register VF failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, register_info.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int spnic_vf_func_free(void *hwdev)
{
	struct spnic_cmd_register_vf unregister;
	u16 out_size = sizeof(unregister);
	int err;

	if (spnic_func_type(hwdev) != TYPE_VF)
		return 0;

	memset(&unregister, 0, sizeof(unregister));
	unregister.op_register = 0;
	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_REGISTER,
				     &unregister, sizeof(unregister),
				     &unregister, &out_size);
	if (err || unregister.msg_head.status || !out_size) {
		PMD_DRV_LOG(ERR, "Unregister VF failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, unregister.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_init_nic_hwdev(void *hwdev)
{
	return spnic_vf_func_init(hwdev);
}

void spnic_free_nic_hwdev(void *hwdev)
{
	if (!hwdev)
		return;

	spnic_vf_func_free(hwdev);
}

int spnic_vf_get_default_cos(void *hwdev, u8 *cos_id)
{
	struct spnic_cmd_vf_dcb_state vf_dcb;
	u16 out_size = sizeof(vf_dcb);
	int err;

	memset(&vf_dcb, 0, sizeof(vf_dcb));

	err = spnic_l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_COS, &vf_dcb,
				     sizeof(vf_dcb), &vf_dcb, &out_size);
	if (err || !out_size || vf_dcb.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get VF default cos failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, vf_dcb.msg_head.status, out_size);
		return -EIO;
	}

	*cos_id = vf_dcb.state.default_cos;

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
