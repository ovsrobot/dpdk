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

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SQ_CI_ATTR_SET,
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

static int spnic_config_vlan(void *hwdev, u8 opcode, u16 vlan_id, u16 func_id)
{
	struct spnic_cmd_vlan_config vlan_info;
	u16 out_size = sizeof(vlan_info);
	int err;

	memset(&vlan_info, 0, sizeof(vlan_info));
	vlan_info.opcode = opcode;
	vlan_info.func_id = func_id;
	vlan_info.vlan_id = vlan_id;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_FUNC_VLAN, &vlan_info,
				     sizeof(vlan_info), &vlan_info, &out_size);
	if (err || !out_size || vlan_info.msg_head.status) {
		PMD_DRV_LOG(ERR, "%s vlan failed, err: %d, status: 0x%x, out size: 0x%x",
			    opcode == SPNIC_CMD_OP_ADD ? "Add" : "Delete",
			    err, vlan_info.msg_head.status, out_size);
		return -EINVAL;
	}

	return 0;
}

int spnic_add_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	if (!hwdev)
		return -EINVAL;

	return spnic_config_vlan(hwdev, SPNIC_CMD_OP_ADD, vlan_id, func_id);
}

int spnic_del_vlan(void *hwdev, u16 vlan_id, u16 func_id)
{
	if (!hwdev)
		return -EINVAL;

	return spnic_config_vlan(hwdev, SPNIC_CMD_OP_DEL, vlan_id, func_id);
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

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_VPORT_ENABLE, &en_state,
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

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CLEAR_QP_RESOURCE, &sq_res,
				     sizeof(sq_res), &sq_res, &out_size);
	if (err || !out_size || sq_res.msg_head.status) {
		PMD_DRV_LOG(ERR, "Clear sq resources failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, sq_res.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

static int spnic_cfg_hw_pause(void *hwdev, u8 opcode,
			       struct nic_pause_config *nic_pause)
{
	struct spnic_cmd_pause_config pause_info;
	u16 out_size = sizeof(pause_info);
	int err;

	memset(&pause_info, 0, sizeof(pause_info));

	pause_info.port_id = spnic_physical_port_id(hwdev);
	pause_info.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET) {
		pause_info.auto_neg = nic_pause->auto_neg;
		pause_info.rx_pause = nic_pause->rx_pause;
		pause_info.tx_pause = nic_pause->tx_pause;
	}

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_PAUSE_INFO,
				     &pause_info, sizeof(pause_info),
				     &pause_info, &out_size);
	if (err || !out_size || pause_info.msg_head.status) {
		PMD_DRV_LOG(ERR, "%s pause info failed, err: %d, status: 0x%x, out size: 0x%x\n",
			    opcode == SPNIC_CMD_OP_SET ? "Set" : "Get",
			    err, pause_info.msg_head.status, out_size);
		return -EIO;
	}

	if (opcode == SPNIC_CMD_OP_GET) {
		nic_pause->auto_neg = pause_info.auto_neg;
		nic_pause->rx_pause = pause_info.rx_pause;
		nic_pause->tx_pause = pause_info.tx_pause;
	}

	return 0;
}

int spnic_set_pause_info(void *hwdev, struct nic_pause_config nic_pause)
{
	if (!hwdev)
		return -EINVAL;

	return spnic_cfg_hw_pause(hwdev, SPNIC_CMD_OP_SET, &nic_pause);
}

int spnic_get_pause_info(void *hwdev, struct nic_pause_config *nic_pause)
{
	if (!hwdev || !nic_pause)
		return -EINVAL;


	return spnic_cfg_hw_pause(hwdev, SPNIC_CMD_OP_GET, nic_pause);
}

int spnic_get_vport_stats(void *hwdev, struct spnic_vport_stats *stats)
{
	struct spnic_port_stats_info stats_info;
	struct spnic_cmd_vport_stats vport_stats;
	u16 out_size = sizeof(vport_stats);
	int err;

	if (!hwdev || !stats)
		return -EINVAL;

	memset(&stats_info, 0, sizeof(stats_info));
	memset(&vport_stats, 0, sizeof(vport_stats));

	stats_info.func_id = spnic_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_GET_VPORT_STAT,
				     &stats_info, sizeof(stats_info),
				     &vport_stats, &out_size);
	if (err || !out_size || vport_stats.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get function stats failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, vport_stats.msg_head.status, out_size);
		return -EIO;
	}

	memcpy(stats, &vport_stats.stats, sizeof(*stats));

	return 0;
}

int spnic_get_phy_port_stats(void *hwdev, struct mag_phy_port_stats *stats)
{
	struct mag_cmd_get_port_stat *port_stats = NULL;
	struct mag_cmd_port_stats_info stats_info;
	u16 out_size = sizeof(*port_stats);
	int err;

	port_stats = rte_zmalloc("port_stats", sizeof(*port_stats), 0);
	if (!port_stats)
		return -ENOMEM;

	memset(&stats_info, 0, sizeof(stats_info));
	stats_info.port_id = spnic_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_PORT_STAT,
				   &stats_info, sizeof(stats_info),
				   port_stats, &out_size);
	if (err || !out_size || port_stats->head.status) {
		PMD_DRV_LOG(ERR,
			"Failed to get port statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, port_stats->head.status, out_size);
		err = -EIO;
		goto out;
	}

	memcpy(stats, &port_stats->counter, sizeof(*stats));

out:
	rte_free(port_stats);

	return err;
}

int spnic_clear_vport_stats(void *hwdev)
{
	struct spnic_cmd_clear_vport_stats clear_vport_stats;
	u16 out_size = sizeof(clear_vport_stats);
	int err;

	if (!hwdev) {
		PMD_DRV_LOG(ERR, "Hwdev is NULL");
		return -EINVAL;
	}

	memset(&clear_vport_stats, 0, sizeof(clear_vport_stats));
	clear_vport_stats.func_id = spnic_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CLEAN_VPORT_STAT,
				     &clear_vport_stats,
				     sizeof(clear_vport_stats),
				     &clear_vport_stats, &out_size);
	if (err || !out_size || clear_vport_stats.msg_head.status) {
		PMD_DRV_LOG(ERR, "Clear vport stats failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, clear_vport_stats.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_clear_phy_port_stats(void *hwdev)
{
	struct mag_cmd_clr_port_stat *port_stats = NULL;
	u16 out_size = sizeof(*port_stats);
	int err;

	port_stats = rte_zmalloc("port_stats", sizeof(*port_stats), 0);
	if (!port_stats)
		return -ENOMEM;

	port_stats->port_id = spnic_physical_port_id(hwdev);

	err = mag_msg_to_mgmt_sync(hwdev, MAG_CMD_GET_PORT_STAT,
				   &port_stats, sizeof(port_stats),
				   port_stats, &out_size);
	if (err || !out_size || port_stats->head.status) {
		PMD_DRV_LOG(ERR,
			"Failed to get port statistics, err: %d, status: 0x%x, out size: 0x%x\n",
			err, port_stats->head.status, out_size);
		err = -EIO;
		goto out;
	}

out:
	rte_free(port_stats);

	return err;
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

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_FUNC_TBL,
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

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_FEATURE_NEGO,
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
	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_REGISTER,
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
	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_REGISTER,
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

int spnic_set_rx_mode(void *hwdev, u32 enable)
{
	struct spnic_rx_mode_config rx_mode_cfg;
	u16 out_size = sizeof(rx_mode_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&rx_mode_cfg, 0, sizeof(rx_mode_cfg));
	rx_mode_cfg.func_id = spnic_global_func_id(hwdev);
	rx_mode_cfg.rx_mode = enable;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_RX_MODE,
				     &rx_mode_cfg, sizeof(rx_mode_cfg),
				     &rx_mode_cfg, &out_size);
	if (err || !out_size || rx_mode_cfg.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set rx mode failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, rx_mode_cfg.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_set_rx_vlan_offload(void *hwdev, u8 en)
{
	struct spnic_cmd_vlan_offload vlan_cfg;
	u16 out_size = sizeof(vlan_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&vlan_cfg, 0, sizeof(vlan_cfg));
	vlan_cfg.func_id = spnic_global_func_id(hwdev);
	vlan_cfg.vlan_offload = en;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_RX_VLAN_OFFLOAD,
				     &vlan_cfg, sizeof(vlan_cfg),
				     &vlan_cfg, &out_size);
	if (err || !out_size || vlan_cfg.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set rx vlan offload failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, vlan_cfg.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

int spnic_set_vlan_fliter(void *hwdev, u32 vlan_filter_ctrl)
{
	struct spnic_cmd_set_vlan_filter vlan_filter;
	u16 out_size = sizeof(vlan_filter);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&vlan_filter, 0, sizeof(vlan_filter));
	vlan_filter.func_id = spnic_global_func_id(hwdev);
	vlan_filter.vlan_filter_ctrl = vlan_filter_ctrl;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_SET_VLAN_FILTER_EN,
				     &vlan_filter, sizeof(vlan_filter),
				     &vlan_filter, &out_size);
	if (err || !out_size || vlan_filter.msg_head.status) {
		PMD_DRV_LOG(ERR, "Failed to set vlan filter, err: %d, status: 0x%x, out size: 0x%x",
			    err, vlan_filter.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

static int spnic_set_rx_lro(void *hwdev, u8 ipv4_en, u8 ipv6_en,
			    u8 lro_max_pkt_len)
{
	struct spnic_cmd_lro_config lro_cfg;
	u16 out_size = sizeof(lro_cfg);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&lro_cfg, 0, sizeof(lro_cfg));
	lro_cfg.func_id = spnic_global_func_id(hwdev);
	lro_cfg.opcode = SPNIC_CMD_OP_SET;
	lro_cfg.lro_ipv4_en = ipv4_en;
	lro_cfg.lro_ipv6_en = ipv6_en;
	lro_cfg.lro_max_pkt_len = lro_max_pkt_len;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_RX_LRO, &lro_cfg,
				     sizeof(lro_cfg), &lro_cfg, &out_size);
	if (err || !out_size || lro_cfg.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set lro offload failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, lro_cfg.msg_head.status, out_size);
		return -EIO;
	}

	return 0;
}

static int spnic_set_rx_lro_timer(void *hwdev, u32 timer_value)
{
	struct spnic_cmd_lro_timer lro_timer;
	u16 out_size = sizeof(lro_timer);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&lro_timer, 0, sizeof(lro_timer));
	lro_timer.opcode = SPNIC_CMD_OP_SET;
	lro_timer.timer = timer_value;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_LRO_TIMER, &lro_timer,
				     sizeof(lro_timer), &lro_timer, &out_size);
	if (err || !out_size || lro_timer.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set lro timer failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, lro_timer.msg_head.status, out_size);

		return -EIO;
	}

	return 0;
}

int spnic_set_rx_lro_state(void *hwdev, u8 lro_en, u32 lro_timer,
			    u32 lro_max_pkt_len)
{
	u8 ipv4_en = 0, ipv6_en = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	ipv4_en = lro_en ? 1 : 0;
	ipv6_en = lro_en ? 1 : 0;

	PMD_DRV_LOG(INFO, "Set LRO max coalesce packet size to %uK",
		    lro_max_pkt_len);

	err = spnic_set_rx_lro(hwdev, ipv4_en, ipv6_en, (u8)lro_max_pkt_len);
	if (err)
		return err;

	/* We don't set LRO timer for VF */
	if (spnic_func_type(hwdev) == TYPE_VF)
		return 0;

	PMD_DRV_LOG(INFO, "Set LRO timer to %u", lro_timer);

	return spnic_set_rx_lro_timer(hwdev, lro_timer);
}

/* RSS config */
int spnic_rss_template_alloc(void *hwdev)
{
	struct spnic_rss_template_mgmt template_mgmt;
	u16 out_size = sizeof(template_mgmt);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&template_mgmt, 0, sizeof(struct spnic_rss_template_mgmt));
	template_mgmt.func_id = spnic_global_func_id(hwdev);
	template_mgmt.cmd = NIC_RSS_CMD_TEMP_ALLOC;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_RSS_TEMP_MGR,
				     &template_mgmt, sizeof(template_mgmt),
				     &template_mgmt, &out_size);
	if (err || !out_size || template_mgmt.msg_head.status) {
		if (template_mgmt.msg_head.status ==
		    SPNIC_MGMT_STATUS_TABLE_FULL) {
			PMD_DRV_LOG(ERR, "There is no more template available");
			return -ENOSPC;
		}
		PMD_DRV_LOG(ERR, "Alloc rss template failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, template_mgmt.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_rss_template_free(void *hwdev)
{
	struct spnic_rss_template_mgmt template_mgmt;
	u16 out_size = sizeof(template_mgmt);
	int err;

	if (!hwdev)
		return -EINVAL;

	memset(&template_mgmt, 0, sizeof(struct spnic_rss_template_mgmt));
	template_mgmt.func_id = spnic_global_func_id(hwdev);
	template_mgmt.cmd = NIC_RSS_CMD_TEMP_FREE;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_RSS_TEMP_MGR,
				     &template_mgmt, sizeof(template_mgmt),
				     &template_mgmt, &out_size);
	if (err || !out_size || template_mgmt.msg_head.status) {
		PMD_DRV_LOG(ERR, "Free rss template failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, template_mgmt.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

static int spnic_rss_cfg_hash_key(void *hwdev, u8 opcode, u8 *key)
{
	struct spnic_cmd_rss_hash_key hash_key;
	u16 out_size = sizeof(hash_key);
	int err;

	if (!hwdev || !key)
		return -EINVAL;

	memset(&hash_key, 0, sizeof(struct spnic_cmd_rss_hash_key));
	hash_key.func_id = spnic_global_func_id(hwdev);
	hash_key.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET)
		memcpy(hash_key.key, key, SPNIC_RSS_KEY_SIZE);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_RSS_HASH_KEY,
				     &hash_key, sizeof(hash_key),
				     &hash_key, &out_size);
	if (err || !out_size || hash_key.msg_head.status) {
		PMD_DRV_LOG(ERR, "%s hash key failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    opcode == SPNIC_CMD_OP_SET ? "Set" : "Get",
			    err, hash_key.msg_head.status, out_size);
		return -EFAULT;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		memcpy(key, hash_key.key, SPNIC_RSS_KEY_SIZE);

	return 0;
}

int spnic_rss_set_hash_key(void *hwdev, u8 *key)
{
	if (!hwdev || !key)
		return -EINVAL;

	return spnic_rss_cfg_hash_key(hwdev, SPNIC_CMD_OP_SET, key);
}

int spnic_rss_get_hash_key(void *hwdev, u8 *key)
{
	if (!hwdev || !key)
		return -EINVAL;

	return spnic_rss_cfg_hash_key(hwdev, SPNIC_CMD_OP_GET, key);
}

int spnic_rss_get_indir_tbl(void *hwdev, u32 *indir_table)
{
	struct spnic_cmd_buf *cmd_buf = NULL;
	u16 *indir_tbl = NULL;
	int err, i;

	if (!hwdev || !indir_table)
		return -EINVAL;

	cmd_buf = spnic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf failed");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(struct nic_rss_indirect_tbl);
	err = spnic_cmdq_detail_resp(hwdev, SPNIC_MOD_L2NIC,
				     SPNIC_UCODE_CMD_GET_RSS_INDIR_TABLE,
				     cmd_buf, cmd_buf, 0);
	if (err) {
		PMD_DRV_LOG(ERR, "Get rss indir table failed");
		spnic_free_cmd_buf(cmd_buf);
		return err;
	}

	indir_tbl = (u16 *)cmd_buf->buf;
	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
		indir_table[i] = *(indir_tbl + i);

	spnic_free_cmd_buf(cmd_buf);
	return 0;
}

int spnic_rss_set_indir_tbl(void *hwdev, const u32 *indir_table)
{
	struct nic_rss_indirect_tbl *indir_tbl = NULL;
	struct spnic_cmd_buf *cmd_buf = NULL;
	u32 i, size;
	u32 *temp = NULL;
	u64 out_param = 0;
	int err;

	if (!hwdev || !indir_table)
		return -EINVAL;

	cmd_buf = spnic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf failed");
		return -ENOMEM;
	}

	cmd_buf->size = sizeof(struct nic_rss_indirect_tbl);
	indir_tbl = (struct nic_rss_indirect_tbl *)cmd_buf->buf;
	memset(indir_tbl, 0, sizeof(*indir_tbl));

	for (i = 0; i < SPNIC_RSS_INDIR_SIZE; i++)
		indir_tbl->entry[i] = (u16)(*(indir_table + i));

	size = (sizeof(indir_tbl->entry)) / (sizeof(u32));
	temp = (u32 *)indir_tbl->entry;
	for (i = 0; i < size; i++)
		temp[i] = cpu_to_be32(temp[i]);

	err = spnic_cmdq_direct_resp(hwdev, SPNIC_MOD_L2NIC,
				     SPNIC_UCODE_CMD_SET_RSS_INDIR_TABLE,
				     cmd_buf, &out_param, 0);
	if (err || out_param != 0) {
		PMD_DRV_LOG(ERR, "Set rss indir table failed");
		err = -EFAULT;
	}

	spnic_free_cmd_buf(cmd_buf);
	return err;
}

int spnic_set_rss_type(void *hwdev, struct spnic_rss_type rss_type)
{
	struct nic_rss_context_tbl *ctx_tbl = NULL;
	struct spnic_cmd_buf *cmd_buf = NULL;
	u32 ctx = 0;
	u64 out_param = 0;
	int err;

	if (!hwdev)
		return -EINVAL;

	cmd_buf = spnic_alloc_cmd_buf(hwdev);
	if (!cmd_buf) {
		PMD_DRV_LOG(ERR, "Allocate cmd buf failed");
		return -ENOMEM;
	}

	ctx |= SPNIC_RSS_TYPE_SET(1, VALID) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv4, IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv6, IPV6) |
	       SPNIC_RSS_TYPE_SET(rss_type.ipv6_ext, IPV6_EXT) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv4, TCP_IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv6, TCP_IPV6) |
	       SPNIC_RSS_TYPE_SET(rss_type.tcp_ipv6_ext, TCP_IPV6_EXT) |
	       SPNIC_RSS_TYPE_SET(rss_type.udp_ipv4, UDP_IPV4) |
	       SPNIC_RSS_TYPE_SET(rss_type.udp_ipv6, UDP_IPV6);

	cmd_buf->size = sizeof(struct nic_rss_context_tbl);
	ctx_tbl = (struct nic_rss_context_tbl *)cmd_buf->buf;
	memset(ctx_tbl, 0, sizeof(*ctx_tbl));
	ctx_tbl->ctx = cpu_to_be32(ctx);

	/* Cfg the RSS context table by command queue */
	err = spnic_cmdq_direct_resp(hwdev, SPNIC_MOD_L2NIC,
				     SPNIC_UCODE_CMD_SET_RSS_CONTEXT_TABLE,
				     cmd_buf, &out_param, 0);

	spnic_free_cmd_buf(cmd_buf);

	if (err || out_param != 0) {
		PMD_DRV_LOG(ERR, "Set rss context table failed, err: %d", err);
		return -EFAULT;
	}

	return 0;
}

int spnic_get_rss_type(void *hwdev, struct spnic_rss_type *rss_type)
{
	struct spnic_rss_context_table ctx_tbl;
	u16 out_size = sizeof(ctx_tbl);
	int err;

	if (!hwdev || !rss_type)
		return -EINVAL;

	memset(&ctx_tbl, 0, sizeof(struct spnic_rss_context_table));
	ctx_tbl.func_id = spnic_global_func_id(hwdev);

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_GET_RSS_CTX_TBL,
				     &ctx_tbl, sizeof(ctx_tbl),
				     &ctx_tbl, &out_size);
	if (err || !out_size || ctx_tbl.msg_head.status) {
		PMD_DRV_LOG(ERR, "Get hash type failed, err: %d, status: 0x%x, out size: 0x%x",
			    err, ctx_tbl.msg_head.status, out_size);
		return -EFAULT;
	}

	rss_type->ipv4	       = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV4);
	rss_type->ipv6	       = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV6);
	rss_type->ipv6_ext     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, IPV6_EXT);
	rss_type->tcp_ipv4     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV4);
	rss_type->tcp_ipv6     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, TCP_IPV6);
	rss_type->tcp_ipv6_ext = SPNIC_RSS_TYPE_GET(ctx_tbl.context,
						     TCP_IPV6_EXT);
	rss_type->udp_ipv4     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV4);
	rss_type->udp_ipv6     = SPNIC_RSS_TYPE_GET(ctx_tbl.context, UDP_IPV6);

	return 0;
}

static int spnic_rss_cfg_hash_engine(void *hwdev, u8 opcode, u8 *type)
{
	struct spnic_cmd_rss_engine_type hash_type;
	u16 out_size = sizeof(hash_type);
	int err;

	if (!hwdev || !type)
		return -EINVAL;

	memset(&hash_type, 0, sizeof(struct spnic_cmd_rss_engine_type));
	hash_type.func_id = spnic_global_func_id(hwdev);
	hash_type.opcode = opcode;
	if (opcode == SPNIC_CMD_OP_SET)
		hash_type.hash_engine = *type;

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_CFG_RSS_HASH_ENGINE,
				     &hash_type, sizeof(hash_type),
				     &hash_type, &out_size);
	if (err || !out_size || hash_type.msg_head.status) {
		PMD_DRV_LOG(ERR, "%s hash engine failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    opcode == SPNIC_CMD_OP_SET ? "Set" : "Get",
			    err, hash_type.msg_head.status, out_size);
		return -EFAULT;
	}

	if (opcode == SPNIC_CMD_OP_GET)
		*type = hash_type.hash_engine;

	return 0;
}

int spnic_rss_get_hash_engine(void *hwdev, u8 *type)
{
	if (!hwdev || !type)
		return -EINVAL;

	return spnic_rss_cfg_hash_engine(hwdev, SPNIC_CMD_OP_GET, type);
}

int spnic_rss_set_hash_engine(void *hwdev, u8 type)
{
	if (!hwdev)
		return -EINVAL;

	return spnic_rss_cfg_hash_engine(hwdev, SPNIC_CMD_OP_SET, &type);
}

int spnic_rss_cfg(void *hwdev, u8 rss_en, u8 tc_num, u8 *prio_tc)
{
	struct spnic_cmd_rss_config rss_cfg;
	u16 out_size = sizeof(rss_cfg);
	int err;

	/* Ucode requires number of TC should be power of 2 */
	if (!hwdev || !prio_tc || (tc_num & (tc_num - 1)))
		return -EINVAL;

	memset(&rss_cfg, 0, sizeof(struct spnic_cmd_rss_config));
	rss_cfg.func_id = spnic_global_func_id(hwdev);
	rss_cfg.rss_en = rss_en;
	rss_cfg.rq_priority_number = tc_num ? (u8)ilog2(tc_num) : 0;

	memcpy(rss_cfg.prio_tc, prio_tc, SPNIC_DCB_UP_MAX);
	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_RSS_CFG, &rss_cfg,
				     sizeof(rss_cfg), &rss_cfg, &out_size);
	if (err || !out_size || rss_cfg.msg_head.status) {
		PMD_DRV_LOG(ERR, "Set rss cfg failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, rss_cfg.msg_head.status, out_size);
		return -EFAULT;
	}

	return 0;
}

int spnic_vf_get_default_cos(void *hwdev, u8 *cos_id)
{
	struct spnic_cmd_vf_dcb_state vf_dcb;
	u16 out_size = sizeof(vf_dcb);
	int err;

	memset(&vf_dcb, 0, sizeof(vf_dcb));

	err = l2nic_msg_to_mgmt_sync(hwdev, SPNIC_CMD_VF_COS, &vf_dcb,
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
