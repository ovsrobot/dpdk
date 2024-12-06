/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 ZTE Corporation
 */

#include "zxdh_ethdev.h"
#include "zxdh_msg.h"
#include "zxdh_np.h"
#include "zxdh_tables.h"
#include "zxdh_logs.h"

#define ZXDH_SDT_VPORT_ATT_TABLE          1
#define ZXDH_SDT_PANEL_ATT_TABLE          2
#define ZXDH_SDT_BROCAST_ATT_TABLE        6
#define ZXDH_SDT_UNICAST_ATT_TABLE        10
#define ZXDH_SDT_MULTICAST_ATT_TABLE      11

#define ZXDH_MAC_HASH_INDEX_BASE          64
#define ZXDH_MAC_HASH_INDEX(index)        (ZXDH_MAC_HASH_INDEX_BASE + (index))
#define ZXDH_MC_GROUP_NUM                 4
#define ZXDH_BASE_VFID                    1152
#define ZXDH_TABLE_HIT_FLAG               128

int zxdh_set_port_attr(uint16_t vfid, struct zxdh_port_attr_table *port_attr)
{
	int ret = 0;

	ZXDH_DTB_ERAM_ENTRY_INFO_T entry = {vfid, (uint32_t *)port_attr};
	ZXDH_DTB_USER_ENTRY_T user_entry_write = {ZXDH_SDT_VPORT_ATT_TABLE, (void *)&entry};

	ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &user_entry_write);
	if (ret != 0)
		PMD_DRV_LOG(ERR, "write vport_att failed vfid:%d failed", vfid);

	return ret;
}

int zxdh_get_port_attr(uint16_t vfid, struct zxdh_port_attr_table *port_attr)
{
	int ret = 0;

	ZXDH_DTB_ERAM_ENTRY_INFO_T entry = {vfid, (uint32_t *)port_attr};
	ZXDH_DTB_USER_ENTRY_T user_entry_get = {ZXDH_SDT_VPORT_ATT_TABLE, &entry};

	ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO, g_dtb_data.queueid, &user_entry_get, 1);
	if (ret != 0)
		PMD_DRV_LOG(ERR, "get port_attr vfid:%d failed, ret:%d ", vfid, ret);

	return ret;
}

int
zxdh_port_attr_init(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct zxdh_port_attr_table port_attr = {0};
	struct zxdh_msg_info msg_info = {0};
	int ret = 0;

	if (hw->is_pf) {
		port_attr.hit_flag = 1;
		port_attr.phy_port = hw->phyport;
		port_attr.pf_vfid = zxdh_vport_to_vfid(hw->vport);
		port_attr.rss_enable = 0;
		if (!hw->is_pf)
			port_attr.is_vf = 1;

		port_attr.mtu = dev->data->mtu;
		port_attr.mtu_enable = 1;
		port_attr.is_up = 0;
		if (!port_attr.rss_enable)
			port_attr.port_base_qid = 0;

		ret = zxdh_set_port_attr(hw->vfid, &port_attr);
		if (ret) {
			PMD_DRV_LOG(ERR, "write port_attr failed");
			return -EAGAIN;
		}
	} else {
		struct zxdh_vf_init_msg *vf_init_msg = &msg_info.data.vf_init_msg;

		zxdh_msg_head_build(hw, ZXDH_VF_PORT_INIT, &msg_info);
		msg_info.msg_head.msg_type = ZXDH_VF_PORT_INIT;
		vf_init_msg->link_up = 1;
		vf_init_msg->base_qid = 0;
		vf_init_msg->rss_enable = 0;
		ret = zxdh_vf_send_msg_to_pf(dev, &msg_info, sizeof(msg_info), NULL, 0);
		if (ret) {
			PMD_DRV_LOG(ERR, "vf port_init failed");
			return -EAGAIN;
		}
	}
	return ret;
};

int
zxdh_port_attr_uninit(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	struct zxdh_msg_info msg_info = {0};
	struct zxdh_port_attr_table port_attr = {0};
	int ret = 0;

	if (hw->is_pf == 1) {
		ZXDH_DTB_ERAM_ENTRY_INFO_T port_attr_entry = {hw->vfid, (uint32_t *)&port_attr};
		ZXDH_DTB_USER_ENTRY_T entry = {
			.sdt_no = ZXDH_SDT_VPORT_ATT_TABLE,
			.p_entry_data = (void *)&port_attr_entry
		};
		ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO, g_dtb_data.queueid, 1, &entry);
		if (ret) {
			PMD_DRV_LOG(ERR, "delete port attr table failed");
			return -ret;
		}
	} else {
		zxdh_msg_head_build(hw, ZXDH_VF_PORT_UNINIT, &msg_info);
		ret = zxdh_vf_send_msg_to_pf(dev, &msg_info, sizeof(msg_info), NULL, 0);
		if (ret) {
			PMD_DRV_LOG(ERR, "vf port tables uninit failed");
			return -ret;
		}
	}
	return ret;
}

int
zxdh_panel_table_init(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;

	if (!hw->is_pf)
		return 0;

	struct zxdh_panel_table panel;

	memset(&panel, 0, sizeof(panel));
	panel.hit_flag = 1;
	panel.pf_vfid = zxdh_vport_to_vfid(hw->vport);
	panel.mtu_enable = 1;
	panel.mtu = dev->data->mtu;

	ZXDH_DTB_ERAM_ENTRY_INFO_T panel_entry = {
		.index = hw->phyport,
		.p_data = (uint32_t *)&panel
	};
	ZXDH_DTB_USER_ENTRY_T entry = {
		.sdt_no = ZXDH_SDT_PANEL_ATT_TABLE,
		.p_entry_data = (void *)&panel_entry
	};
	int ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO, g_dtb_data.queueid, 1, &entry);

	if (ret) {
		PMD_DRV_LOG(ERR, "Insert eram-panel failed, code:%u", ret);
		return -EAGAIN;
	}

	return ret;
}

int
zxdh_set_mac_table(uint16_t vport, struct rte_ether_addr *addr,  uint8_t hash_search_idx)
{
	struct zxdh_mac_unicast_table unicast_table = {0};
	struct zxdh_mac_multicast_table multicast_table = {0};
	union zxdh_virport_num vport_num = (union zxdh_virport_num)vport;
	uint32_t ret;
	uint16_t group_id = 0;

	if (rte_is_unicast_ether_addr(addr)) {
		rte_memcpy(unicast_table.key.dmac_addr, addr, sizeof(struct rte_ether_addr));
		unicast_table.entry.hit_flag = 0;
		unicast_table.entry.vfid = vport_num.vfid;

		ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
			.p_actu_key = (uint8_t *)&unicast_table.key,
			.p_rst = (uint8_t *)&unicast_table.entry
		};
		ZXDH_DTB_USER_ENTRY_T entry_get = {
			.sdt_no = ZXDH_MAC_HASH_INDEX(hash_search_idx),
			.p_entry_data = (void *)&dtb_hash_entry
		};

		ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_get);
		if (ret) {
			PMD_DRV_LOG(ERR, "Insert mac_table failed");
			return -ret;
		}
	} else {
		for (group_id = 0; group_id < 4; group_id++) {
			multicast_table.key.vf_group_id = group_id;
			rte_memcpy(multicast_table.key.mac_addr, addr,
				sizeof(struct rte_ether_addr));
			ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
				.p_actu_key = (uint8_t *)&multicast_table.key,
				.p_rst = (uint8_t *)&multicast_table.entry
			};

			ZXDH_DTB_USER_ENTRY_T entry_get = {
				.sdt_no = ZXDH_MAC_HASH_INDEX(hash_search_idx),
				.p_entry_data = (void *)&dtb_hash_entry
			};

			ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO, g_dtb_data.queueid,
					&entry_get, 1);
			uint8_t index = (vport_num.vfid % 64) / 32;
			if (ret == 0) {
				if (vport_num.vf_flag) {
					if (group_id == vport_num.vfid / 64)
						multicast_table.entry.mc_bitmap[index] |=
							rte_cpu_to_be_32(UINT32_C(1) <<
							(31 - (vport_num.vfid % 64) % 32));
				} else {
					if (group_id == vport_num.vfid / 64)
						multicast_table.entry.mc_pf_enable =
							rte_cpu_to_be_32((1 << 30));
				}
			} else {
				if (vport_num.vf_flag) {
					if (group_id == vport_num.vfid / 64)
						multicast_table.entry.mc_bitmap[index] |=
							rte_cpu_to_be_32(UINT32_C(1) <<
							(31 - (vport_num.vfid % 64) % 32));
					else
						multicast_table.entry.mc_bitmap[index] = false;
				} else {
					if (group_id == vport_num.vfid / 64)
						multicast_table.entry.mc_pf_enable =
							rte_cpu_to_be_32((1 << 30));
					else
						multicast_table.entry.mc_pf_enable = false;
				}
			}

			ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO, g_dtb_data.queueid,
						1, &entry_get);
			if (ret) {
				PMD_DRV_LOG(ERR, "add mac_table failed, code:%d", ret);
				return -ret;
			}
		}
	}
	return 0;
}

int
zxdh_del_mac_table(uint16_t vport, struct rte_ether_addr *addr,  uint8_t hash_search_idx)
{
	struct zxdh_mac_unicast_table unicast_table = {0};
	struct zxdh_mac_multicast_table multicast_table = {0};
	union zxdh_virport_num vport_num = (union zxdh_virport_num)vport;
	uint32_t ret, del_flag = 0;
	uint16_t group_id = 0;

	if (rte_is_unicast_ether_addr(addr)) {
		rte_memcpy(unicast_table.key.dmac_addr, addr, sizeof(struct rte_ether_addr));
		unicast_table.entry.hit_flag = 0;
		unicast_table.entry.vfid = vport_num.vfid;

		ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
			.p_actu_key = (uint8_t *)&unicast_table.key,
			.p_rst = (uint8_t *)&unicast_table.entry
		};

		ZXDH_DTB_USER_ENTRY_T entry_get = {
			.sdt_no = ZXDH_MAC_HASH_INDEX(hash_search_idx),
			.p_entry_data = (void *)&dtb_hash_entry
		};

		ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO,
					g_dtb_data.queueid, 1, &entry_get);
		if (ret) {
			PMD_DRV_LOG(ERR, "delete l2_fwd_hash_table failed, code:%d", ret);
			return -ret;
		}
	} else {
		multicast_table.key.vf_group_id = vport_num.vfid / 64;
		rte_memcpy(multicast_table.key.mac_addr, addr, sizeof(struct rte_ether_addr));

		ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
			.p_actu_key = (uint8_t *)&multicast_table.key,
			.p_rst = (uint8_t *)&multicast_table.entry
		};

		ZXDH_DTB_USER_ENTRY_T entry_get = {
			.sdt_no = ZXDH_MAC_HASH_INDEX(hash_search_idx),
			.p_entry_data = (void *)&dtb_hash_entry
		};
		uint8_t index = (vport_num.vfid % 64) / 32;

		ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, &entry_get, 1);
		if (vport_num.vf_flag)
			multicast_table.entry.mc_bitmap[index] &=
				~(rte_cpu_to_be_32(UINT32_C(1) <<
				(31 - (vport_num.vfid % 64) % 32)));
		else
			multicast_table.entry.mc_pf_enable = 0;

		ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_get);
		if (ret) {
			PMD_DRV_LOG(ERR, "mac_addr_add mc_table failed, code:%d", ret);
			return -ret;
		}

		for (group_id = 0; group_id < ZXDH_MC_GROUP_NUM; group_id++) {
			multicast_table.key.vf_group_id = group_id;
			rte_memcpy(multicast_table.key.mac_addr, addr,
				sizeof(struct rte_ether_addr));
			ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
				.p_actu_key = (uint8_t *)&multicast_table.key,
				.p_rst = (uint8_t *)&multicast_table.entry
			};
			ZXDH_DTB_USER_ENTRY_T entry_get = {
				.sdt_no = ZXDH_MAC_HASH_INDEX(hash_search_idx),
				.p_entry_data = (void *)&dtb_hash_entry
			};

			ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO, g_dtb_data.queueid,
						&entry_get, 1);
			if (multicast_table.entry.mc_bitmap[0] == 0 &&
				multicast_table.entry.mc_bitmap[1] == 0 &&
				multicast_table.entry.mc_pf_enable == 0) {
				if (group_id == (ZXDH_MC_GROUP_NUM - 1))
					del_flag = 1;
			} else {
				break;
			}
		}
		if (del_flag) {
			for (group_id = 0; group_id < ZXDH_MC_GROUP_NUM; group_id++) {
				multicast_table.key.vf_group_id = group_id;
				rte_memcpy(multicast_table.key.mac_addr, addr,
					sizeof(struct rte_ether_addr));
				ZXDH_DTB_HASH_ENTRY_INFO_T dtb_hash_entry = {
					.p_actu_key  = (uint8_t *)&multicast_table.key,
					.p_rst = (uint8_t *)&multicast_table.entry
				};
				ZXDH_DTB_USER_ENTRY_T entry_get = {
					.sdt_no  = ZXDH_MAC_HASH_INDEX(hash_search_idx),
					.p_entry_data = (void *)&dtb_hash_entry
				};
				ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO,
						g_dtb_data.queueid, 1, &entry_get);
			}
		}
	}
	return 0;
}

int zxdh_promisc_table_init(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint32_t ret, vf_group_id = 0;
	struct zxdh_brocast_table brocast_table = {0};
	struct zxdh_unitcast_table uc_table = {0};
	struct zxdh_multicast_table mc_table = {0};

	if (!hw->is_pf)
		return 0;

	for (; vf_group_id < 4; vf_group_id++) {
		brocast_table.flag = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_brocast_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&brocast_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_brocast = {
			.sdt_no = ZXDH_SDT_BROCAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_brocast_entry
		};

		ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_brocast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write brocast table failed");
			return ret;
		}

		uc_table.uc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_uc_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&uc_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_unicast = {
			.sdt_no = ZXDH_SDT_UNICAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_uc_entry
		};

		ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_unicast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write unicast table failed");
			return ret;
		}

		mc_table.mc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_mc_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&mc_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_multicast = {
			.sdt_no = ZXDH_SDT_MULTICAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_mc_entry
		};

		ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO, g_dtb_data.queueid,
					1, &entry_multicast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write multicast table failed");
			return ret;
		}
	}

	return ret;
}

int zxdh_promisc_table_uninit(struct rte_eth_dev *dev)
{
	struct zxdh_hw *hw = dev->data->dev_private;
	uint32_t ret, vf_group_id = 0;
	struct zxdh_brocast_table brocast_table = {0};
	struct zxdh_unitcast_table uc_table = {0};
	struct zxdh_multicast_table mc_table = {0};

	if (!hw->is_pf)
		return 0;

	for (; vf_group_id < 4; vf_group_id++) {
		brocast_table.flag = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_brocast_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&brocast_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_brocast = {
			.sdt_no = ZXDH_SDT_BROCAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_brocast_entry
		};

		ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_brocast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write brocast table failed");
			return ret;
		}

		uc_table.uc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_uc_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&uc_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_unicast = {
			.sdt_no = ZXDH_SDT_UNICAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_uc_entry
		};

		ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO,
				g_dtb_data.queueid, 1, &entry_unicast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write unicast table failed");
			return ret;
		}

		mc_table.mc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG);
		ZXDH_DTB_ERAM_ENTRY_INFO_T eram_mc_entry = {
			.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vf_group_id,
			.p_data = (uint32_t *)&mc_table
		};
		ZXDH_DTB_USER_ENTRY_T entry_multicast = {
			.sdt_no = ZXDH_SDT_MULTICAST_ATT_TABLE,
			.p_entry_data = (void *)&eram_mc_entry
		};

		ret = zxdh_np_dtb_table_entry_delete(ZXDH_DEVICE_NO, g_dtb_data.queueid,
					1, &entry_multicast);
		if (ret) {
			PMD_DRV_LOG(ERR, "write multicast table failed");
			return ret;
		}
	}

	return ret;
}

int zxdh_dev_unicast_table_set(struct zxdh_hw *hw, uint16_t vport, bool enable)
{
	int16_t ret = 0;
	struct zxdh_unitcast_table uc_table = {0};
	union zxdh_virport_num vport_num = (union zxdh_virport_num)vport;

	ZXDH_DTB_ERAM_ENTRY_INFO_T uc_table_entry = {
		.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vport_num.vfid / 64,
		.p_data = (uint32_t *)&uc_table
	};
	ZXDH_DTB_USER_ENTRY_T entry = {
		.sdt_no = ZXDH_SDT_UNICAST_ATT_TABLE,
		.p_entry_data = (void *)&uc_table_entry
	};

	ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO, g_dtb_data.queueid, &entry, 1);
	if (ret) {
		PMD_DRV_LOG(ERR, "unicast_table_get_failed:%d", hw->vfid);
		return -ret;
	}

	if (vport_num.vf_flag) {
		if (enable)
			uc_table.bitmap[(vport_num.vfid % 64) / 32] |=
					UINT32_C(1) << (31 - (vport_num.vfid % 64) % 32);
		else
			uc_table.bitmap[(vport_num.vfid % 64) / 32] &=
					~(UINT32_C(1) << (31 - (vport_num.vfid % 64) % 32));
	} else {
		uc_table.uc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG + (enable << 6));
	}

	ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO, g_dtb_data.queueid, 1, &entry);
	if (ret) {
		PMD_DRV_LOG(ERR, "unicast_table_set_failed:%d",  hw->vfid);
		return -ret;
	}
	return 0;
}

int zxdh_dev_multicast_table_set(struct zxdh_hw *hw, uint16_t vport, bool enable)
{
	int16_t ret = 0;
	struct zxdh_multicast_table mc_table = {0};
	union zxdh_virport_num vport_num = (union zxdh_virport_num)vport;

	ZXDH_DTB_ERAM_ENTRY_INFO_T mc_table_entry = {
		.index = ((hw->vfid - ZXDH_BASE_VFID) << 2) + vport_num.vfid / 64,
		.p_data = (uint32_t *)&mc_table
	};
	ZXDH_DTB_USER_ENTRY_T entry = {
		.sdt_no = ZXDH_SDT_MULTICAST_ATT_TABLE,
		.p_entry_data = (void *)&mc_table_entry
	};

	ret = zxdh_np_dtb_table_entry_get(ZXDH_DEVICE_NO, g_dtb_data.queueid, &entry, 1);
	if (ret) {
		PMD_DRV_LOG(ERR, "allmulti_table_get_failed:%d", hw->vfid);
		return -ret;
	}

	if (vport_num.vf_flag) {
		if (enable)
			mc_table.bitmap[(vport_num.vfid % 64) / 32] |=
					UINT32_C(1) << (31 - (vport_num.vfid % 64) % 32);
		else
			mc_table.bitmap[(vport_num.vfid % 64) / 32] &=
					~(UINT32_C(1) << (31 - (vport_num.vfid % 64) % 32));

	} else {
		mc_table.mc_flood_pf_enable = rte_be_to_cpu_32(ZXDH_TABLE_HIT_FLAG + (enable << 6));
	}
	ret = zxdh_np_dtb_table_entry_write(ZXDH_DEVICE_NO, g_dtb_data.queueid, 1, &entry);
	if (ret) {
		PMD_DRV_LOG(ERR, "allmulti_table_set_failed:%d", hw->vfid);
		return -ret;
	}
	return 0;
}
