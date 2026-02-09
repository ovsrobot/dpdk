/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_PHY_H__
#define __SXE_PHY_H__

#include <rte_ethdev.h>
#include "drv_msg.h"
#include "sxe_cli.h"
#include "sxe_msg.h"

#define SXE_SFF_BASE_ADDR			0x0
#define SXE_SFF_IDENTIFIER			0x0
#define SXE_SFF_10GBE_COMP_CODES		0x3
#define SXE_SFF_1GBE_COMP_CODES			0x6
#define SXE_SFF_CABLE_TECHNOLOGY		0x8
#define SXE_SFF_8472_DIAG_MONITOR_TYPE		0x5C
#define SXE_SFF_8472_COMPLIANCE			0x5E

#define SXE_SFF_IDENTIFIER_SFP			0x3
#define SXE_SFF_ADDRESSING_MODE			0x4
#define SXE_SFF_8472_UNSUP			0x0
#define SXE_SFF_DDM_IMPLEMENTED			0x40
#define SXE_SFF_DA_PASSIVE_CABLE		0x4
#define SXE_SFF_DA_ACTIVE_CABLE			0x8
#define SXE_SFF_DA_SPEC_ACTIVE_LIMITING		0x4
#define SXE_SFF_1GBASESX_CAPABLE		0x1
#define SXE_SFF_1GBASELX_CAPABLE		0x2
#define SXE_SFF_1GBASET_CAPABLE			0x8
#define SXE_SFF_10GBASESR_CAPABLE		0x10
#define SXE_SFF_10GBASELR_CAPABLE		0x20

#define SXE_SFP_COMP_CODE_SIZE			10
#define SXE_SFP_EEPROM_SIZE_MAX			512

#define SXE_IRQ_LINK_UPDATE	  ((u32)(1 << 0))
#define SXE_IRQ_LINK_CONFIG	  ((u32)(1 << 3))
struct sxe_adapter;

enum sxe_media_type {
	SXE_MEDIA_TYPE_UNKWON = 0,
	SXE_MEDIA_TYPE_FIBER  = 1,
};

enum sxe_phy_idx {
	SXE_SFP_IDX = 0,
	SXE_PHY_MAX,
};

enum sxe_sfp_type {
	SXE_SFP_TYPE_DA_CU	   = 0,
	SXE_SFP_TYPE_SRLR		= 1,
	SXE_SFP_TYPE_1G_CU	   = 2,
	SXE_SFP_TYPE_1G_SXLX	 = 4,
	SXE_SFP_TYPE_UNKNOWN	 = 0xFFFF,
};

struct sxe_sfp_info {
	enum sxe_sfp_type	type;
	bool			multispeed_fiber;
};

struct sxe_phy_context {
	bool is_sfp;
	bool sfp_tx_laser_disabled;
	u32  speed;
	u32  autoneg_advertised;
	struct sxe_sfp_info sfp_info;
};

s32 sxe_phy_init(struct sxe_adapter *adapter);

s32 sxe_link_update(struct rte_eth_dev *dev, int wait_to_complete);

s32 sxe_link_status_update(struct rte_eth_dev *dev);

void sxe_sfp_tx_laser_enable(struct sxe_adapter *adapter);

void sxe_sfp_tx_laser_disable(struct sxe_adapter *adapter);

int sxe_dev_set_link_up(struct rte_eth_dev *dev);

int sxe_dev_set_link_down(struct rte_eth_dev *dev);

void sxe_wait_setup_link_complete(struct rte_eth_dev *dev,
						uint32_t timeout_ms);

int sxe_get_module_info(struct rte_eth_dev *dev,
			struct rte_eth_dev_module_info *info);

int sxe_get_module_eeprom(struct rte_eth_dev *dev,
				struct rte_dev_eeprom_info *info);
s32 sxe_sfp_identify(struct sxe_adapter *adapter);
s32 sxe_sfp_reset(struct sxe_adapter *adapter);

s32 sxe_pcs_sds_init(struct rte_eth_dev *dev,
				sxe_pcs_mode_e mode, u32 max_frame);

s32 sxe_sfp_rate_select(struct sxe_adapter *adapter, sxe_sfp_rate_e rate);

s32 sxe_multispeed_sfp_link_configure(struct rte_eth_dev *dev, u32 speed, bool is_in_thread);

s32 sxe_conf_speed_get(struct rte_eth_dev *dev, u32 *conf_speeds);

s32 sxe_fc_enable(struct sxe_adapter *adapter);

void sxe_link_info_get(struct sxe_adapter *adapter, u32 *link_speed, bool *link_up);

s32 sxe_pfc_enable(struct sxe_adapter *adapter, u8 tc_idx);

void sxe_sfp_link_capabilities_get(struct sxe_adapter *adapter, u32 *speed,
							bool *autoneg);

s32 sxe_sfp_link_configure(struct rte_eth_dev *dev);

void sxe_mac_configure(struct sxe_adapter *adapter);

#endif
