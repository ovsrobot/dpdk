/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_DCB_H__
#define __SXE_DCB_H__
#include <stdbool.h>

#define PBA_STRATEGY_EQUAL	   (0)
#define PBA_STRATEGY_WEIGHTED	(1)
#define MAX_BW_GROUP			 8
#define MAX_USER_PRIORITY		8
#define SXE_DCB_MAX_TRAFFIC_CLASS		8

enum sxe_dcb_strict_prio_type {
	DCB_PRIO_NONE = 0,
	DCB_PRIO_GROUP,
	DCB_PRIO_LINK
};
enum {
	DCB_PATH_TX   =  0,
	DCB_PATH_RX   =  1,
	DCB_PATH_NUM  =  DCB_PATH_RX + 1,
};

enum sxe_dcb_tsa {
	sxe_dcb_tsa_ets = 0,
	sxe_dcb_tsa_group_strict_cee,
	sxe_dcb_tsa_strict
};

enum sxe_dcb_pba_config {
	SXE_DCB_PBA_EQUAL = PBA_STRATEGY_EQUAL,
	SXE_DCB_PBA_80_48 = PBA_STRATEGY_WEIGHTED
};

struct sxe_dcb_num_tcs {
	u8 pg_tcs;
	u8 pfc_tcs;
};

struct sxe_tc_bw_alloc {
	u8 bwg_id;
	u8 bwg_percent;
	u8 link_percent;
	u8 up_to_tc_bitmap;
	u16 data_credits_refill;
	u16 data_credits_max;
	enum sxe_dcb_strict_prio_type prio_type;
};

enum sxe_dcb_pfc_type {
	pfc_disabled = 0,
	pfc_enabled_full,
	pfc_enabled_tx,
	pfc_enabled_rx
};

struct sxe_tc_config {
	struct sxe_tc_bw_alloc channel[DCB_PATH_NUM];
	enum sxe_dcb_pfc_type  pfc_type;

	u16 desc_credits_max;
	u8 tc;
};

struct sxe_dcb_config {
	struct sxe_tc_config tc_config[SXE_DCB_MAX_TRAFFIC_CLASS];
	struct sxe_dcb_num_tcs num_tcs;
	u8 bwg_link_percent[DCB_PATH_NUM][MAX_BW_GROUP];
	bool pfc_mode_enable;
	bool round_robin_enable;

	enum sxe_dcb_pba_config rx_pba_config;
	bool vmdq_active;
};

struct sxe_bw_config {
	u8 tc_num;
};

struct sxe_dcb_context {
	struct sxe_dcb_config config;
	struct sxe_bw_config bw_config;
};

void sxe_dcb_init(struct rte_eth_dev *dev);

s32 sxe_priority_flow_ctrl_set(struct rte_eth_dev *dev,
					struct rte_eth_pfc_conf *pfc_conf);

s32 sxe_get_dcb_info(struct rte_eth_dev *dev,
			struct rte_eth_dcb_info *dcb_info);

void sxe_dcb_configure(struct rte_eth_dev *dev);

void sxe_dcb_vmdq_rx_hw_configure(struct rte_eth_dev *dev);

#endif
