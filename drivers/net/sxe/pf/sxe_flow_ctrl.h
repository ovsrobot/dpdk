/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_FLOW_CTRL_H__
#define __SXE_FLOW_CTRL_H__

s32 sxe_flow_ctrl_enable(struct rte_eth_dev *dev);

s32 sxe_flow_ctrl_get(struct rte_eth_dev *dev,
					struct rte_eth_fc_conf *fc_conf);

s32 sxe_flow_ctrl_set(struct rte_eth_dev *dev,
					struct rte_eth_fc_conf *fc_conf);

#endif
