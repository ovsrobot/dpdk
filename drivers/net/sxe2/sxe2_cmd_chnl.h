/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2025, Wuxi Stars Micro System Technologies Co., Ltd.
 */

#ifndef __SXE2_CMD_CHNL_H__
#define __SXE2_CMD_CHNL_H__

#include "sxe2_ethdev.h"
#include "sxe2_drv_cmd.h"
#include "sxe2_ioctl_chnl_func.h"

s32 sxe2_drv_dev_caps_get(struct sxe2_adapter *adapter,
		struct sxe2_drv_dev_caps_resp *dev_caps);

s32 sxe2_drv_dev_info_get(struct sxe2_adapter *adapter,
		struct sxe2_drv_dev_info_resp *dev_info_resp);

s32 sxe2_drv_dev_fw_info_get(struct sxe2_adapter *adapter,
		struct sxe2_drv_dev_fw_info_resp *dev_fw_info_resp);

s32 sxe2_drv_vsi_add(struct sxe2_adapter *adapter, struct sxe2_vsi *vsi);

s32 sxe2_drv_vsi_del(struct sxe2_adapter *adapter, struct sxe2_vsi *vsi);

s32 sxe2_drv_rxq_switch(struct sxe2_adapter *adapter, struct sxe2_rx_queue *rxq, bool enable);

s32 sxe2_drv_txq_switch(struct sxe2_adapter *adapter, struct sxe2_tx_queue *txq, bool enable);

s32 sxe2_drv_rxq_ctxt_cfg(struct sxe2_adapter *adapter, struct sxe2_rx_queue *rxq, u16 rxq_cnt);

s32 sxe2_drv_txq_ctxt_cfg(struct sxe2_adapter *adapter, struct sxe2_tx_queue *txq, u16 txq_cnt);

#endif
