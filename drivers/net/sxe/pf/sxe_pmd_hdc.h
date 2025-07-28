/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_HOST_HDC_H__
#define __SXE_HOST_HDC_H__

#include "sxe_hdc.h"
#include "sxe_hw.h"
#include "sxe_errno.h"

#define SXE_HDC_SUCCESS			  0
#define SXE_HDC_FALSE				SXE_ERR_HDC(1)
#define SXE_HDC_INVAL_PARAM		  SXE_ERR_HDC(2)
#define SXE_HDC_BUSY				 SXE_ERR_HDC(3)
#define SXE_HDC_FW_OPS_FAILED		SXE_ERR_HDC(4)
#define SXE_HDC_FW_OV_TIMEOUT		SXE_ERR_HDC(5)
#define SXE_HDC_REQ_ACK_HEAD_ERR	 SXE_ERR_HDC(6)
#define SXE_HDC_REQ_ACK_TLEN_ERR	 SXE_ERR_HDC(7)
#define SXE_HDC_PKG_SKIP_ERR		 SXE_ERR_HDC(8)
#define SXE_HDC_PKG_OTHER_ERR		SXE_ERR_HDC(9)
#define SXE_HDC_RETRY_ERR			SXE_ERR_HDC(10)
#define SXE_FW_STATUS_ERR			SXE_ERR_HDC(11)

struct sxe_hdc_data_info {
	u8 *data;
	u16 len;
};

struct sxe_hdc_trans_info {
	struct sxe_hdc_data_info in;
	struct sxe_hdc_data_info out;
};

s32 sxe_driver_cmd_trans(struct sxe_hw *hw, u16 opcode,
					void *req_data, u16 req_len,
					void *resp_data, u16 resp_len);

void sxe_hdc_channel_init(void);

void sxe_hdc_channel_uninit(void);

s32 sxe_fw_time_sync(struct sxe_hw *hw);

#endif
