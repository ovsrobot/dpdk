/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __SXE_HDC_H__
#define __SXE_HDC_H__

#ifdef SXE_HOST_DRIVER
#include "sxe_drv_type.h"
#endif

#define HDC_CACHE_TOTAL_LEN	 (16 * 1024)
#define ONE_PACKET_LEN_MAX	  (1024)
#define DWORD_NUM			   (256)
#define HDC_TRANS_RETRY_COUNT   (3)


typedef enum sxe_hdc_errno_code {
	PKG_OK			= 0,
	PKG_ERR_REQ_LEN,
	PKG_ERR_RESP_LEN,
	PKG_ERR_PKG_SKIP,
	PKG_ERR_NODATA,
	PKG_ERR_PF_LK,
	PKG_ERR_OTHER,
} sxe_hdc_errno_code_e;

typedef union hdc_header {
	struct {
		u8 pid:4;
		u8 err_code:4;
		u8 len;
		u16 start_pkg:1;
		u16 end_pkg:1;
		u16 is_rd:1;
		u16 msi:1;
		u16 total_len:12;
	} head;
	u32 dw0;
} hdc_header_u;

#endif
