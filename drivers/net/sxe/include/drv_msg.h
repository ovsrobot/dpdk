/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */

#ifndef __DRV_MSG_H__
#define __DRV_MSG_H__

#ifdef SXE_HOST_DRIVER
#include "sxe_drv_type.h"
#endif

#define SXE_VERSION_LEN 32

typedef struct sxe_version_resp {
	u8 fw_version[SXE_VERSION_LEN];
} sxe_version_resp_s;

#endif
