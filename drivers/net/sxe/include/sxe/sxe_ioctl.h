/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef _SXE_IOCTL_H_
#define _SXE_IOCTL_H_

#ifdef SXE_HOST_DRIVER
#include "sxe_drv_type.h"
#endif

struct sxe_ioctl_sync_cmd {
	U64   traceid;
	void *in_data;
	U32   in_len;
	void *out_data;
	U32   out_len;
};

#define SXE_CMD_IOCTL_SYNC_CMD _IOWR('M', 1, struct sxe_ioctl_sync_cmd)

#endif
