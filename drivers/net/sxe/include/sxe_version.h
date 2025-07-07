/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C), 2022, Linkdata Technology Co., Ltd.
 */
#ifndef __SXE_VER_H__
#define __SXE_VER_H__

#define SXE_VERSION				"0.0.0.0"
#define SXE_COMMIT_ID			  "852946d"
#define SXE_BRANCH				 "feature/sagitta-1.3.0-P3-dpdk_patch"
#define SXE_BUILD_TIME			 "2025-04-03 17:15:31"

#define SXE_DRV_NAME				   "sxe"
#define SXEVF_DRV_NAME				 "sxevf"
#define SXE_DRV_LICENSE				"GPL v2"
#define SXE_DRV_AUTHOR				 "sxe"
#define SXEVF_DRV_AUTHOR			   "sxevf"
#define SXE_DRV_DESCRIPTION			"sxe driver"
#define SXEVF_DRV_DESCRIPTION		  "sxevf driver"

#define SXE_FW_NAME					 "soc"
#define SXE_FW_ARCH					 "arm32"

#ifndef PS3_CFG_RELEASE
#define PS3_SXE_FW_BUILD_MODE			 "debug"
#else
#define PS3_SXE_FW_BUILD_MODE			 "release"
#endif

#endif
