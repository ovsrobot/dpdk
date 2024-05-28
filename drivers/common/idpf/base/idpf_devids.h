/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2024 Intel Corporation
 */

#ifndef _IDPF_DEVIDS_H_
#define _IDPF_DEVIDS_H_

#ifndef LINUX_SUPPORT
/* Vendor ID */
#define IDPF_INTEL_VENDOR_ID		0x8086
#endif /* LINUX_SUPPORT */

/* Device IDs */
#define IDPF_DEV_ID_PF			0x1452
#define IDPF_DEV_ID_VF			0x145C
#ifdef SIOV_SUPPORT
#define IDPF_DEV_ID_VF_SIOV		0x0DD5
#endif /* SIOV_SUPPORT */

#endif /* _IDPF_DEVIDS_H_ */
