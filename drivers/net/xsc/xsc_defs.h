/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef XSC_DEFS_H_
#define XSC_DEFS_H_

#define XSC_PCI_VENDOR_ID		0x1f67
#define XSC_PCI_DEV_ID_MS		0x1111

enum xsc_nic_mode {
	XSC_NIC_MODE_LEGACY,
	XSC_NIC_MODE_SWITCHDEV,
	XSC_NIC_MODE_SOC,
};

enum xsc_pph_type {
	XSC_PPH_NONE	= 0,
	XSC_RX_PPH	= 0x1,
	XSC_TX_PPH	= 0x2,
	XSC_VFREP_PPH	= 0x4,
	XSC_UPLINK_PPH	= 0x8,
};

enum xsc_flow_mode {
	XSC_FLOW_OFF_HW_ONLY,
	XSC_FLOW_ON_HW_ONLY,
	XSC_FLOW_ON_HW_FIRST,
	XSC_FLOW_HOTSPOT,
	XSC_FLOW_MODE_NULL = 7,
	XSC_FLOW_MODE_MAX,
};

#endif /* XSC_DEFS_H_ */

