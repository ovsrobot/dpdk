/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef XSC_DEFS_H_
#define XSC_DEFS_H_

#define XSC_PCI_VENDOR_ID		0x1f67
#define XSC_PCI_DEV_ID_MS		0x1111

#define XSC_VFREP_BASE_LOGICAL_PORT 1081



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

enum xsc_funcid_type {
	XSC_FUNCID_TYPE_INVAL	= 0x0,
	XSC_EMU_FUNCID		= 0x1,
	XSC_PHYPORT_MAC_FUNCID	= 0x2,
	XSC_VF_IOCTL_FUNCID	= 0x3,
	XSC_PHYPORT_LAG_FUNCID	= 0x4,
	XSC_FUNCID_TYPE_UNKNOWN	= 0x5,
};

enum xsc_phy_port_type {
	XSC_PORT_TYPE_NONE = 0,
	XSC_PORT_TYPE_UPLINK, /* mac0rep */
	XSC_PORT_TYPE_UPLINK_BOND, /* bondrep */
	XSC_PORT_TYPE_PFVF, /*hasreps: vfrep*/
	XSC_PORT_TYPE_PFHPF, /*hasreps: host pf rep*/
	XSC_PORT_TYPE_UNKNOWN,
};

#define XSC_PHY_PORT_NUM 1

#endif /* XSC_DEFS_H_ */

