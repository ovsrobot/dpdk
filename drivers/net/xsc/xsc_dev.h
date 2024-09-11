/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_DEV_H_
#define _XSC_DEV_H_

#include <infiniband/verbs.h>

#define XSC_PPH_MODE_ARG "pph_mode"
#define XSC_NIC_MODE_ARG "nic_mode"
#define XSC_FLOW_MODE_ARG "flow_mode"

struct xsc_hwinfo {
	uint8_t valid; /* 1: current phy info is valid, 0 : invalid */
	uint32_t pcie_no; /* pcie number , 0 or 1 */
	uint32_t func_id; /* pf glb func id */
	uint32_t pcie_host; /* host pcie number */
	uint32_t mac_phy_port; /* mac port */
	uint32_t funcid_to_logic_port_off; /* port func id offset  */
	uint16_t lag_id;
	uint16_t raw_qp_id_base;
	uint16_t raw_rss_qp_id_base;
	uint16_t pf0_vf_funcid_base;
	uint16_t pf0_vf_funcid_top;
	uint16_t pf1_vf_funcid_base;
	uint16_t pf1_vf_funcid_top;
	uint16_t pcie0_pf_funcid_base;
	uint16_t pcie0_pf_funcid_top;
	uint16_t pcie1_pf_funcid_base;
	uint16_t pcie1_pf_funcid_top;
	uint16_t lag_port_start;
	uint16_t raw_tpe_qp_num;
	int send_seg_num;
	int recv_seg_num;
	uint8_t on_chip_tbl_vld;
	uint8_t dma_rw_tbl_vld;
	uint8_t pct_compress_vld;
	uint32_t chip_version;
	uint32_t hca_core_clock;
	uint8_t mac_bit;
	uint8_t esw_mode;
};

struct xsc_devargs {
	int nic_mode;
	int flow_mode;
	int pph_mode;
};

struct xsc_dev {
	struct rte_pci_device *pci_dev;
	struct xsc_devargs devargs;
	struct xsc_hwinfo hwinfo;
	struct ibv_context *ibv_ctx;
	struct ibv_pd *ibv_pd;
	char ibv_name[IBV_SYSFS_NAME_MAX];
	void *bar_addr;
	uint64_t bar_len;
	int ctrl_fd;
};

int xsc_dev_init(struct rte_pci_device *pci_dev, struct xsc_dev **dev);
void xsc_dev_uninit(struct xsc_dev *dev);

#endif /* _XSC_DEV_H_ */
