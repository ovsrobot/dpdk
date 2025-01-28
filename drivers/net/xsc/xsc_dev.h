/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_DEV_H_
#define _XSC_DEV_H_

#include <rte_ethdev.h>
#include <ethdev_driver.h>
#include <rte_interrupts.h>
#include <rte_bitmap.h>
#include <rte_malloc.h>
#include <bus_pci_driver.h>

#include "xsc_defs.h"
#include "xsc_log.h"

#define XSC_PPH_MODE_ARG	"pph_mode"
#define XSC_NIC_MODE_ARG	"nic_mode"
#define XSC_FLOW_MODE_ARG	"flow_mode"

#define XSC_FUNCID_TYPE_MASK	0x1c000
#define XSC_FUNCID_MASK		0x3fff

#define XSC_DEV_PCT_IDX_INVALID	0xFFFFFFFF
#define XSC_DEV_REPR_ID_INVALID	0x7FFFFFFF

struct xsc_hwinfo {
	uint32_t pcie_no; /* pcie number , 0 or 1 */
	uint32_t func_id; /* pf glb func id */
	uint32_t pcie_host; /* host pcie number */
	uint32_t mac_phy_port; /* mac port */
	uint32_t funcid_to_logic_port_off; /* port func id offset */
	uint32_t chip_version;
	uint32_t hca_core_clock;
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
	uint8_t send_seg_num;
	uint8_t recv_seg_num;
	uint8_t valid; /* 1: current phy info is valid, 0 : invalid */
	uint8_t on_chip_tbl_vld;
	uint8_t dma_rw_tbl_vld;
	uint8_t pct_compress_vld;
	uint8_t mac_bit;
	uint8_t esw_mode;
};

struct xsc_devargs {
	int nic_mode;
	int flow_mode;
	int pph_mode;
};

struct xsc_repr_info {
	int repr_id;
	enum xsc_port_type port_type;
	int pf_bond;

	uint32_t ifindex;
	const char *phys_dev_name;
	uint32_t funcid;

	uint16_t logical_port;
	uint16_t local_dstinfo;
	uint16_t peer_logical_port;
	uint16_t peer_dstinfo;
};

struct xsc_repr_port {
	struct xsc_dev *xdev;
	struct xsc_repr_info info;
	void *drv_data;
	struct xsc_dev_pct_list def_pct_list;
};

struct xsc_dev_config {
	uint8_t pph_flag;
	uint8_t hw_csum;
	uint8_t tso;
	uint32_t tso_max_payload_sz;
};

struct xsc_dev {
	struct rte_pci_device *pci_dev;
	const struct xsc_dev_ops *dev_ops;
	struct xsc_devargs devargs;
	struct xsc_hwinfo hwinfo;
	struct rte_eth_link pf_dev_link;
	uint32_t link_speed_capa;
	int vfos_logical_in_port;
	int vfrep_offset;

	struct rte_intr_handle *intr_handle;
	struct xsc_repr_port *repr_ports;
	int num_repr_ports; /* PF and VF representor ports num */
	int ifindex;
	int port_id; /* Probe dev */
	void *dev_priv;
	char name[PCI_PRI_STR_SIZE];
	void *bar_addr;
	void *jumbo_buffer_pa;
	void *jumbo_buffer_va;
	uint64_t bar_len;
	int ctrl_fd;
};

struct xsc_dev_ops {
	TAILQ_ENTRY(xsc_dev_ops) entry;
	enum rte_pci_kernel_driver kdrv;
	int (*dev_init)(struct xsc_dev *xdev);
	int (*dev_close)(struct xsc_dev *xdev);
};

void xsc_dev_ops_register(struct xsc_dev_ops *new_ops);
int xsc_dev_init(struct rte_pci_device *pci_dev, struct xsc_dev **dev);
void xsc_dev_uninit(struct xsc_dev *xdev);
int xsc_dev_close(struct xsc_dev *xdev, int repr_id);
bool xsc_dev_is_vf(struct xsc_dev *xdev);

#endif /* _XSC_DEV_H_ */
