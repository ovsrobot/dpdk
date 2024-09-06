/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_CTRL_H_
#define _XSC_CTRL_H_

#include <sys/ioctl.h>

#define XSC_IOCTL_CHECK_FIELD	0x01234567

#define XSC_IOCTL_MAGIC	0x1b
#define XSC_IOCTL_CMDQ \
	_IOWR(XSC_IOCTL_MAGIC, 1, struct xsc_ioctl_hdr)
#define XSC_IOCTL_DRV_GET \
	_IOR(XSC_IOCTL_MAGIC, 2, struct xsc_ioctl_hdr)
#define XSC_IOCTL_CMDQ_RAW \
	_IOWR(XSC_IOCTL_MAGIC, 5, struct xsc_ioctl_hdr)

enum xsc_ioctl_opcode {
	XSC_IOCTL_GET_HW_INFO			= 0x100,
};

enum xsc_ioctl_opmod {
	XSC_IOCTL_OP_GET_LOCAL,
};

struct xsc_ioctl_attr {
	uint16_t opcode; /* ioctl cmd */
	uint16_t length; /* data length */
	uint32_t error;  /* ioctl error info */
	uint8_t data[0]; /* specific table info */
};

struct xsc_ioctl_hdr {
	uint32_t check_field;
	uint32_t domain;
	uint32_t bus;
	uint32_t devfn;
	struct xsc_ioctl_attr attr;
};

/* ioctl */
struct xsc_inbox_hdr {
	__be16     opcode;
	uint8_t    rsvd[4];
	__be16     opmod;
};

struct xsc_outbox_hdr {
	uint8_t     status;
	uint8_t     rsvd[3];
	__be32      syndrome;
};

/* ioctl mbox */
struct xsc_ioctl_mbox_in {
	struct xsc_inbox_hdr	hdr;
	__be16			len;
	__be16			rsvd;
	uint8_t			data[];
};

struct xsc_ioctl_mbox_out {
	struct xsc_outbox_hdr   hdr;
	__be32                  error;
	__be16                  len;
	__be16                  rsvd;
	uint8_t                 data[];
};

struct xsc_ioctl_data_tl {
	uint16_t table;
	uint16_t opmod;
	uint16_t length;
	uint16_t rsvd;
};

struct xsc_ioctl_get_hwinfo {
	uint32_t domain;
	uint32_t bus;
	uint32_t devfn;
	uint32_t pcie_no;
	uint32_t func_id;
	uint32_t pcie_host;
	uint32_t mac_phy_port;
	uint32_t funcid_to_logic_port_off;
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

int xsc_ioctl(struct xsc_dev *dev, int cmd, int opcode,
	      void *data_in, int in_len, void *data_out, int out_len);
int xsc_mailbox_exec(struct xsc_dev *dev, void *data_in,
		     int in_len, void *data_out, int out_len);

#endif /* _XSC_CTRL_H_ */
