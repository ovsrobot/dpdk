/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 Yunsilicon Technology Co., Ltd.
 */

#ifndef _XSC_CTRL_H_
#define _XSC_CTRL_H_

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <infiniband/verbs.h>

#ifndef PAGE_SIZE
#define PAGE_SIZE	4096
#endif

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

#define XSC_DIV_ROUND_UP(n, d) ({ \
	typeof(d) _d = (d); \
	typeof(n) _n = (n); \
	((_n) + (_d) - 1) / (_d); \
})

enum {
	XSC_CMD_OP_MODIFY_RAW_QP = 0x81f,
	XSC_CMD_OP_IOCTL_FLOW    = 0x900,
	XSC_CMD_OP_MAX
};

enum {
	XSC_IOCTL_SET_QP_STATUS = 0x200,
	XSC_IOCTL_SET_MAX
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

enum {
	XSC_QUEUE_TYPE_RDMA_RC    = 0,
	XSC_QUEUE_TYPE_RDMA_MAD   = 1,
	XSC_QUEUE_TYPE_RAW        = 2,
	XSC_QUEUE_TYPE_VIRTIO_NET = 3,
	XSC_QUEUE_TYPE_VIRTIO_BLK = 4,
	XSC_QUEUE_TYPE_RAW_TPE    = 5,
	XSC_QUEUE_TYPE_RAW_TSO    = 6,
	XSC_QUEUE_TYPE_RAW_TX     = 7,
	XSC_QUEUE_TYPE_INVALID    = 0xFF,
};
enum  xsc_flow_tbl_id {
	XSC_FLOW_TBL_IPAT = 0,
	XSC_FLOW_TBL_PCT_V4 = 4,
	XSC_FLOW_TBL_EPAT = 19,
	XSC_FLOW_TBL_MAX
};

enum xsc_ioctl_op {
	XSC_IOCTL_OP_ADD,
	XSC_IOCTL_OP_DEL,
	XSC_IOCTL_OP_GET,
	XSC_IOCTL_OP_CLR,
	XSC_IOCTL_OP_MOD,
	XSC_IOCTL_OP_MAX
};


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

struct xsc_nic_attr {
	__be16       caps;
	__be16       caps_mask;
	uint8_t      mac_addr[6];
};

struct xsc_rss_modify_attr {
	uint8_t      caps_mask;
	uint8_t      rss_en;
	__be16       rqn_base;
	__be16       rqn_num;
	uint8_t      hfunc;
	__be32       hash_tmpl;
	uint8_t      hash_key[52];
};

struct xsc_cmd_modify_nic_hca_mbox_in {
	struct xsc_inbox_hdr            hdr;
	struct xsc_nic_attr             nic;
	struct xsc_rss_modify_attr      rss;
};

struct xsc_cmd_modify_nic_hca_mbox_out {
	struct xsc_outbox_hdr   hdr;
	uint8_t                 rsvd0[4];
};

struct xsc_create_qp_request {
	__be16                  input_qpn;
	__be16                  pa_num;
	uint8_t                 qp_type;
	uint8_t                 log_sq_sz;
	uint8_t                 log_rq_sz;
	uint8_t                 dma_direct;
	__be32                  pdn;
	__be16                  cqn_send;
	__be16                  cqn_recv;
	__be16                  glb_funcid;
	uint8_t                 page_shift;
	uint8_t                 rsvd;
	__be64                  pas[];
};

struct xsc_create_multiqp_mbox_in {
	struct xsc_inbox_hdr    hdr;
	__be16                  qp_num;
	uint8_t                 qp_type;
	uint8_t                 rsvd;
	__be32                  req_len;
	uint8_t                 data[];
};

struct xsc_create_multiqp_mbox_out {
	struct xsc_outbox_hdr   hdr;
	__be32                  qpn_base;
};


struct xsc_destroy_qp_mbox_in {
	struct xsc_inbox_hdr        hdr;
	__be32                  qpn;
	uint8_t                 rsvd[4];
};

struct xsc_destroy_qp_mbox_out {
	struct xsc_outbox_hdr   hdr;
	uint8_t                 rsvd[8];
};

struct xsc_ioctl_qp_range {
	uint16_t                opcode;
	int                     num;
	uint32_t                qpn;
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

/* for xscdv providers */
#if !HAVE_XSC_DV_PROVIDER
enum xscdv_obj_type {
	XSCDV_OBJ_QP    = 1 << 0,
	XSCDV_OBJ_CQ    = 1 << 1,
	XSCDV_OBJ_SRQ   = 1 << 2,
	XSCDV_OBJ_RWQ   = 1 << 3,
	XSCDV_OBJ_DM    = 1 << 4,
	XSCDV_OBJ_AH    = 1 << 5,
	XSCDV_OBJ_PD    = 1 << 6,
};

enum xsc_qp_create_flags {
	XSC_QP_CREATE_RAWPACKE_TSO  = 1 << 0,
	XSC_QP_CREATE_RAWPACKET_TSO = 1 << 0,
	XSC_QP_CREATE_RAWPACKET_TX  = 1 << 1,
};

struct xscdv_cq_init_attr {
	uint64_t comp_mask; /* Use enum xscdv_cq_init_attr_mask */
	uint8_t cqe_comp_res_format; /* Use enum xscdv_cqe_comp_res_format */
	uint32_t flags;
	uint16_t cqe_size; /* when XSCDV_CQ_INIT_ATTR_MASK_CQE_SIZE set */
};

struct xscdv_obj {
	struct {
		struct ibv_qp           *in;
		struct xscdv_qp         *out;
	} qp;
	struct {
		struct ibv_cq           *in;
		struct xscdv_cq         *out;
	} cq;
};

struct xscdv_qp {
	__le32                  *dbrec;
	struct {
		void            *buf;
		uint32_t        wqe_cnt;
		uint32_t        stride;
		__le32          *db;
	} sq;
	struct {
		void            *buf;
		uint32_t        wqe_cnt;
		uint32_t        stride;
		__le32          *db;
	} rq;
	uint64_t                comp_mask;
	uint32_t                tirn;
	uint32_t                tisn;
	uint32_t                rqn;
	uint32_t                sqn;
};

struct xscdv_cq {
	void                    *buf;
	__le32                  *dbrec;
	__le32                  *db;
	uint32_t                cqe_cnt;
	uint32_t                cqe_size;
	uint32_t                cqn;
	uint64_t                comp_mask;
};

#endif

int xsc_ioctl(struct xsc_dev *dev, int cmd, int opcode,
	      void *data_in, int in_len, void *data_out, int out_len);
int xsc_mailbox_exec(struct xsc_dev *dev, void *data_in,
		     int in_len, void *data_out, int out_len);

#endif /* _XSC_CTRL_H_ */
