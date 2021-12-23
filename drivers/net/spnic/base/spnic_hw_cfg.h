/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#ifndef _SPNIC_HW_CFG_H_
#define _SPNIC_HW_CFG_H_

#define CFG_MAX_CMD_TIMEOUT	30000 /* ms */

#define K_UNIT              BIT(10)
#define M_UNIT              BIT(20)
#define G_UNIT              BIT(30)

/* Number of PFs and VFs */
#define HOST_PF_NUM		4
#define HOST_VF_NUM		0
#define HOST_OQID_MASK_VAL	2

#define L2NIC_SQ_DEPTH      (4 * K_UNIT)
#define L2NIC_RQ_DEPTH      (4 * K_UNIT)

enum intr_type {
	INTR_TYPE_MSIX,
	INTR_TYPE_MSI,
	INTR_TYPE_INT,
	INTR_TYPE_NONE
};

/* Service type relates define */
enum cfg_svc_type_en {
	CFG_SVC_NIC_BIT0 = (1 << 0)
};

struct nic_service_cap {
	u16 max_sqs;
	u16 max_rqs;
};

/* Device capability */
struct service_cap {
	enum cfg_svc_type_en svc_type; /* User input service type */
	enum cfg_svc_type_en chip_svc_type; /* HW supported service type */

	u8 host_id;
	u8 ep_id;
	u8 er_id;	/* PF/VF's ER */
	u8 port_id;	/* PF/VF's physical port */

	u16 host_total_function;
	u8 pf_num;
	u8 pf_id_start;
	u16 vf_num;	/* max numbers of vf in current host */
	u16 vf_id_start;

	u8 flexq_en;
	u8 cos_valid_bitmap;
	u16 max_vf;	/* max VF number that PF supported */

	struct nic_service_cap nic_cap; /* NIC capability */
};

struct cfg_mgmt_info {
	void *hwdev;
	struct service_cap svc_cap;
};

enum spnic_cfg_cmd {
	SPNIC_CFG_CMD_GET_DEV_CAP = 0,
};

struct spnic_cfg_cmd_dev_cap {
	u8 status;
	u8 version;
	u8 rsvd0[6];

	u16 func_id;
	u16 rsvd1;

	/* Public resource */
	u8 host_id;
	u8 ep_id;
	u8 er_id;
	u8 port_id;

	u16 host_total_func;
	u8 host_pf_num;
	u8 pf_id_start;
	u16 host_vf_num;
	u16 vf_id_start;
	u32 rsvd_host;

	u16 svc_cap_en;
	u16 max_vf;
	u8 flexq_en;
	u8 valid_cos_bitmap;
	/* Reserved for func_valid_cos_bitmap */
	u16 rsvd_cos;

	u32 rsvd[11];

	/* l2nic */
	u16 nic_max_sq_id;
	u16 nic_max_rq_id;
	u32 rsvd_nic[3];

	u32 rsvd_glb[60];
};

#define IS_NIC_TYPE(dev) \
	(((u32)(dev)->cfg_mgmt->svc_cap.chip_svc_type) & CFG_SVC_NIC_BIT0)

int spnic_init_capability(void *dev);
void spnic_free_capability(void *dev);

u8 spnic_physical_port_id(void *hwdev);

int cfg_mbx_vf_proc_msg(void *hwdev, void *pri_handle, u16 cmd, void *buf_in,
			u16 in_size, void *buf_out, u16 *out_size);
#endif /* _SPNIC_HW_CFG_H_ */
