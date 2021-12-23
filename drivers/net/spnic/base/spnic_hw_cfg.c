/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include "spnic_compat.h"
#include "spnic_mgmt.h"
#include "spnic_mbox.h"
#include "spnic_hwdev.h"
#include "spnic_hwif.h"
#include "spnic_hw_cfg.h"

static void parse_pub_res_cap(struct service_cap *cap,
			      struct spnic_cfg_cmd_dev_cap *dev_cap,
			      enum func_type type)
{
	cap->host_id = dev_cap->host_id;
	cap->ep_id = dev_cap->ep_id;
	cap->er_id = dev_cap->er_id;
	cap->port_id = dev_cap->port_id;

	cap->svc_type = dev_cap->svc_cap_en;
	cap->chip_svc_type = cap->svc_type;

	cap->cos_valid_bitmap = dev_cap->valid_cos_bitmap;
	cap->flexq_en = dev_cap->flexq_en;

	cap->host_total_function = dev_cap->host_total_func;
	cap->max_vf = 0;
	if (type == TYPE_PF || type == TYPE_PPF) {
		cap->max_vf = dev_cap->max_vf;
		cap->pf_num = dev_cap->host_pf_num;
		cap->pf_id_start = dev_cap->pf_id_start;
		cap->vf_num = dev_cap->host_vf_num;
		cap->vf_id_start = dev_cap->vf_id_start;
	}

	PMD_DRV_LOG(INFO, "Get public resource capability: ");
	PMD_DRV_LOG(INFO, "host_id: 0x%x, ep_id: 0x%x, er_id: 0x%x, "
		    "port_id: 0x%x",
		    cap->host_id, cap->ep_id, cap->er_id, cap->port_id);
	PMD_DRV_LOG(INFO, "host_total_function: 0x%x, max_vf: 0x%x",
		    cap->host_total_function, cap->max_vf);
	PMD_DRV_LOG(INFO, "host_pf_num: 0x%x, pf_id_start: 0x%x, host_vf_num: 0x%x, vf_id_start: 0x%x",
		    cap->pf_num, cap->pf_id_start,
		    cap->vf_num, cap->vf_id_start);
}

static void parse_l2nic_res_cap(struct service_cap *cap,
				struct spnic_cfg_cmd_dev_cap *dev_cap)
{
	struct nic_service_cap *nic_cap = &cap->nic_cap;

	nic_cap->max_sqs = dev_cap->nic_max_sq_id + 1;
	nic_cap->max_rqs = dev_cap->nic_max_rq_id + 1;

	PMD_DRV_LOG(INFO, "L2nic resource capbility, max_sqs: 0x%x, "
		    "max_rqs: 0x%x",
		    nic_cap->max_sqs, nic_cap->max_rqs);
}

static void parse_dev_cap(struct spnic_hwdev *dev,
			  struct spnic_cfg_cmd_dev_cap *dev_cap,
			  enum func_type type)
{
	struct service_cap *cap = &dev->cfg_mgmt->svc_cap;

	parse_pub_res_cap(cap, dev_cap, type);

	if (IS_NIC_TYPE(dev))
		parse_l2nic_res_cap(cap, dev_cap);
}

static int get_cap_from_fw(struct spnic_hwdev *hwdev, enum func_type type)
{
	struct spnic_cfg_cmd_dev_cap dev_cap;
	u16 out_len = sizeof(dev_cap);
	int err;

	memset(&dev_cap, 0, sizeof(dev_cap));
	dev_cap.func_id = spnic_global_func_id(hwdev);
	err = spnic_msg_to_mgmt_sync(hwdev, SPNIC_MOD_CFGM,
				     SPNIC_CFG_CMD_GET_DEV_CAP,
				     &dev_cap, sizeof(dev_cap),
				     &dev_cap, &out_len, 0);
	if (err || dev_cap.status || !out_len) {
		PMD_DRV_LOG(ERR, "Get capability from FW failed, err: %d, "
			    "status: 0x%x, out size: 0x%x",
			    err, dev_cap.status, out_len);
		return -EFAULT;
	}

	parse_dev_cap(hwdev, &dev_cap, type);
	return 0;
}

static int get_dev_cap(struct spnic_hwdev *hwdev)
{
	enum func_type type = SPNIC_FUNC_TYPE(hwdev);

	switch (type) {
	case TYPE_PF:
	case TYPE_PPF:
	case TYPE_VF:
		if (get_cap_from_fw(hwdev, type) != 0)
			return -EFAULT;
		break;
	default:
		PMD_DRV_LOG(ERR, "Unsupported PCIe function type: %d", type);
		return -EINVAL;
	}

	return 0;
}

int cfg_mbx_vf_proc_msg(void *hwdev, __rte_unused void *pri_handle, u16 cmd,
			__rte_unused void *buf_in, __rte_unused u16 in_size,
			__rte_unused void *buf_out, __rte_unused u16 *out_size)
{
	struct spnic_hwdev *dev = hwdev;

	if (!dev)
		return -EINVAL;

	PMD_DRV_LOG(WARNING,
		    "Unsupported cfg mbox vf event %d to process", cmd);

	return 0;
}

int spnic_init_capability(void *dev)
{
	struct spnic_hwdev *hwdev = (struct spnic_hwdev *)dev;
	struct cfg_mgmt_info *cfg_mgmt = NULL;
	int err;

	cfg_mgmt = rte_zmalloc("cfg_mgmt", sizeof(*cfg_mgmt),
			       SPNIC_MEM_ALLOC_ALIGN_MIN);
	if (!cfg_mgmt)
		return -ENOMEM;

	memset(cfg_mgmt, 0, sizeof(struct cfg_mgmt_info));
	hwdev->cfg_mgmt = cfg_mgmt;
	cfg_mgmt->hwdev = hwdev;

	err = get_dev_cap(hwdev);
	if (err) {
		rte_free(cfg_mgmt);
		hwdev->cfg_mgmt = NULL;
	}

	return err;
}

void spnic_free_capability(void *dev)
{
	rte_free(((struct spnic_hwdev *)dev)->cfg_mgmt);
}

/* *
 * @brief spnic_support_nic - function support nic
 * @param hwdev: device pointer to hwdev
 * @retval true: function support nic
 * @retval false: function not support nic
 */
bool spnic_support_nic(void *hwdev)
{
	struct spnic_hwdev *dev = (struct spnic_hwdev *)hwdev;

	if (!hwdev)
		return false;

	if (!IS_NIC_TYPE(dev))
		return false;

	return true;
}

u16 spnic_func_max_sqs(void *hwdev)
{
	struct spnic_hwdev *dev = hwdev;

	if (!dev) {
		PMD_DRV_LOG(INFO, "Hwdev is NULL for getting max_sqs");
		return 0;
	}

	return dev->cfg_mgmt->svc_cap.nic_cap.max_sqs;
}

u16 spnic_func_max_rqs(void *hwdev)
{
	struct spnic_hwdev *dev = hwdev;

	if (!dev) {
		PMD_DRV_LOG(INFO, "Hwdev is NULL for getting max_rqs");
		return 0;
	}

	return dev->cfg_mgmt->svc_cap.nic_cap.max_rqs;
}

u8 spnic_physical_port_id(void *hwdev)
{
	struct spnic_hwdev *dev = hwdev;

	if (!dev) {
		PMD_DRV_LOG(INFO, "Hwdev is NULL for getting physical port id");
		return 0;
	}

	return dev->cfg_mgmt->svc_cap.port_id;
}
