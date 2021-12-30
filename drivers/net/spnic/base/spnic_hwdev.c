/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_hwif.h"
#include "spnic_eqs.h"
#include "spnic_mgmt.h"
#include "spnic_cmd.h"
#include "spnic_mbox.h"
#include "spnic_hwdev.h"

typedef void (*mgmt_event_cb)(void *handle, void *buf_in, u16 in_size,
			      void *buf_out, u16 *out_size);

struct mgmt_event_handle {
	u16 cmd;
	mgmt_event_cb proc;
};

int spnic_vf_handle_pf_comm_mbox(void *handle, __rte_unused void *pri_handle,
			   __rte_unused u16 cmd, __rte_unused void *buf_in,
			   __rte_unused u16 in_size, __rte_unused void *buf_out,
			   __rte_unused u16 *out_size)
{
	struct spnic_hwdev *hwdev = handle;

	if (!hwdev)
		return -EINVAL;

	PMD_DRV_LOG(WARNING, "Unsupported pf mbox event %d to process", cmd);

	return 0;
}

static void fault_event_handler(__rte_unused void *hwdev,
				__rte_unused void *buf_in,
				__rte_unused u16 in_size,
				__rte_unused void *buf_out,
				__rte_unused u16 *out_size)
{
	PMD_DRV_LOG(WARNING, "Unsupported fault event handler");
}

static void ffm_event_msg_handler(__rte_unused void *hwdev,
				  void *buf_in, u16 in_size,
				  __rte_unused void *buf_out, u16 *out_size)
{
	struct ffm_intr_info *intr = NULL;

	if (in_size != sizeof(*intr)) {
		PMD_DRV_LOG(ERR, "Invalid fault event report, length: %d, should be %d",
			    in_size, (int)(sizeof(*intr)));
		return;
	}

	intr = buf_in;

	PMD_DRV_LOG(ERR, "node_id: 0x%x, err_type: 0x%x, err_level: %d, "
		    "err_csr_addr: 0x%08x, err_csr_value: 0x%08x",
		    intr->node_id, intr->err_type, intr->err_level,
		    intr->err_csr_addr, intr->err_csr_value);

	*out_size = sizeof(*intr);
}

const struct mgmt_event_handle mgmt_event_proc[] = {
	{
		.cmd	= MGMT_CMD_FAULT_REPORT,
		.proc	= fault_event_handler,
	},

	{
		.cmd	= MGMT_CMD_FFM_SET,
		.proc	= ffm_event_msg_handler,
	},
};

void spnic_pf_handle_mgmt_comm_event(void *handle, __rte_unused void *pri_handle,
			       u16 cmd, void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size)
{
	struct spnic_hwdev *hwdev = handle;
	u32 i, event_num = RTE_DIM(mgmt_event_proc);

	if (!hwdev)
		return;

	for (i = 0; i < event_num; i++) {
		if (cmd == mgmt_event_proc[i].cmd) {
			if (mgmt_event_proc[i].proc)
				mgmt_event_proc[i].proc(handle, buf_in, in_size,
							buf_out, out_size);

			return;
		}
	}

	PMD_DRV_LOG(WARNING, "Unsupported mgmt cpu event %d to process", cmd);
}

static int spnic_comm_pf_to_mgmt_init(struct spnic_hwdev *hwdev)
{
	int err;

	/* VF does not support send msg to mgmt directly */
	if (spnic_func_type(hwdev) == TYPE_VF)
		return 0;

	err = spnic_pf_to_mgmt_init(hwdev);
	if (err)
		return err;

	return 0;
}

static void spnic_comm_pf_to_mgmt_free(struct spnic_hwdev *hwdev)
{
	/* VF does not support send msg to mgmt directly */
	if (spnic_func_type(hwdev) == TYPE_VF)
		return;

	spnic_pf_to_mgmt_free(hwdev);
}

static int init_mgmt_channel(struct spnic_hwdev *hwdev)
{
	int err;

	err = spnic_aeqs_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init async event queues failed");
		return err;
	}

	err = spnic_comm_pf_to_mgmt_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mgmt channel failed");
		goto msg_init_err;
	}

	err = spnic_func_to_func_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mailbox channel failed");
		goto func_to_func_init_err;
	}

	return 0;

func_to_func_init_err:
	spnic_comm_pf_to_mgmt_free(hwdev);

msg_init_err:
	spnic_aeqs_free(hwdev);

	return err;
}

static void free_mgmt_channel(struct spnic_hwdev *hwdev)
{
	spnic_func_to_func_free(hwdev);
	spnic_comm_pf_to_mgmt_free(hwdev);
	spnic_aeqs_free(hwdev);
}

static int spnic_init_comm_ch(struct spnic_hwdev *hwdev)
{
	int err;

	err = init_mgmt_channel(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mgmt channel failed");
		return err;
	}

	return 0;
}

static void spnic_uninit_comm_ch(struct spnic_hwdev *hwdev)
{
	free_mgmt_channel(hwdev);
}

int spnic_init_hwdev(struct spnic_hwdev *hwdev)
{
	int err;

	hwdev->chip_fault_stats = rte_zmalloc("chip_fault_stats",
					      SPNIC_CHIP_FAULT_SIZE,
					      RTE_CACHE_LINE_SIZE);
	if (!hwdev->chip_fault_stats) {
		PMD_DRV_LOG(ERR, "Alloc memory for chip_fault_stats failed");
		return -ENOMEM;
	}

	err = spnic_init_hwif(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Initialize hwif failed");
		goto init_hwif_err;
	}

	err = spnic_init_comm_ch(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init communication channel failed");
		goto init_comm_ch_err;
	}

	return 0;

init_comm_ch_err:
	spnic_free_hwif(hwdev);

init_hwif_err:
	rte_free(hwdev->chip_fault_stats);

	return -EFAULT;
}

void spnic_free_hwdev(struct spnic_hwdev *hwdev)
{
	spnic_uninit_comm_ch(hwdev);

	spnic_free_hwif(hwdev);

	rte_free(hwdev->chip_fault_stats);
}
