/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_hwif.h"
#include "spnic_mgmt.h"
#include "spnic_mbox.h"
#include "spnic_hwdev.h"

int vf_handle_pf_comm_mbox(void *handle, __rte_unused void *pri_handle,
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

static int init_mgmt_channel(struct spnic_hwdev *hwdev)
{
	int err;

	err = spnic_func_to_func_init(hwdev);
	if (err) {
		PMD_DRV_LOG(ERR, "Init mailbox channel failed");
		goto func_to_func_init_err;
	}

	return 0;

func_to_func_init_err:

	return err;
}

static void free_mgmt_channel(struct spnic_hwdev *hwdev)
{
	spnic_func_to_func_free(hwdev);
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
