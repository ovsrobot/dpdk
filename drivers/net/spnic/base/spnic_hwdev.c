/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ramaxel Memory Technology, Ltd
 */

#include "spnic_compat.h"
#include "spnic_csr.h"
#include "spnic_hwif.h"
#include "spnic_hwdev.h"

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

	return 0;

init_hwif_err:
	rte_free(hwdev->chip_fault_stats);

	return -EFAULT;
}

void spnic_free_hwdev(struct spnic_hwdev *hwdev)
{
	spnic_free_hwif(hwdev);

	rte_free(hwdev->chip_fault_stats);
}
