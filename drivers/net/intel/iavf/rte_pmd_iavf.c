/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2025 Intel Corporation
 */

#include <eal_export.h>

#include "iavf.h"
#include "rte_pmd_iavf.h"

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_pmd_iavf_restore, 25.11)
int
rte_pmd_iavf_restore(uint16_t port)
{
	struct rte_eth_dev *dev;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port, -ENODEV);

	dev = &rte_eth_devices[port];

	if (!is_iavf_supported(dev)) {
		PMD_DRV_LOG(ERR, "Cannot restore VF, port %u is not an IAVF device.", port);
		return -ENOTSUP;
	}

	iavf_handle_hw_reset(dev, true);

	return 0;
}
