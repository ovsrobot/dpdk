/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026 NVIDIA Corporation & Affiliates
 */

#include <errno.h>
#include <stdbool.h>

#include <ethdev_driver.h>
#include <rte_common.h>

#include "mlx5_utils.h"
#include "mlx5_lsc_intr.h"

int
mlx5_lsc_intr_setup(struct rte_eth_dev *dev)
{
	DRV_LOG(ERR, "port %u does not support LSC interrupts", dev->data->port_id);
	return -ENOTSUP;
}

void
mlx5_lsc_intr_cleanup(struct rte_eth_dev *dev __rte_unused)
{
}
