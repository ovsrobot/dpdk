/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 NVIDIA Corporation & Affiliates
 */

/**
 * @file
 *
 * mlx5_flow_hw.c source file is included in the build only on Linux.
 * Functions defined there are compiled if and only if available rdma-core supports DV.
 *
 * This file contains stubs (through weak linking) for any functions exported from that file.
 */

#include "mlx5_flow.h"

/*
 * This is a stub for the real implementation of this function in mlx5_flow_hw.c in case:
 * - PMD is compiled on Windows or
 * - available rdma-core does not support HWS.
 */
__rte_weak int
mlx5_flow_hw_ctrl_flow_dmac(struct rte_eth_dev *dev __rte_unused,
			    const struct rte_ether_addr *addr __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}

/*
 * This is a stub for the real implementation of this function in mlx5_flow_hw.c in case:
 * - PMD is compiled on Windows or
 * - available rdma-core does not support HWS.
 */
__rte_weak int
mlx5_flow_hw_ctrl_flow_dmac_vlan(struct rte_eth_dev *dev __rte_unused,
				 const struct rte_ether_addr *addr __rte_unused,
				 const uint16_t vlan __rte_unused)
{
	rte_errno = ENOTSUP;
	return -rte_errno;
}
