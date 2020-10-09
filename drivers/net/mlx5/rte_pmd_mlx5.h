/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef RTE_PMD_PRIVATE_MLX5_H_
#define RTE_PMD_PRIVATE_MLX5_H_

/**
 * @file
 * MLX5 public header.
 *
 * This interface provides the ability to support private PMD
 * dynamic flags.
 */

#define RTE_PMD_MLX5_FINE_GRANULARITY_INLINE "mlx5_fine_granularity_inline"

/**
 * Returns the dynamic flags name, that are supported.
 *
 * @param[out] names
 *   Array that is used to return the supported dynamic flags names.
 * @param[in] n
 *   The number of elements in the names array.
 *
 * @return
 *   The number of dynamic flags that were copied if not negative.
 *   Otherwise:
 *   - ENOMEM - not enough entries in the array
 *   - EINVAL - invalid array entry
 */
__rte_experimental
int rte_pmd_mlx5_get_dyn_flag_names(char *names[], unsigned int n);

/**
 * Synchronize the flows to make them take effort on hardware.
 *
 * @param[in] port_id
 *   The port identifier of the Ethernet device..
 * @param[in] domains
 *   Bitmask of domains in which synchronization will be done.
 *   Refer to "/usr/include/infiniband/mlx5dv.h"
 *   The index of bit that set represents the corresponding domain ID.
 *
 * @return
 *   - (0) if successful.
 *   - (-EINVAL) if bad parameter.
 *   - (-ENOTSUP) if hardware doesn't support.
 *   - Other errors
 */
__rte_experimental
int rte_pmd_mlx5_sync_flow(uint16_t port_id, uint32_t domains);

#endif
