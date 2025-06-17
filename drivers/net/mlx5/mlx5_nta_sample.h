/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA Corporation & Affiliates
 */

#ifndef MLX5_NTA_SAMPLE_H
#define MLX5_NTA_SAMPLE_H

#include <stdint.h>

struct rte_flow_hw *
mlx5_flow_nta_handle_sample(struct rte_eth_dev *dev,
			    enum mlx5_flow_type type,
			    const struct rte_flow_attr *attr,
			    const struct rte_flow_item pattern[],
			    const struct rte_flow_action actions[],
			    uint64_t item_flags, uint64_t action_flags,
			    struct rte_flow_error *error);

void
mlx5_nta_release_sample_group(struct rte_eth_dev *dev, uint32_t group);

void
mlx5_free_sample_context(struct rte_eth_dev *dev);

#endif /* MLX5_NTA_SAMPLE_H */
