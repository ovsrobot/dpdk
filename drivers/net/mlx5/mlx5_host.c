/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include <rte_flow.h>
#include <rte_pmd_mlx5.h>
#include <mlx5_malloc.h>

#include "mlx5_flow.h"
#include "mlx5.h"

#include "hws/host/mlx5dr_host.h"

struct rte_pmd_mlx5_dr_action_cache {
	enum rte_flow_action_type type;
	void *release_data;
	struct mlx5dr_dev_action *dr_dev_action;
	LIST_ENTRY(rte_pmd_mlx5_dr_action_cache) next;
};

struct rte_pmd_mlx5_dev_process {
	struct mlx5dr_dev_process *dr_dev_process;
	struct mlx5dr_dev_context *dr_dev_ctx;
	uint16_t port_id;
	LIST_HEAD(action_head, rte_pmd_mlx5_dr_action_cache) head;
};

struct rte_pmd_mlx5_dev_process *
rte_pmd_mlx5_host_process_open(uint16_t port_id,
			       struct rte_pmd_mlx5_host_device_info *info)
{
	struct rte_pmd_mlx5_dev_process *dev_process;
	struct mlx5dr_dev_context_attr dr_attr = {0};
	struct mlx5dr_dev_process *dr_dev_process;
	const struct mlx5_priv *priv;

	dev_process = mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
				  sizeof(struct rte_pmd_mlx5_dev_process),
				  MLX5_MALLOC_ALIGNMENT,
				  SOCKET_ID_ANY);
	if (!dev_process) {
		rte_errno = ENOMEM;
		return NULL;
	}

	if (info->type == RTE_PMD_MLX5_DEVICE_TYPE_DPA)
		dr_dev_process = mlx5dr_host_process_open(info->dpa.process, info->dpa.outbox);
	else
		dr_dev_process = mlx5dr_host_process_open(NULL, NULL);

	if (!dr_dev_process)
		goto free_dev_process;

	dev_process->port_id = port_id;
	dev_process->dr_dev_process = dr_dev_process;

	priv = rte_eth_devices[port_id].data->dev_private;
	dr_attr.queue_size = info->queue_size;
	dr_attr.queues = info->queues;

	dev_process->dr_dev_ctx =  mlx5dr_host_context_bind(dr_dev_process,
							    priv->dr_ctx,
							    &dr_attr);
	if (!dev_process->dr_dev_ctx)
		goto close_process;

	return (struct rte_pmd_mlx5_dev_process *)dev_process;

close_process:
	mlx5dr_host_process_close(dr_dev_process);
free_dev_process:
	mlx5_free(dev_process);
	return NULL;
}

int
rte_pmd_mlx5_host_process_close(struct rte_pmd_mlx5_dev_process *dev_process)
{
	struct mlx5dr_dev_process *dr_dev_process = dev_process->dr_dev_process;

	mlx5dr_host_context_unbind(dr_dev_process, dev_process->dr_dev_ctx);
	mlx5dr_host_process_close(dr_dev_process);
	mlx5_free(dev_process);
	return 0;
}

struct rte_pmd_mlx5_dev_ctx *
rte_pmd_mlx5_host_get_dev_ctx(struct rte_pmd_mlx5_dev_process *dev_process)
{
	return (struct rte_pmd_mlx5_dev_ctx *)dev_process->dr_dev_ctx;
}

struct rte_pmd_mlx5_dev_table *
rte_pmd_mlx5_host_table_bind(struct rte_pmd_mlx5_dev_process *dev_process,
			     struct rte_flow_template_table *table)
{
	struct mlx5dr_dev_process *dr_dev_process;
	struct mlx5dr_dev_matcher *dr_dev_matcher;
	struct mlx5dr_matcher *matcher;

	if (rte_flow_table_resizable(&table->cfg.attr)) {
		rte_errno = EINVAL;
		return NULL;
	}

	dr_dev_process = dev_process->dr_dev_process;
	matcher = table->matcher_info[0].matcher;

	dr_dev_matcher = mlx5dr_host_matcher_bind(dr_dev_process, matcher);

	return (struct rte_pmd_mlx5_dev_table *)dr_dev_matcher;
}

int
rte_pmd_mlx5_host_table_unbind(struct rte_pmd_mlx5_dev_process *dev_process,
			       struct rte_pmd_mlx5_dev_table *dev_table)
{
	struct mlx5dr_dev_process *dr_dev_process;
	struct mlx5dr_dev_matcher *dr_dev_matcher;

	dr_dev_process = dev_process->dr_dev_process;
	dr_dev_matcher = (struct mlx5dr_dev_matcher *)dev_table;

	return mlx5dr_host_matcher_unbind(dr_dev_process, dr_dev_matcher);
}

struct rte_pmd_mlx5_dev_action *
rte_pmd_mlx5_host_action_bind(struct rte_pmd_mlx5_dev_process *dev_process,
			      struct rte_pmd_mlx5_host_action *action)
{
	struct rte_eth_dev *dev = &rte_eth_devices[dev_process->port_id];
	struct rte_pmd_mlx5_dr_action_cache *action_cache;
	struct mlx5dr_dev_process *dr_dev_process;
	struct mlx5dr_dev_action *dr_dev_action;
	struct mlx5dr_action *dr_action;
	void *release_data;

	dr_dev_process = dev_process->dr_dev_process;

	action_cache = mlx5_malloc(MLX5_MEM_SYS | MLX5_MEM_ZERO,
				   sizeof(*action_cache),
				   MLX5_MALLOC_ALIGNMENT,
				   SOCKET_ID_ANY);
	if (!action_cache) {
		rte_errno = ENOMEM;
		return NULL;
	}

	dr_action = mlx5_flow_hw_get_dr_action(dev, action, &release_data);
	if (!dr_action) {
		DRV_LOG(ERR, "Failed to get dr action type %d", action->type);
		goto free_rte_host_action;
	}

	dr_dev_action = mlx5dr_host_action_bind(dr_dev_process, dr_action);
	if (!dr_dev_action) {
		DRV_LOG(ERR, "Failed to bind dr_action");
		goto put_dr_action;
	}

	action_cache->type = action->type;
	action_cache->release_data = release_data;
	action_cache->dr_dev_action = dr_dev_action;
	LIST_INSERT_HEAD(&dev_process->head, action_cache, next);

	return (struct rte_pmd_mlx5_dev_action *)dr_dev_action;

put_dr_action:
	mlx5_flow_hw_put_dr_action(dev, action->type, release_data);
free_rte_host_action:
	mlx5_free(action_cache);
	return NULL;
}

int
rte_pmd_mlx5_host_action_unbind(struct rte_pmd_mlx5_dev_process *dev_process,
				struct rte_pmd_mlx5_dev_action *dev_action)
{
	struct rte_eth_dev *dev = &rte_eth_devices[dev_process->port_id];
	struct rte_pmd_mlx5_dr_action_cache *action_cache;
	struct mlx5dr_dev_process *dr_dev_process;
	struct mlx5dr_dev_action *dr_dev_action;

	dr_dev_process = dev_process->dr_dev_process;
	dr_dev_action = (struct mlx5dr_dev_action *)dev_action;

	LIST_FOREACH(action_cache, &dev_process->head, next) {
		if (action_cache->dr_dev_action == dr_dev_action) {
			LIST_REMOVE(action_cache, next);
			mlx5dr_host_action_unbind(dr_dev_process, dr_dev_action);
			mlx5_flow_hw_put_dr_action(dev,
						   action_cache->type,
						   action_cache->release_data);
			mlx5_free(action_cache);
			return 0;
		}
	}

	DRV_LOG(ERR, "Failed to find dr aciton to unbind");
	rte_errno = EINVAL;
	return rte_errno;
}

size_t rte_pmd_mlx5_host_get_dev_rule_handle_size(void)
{
	return mlx5dr_host_rule_get_dev_rule_handle_size();
}
