/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2024 NVIDIA Corporation & Affiliates
 */

#include <rte_flow.h>
#include "mlx5_malloc.h"
#include "mlx5.h"
#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_rx.h"

struct mlx5_nta_sample_ctx {
	uint32_t groups_num;
	struct mlx5_indexed_pool *group_ids;
	struct mlx5_list *mirror_actions; /* cache FW mirror actions */
	struct mlx5_list *sample_groups; /* cache groups for sample actions */
	struct mlx5_list *suffix_groups; /* cache groups for suffix actions */
};

static uint32_t
alloc_cached_group(struct rte_eth_dev *dev)
{
	void *obj;
	uint32_t idx = 0;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_nta_sample_ctx *ctx = priv->nta_sample_ctx;

	obj = mlx5_ipool_malloc(ctx->group_ids, &idx);
	if (obj == NULL)
		return 0;
	return idx + MLX5_FLOW_TABLE_SAMPLE_BASE;
}

static void
release_cached_group(struct rte_eth_dev *dev, uint32_t group)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_nta_sample_ctx *sample_ctx = priv->nta_sample_ctx;

	mlx5_ipool_free(sample_ctx->group_ids, group - MLX5_FLOW_TABLE_SAMPLE_BASE);
}

static void
mlx5_free_sample_context(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_nta_sample_ctx *ctx = priv->nta_sample_ctx;

	if (ctx == NULL)
		return;
	if (ctx->sample_groups != NULL)
		mlx5_list_destroy(ctx->sample_groups);
	if (ctx->suffix_groups != NULL)
		mlx5_list_destroy(ctx->suffix_groups);
	if (ctx->group_ids != NULL)
		mlx5_ipool_destroy(ctx->group_ids);
	if (ctx->mirror_actions != NULL)
		mlx5_list_destroy(ctx->mirror_actions);
	mlx5_free(ctx);
	priv->nta_sample_ctx = NULL;
}

struct mlx5_nta_sample_cached_mirror {
	struct mlx5_flow_template_table_cfg table_cfg;
	uint32_t sample_group;
	uint32_t suffix_group;
	struct mlx5_mirror *mirror;
	struct mlx5_list_entry entry;
};

struct mlx5_nta_sample_cached_mirror_ctx {
	struct mlx5_flow_template_table_cfg *table_cfg;
	uint32_t sample_group;
	uint32_t suffix_group;
};

static struct mlx5_list_entry *
mlx5_nta_sample_create_cached_mirror(void *cache_ctx, void *cb_ctx)
{
	struct rte_eth_dev *dev = cache_ctx;
	struct mlx5_nta_sample_cached_mirror_ctx *ctx = cb_ctx;
	struct rte_flow_action_jump mirror_jump_conf = { .group = ctx->sample_group };
	struct rte_flow_action_jump suffix_jump_conf = { .group = ctx->suffix_group };
	struct rte_flow_action mirror_sample_actions[2] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &mirror_jump_conf,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_END
		}
	};
	struct rte_flow_action_sample mirror_conf = {
		.ratio = 1,
		.actions = mirror_sample_actions,
	};
	struct rte_flow_action mirror_actions[3] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_SAMPLE,
			.conf = &mirror_conf,
		},
		[1] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &suffix_jump_conf,
		},
		[2] = {
			.type = RTE_FLOW_ACTION_TYPE_END
		}
	};
	struct mlx5_nta_sample_cached_mirror *obj = mlx5_malloc(MLX5_MEM_ANY,
								sizeof(*obj), 0,
								SOCKET_ID_ANY);
	if (obj == NULL)
		return NULL;
	obj->mirror = mlx5_hw_create_mirror(dev, ctx->table_cfg, mirror_actions, NULL);
	if (obj->mirror == NULL) {
		mlx5_free(obj);
		return NULL;
	}
	obj->sample_group = ctx->sample_group;
	obj->suffix_group = ctx->suffix_group;
	obj->table_cfg = *ctx->table_cfg;
	return &obj->entry;
}

static struct mlx5_list_entry *
mlx5_nta_sample_clone_cached_mirror(void *tool_ctx __rte_unused,
				    struct mlx5_list_entry *entry,
				    void *cb_ctx __rte_unused)
{
	struct mlx5_nta_sample_cached_mirror *cached_obj =
		container_of(entry, struct mlx5_nta_sample_cached_mirror, entry);
	struct mlx5_nta_sample_cached_mirror *new_obj = mlx5_malloc(MLX5_MEM_ANY,
								    sizeof(*new_obj), 0,
								    SOCKET_ID_ANY);

	if (new_obj == NULL)
		return NULL;
	memcpy(new_obj, cached_obj, sizeof(*new_obj));
	return &new_obj->entry;
}

static int
mlx5_nta_sample_match_cached_mirror(void *cache_ctx __rte_unused,
				    struct mlx5_list_entry *entry, void *cb_ctx)
{
	bool match;
	struct mlx5_nta_sample_cached_mirror_ctx *ctx = cb_ctx;
	struct mlx5_nta_sample_cached_mirror *obj =
		container_of(entry, struct mlx5_nta_sample_cached_mirror, entry);

	match = obj->sample_group == ctx->sample_group &&
		obj->suffix_group == ctx->suffix_group &&
		memcmp(&obj->table_cfg, ctx->table_cfg, sizeof(obj->table_cfg)) == 0;

	return match ? 0 : ~0;
}

static void
mlx5_nta_sample_remove_cached_mirror(void *cache_ctx, struct mlx5_list_entry *entry)
{
	struct rte_eth_dev *dev = cache_ctx;
	struct mlx5_nta_sample_cached_mirror *obj =
		container_of(entry, struct mlx5_nta_sample_cached_mirror, entry);
	mlx5_hw_mirror_destroy(dev, obj->mirror);
	mlx5_free(obj);
}

static void
mlx5_nta_sample_clone_free_cached_mirror(void *cache_ctx __rte_unused,
					 struct mlx5_list_entry *entry)
{
	struct mlx5_nta_sample_cached_mirror *cloned_obj =
		container_of(entry, struct mlx5_nta_sample_cached_mirror, entry);

	mlx5_free(cloned_obj);
}

struct mlx5_nta_sample_cached_group {
	const struct rte_flow_action *actions;
	size_t actions_size;
	uint32_t group;
	struct mlx5_list_entry entry;
};

struct mlx5_nta_sample_cached_group_ctx {
	struct rte_flow_action *actions;
	size_t actions_size;
};

static int
serialize_actions(struct mlx5_nta_sample_cached_group_ctx *obj_ctx)
{
	if (obj_ctx->actions_size == 0) {
		uint8_t *tgt_buffer;
		int size = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, NULL, 0, obj_ctx->actions, NULL);
		if (size < 0)
			return size;
		tgt_buffer = mlx5_malloc(MLX5_MEM_ANY, size, 0, SOCKET_ID_ANY);
		if (tgt_buffer == NULL)
			return -ENOMEM;
		obj_ctx->actions_size = size;
		size = rte_flow_conv(RTE_FLOW_CONV_OP_ACTIONS, tgt_buffer, size,
				     obj_ctx->actions, NULL);
		if (size < 0) {
			mlx5_free(tgt_buffer);
			return size;
		}
		obj_ctx->actions = (struct rte_flow_action *)tgt_buffer;
	}
	return obj_ctx->actions_size;
}

static struct mlx5_list_entry *
mlx5_nta_sample_create_cached_group(void *cache_ctx, void *cb_ctx)
{
	struct rte_eth_dev *dev = cache_ctx;
	struct mlx5_nta_sample_cached_group_ctx *obj_ctx = cb_ctx;
	struct mlx5_nta_sample_cached_group *obj;
	int actions_size = serialize_actions(obj_ctx);

	if (actions_size < 0)
		return NULL;
	obj = mlx5_malloc(MLX5_MEM_ANY, sizeof(*obj), 0, SOCKET_ID_ANY);
	if (obj == NULL)
		return NULL;
	obj->group = alloc_cached_group(dev);
	if (obj->group == 0) {
		mlx5_free(obj);
		return NULL;
	}
	obj->actions = obj_ctx->actions;
	obj->actions_size = obj_ctx->actions_size;
	return &obj->entry;
}

static int
mlx5_nta_sample_match_cached_group(void *cache_ctx __rte_unused,
				   struct mlx5_list_entry *entry, void *cb_ctx)
{
	struct mlx5_nta_sample_cached_group_ctx *obj_ctx = cb_ctx;
	int actions_size = serialize_actions(obj_ctx);
	struct mlx5_nta_sample_cached_group *cached_obj =
		container_of(entry, struct mlx5_nta_sample_cached_group, entry);
	if (actions_size < 0)
		return ~0;
	return memcmp(cached_obj->actions, obj_ctx->actions, actions_size);
}

static void
mlx5_nta_sample_remove_cached_group(void *cache_ctx, struct mlx5_list_entry *entry)
{
	struct rte_eth_dev *dev = cache_ctx;
	struct mlx5_nta_sample_cached_group *cached_obj =
		container_of(entry, struct mlx5_nta_sample_cached_group, entry);

	release_cached_group(dev, cached_obj->group);
	mlx5_free((void *)(uintptr_t)cached_obj->actions);
	mlx5_free(cached_obj);
}

static struct mlx5_list_entry *
mlx5_nta_sample_clone_cached_group(void *tool_ctx __rte_unused,
				   struct mlx5_list_entry *entry,
				   void *cb_ctx __rte_unused)
{
	struct mlx5_nta_sample_cached_group *cached_obj =
		container_of(entry, struct mlx5_nta_sample_cached_group, entry);
	struct mlx5_nta_sample_cached_group *new_obj;

	new_obj = mlx5_malloc(MLX5_MEM_ANY, sizeof(*new_obj), 0, SOCKET_ID_ANY);
	if (new_obj == NULL)
		return NULL;
	memcpy(new_obj, cached_obj, sizeof(*new_obj));
	return &new_obj->entry;
}

static void
mlx5_nta_sample_free_cloned_cached_group(void *cache_ctx __rte_unused,
					 struct mlx5_list_entry *entry)
{
	struct mlx5_nta_sample_cached_group *cloned_obj =
		container_of(entry, struct mlx5_nta_sample_cached_group, entry);

	mlx5_free(cloned_obj);
}

static int
mlx5_init_nta_sample_context(struct rte_eth_dev *dev)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_indexed_pool_config ipool_cfg = {
		.size = 0,
		.trunk_size = 32,
		.grow_trunk = 5,
		.grow_shift = 1,
		.need_lock = 1,
		.release_mem_en = !!priv->sh->config.reclaim_mode,
		.max_idx = MLX5_FLOW_TABLE_SAMPLE_NUM,
		.type = "mlx5_nta_sample"
	};
	struct mlx5_nta_sample_ctx *ctx = mlx5_malloc(MLX5_MEM_ZERO,
						      sizeof(*ctx), 0, SOCKET_ID_ANY);

	if (ctx == NULL)
		return -ENOMEM;
	priv->nta_sample_ctx = ctx;
	ctx->group_ids = mlx5_ipool_create(&ipool_cfg);
	if (ctx->group_ids == NULL)
		goto error;
	ctx->sample_groups = mlx5_list_create("nta sample groups", dev, true,
					      mlx5_nta_sample_create_cached_group,
					      mlx5_nta_sample_match_cached_group,
					      mlx5_nta_sample_remove_cached_group,
					      mlx5_nta_sample_clone_cached_group,
					      mlx5_nta_sample_free_cloned_cached_group);
	if (ctx->sample_groups == NULL)
		goto error;
	ctx->suffix_groups = mlx5_list_create("nta sample suffix groups", dev, true,
					      mlx5_nta_sample_create_cached_group,
					      mlx5_nta_sample_match_cached_group,
					      mlx5_nta_sample_remove_cached_group,
					      mlx5_nta_sample_clone_cached_group,
					      mlx5_nta_sample_free_cloned_cached_group);
	if (ctx->suffix_groups == NULL)
		goto error;
	ctx->mirror_actions = mlx5_list_create("nta sample mirror actions", dev, true,
					       mlx5_nta_sample_create_cached_mirror,
					       mlx5_nta_sample_match_cached_mirror,
					       mlx5_nta_sample_remove_cached_mirror,
					       mlx5_nta_sample_clone_cached_mirror,
					       mlx5_nta_sample_clone_free_cached_mirror);
	if (ctx->mirror_actions == NULL)
		goto error;
	return 0;

error:
	mlx5_free_sample_context(dev);
	return -ENOMEM;
}

static struct mlx5_mirror *
get_registered_mirror(struct mlx5_flow_template_table_cfg *table_cfg,
		      struct mlx5_list *cache,
		      uint32_t sample_group,
		      uint32_t suffix_group)
{
	struct mlx5_nta_sample_cached_mirror_ctx ctx = {
		.table_cfg = table_cfg,
		.sample_group = sample_group,
		.suffix_group = suffix_group
	};
	struct mlx5_list_entry *ent = mlx5_list_register(cache, &ctx);
	return ent ? container_of(ent, struct mlx5_nta_sample_cached_mirror, entry)->mirror : NULL;
}

static uint32_t
get_registered_group(struct rte_flow_action *actions, struct mlx5_list *cache)
{
	struct mlx5_nta_sample_cached_group_ctx ctx = {
		.actions = actions
	};
	struct mlx5_list_entry *ent = mlx5_list_register(cache, &ctx);
	return ent ? container_of(ent, struct mlx5_nta_sample_cached_group, entry)->group : 0;
}

static struct mlx5_mirror *
mlx5_create_nta_mirror(struct rte_eth_dev *dev,
		       const struct rte_flow_attr *attr,
		       struct rte_flow_action *sample_actions,
		       struct rte_flow_action *suffix_actions,
		       struct rte_flow_error *error)
{
	struct mlx5_mirror *mirror;
	uint32_t sample_group, suffix_group;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_nta_sample_ctx *ctx = priv->nta_sample_ctx;
	struct mlx5_flow_template_table_cfg table_cfg = {
		.external = true,
		.attr = {
			.flow_attr = {
				.ingress = attr->ingress,
				.egress = attr->egress,
				.transfer = attr->transfer
			}
		}
	};

	sample_group = get_registered_group(sample_actions, ctx->sample_groups);
	if (sample_group == 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					   NULL, "Failed to register sample group");
		return NULL;
	}
	suffix_group = get_registered_group(suffix_actions, ctx->suffix_groups);
	if (suffix_group == 0) {
		rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					   NULL, "Failed to register suffix group");
		return NULL;
	}
	mirror = get_registered_mirror(&table_cfg, ctx->mirror_actions, sample_group, suffix_group);
	return mirror;
}

static void
mlx5_nta_parse_sample_actions(const struct rte_flow_action *action,
			      const struct rte_flow_action **sample_action,
			      struct rte_flow_action *prefix_actions,
			      struct rte_flow_action *suffix_actions)
{
	struct rte_flow_action *pa = prefix_actions;
	struct rte_flow_action *sa = suffix_actions;

	*sample_action = NULL;
	do {
		if (action->type == RTE_FLOW_ACTION_TYPE_SAMPLE) {
			*sample_action = action;
		} else if (*sample_action == NULL) {
			if (action->type == RTE_FLOW_ACTION_TYPE_VOID)
				continue;
			*(pa++) = *action;
		} else {
			if (action->type == RTE_FLOW_ACTION_TYPE_VOID)
				continue;
			*(sa++) = *action;
		}
	} while ((action++)->type != RTE_FLOW_ACTION_TYPE_END);
}

struct rte_flow_hw *
mlx5_flow_nta_handle_sample(struct rte_eth_dev *dev,
			    const struct rte_flow_attr *attr,
			    const struct rte_flow_item pattern[] __rte_unused,
			    const struct rte_flow_action actions[] __rte_unused,
			    struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_mirror *mirror;
	const struct rte_flow_action *sample;
	struct rte_flow_action *sample_actions;
	const struct rte_flow_action_sample *sample_conf;
	struct rte_flow_action prefix_actions[MLX5_HW_MAX_ACTS] = { 0 };
	struct rte_flow_action suffix_actions[MLX5_HW_MAX_ACTS] = { 0 };

	if (priv->nta_sample_ctx == NULL) {
		int rc = mlx5_init_nta_sample_context(dev);
		if (rc != 0) {
			rte_flow_error_set(error, -rc, RTE_FLOW_ERROR_TYPE_ACTION,
					   NULL, "Failed to allocate sample context");
			return NULL;
		}
	}
	mlx5_nta_parse_sample_actions(actions, &sample, prefix_actions, suffix_actions);
	sample_conf = (const struct rte_flow_action_sample *)sample->conf;
	sample_actions = (struct rte_flow_action *)(uintptr_t)sample_conf->actions;
	mirror = mlx5_create_nta_mirror(dev, attr, sample_actions,
					suffix_actions, error);
	if (mirror == NULL)
		goto error;
error:
	return NULL;
}
