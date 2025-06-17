/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2025 NVIDIA Corporation & Affiliates
 */

#include <rte_flow.h>
#include "mlx5_malloc.h"
#include "mlx5.h"
#include "mlx5_defs.h"
#include "mlx5_flow.h"
#include "mlx5_rx.h"

SLIST_HEAD(mlx5_flow_head, rte_flow_hw);

struct mlx5_nta_sample_ctx {
	uint32_t groups_num;
	struct mlx5_indexed_pool *group_ids;
	struct mlx5_list *mirror_actions; /* cache FW mirror actions */
	struct mlx5_list *sample_groups; /* cache groups for sample actions */
	struct mlx5_list *suffix_groups; /* cache groups for suffix actions */
};

static void
release_chained_flows(struct rte_eth_dev *dev, struct mlx5_flow_head *flow_head,
		      enum mlx5_flow_type type)
{
	struct rte_flow_hw *flow = SLIST_FIRST(flow_head);

	if (flow) {
		flow->nt2hws->chaned_flow = 0;
		flow_hw_list_destroy(dev, type, (uintptr_t)flow);
	}
}

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

void
mlx5_nta_release_sample_group(struct rte_eth_dev *dev, uint32_t group)
{
	release_cached_group(dev, group);
}

void
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

static int
mlx5_nta_create_mirror_action(struct rte_eth_dev *dev,
			      const struct rte_flow_attr *attr,
			      struct rte_flow_action *sample_actions,
			      struct rte_flow_action *suffix_actions,
			      struct mlx5_rte_flow_action_mirror *mirror_conf,
			      struct rte_flow_error *error)
{
	struct mlx5_priv *priv = dev->data->dev_private;
	struct mlx5_nta_sample_ctx *ctx = priv->nta_sample_ctx;
	struct mlx5_flow_template_table_cfg table_cfg = {
		.external = true,
		.attr = {
			.flow_attr = *attr
		}
	};

	mirror_conf->sample_group = get_registered_group(sample_actions, ctx->sample_groups);
	if (mirror_conf->sample_group == 0)
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "Failed to register sample group");
	mirror_conf->suffix_group = get_registered_group(suffix_actions, ctx->suffix_groups);
	if (mirror_conf->suffix_group == 0)
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
					  NULL, "Failed to register suffix group");
	mirror_conf->mirror = get_registered_mirror(&table_cfg, ctx->mirror_actions,
						    mirror_conf->sample_group,
						    mirror_conf->suffix_group);
	return 0;
}

static void
save_sample_group(struct rte_flow_hw *flow, uint32_t group)
{
	flow->nt2hws->sample_group = group;
}

static uint32_t
generate_random_mask(uint32_t ratio)
{
	uint32_t i;
	double goal = 1.0 / ratio;

	/* Check if the ratio value is power of 2 */
	if (rte_popcount32(ratio) == 1) {
		for (i = 2; i < UINT32_WIDTH; i++) {
			if (RTE_BIT32(i) == ratio)
				return RTE_BIT32(i) - 1;
		}
	}

	/*
	 * Find the last power of 2 with ratio larger then the goal.
	 */
	for (i = 2; i < UINT32_WIDTH; i++) {
		double res = 1.0 / RTE_BIT32(i);

		if (res < goal)
			return RTE_BIT32(i - 1) - 1;
	}

	return UINT32_MAX;
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

static bool
validate_prefix_actions(const struct rte_flow_action *actions)
{
	uint32_t i = 0;

	while (actions[i].type != RTE_FLOW_ACTION_TYPE_END)
		i++;
	return i < MLX5_HW_MAX_ACTS - 1;
}

static void
action_append(struct rte_flow_action *actions, const struct rte_flow_action *last)
{
	uint32_t i = 0;

	while (actions[i].type != RTE_FLOW_ACTION_TYPE_END)
		i++;
	actions[i] = *last;
}

static int
create_mirror_aux_flows(struct rte_eth_dev *dev,
			enum mlx5_flow_type type,
			const struct rte_flow_attr *attr,
			struct rte_flow_action *suffix_actions,
			struct rte_flow_action *sample_actions,
			struct mlx5_rte_flow_action_mirror *mirror_conf,
			struct mlx5_flow_head *flow_head,
			struct rte_flow_error *error)
{
	const struct rte_flow_attr suffix_attr = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
		.group = mirror_conf->suffix_group,
	};
	const struct rte_flow_attr sample_attr = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
		.group = mirror_conf->sample_group,
	};
	const struct rte_flow_item secondary_pattern[1] = {
		[0] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	int ret, encap_idx, actions_num;
	uint64_t suffix_action_flags, sample_action_flags;
	const struct rte_flow_action *qrss_action = NULL, *mark_action = NULL;
	struct rte_flow_hw *suffix_flow = NULL, *sample_flow = NULL;

	suffix_action_flags = mlx5_flow_hw_action_flags_get(suffix_actions,
						       &qrss_action, &mark_action,
						       &encap_idx, &actions_num, error);
	if (qrss_action != NULL && qrss_action->type == RTE_FLOW_ACTION_TYPE_RSS)
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION, NULL,
			"RSS action is not supported in suffix sample action");
	sample_action_flags = mlx5_flow_hw_action_flags_get(sample_actions,
						       &qrss_action, &mark_action,
						       &encap_idx, &actions_num, error);
	if (qrss_action != NULL && qrss_action->type == RTE_FLOW_ACTION_TYPE_RSS)
		return rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION, NULL,
			"RSS action is not supported in sample action");
	ret = flow_hw_create_flow(dev, type, &suffix_attr,
				  secondary_pattern, suffix_actions,
				  MLX5_FLOW_LAYER_OUTER_L2, suffix_action_flags,
				  true, &suffix_flow, error);
	if (ret != 0)
		return ret;
	save_sample_group(suffix_flow, mirror_conf->suffix_group);
	ret = flow_hw_create_flow(dev, type, &sample_attr,
				  secondary_pattern, sample_actions,
				  MLX5_FLOW_LAYER_OUTER_L2, sample_action_flags,
				  true, &sample_flow, error);
	if (ret != 0) {
		flow_hw_destroy(dev, suffix_flow);
		return ret;
	}
	save_sample_group(sample_flow, mirror_conf->sample_group);
	suffix_flow->nt2hws->chaned_flow = 1;
	SLIST_INSERT_HEAD(flow_head, suffix_flow, nt2hws->next);
	sample_flow->nt2hws->chaned_flow = 1;
	SLIST_INSERT_HEAD(flow_head, sample_flow, nt2hws->next);
	return 0;
}

static struct rte_flow_hw *
create_sample_flow(struct rte_eth_dev *dev,
		   enum mlx5_flow_type type,
		   const struct rte_flow_attr *attr,
		   uint32_t ratio,
		   uint32_t sample_group,
		   struct mlx5_rte_flow_action_mirror *mirror_conf,
		   struct rte_flow_error *error)
{
	struct rte_flow_hw *sample_flow = NULL;
	uint32_t random_mask = generate_random_mask(ratio);
	const struct rte_flow_attr sample_attr = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
		.group = sample_group,
	};
	const struct rte_flow_item sample_pattern[2] = {
		[0] = {
			.type = RTE_FLOW_ITEM_TYPE_RANDOM,
			.mask = &(struct rte_flow_item_random) {
				.value = random_mask
			},
			.spec = &(struct rte_flow_item_random) {
				.value = 1
			},
		},
		[1] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	const struct rte_flow_action sample_actions[2] = {
		[0] = {
			.type = (enum rte_flow_action_type)MLX5_RTE_FLOW_ACTION_TYPE_MIRROR,
			.conf = mirror_conf
		},
		[1] = { .type = RTE_FLOW_ACTION_TYPE_END }
	};

	if (random_mask > UINT16_MAX)
		return NULL;
	flow_hw_create_flow(dev, type, &sample_attr, sample_pattern, sample_actions,
			    0, 0, true, &sample_flow, error);
	save_sample_group(sample_flow, sample_group);
	return sample_flow;
}

static struct rte_flow_hw *
create_sample_miss_flow(struct rte_eth_dev *dev,
			enum mlx5_flow_type type,
			const struct rte_flow_attr *attr,
			uint32_t sample_group, uint32_t suffix_group,
			const struct rte_flow_action *miss_actions,
			struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_hw *miss_flow = NULL;
	const struct rte_flow_attr miss_attr = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
		.group = suffix_group,
	};
	const struct rte_flow_item miss_pattern[1] = {
		[0] = { .type = RTE_FLOW_ITEM_TYPE_END }
	};
	const struct rte_flow_group_attr sample_group_attr = {
		.ingress = attr->ingress,
		.egress = attr->egress,
		.transfer = attr->transfer,
	};
	const struct rte_flow_action sample_miss_actions[2] = {
		[0] = {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump) { .group = suffix_group }
		},
		[1] = { .type = RTE_FLOW_ACTION_TYPE_END }
	};

	ret = mlx5_flow_hw_group_set_miss_actions(dev, sample_group, &sample_group_attr,
					     sample_miss_actions, error);
	if (ret != 0)
		return NULL;
	flow_hw_create_flow(dev, type, &miss_attr, miss_pattern, miss_actions,
			    0, 0, true, &miss_flow, error);
	return miss_flow;
}

static struct rte_flow_hw *
mlx5_nta_create_sample_flow(struct rte_eth_dev *dev,
			     enum mlx5_flow_type type,
			     const struct rte_flow_attr *attr,
			     uint32_t sample_ratio,
			     uint64_t item_flags, uint64_t action_flags,
			     const struct rte_flow_item *pattern,
			     struct rte_flow_action *prefix_actions,
			     struct rte_flow_action *suffix_actions,
			     struct rte_flow_action *sample_actions,
			     struct mlx5_rte_flow_action_mirror *mirror_conf,
			     struct rte_flow_error *error)
{
	int ret;
	uint32_t sample_group = alloc_cached_group(dev);
	struct mlx5_flow_head flow_head = SLIST_HEAD_INITIALIZER(NULL);
	struct rte_flow_hw *base_flow = NULL, *sample_flow, *miss_flow = NULL;

	if (sample_group == 0)
		goto error;
	ret = create_mirror_aux_flows(dev, type, attr,
				      suffix_actions, sample_actions,
				      mirror_conf, &flow_head, error);
	if (ret != 0)
		return NULL;
	miss_flow = create_sample_miss_flow(dev, type, attr,
					    sample_group, mirror_conf->suffix_group,
					    suffix_actions, error);
	if (miss_flow == NULL)
		goto error;
	miss_flow->nt2hws->chaned_flow = 1;
	SLIST_INSERT_HEAD(&flow_head, miss_flow, nt2hws->next);
	sample_flow = create_sample_flow(dev, type, attr, sample_ratio, sample_group,
					 mirror_conf, error);
	if (sample_flow == NULL)
		goto error;
	sample_flow->nt2hws->chaned_flow = 1;
	SLIST_INSERT_HEAD(&flow_head, sample_flow, nt2hws->next);
	action_append(prefix_actions,
		&(struct rte_flow_action) {
			.type = RTE_FLOW_ACTION_TYPE_JUMP,
			.conf = &(struct rte_flow_action_jump) { .group = sample_group }
		});
	ret = flow_hw_create_flow(dev, type, attr, pattern, prefix_actions,
				  item_flags, action_flags, true, &base_flow, error);
	if (ret != 0)
		goto error;
	SLIST_INSERT_HEAD(&flow_head, base_flow, nt2hws->next);
	return base_flow;

error:
	release_chained_flows(dev, &flow_head, type);
	return NULL;
}

static struct rte_flow_hw *
mlx5_nta_create_mirror_flow(struct rte_eth_dev *dev,
			     enum mlx5_flow_type type,
			     const struct rte_flow_attr *attr,
			     uint64_t item_flags, uint64_t action_flags,
			     const struct rte_flow_item *pattern,
			     struct rte_flow_action *prefix_actions,
			     struct rte_flow_action *suffix_actions,
			     struct rte_flow_action *sample_actions,
			     struct mlx5_rte_flow_action_mirror *mirror_conf,
			     struct rte_flow_error *error)
{
	int ret;
	struct rte_flow_hw *base_flow = NULL;
	struct mlx5_flow_head flow_head = SLIST_HEAD_INITIALIZER(NULL);

	ret = create_mirror_aux_flows(dev, type, attr,
				      suffix_actions, sample_actions,
				      mirror_conf, &flow_head, error);
	if (ret != 0)
		return NULL;
	action_append(prefix_actions,
		&(struct rte_flow_action) {
			.type = (enum rte_flow_action_type)MLX5_RTE_FLOW_ACTION_TYPE_MIRROR,
			.conf = mirror_conf
		});
	ret = flow_hw_create_flow(dev, type, attr, pattern, prefix_actions,
				  item_flags, action_flags,
				  true, &base_flow, error);
	if (ret != 0)
		goto error;
	SLIST_INSERT_HEAD(&flow_head, base_flow, nt2hws->next);
	return base_flow;

error:
	release_chained_flows(dev, &flow_head, type);
	return NULL;
}

struct rte_flow_hw *
mlx5_flow_nta_handle_sample(struct rte_eth_dev *dev,
			    enum mlx5_flow_type type,
			    const struct rte_flow_attr *attr,
			    const struct rte_flow_item pattern[],
			    const struct rte_flow_action actions[],
			    uint64_t item_flags, uint64_t action_flags,
			    struct rte_flow_error *error)
{
	int ret;
	struct mlx5_priv *priv = dev->data->dev_private;
	struct rte_flow_hw *flow = NULL;
	const struct rte_flow_action *sample;
	struct rte_flow_action *sample_actions;
	const struct rte_flow_action_sample *sample_conf;
	struct mlx5_rte_flow_action_mirror mirror_conf = { NULL };
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
	if (!validate_prefix_actions(prefix_actions)) {
		rte_flow_error_set(error, -EINVAL, RTE_FLOW_ERROR_TYPE_ACTION,
				   NULL, "Too many actions");
		return NULL;
	}
	sample_conf = (const struct rte_flow_action_sample *)sample->conf;
	sample_actions = (struct rte_flow_action *)(uintptr_t)sample_conf->actions;
	ret = mlx5_nta_create_mirror_action(dev, attr, sample_actions,
					    suffix_actions, &mirror_conf, error);
	if (ret != 0)
		return NULL;
	if (sample_conf->ratio == 1) {
		flow = mlx5_nta_create_mirror_flow(dev, type, attr, item_flags, action_flags,
						   pattern, prefix_actions, suffix_actions,
						   sample_actions, &mirror_conf, error);
	} else {
		flow = mlx5_nta_create_sample_flow(dev, type, attr, sample_conf->ratio,
						   item_flags, action_flags, pattern,
						   prefix_actions, suffix_actions,
						   sample_actions, &mirror_conf, error);
	}
	return flow;
}
