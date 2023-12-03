/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 NVIDIA Corporation & Affiliates
 */

#include <rte_flow.h>

#include <mlx5_malloc.h>
#include <stdint.h>

#include "generic/rte_byteorder.h"
#include "mlx5.h"
#include "mlx5_flow.h"
#include "rte_pmd_mlx5.h"

#if defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H)

#define MAX_GENEVE_OPTION_DATA_SIZE 32
#define MAX_GENEVE_OPTION_TOTAL_DATA_SIZE \
		(MAX_GENEVE_OPTION_DATA_SIZE * MAX_GENEVE_OPTIONS_RESOURCES)

/**
 * Single DW inside GENEVE TLV option.
 */
struct mlx5_geneve_tlv_resource {
	struct mlx5_devx_obj *obj; /* FW object returned in parser creation. */
	uint32_t modify_field; /* Modify field ID for this DW. */
	uint8_t offset; /* Offset used in obj creation, from option start. */
};

/**
 * Single GENEVE TLV option context.
 * May include some FW objects for different DWs in same option.
 */
struct mlx5_geneve_tlv_option {
	uint8_t type;
	uint16_t class;
	uint8_t class_mode;
	struct mlx5_hl_data match_data[MAX_GENEVE_OPTION_DATA_SIZE];
	uint32_t match_data_size;
	struct mlx5_hl_data hl_ok_bit;
	struct mlx5_geneve_tlv_resource resources[MAX_GENEVE_OPTIONS_RESOURCES];
	RTE_ATOMIC(uint32_t) refcnt;
};

/**
 * List of GENEVE TLV options.
 */
struct mlx5_geneve_tlv_options {
	/* List of configured GENEVE TLV options. */
	struct mlx5_geneve_tlv_option options[MAX_GENEVE_OPTIONS_RESOURCES];
	/*
	 * Copy of list given in parser creation, use to compare with new
	 * configuration.
	 */
	struct rte_pmd_mlx5_geneve_tlv spec[MAX_GENEVE_OPTIONS_RESOURCES];
	rte_be32_t buffer[MAX_GENEVE_OPTION_TOTAL_DATA_SIZE];
	uint8_t nb_options; /* Number entries in above lists. */
	RTE_ATOMIC(uint32_t) refcnt;
};

/**
 * Check if type and class is matching to given GENEVE TLV option.
 *
 * @param type
 *   GENEVE option type.
 * @param class
 *   GENEVE option class.
 * @param option
 *   Pointer to GENEVE TLV option structure.
 *
 * @return
 *   True if this type and class match to this option, false otherwise.
 */
static inline bool
option_match_type_and_class(uint8_t type, uint16_t class,
			    struct mlx5_geneve_tlv_option *option)
{
	if (type != option->type)
		return false;
	if (option->class_mode == 1 && option->class != class)
		return false;
	return true;
}

/**
 * Get GENEVE TLV option matching to given type and class.
 *
 * @param priv
 *   Pointer to port's private data.
 * @param type
 *   GENEVE option type.
 * @param class
 *   GENEVE option class.
 *
 * @return
 *   Pointer to option structure if exist, NULL otherwise and rte_errno is set.
 */
static struct mlx5_geneve_tlv_option *
mlx5_geneve_tlv_option_get(const struct mlx5_priv *priv, uint8_t type,
			   uint16_t class)
{
	struct mlx5_geneve_tlv_options *options;
	uint8_t i;

	if (priv->tlv_options == NULL) {
		DRV_LOG(ERR,
			"Port %u doesn't have configured GENEVE TLV options.",
			priv->dev_data->port_id);
		rte_errno = EINVAL;
		return NULL;
	}
	options = priv->tlv_options;
	MLX5_ASSERT(options != NULL);
	for (i = 0; i < options->nb_options; ++i) {
		struct mlx5_geneve_tlv_option *option = &options->options[i];

		if (option_match_type_and_class(type, class, option))
			return option;
	}
	DRV_LOG(ERR, "TLV option type %u class %u doesn't exist.", type, class);
	rte_errno = ENOENT;
	return NULL;
}

int
mlx5_get_geneve_hl_data(const void *dr_ctx, uint8_t type, uint16_t class,
			struct mlx5_hl_data ** const hl_ok_bit,
			uint8_t *num_of_dws,
			struct mlx5_hl_data ** const hl_dws,
			bool *ok_bit_on_class)
{
	uint16_t port_id;

	MLX5_ETH_FOREACH_DEV(port_id, NULL) {
		struct mlx5_priv *priv;
		struct mlx5_geneve_tlv_option *option;

		priv = rte_eth_devices[port_id].data->dev_private;
		if (priv->dr_ctx != dr_ctx)
			continue;
		/* Find specific option inside list. */
		option = mlx5_geneve_tlv_option_get(priv, type, class);
		if (option == NULL)
			return -rte_errno;
		*hl_ok_bit = &option->hl_ok_bit;
		*hl_dws = option->match_data;
		*num_of_dws = option->match_data_size;
		*ok_bit_on_class = !!(option->class_mode == 1);
		return 0;
	}
	DRV_LOG(ERR, "DR CTX %p doesn't belong to any DPDK port.", dr_ctx);
	return -EINVAL;
}

/**
 * Create single GENEVE TLV option sample.
 *
 * @param ctx
 *   Context returned from mlx5 open_device() glue function.
 * @param attr
 *   Pointer to GENEVE TLV option attributes structure.
 * @param query_attr
 *   Pointer to match sample info attributes structure.
 * @param match_data
 *   Pointer to header layout structure to update.
 * @param resource
 *   Pointer to single sample context to fill.
 *
 * @return
 *   0 on success, a negative errno otherwise and rte_errno is set.
 */
static int
mlx5_geneve_tlv_option_create_sample(void *ctx,
		      struct mlx5_devx_geneve_tlv_option_attr *attr,
		      struct mlx5_devx_match_sample_info_query_attr *query_attr,
		      struct mlx5_hl_data *match_data,
		      struct mlx5_geneve_tlv_resource *resource)
{
	struct mlx5_devx_obj *obj;
	int ret;

	obj = mlx5_devx_cmd_create_geneve_tlv_option(ctx, attr);
	if (obj == NULL)
		return -rte_errno;
	ret = mlx5_devx_cmd_query_geneve_tlv_option(ctx, obj, query_attr);
	if (ret) {
		claim_zero(mlx5_devx_cmd_destroy(obj));
		return ret;
	}
	resource->obj = obj;
	resource->offset = attr->sample_offset;
	resource->modify_field = query_attr->modify_field_id;
	match_data->dw_offset = query_attr->sample_dw_data;
	match_data->dw_mask = 0xffffffff;
	return 0;
}

/**
 * Destroy single GENEVE TLV option sample.
 *
 * @param resource
 *   Pointer to single sample context to clean.
 */
static void
mlx5_geneve_tlv_option_destroy_sample(struct mlx5_geneve_tlv_resource *resource)
{
	claim_zero(mlx5_devx_cmd_destroy(resource->obj));
	resource->obj = NULL;
}

/**
 * Create single GENEVE TLV option.
 *
 * @param ctx
 *   Context returned from mlx5 open_device() glue function.
 * @param spec
 *   Pointer to user configuration.
 * @param option
 *   Pointer to single GENEVE TLV option to fill.
 *
 * @return
 *   0 on success, a negative errno otherwise and rte_errno is set.
 */
static int
mlx5_geneve_tlv_option_create(void *ctx, const struct rte_pmd_mlx5_geneve_tlv *spec,
			      struct mlx5_geneve_tlv_option *option)
{
	struct mlx5_devx_geneve_tlv_option_attr attr = {
		.option_class = spec->option_class,
		.option_type = spec->option_type,
		.option_data_len = spec->option_len,
		.option_class_ignore = spec->match_on_class_mode == 1 ? 0 : 1,
		.offset_valid = 1,
	};
	struct mlx5_devx_match_sample_info_query_attr query_attr = {0};
	struct mlx5_geneve_tlv_resource *resource;
	uint8_t i, resource_id = 0;
	int ret;

	if (spec->match_on_class_mode == 2) {
		/* Header is matchable, create sample for DW0. */
		attr.sample_offset = 0;
		resource = &option->resources[resource_id];
		ret = mlx5_geneve_tlv_option_create_sample(ctx, &attr,
							   &query_attr,
							   &option->match_data[0],
							   resource);
		if (ret)
			return ret;
		resource_id++;
	}
	/*
	 * Create FW object for each DW request by user.
	 * Starting from 1 since FW offset starts from header.
	 */
	for (i = 1; i <= spec->sample_len; ++i) {
		if (spec->match_data_mask[i - 1] == 0)
			continue;
		/* offset of data + offset inside data = specific DW offset. */
		attr.sample_offset = spec->offset + i;
		resource = &option->resources[resource_id];
		ret = mlx5_geneve_tlv_option_create_sample(ctx, &attr,
							   &query_attr,
							   &option->match_data[i],
							   resource);
		if (ret)
			goto error;
		resource_id++;
	}
	/*
	 * Update the OK bit information according to last query.
	 * It should be same for each query under same option.
	 */
	option->hl_ok_bit.dw_offset = query_attr.sample_dw_ok_bit;
	option->hl_ok_bit.dw_mask = 1 << query_attr.sample_dw_ok_bit_offset;
	option->match_data_size = spec->sample_len + 1;
	option->type = spec->option_type;
	option->class = spec->option_class;
	option->class_mode = spec->match_on_class_mode;
	rte_atomic_store_explicit(&option->refcnt, 0, rte_memory_order_relaxed);
	return 0;
error:
	for (i = 0; i < resource_id; ++i) {
		resource = &option->resources[i];
		mlx5_geneve_tlv_option_destroy_sample(resource);
	}
	return ret;
}

/**
 * Destroy single GENEVE TLV option.
 *
 * @param option
 *   Pointer to single GENEVE TLV option to destroy.
 *
 * @return
 *   0 on success, a negative errno otherwise and rte_errno is set.
 */
static int
mlx5_geneve_tlv_option_destroy(struct mlx5_geneve_tlv_option *option)
{
	uint8_t i;

	if (rte_atomic_load_explicit(&option->refcnt, rte_memory_order_relaxed)) {
		DRV_LOG(ERR,
			"Option type %u class %u is still in used by %u tables.",
			option->type, option->class, option->refcnt);
		rte_errno = EBUSY;
		return -rte_errno;
	}
	for (i = 0; option->resources[i].obj != NULL; ++i)
		mlx5_geneve_tlv_option_destroy_sample(&option->resources[i]);
	return 0;
}

/**
 * Copy the GENEVE TLV option user configuration for future comparing.
 *
 * @param dst
 *   Pointer to internal user configuration copy.
 * @param src
 *   Pointer to user configuration.
 * @param match_data_mask
 *   Pointer to allocated data array.
 */
static void
mlx5_geneve_tlv_option_copy(struct rte_pmd_mlx5_geneve_tlv *dst,
			    const struct rte_pmd_mlx5_geneve_tlv *src,
			    rte_be32_t *match_data_mask)
{
	uint8_t i;

	dst->option_type = src->option_type;
	dst->option_class = src->option_class;
	dst->option_len = src->option_len;
	dst->offset = src->offset;
	dst->match_on_class_mode = src->match_on_class_mode;
	dst->sample_len = src->sample_len;
	for (i = 0; i < dst->sample_len; ++i)
		match_data_mask[i] = src->match_data_mask[i];
	dst->match_data_mask = match_data_mask;
}

/**
 * Create list of GENEVE TLV options according to user configuration list.
 *
 * @param sh
 *   Shared context the options are being created on.
 * @param tlv_list
 *   A list of GENEVE TLV options to create parser for them.
 * @param nb_options
 *   The number of options in TLV list.
 *
 * @return
 *   A pointer to GENEVE TLV options parser structure on success,
 *   NULL otherwise and rte_errno is set.
 */
static struct mlx5_geneve_tlv_options *
mlx5_geneve_tlv_options_create(struct mlx5_dev_ctx_shared *sh,
			       const struct rte_pmd_mlx5_geneve_tlv tlv_list[],
			       uint8_t nb_options)
{
	struct mlx5_geneve_tlv_options *options;
	const struct rte_pmd_mlx5_geneve_tlv *spec;
	rte_be32_t *data_mask;
	uint8_t i, j;
	int ret;

	options = mlx5_malloc(MLX5_MEM_ZERO | MLX5_MEM_RTE,
			      sizeof(struct mlx5_geneve_tlv_options),
			      RTE_CACHE_LINE_SIZE, SOCKET_ID_ANY);
	if (options == NULL) {
		DRV_LOG(ERR,
			"Failed to allocate memory for GENEVE TLV options.");
		rte_errno = ENOMEM;
		return NULL;
	}
	for (i = 0; i < nb_options; ++i) {
		spec = &tlv_list[i];
		ret = mlx5_geneve_tlv_option_create(sh->cdev->ctx, spec,
						    &options->options[i]);
		if (ret < 0)
			goto error;
		/* Copy the user list for comparing future configuration. */
		data_mask = options->buffer + i * MAX_GENEVE_OPTION_DATA_SIZE;
		mlx5_geneve_tlv_option_copy(&options->spec[i], spec, data_mask);
	}
	MLX5_ASSERT(sh->phdev->sh == NULL);
	sh->phdev->sh = sh;
	options->nb_options = nb_options;
	options->refcnt = 1;
	return options;
error:
	for (j = 0; j < i; ++j)
		mlx5_geneve_tlv_option_destroy(&options->options[j]);
	mlx5_free(options);
	return NULL;
}

/**
 * Destroy GENEVE TLV options structure.
 *
 * @param options
 *   Pointer to GENEVE TLV options structure to destroy.
 * @param phdev
 *   Pointer physical device options were created on.
 *
 * @return
 *   0 on success, a negative errno otherwise and rte_errno is set.
 */
int
mlx5_geneve_tlv_options_destroy(struct mlx5_geneve_tlv_options *options,
				struct mlx5_physical_device *phdev)
{
	uint8_t i;
	int ret;

	if (--options->refcnt)
		return 0;
	for (i = 0; i < options->nb_options; ++i) {
		ret = mlx5_geneve_tlv_option_destroy(&options->options[i]);
		if (ret < 0) {
			DRV_LOG(ERR,
				"Failed to destroy option %u, %u/%u is already destroyed.",
				i, i, options->nb_options);
			return ret;
		}
	}
	mlx5_free(options);
	phdev->tlv_options = NULL;
	phdev->sh = NULL;
	return 0;
}

/**
 * Check if GENEVE TLV options are hosted on the current port
 * and the port can be closed
 *
 * @param priv
 *   Device private data.
 *
 * @return
 *   0 on success, a negative EBUSY and rte_errno is set.
 */
int
mlx5_geneve_tlv_options_check_busy(struct mlx5_priv *priv)
{
	struct mlx5_physical_device *phdev = mlx5_get_locked_physical_device(priv);
	struct mlx5_dev_ctx_shared *sh = priv->sh;

	if (!phdev || phdev->sh != sh) {
		mlx5_unlock_physical_device();
		return 0;
	}
	if (!sh->phdev->tlv_options || sh->phdev->tlv_options->refcnt == 1) {
		/* Mark port as being closed one */
		sh->phdev->sh = NULL;
		mlx5_unlock_physical_device();
		return 0;
	}
	mlx5_unlock_physical_device();
	rte_errno = EBUSY;
	return -EBUSY;
}

/**
 * Validate GENEVE TLV option user request structure.
 *
 * @param attr
 *   Pointer to HCA attribute structure.
 * @param option
 *   Pointer to user configuration.
 *
 * @return
 *   0 on success, a negative errno otherwise and rte_errno is set.
 */
static int
mlx5_geneve_tlv_option_validate(struct mlx5_hca_attr *attr,
				const struct rte_pmd_mlx5_geneve_tlv *option)
{
	if (option->option_len > attr->max_geneve_tlv_option_data_len) {
		DRV_LOG(ERR,
			"GENEVE TLV option length (%u) exceeds the limit (%u).",
			option->option_len,
			attr->max_geneve_tlv_option_data_len);
		rte_errno = ENOTSUP;
		return -rte_errno;
	}
	if (option->option_len < option->offset + option->sample_len) {
		DRV_LOG(ERR,
			"GENEVE TLV option length is smaller than (offset + sample_len).");
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (option->match_on_class_mode > 2) {
		DRV_LOG(ERR,
			"GENEVE TLV option match_on_class_mode is invalid.");
		rte_errno = EINVAL;
		return -rte_errno;
	}
	return 0;
}

/**
 * Get the number of requested DWs in given GENEVE TLV option.
 *
 * @param option
 *   Pointer to user configuration.
 *
 * @return
 *   Number of requested DWs for given GENEVE TLV option.
 */
static uint8_t
mlx5_geneve_tlv_option_get_nb_dws(const struct rte_pmd_mlx5_geneve_tlv *option)
{
	uint8_t nb_dws = 0;
	uint8_t i;

	if (option->match_on_class_mode == 2)
		nb_dws++;
	for (i = 0; i < option->sample_len; ++i) {
		if (option->match_data_mask[i] == 0xffffffff)
			nb_dws++;
	}
	return nb_dws;
}

/**
 * Compare GENEVE TLV option user request structure.
 *
 * @param option1
 *   Pointer to first user configuration.
 * @param option2
 *   Pointer to second user configuration.
 *
 * @return
 *   True if the options are equal, false otherwise.
 */
static bool
mlx5_geneve_tlv_option_compare(const struct rte_pmd_mlx5_geneve_tlv *option1,
			       const struct rte_pmd_mlx5_geneve_tlv *option2)
{
	uint8_t i;

	if (option1->option_type != option2->option_type ||
	    option1->option_class != option2->option_class ||
	    option1->option_len != option2->option_len ||
	    option1->offset != option2->offset ||
	    option1->match_on_class_mode != option2->match_on_class_mode ||
	    option1->sample_len != option2->sample_len)
		return false;
	for (i = 0; i < option1->sample_len; ++i) {
		if (option1->match_data_mask[i] != option2->match_data_mask[i])
			return false;
	}
	return true;
}

/**
 * Check whether the given GENEVE TLV option list is equal to internal list.
 * The lists are equal when they have same size and same options in the same
 * order inside the list.
 *
 * @param options
 *   Pointer to GENEVE TLV options structure.
 * @param tlv_list
 *   A list of GENEVE TLV options to compare.
 * @param nb_options
 *   The number of options in TLV list.
 *
 * @return
 *   True if the lists are equal, false otherwise.
 */
static bool
mlx5_is_same_geneve_tlv_options(const struct mlx5_geneve_tlv_options *options,
				const struct rte_pmd_mlx5_geneve_tlv tlv_list[],
				uint8_t nb_options)
{
	const struct rte_pmd_mlx5_geneve_tlv *spec = options->spec;
	uint8_t i;

	if (options->nb_options != nb_options)
		return false;
	for (i = 0; i < nb_options; ++i) {
		if (!mlx5_geneve_tlv_option_compare(&spec[i], &tlv_list[i]))
			return false;
	}
	return true;
}

void *
mlx5_geneve_tlv_parser_create(uint16_t port_id,
			      const struct rte_pmd_mlx5_geneve_tlv tlv_list[],
			      uint8_t nb_options)
{
	struct mlx5_geneve_tlv_options *options = NULL;
	struct mlx5_physical_device *phdev;
	struct rte_eth_dev *dev;
	struct mlx5_priv *priv;
	struct mlx5_hca_attr *attr;
	uint8_t total_dws = 0;
	uint8_t i;

	/*
	 * Validate the input before taking a lock and before any memory
	 * allocation.
	 */
	if (rte_eth_dev_is_valid_port(port_id) < 0) {
		DRV_LOG(ERR, "There is no Ethernet device for port %u.",
			port_id);
		rte_errno = ENODEV;
		return NULL;
	}
	dev = &rte_eth_devices[port_id];
	priv = dev->data->dev_private;
	if (priv->tlv_options) {
		DRV_LOG(ERR, "Port %u already has GENEVE TLV parser.", port_id);
		rte_errno = EEXIST;
		return NULL;
	}
	if (priv->sh->config.dv_flow_en < 2) {
		DRV_LOG(ERR,
			"GENEVE TLV parser is only supported for HW steering.");
		rte_errno = ENOTSUP;
		return NULL;
	}
	attr = &priv->sh->cdev->config.hca_attr;
	MLX5_ASSERT(MAX_GENEVE_OPTIONS_RESOURCES <=
		    attr->max_geneve_tlv_options);
	if (!attr->geneve_tlv_option_offset || !attr->geneve_tlv_sample ||
	    !attr->query_match_sample_info || !attr->geneve_tlv_opt) {
		DRV_LOG(ERR, "Not enough capabilities to support GENEVE TLV parser, maybe old FW version");
		rte_errno = ENOTSUP;
		return NULL;
	}
	if (nb_options > MAX_GENEVE_OPTIONS_RESOURCES) {
		DRV_LOG(ERR,
			"GENEVE TLV option number (%u) exceeds the limit (%u).",
			nb_options, MAX_GENEVE_OPTIONS_RESOURCES);
		rte_errno = EINVAL;
		return NULL;
	}
	for (i = 0; i < nb_options; ++i) {
		if (mlx5_geneve_tlv_option_validate(attr, &tlv_list[i]) < 0) {
			DRV_LOG(ERR, "GENEVE TLV option %u is invalid.", i);
			return NULL;
		}
		total_dws += mlx5_geneve_tlv_option_get_nb_dws(&tlv_list[i]);
	}
	if (total_dws > MAX_GENEVE_OPTIONS_RESOURCES) {
		DRV_LOG(ERR,
			"Total requested DWs (%u) exceeds the limit (%u).",
			total_dws, MAX_GENEVE_OPTIONS_RESOURCES);
		rte_errno = EINVAL;
		return NULL;
	}
	/* Take lock for this physical device and manage the options. */
	phdev = mlx5_get_locked_physical_device(priv);
	options = priv->sh->phdev->tlv_options;
	if (options) {
		if (!mlx5_is_same_geneve_tlv_options(options, tlv_list,
						     nb_options)) {
			mlx5_unlock_physical_device();
			DRV_LOG(ERR, "Another port has already prepared different GENEVE TLV parser.");
			rte_errno = EEXIST;
			return NULL;
		}
		if (phdev->sh == NULL) {
			mlx5_unlock_physical_device();
			DRV_LOG(ERR, "GENEVE TLV options are hosted on port being closed.");
			rte_errno = EBUSY;
			return NULL;
		}
		/* Use existing options. */
		options->refcnt++;
		goto exit;
	}
	/* Create GENEVE TLV options for this physical device. */
	options = mlx5_geneve_tlv_options_create(priv->sh, tlv_list, nb_options);
	if (!options) {
		mlx5_unlock_physical_device();
		return NULL;
	}
	phdev->tlv_options = options;
exit:
	mlx5_unlock_physical_device();
	priv->tlv_options = options;
	return priv;
}

int
mlx5_geneve_tlv_parser_destroy(void *handle)
{
	struct mlx5_priv *priv = (struct mlx5_priv *)handle;
	struct mlx5_physical_device *phdev;
	int ret;

	if (priv == NULL) {
		DRV_LOG(ERR, "Handle input is invalid (NULL).");
		rte_errno = EINVAL;
		return -rte_errno;
	}
	if (priv->tlv_options == NULL) {
		DRV_LOG(ERR, "This parser has been already released.");
		rte_errno = ENOENT;
		return -rte_errno;
	}
	/* Take lock for this physical device and manage the options. */
	phdev = mlx5_get_locked_physical_device(priv);
	/* Destroy the options */
	ret = mlx5_geneve_tlv_options_destroy(phdev->tlv_options, phdev);
	if (ret < 0) {
		mlx5_unlock_physical_device();
		return ret;
	}
	priv->tlv_options = NULL;
	mlx5_unlock_physical_device();
	return 0;
}

#endif /* defined(HAVE_IBV_FLOW_DV_SUPPORT) || !defined(HAVE_INFINIBAND_VERBS_H) */
