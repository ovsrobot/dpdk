/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef MLX5_GLUE_H_
#define MLX5_GLUE_H_

#include <stddef.h>
#include <stdint.h>

#include <rte_byteorder.h>
#include <mlx5_win_defs.h>

#ifndef MLX5_GLUE_VERSION
#define MLX5_GLUE_VERSION ""
#endif

/* LIB_GLUE_VERSION must be updated every time this structure is modified. */
struct mlx5_glue {
	const char *version;
	void *(*devx_obj_create)(void *ctx,
				 void *in, size_t inlen,
				 void *out, size_t outlen);
	int (*devx_obj_destroy)(void *obj);
	int (*devx_obj_query)(void *obj,
			      void *in, size_t inlen,
			      void *out, size_t outlen);
	int (*devx_obj_modify)(void *obj,
			       void *in, size_t inlen,
			       void *out, size_t outlen);
	int (*devx_general_cmd)(void *ctx,
			       void *in, size_t inlen,
			       void *out, size_t outlen);
	int (*devx_umem_dereg)(void *umem);
	void *(*devx_umem_reg)(void *ctx,
			void *addr, size_t size,
			uint32_t access, uint32_t *id);
	void *(*devx_alloc_uar)(void *ctx,
			uint32_t flags);
	void (*devx_free_uar)(void *uar);
	void *(*get_device_list)(int *num_devices);
	void (*free_device_list)(void *list);
	void *(*open_device)(void *device);
	int (*close_device)(void *ctx);
	int (*query_device)(void *device_bdf, void *dev_inf);
	void* (*query_hca_iseg)(void *ctx, uint32_t *cb_iseg);
	int (*devx_obj_query_async)(void *obj,
				    const void *in, size_t inlen,
				    size_t outlen, uint64_t wr_id,
				    void *cmd_comp);
	void *(*devx_fs_rule_add)(void *ctx, void *in, uint32_t inlen);
	int (*devx_fs_rule_del)(void *flow);
	int (*devx_query_eqn)(void *context, uint32_t cpus, uint32_t *eqn);
};

extern const struct mlx5_glue *mlx5_glue;

#endif /* MLX5_GLUE_H_ */
