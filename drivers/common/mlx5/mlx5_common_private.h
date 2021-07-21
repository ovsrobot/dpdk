/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Mellanox Technologies, Ltd
 */

#ifndef _MLX5_COMMON_PRIVATE_H_
#define _MLX5_COMMON_PRIVATE_H_

#include <rte_pci.h>
#include <rte_bus_auxiliary.h>

#include "mlx5_common.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Common bus driver: */

struct mlx5_common_device {
	struct rte_device *dev;
	TAILQ_ENTRY(mlx5_common_device) next;
	uint32_t classes_loaded;
};

int mlx5_common_dev_probe(struct rte_device *eal_dev);
int mlx5_common_dev_remove(struct rte_device *eal_dev);
int mlx5_common_dev_dma_map(struct rte_device *dev, void *addr, uint64_t iova,
			    size_t len);
int mlx5_common_dev_dma_unmap(struct rte_device *dev, void *addr, uint64_t iova,
			      size_t len);

/* Common PCI bus driver: */

void mlx5_common_driver_on_register_pci(struct mlx5_class_driver *driver);
bool mlx5_dev_pci_match(const struct mlx5_class_driver *drv,
			const struct rte_device *dev);

/* Common auxiliary bus driver: */
void mlx5_common_auxiliary_init(void);
struct ibv_device *mlx5_get_aux_ibv_device(
		const struct rte_auxiliary_device *dev);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _MLX5_COMMON_PRIVATE_H_ */
