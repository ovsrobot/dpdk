/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include "rte_bus_mlx5_pci.h"
#include <mlx5_common_utils.h>

static TAILQ_HEAD(mlx5_pci_bus_drv_head, rte_mlx5_pci_driver) drv_list =
				TAILQ_HEAD_INITIALIZER(drv_list);

static const struct {
	const char *name;
	unsigned int dev_class;
} mlx5_classes[] = {
	{ .name = "vdpa", .dev_class = MLX5_CLASS_VDPA },
	{ .name = "net", .dev_class = MLX5_CLASS_NET },
};

static const unsigned int mlx5_valid_class_combo[] = {
	MLX5_CLASS_NET,
	MLX5_CLASS_VDPA,
	/* New class combination should be added here */
};

static int class_name_to_val(const char *class_name)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(mlx5_classes); i++) {
		if (strcmp(class_name, mlx5_classes[i].name) == 0)
			return mlx5_classes[i].dev_class;

	}
	return -EINVAL;
}

static int
mlx5_bus_opt_handler(__rte_unused const char *key, const char *class_names,
		     void *opaque)
{
	int *ret = opaque;
	char *nstr_org;
	int class_val;
	char *found;
	char *nstr;

	*ret = 0;
	nstr = strdup(class_names);
	if (!nstr) {
		*ret = -ENOMEM;
		return *ret;
	}

	nstr_org = nstr;
	while (nstr) {
		/* Extract each individual class name */
		found = strsep(&nstr, ":");
		if (!found)
			continue;

		/* Check if its a valid class */
		class_val = class_name_to_val(found);
		if (class_val < 0) {
			*ret = -EINVAL;
			goto err;
		}

		*ret |= class_val;
	}
err:
	free(nstr_org);
	if (*ret < 0)
		DRV_LOG(ERR, "Invalid mlx5 class options %s. Maybe typo in device class argument setting?",
			class_names);
	return *ret;
}

static int
parse_class_options(const struct rte_devargs *devargs)
{
	const char *key = MLX5_CLASS_ARG_NAME;
	struct rte_kvargs *kvlist;
	int ret = 0;

	if (devargs == NULL)
		return 0;
	kvlist = rte_kvargs_parse(devargs->args, NULL);
	if (kvlist == NULL)
		return 0;
	if (rte_kvargs_count(kvlist, key))
		rte_kvargs_process(kvlist, key, mlx5_bus_opt_handler, &ret);
	rte_kvargs_free(kvlist);
	return ret;
}

void
rte_mlx5_pci_driver_register(struct rte_mlx5_pci_driver *driver)
{
	TAILQ_INSERT_TAIL(&drv_list, driver, next);
}

static bool
mlx5_bus_match(const struct rte_mlx5_pci_driver *drv,
	       const struct rte_pci_device *pci_dev)
{
	const struct rte_pci_id *id_table;

	for (id_table = drv->pci_driver.id_table; id_table->vendor_id != 0;
	     id_table++) {
		/* check if device's ids match the class driver's ones */
		if (id_table->vendor_id != pci_dev->id.vendor_id &&
				id_table->vendor_id != PCI_ANY_ID)
			continue;
		if (id_table->device_id != pci_dev->id.device_id &&
				id_table->device_id != PCI_ANY_ID)
			continue;
		if (id_table->subsystem_vendor_id !=
		    pci_dev->id.subsystem_vendor_id &&
		    id_table->subsystem_vendor_id != PCI_ANY_ID)
			continue;
		if (id_table->subsystem_device_id !=
		    pci_dev->id.subsystem_device_id &&
		    id_table->subsystem_device_id != PCI_ANY_ID)
			continue;
		if (id_table->class_id != pci_dev->id.class_id &&
				id_table->class_id != RTE_CLASS_ANY_ID)
			continue;

		return true;
	}
	return false;
}

static int is_valid_class_combo(uint32_t user_classes)
{
	unsigned int i;

	/* Verify if user specified valid supported combination */
	for (i = 0; i < RTE_DIM(mlx5_valid_class_combo); i++) {
		if (mlx5_valid_class_combo[i] == user_classes)
			return 0;
	}
	/* Not found any valid class combination */
	return -EINVAL;
}

static int validate_single_class_dma_ops(void)
{
	struct rte_mlx5_pci_driver *class;
	int dma_map_classes = 0;

	TAILQ_FOREACH(class, &drv_list, next) {
		if (class->pci_driver.dma_map)
			dma_map_classes++;
	}
	if (dma_map_classes > 1) {
		DRV_LOG(ERR, "Multiple classes with DMA ops is unsupported");
		return -EINVAL;
	}
	return 0;
}

/**
 * DPDK callback to register to probe multiple PCI class devices.
 *
 * @param[in] pci_drv
 *   PCI driver structure.
 * @param[in] dev
 *   PCI device information.
 *
 * @return
 *   0 on success, 1 to skip this driver, a negative errno value otherwise
 *   and rte_errno is set.
 */
static int
mlx5_bus_pci_probe(struct rte_pci_driver *drv __rte_unused,
		   struct rte_pci_device *dev)
{
	struct rte_mlx5_pci_driver *class;
	uint32_t user_classes = 0;
	int ret;

	ret = validate_single_class_dma_ops();
	if (ret)
		return ret;

	ret = parse_class_options(dev->device.devargs);
	if (ret < 0)
		return ret;

	user_classes = ret;
	if (user_classes) {
		/* Validate combination here */
		ret = is_valid_class_combo(user_classes);
		if (ret) {
			DRV_LOG(ERR, "Unsupported mlx5 classes supplied");
			return ret;
		}
	}

	/* Default to net class */
	if (user_classes == 0)
		user_classes = MLX5_CLASS_NET;

	TAILQ_FOREACH(class, &drv_list, next) {
		if (!mlx5_bus_match(class, dev))
			continue;

		if ((class->dev_class & user_classes) == 0)
			continue;

		ret = -EINVAL;
		if (class->loaded) {
			/* If already loaded and class driver can handle
			 * reprobe, probe such class driver again.
			 */
			if (class->pci_driver.drv_flags & RTE_PCI_DRV_PROBE_AGAIN)
				ret = class->pci_driver.probe(drv, dev);
		} else {
			ret = class->pci_driver.probe(drv, dev);
		}
		if (!ret)
			class->loaded = true;
	}
	return 0;
}

/**
 * DPDK callback to remove one or more class devices for a PCI device.
 *
 * This function removes all class devices belong to a given PCI device.
 *
 * @param[in] pci_dev
 *   Pointer to the PCI device.
 *
 * @return
 *   0 on success, the function cannot fail.
 */
static int
mlx5_bus_pci_remove(struct rte_pci_device *dev)
{
	struct rte_mlx5_pci_driver *class;

	/* Remove each class driver in reverse order */
	TAILQ_FOREACH_REVERSE(class, &drv_list, mlx5_pci_bus_drv_head, next) {
		if (class->loaded)
			class->pci_driver.remove(dev);
	}
	return 0;
}

static int
mlx5_bus_pci_dma_map(struct rte_pci_device *dev, void *addr,
		     uint64_t iova, size_t len)
{
	struct rte_mlx5_pci_driver *class;
	int ret = -EINVAL;

	TAILQ_FOREACH(class, &drv_list, next) {
		if (!class->pci_driver.dma_map)
			continue;

		return class->pci_driver.dma_map(dev, addr, iova, len);
	}
	return ret;
}

static int
mlx5_bus_pci_dma_unmap(struct rte_pci_device *dev, void *addr,
		       uint64_t iova, size_t len)
{
	struct rte_mlx5_pci_driver *class;
	int ret = -EINVAL;

	TAILQ_FOREACH_REVERSE(class, &drv_list, mlx5_pci_bus_drv_head, next) {
		if (!class->pci_driver.dma_unmap)
			continue;

		return class->pci_driver.dma_unmap(dev, addr, iova, len);
	}
	return ret;
}

static const struct rte_pci_id mlx5_bus_pci_id_map[] = {
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX4LXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5EXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
			       PCI_DEVICE_ID_MELLANOX_CONNECTX5BFVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6VF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6DX)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6DXVF)
	},
	{
		RTE_PCI_DEVICE(PCI_VENDOR_ID_MELLANOX,
				PCI_DEVICE_ID_MELLANOX_CONNECTX6DXBF)
	},
	{
		.vendor_id = 0
	}
};

static struct rte_pci_driver mlx5_bus_driver = {
	.driver = {
		.name = "mlx5_bus_pci",
	},
	.id_table = mlx5_bus_pci_id_map,
	.probe = mlx5_bus_pci_probe,
	.remove = mlx5_bus_pci_remove,
	.dma_map = mlx5_bus_pci_dma_map,
	.dma_unmap = mlx5_bus_pci_dma_unmap,
	.drv_flags = RTE_PCI_DRV_INTR_LSC | RTE_PCI_DRV_INTR_RMV |
		     RTE_PCI_DRV_PROBE_AGAIN,
};

RTE_PMD_REGISTER_PCI(mlx5_bus, mlx5_bus_driver);
RTE_PMD_REGISTER_PCI_TABLE(mlx5_bus, mlx5_bus_pci_id_map);
