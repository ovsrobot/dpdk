/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include <rte_mldev.h>
#include <rte_mldev_pmd.h>

static struct rte_ml_dev ml_devices[RTE_MLDEV_MAX_DEVS];

static struct rte_ml_dev_global ml_dev_globals = {
	.devs = ml_devices, .data = {NULL}, .nb_devs = 0, .max_devs = RTE_MLDEV_MAX_DEVS};

struct rte_ml_dev *
rte_ml_dev_pmd_get_dev(int16_t dev_id)
{
	return &ml_dev_globals.devs[dev_id];
}

struct rte_ml_dev *
rte_ml_dev_pmd_get_named_dev(const char *name)
{
	struct rte_ml_dev *dev;
	int16_t dev_id;

	if (name == NULL)
		return NULL;

	for (dev_id = 0; dev_id < RTE_MLDEV_MAX_DEVS; dev_id++) {
		dev = rte_ml_dev_pmd_get_dev(dev_id);
		if ((dev->attached == ML_DEV_ATTACHED) && (strcmp(dev->data->name, name) == 0))
			return dev;
	}

	return NULL;
}

struct rte_ml_dev *
rte_ml_dev_pmd_allocate(const char *name, uint8_t socket_id)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	struct rte_ml_dev *dev;
	int16_t dev_id;

	if (rte_ml_dev_pmd_get_named_dev(name) != NULL) {
		ML_DEV_LOG(ERR, "ML device with name %s already allocated!", name);
		return NULL;
	}

	/* Get a free device ID */
	for (dev_id = 0; dev_id < RTE_MLDEV_MAX_DEVS; dev_id++) {
		dev = rte_ml_dev_pmd_get_dev(dev_id);
		if (dev->attached == ML_DEV_DETACHED)
			break;
	}

	if (dev_id == RTE_MLDEV_MAX_DEVS) {
		ML_DEV_LOG(ERR, "Reached maximum number of ML devices");
		return NULL;
	}

	if (dev->data == NULL) {
		/* Reserve memzone name */
		sprintf(mz_name, "rte_ml_dev_data_%d", dev_id);
		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			mz = rte_memzone_reserve(mz_name, sizeof(struct rte_ml_dev_data), socket_id,
						 0);
			ML_DEV_LOG(DEBUG, "PRIMARY: reserved memzone for %s (%p)", mz_name, mz);
		} else {
			mz = rte_memzone_lookup(mz_name);
			ML_DEV_LOG(DEBUG, "SECONDARY: looked up memzone for %s (%p)", mz_name, mz);
		}

		if (mz == NULL)
			return NULL;

		ml_dev_globals.data[dev_id] = mz->addr;
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			memset(ml_dev_globals.data[dev_id], 0, sizeof(struct rte_ml_dev_data));

		dev->data = ml_dev_globals.data[dev_id];
		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			strlcpy(dev->data->name, name, RTE_ML_STR_MAX);
			dev->data->dev_id = dev_id;
			dev->data->socket_id = socket_id;
			dev->data->dev_started = 0;
			ML_DEV_LOG(DEBUG, "PRIMARY: init mldev data");
		}

		ML_DEV_LOG(DEBUG, "Data for %s: dev_id %d, socket %u", dev->data->name,
			   dev->data->dev_id, dev->data->socket_id);

		dev->attached = ML_DEV_ATTACHED;
		ml_dev_globals.nb_devs++;
	}

	return dev;
}

int
rte_ml_dev_pmd_release(struct rte_ml_dev *dev)
{
	char mz_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;
	int16_t dev_id;
	int ret = 0;

	if (dev == NULL)
		return -EINVAL;

	dev_id = dev->data->dev_id;

	/* Memzone lookup */
	sprintf(mz_name, "rte_ml_dev_data_%d", dev_id);
	mz = rte_memzone_lookup(mz_name);
	if (mz == NULL)
		return -ENOMEM;

	RTE_ASSERT(ml_dev_globals.data[dev_id] == mz->addr);
	ml_dev_globals.data[dev_id] = NULL;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		ML_DEV_LOG(DEBUG, "PRIMARY: free memzone of %s (%p)", mz_name, mz);
		ret = rte_memzone_free(mz);
	} else {
		ML_DEV_LOG(DEBUG, "SECONDARY: don't free memzone of %s (%p)", mz_name, mz);
	}

	dev->attached = ML_DEV_DETACHED;
	ml_dev_globals.nb_devs--;

	return ret;
}

uint16_t
rte_ml_dev_count(void)
{
	return ml_dev_globals.nb_devs;
}

int
rte_ml_dev_is_valid_dev(int16_t dev_id)
{
	struct rte_ml_dev *dev = NULL;

	if (dev_id >= ml_dev_globals.max_devs || ml_devices[dev_id].data == NULL)
		return 0;

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (dev->attached != ML_DEV_ATTACHED)
		return 0;
	else
		return 1;
}

int
rte_ml_dev_socket_id(int16_t dev_id)
{
	struct rte_ml_dev *dev;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);

	return dev->data->socket_id;
}

int
rte_ml_dev_info_get(int16_t dev_id, struct rte_ml_dev_info *dev_info)
{
	struct rte_ml_dev *dev;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (*dev->dev_ops->dev_info_get == NULL)
		return -ENOTSUP;

	if (dev_info == NULL) {
		ML_DEV_LOG(ERR, "Dev %d, dev_info cannot be NULL\n", dev_id);
		return -EINVAL;
	}
	memset(dev_info, 0, sizeof(struct rte_ml_dev_info));

	return (*dev->dev_ops->dev_info_get)(dev, dev_info);
}

int
rte_ml_dev_configure(int16_t dev_id, const struct rte_ml_dev_config *config)
{
	struct rte_ml_dev_info dev_info;
	struct rte_ml_dev *dev;
	int ret;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (*dev->dev_ops->dev_configure == NULL)
		return -ENOTSUP;

	if (dev->data->dev_started) {
		ML_DEV_LOG(ERR, "Device %d must be stopped to allow configuration", dev_id);
		return -EBUSY;
	}

	if (config == NULL) {
		ML_DEV_LOG(ERR, "Dev %d, config cannot be NULL\n", dev_id);
		return -EINVAL;
	}

	ret = rte_ml_dev_info_get(dev_id, &dev_info);
	if (ret < 0)
		return ret;

	if (config->nb_queue_pairs > dev_info.max_queue_pairs) {
		ML_DEV_LOG(ERR, "Device %d num of queues %u > %u\n", dev_id, config->nb_queue_pairs,
			   dev_info.max_queue_pairs);
		return -EINVAL;
	}

	return (*dev->dev_ops->dev_configure)(dev, config);
}

int
rte_ml_dev_close(int16_t dev_id)
{
	struct rte_ml_dev *dev;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (*dev->dev_ops->dev_close == NULL)
		return -ENOTSUP;

	/* Device must be stopped before it can be closed */
	if (dev->data->dev_started == 1) {
		ML_DEV_LOG(ERR, "Device %d must be stopped before closing", dev_id);
		return -EBUSY;
	}

	return (*dev->dev_ops->dev_close)(dev);
}

int
rte_ml_dev_start(int16_t dev_id)
{
	struct rte_ml_dev *dev;
	int ret;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (*dev->dev_ops->dev_start == NULL)
		return -ENOTSUP;

	if (dev->data->dev_started != 0) {
		ML_DEV_LOG(ERR, "Device %d is already started", dev_id);
		return -EBUSY;
	}

	ret = (*dev->dev_ops->dev_start)(dev);
	if (ret == 0)
		dev->data->dev_started = 1;

	return ret;
}

int
rte_ml_dev_stop(int16_t dev_id)
{
	struct rte_ml_dev *dev;
	int ret;

	if (!rte_ml_dev_is_valid_dev(dev_id)) {
		ML_DEV_LOG(ERR, "Invalid dev_id = %d\n", dev_id);
		return -EINVAL;
	}

	dev = rte_ml_dev_pmd_get_dev(dev_id);
	if (*dev->dev_ops->dev_stop == NULL)
		return -ENOTSUP;

	if (dev->data->dev_started == 0) {
		ML_DEV_LOG(ERR, "Device %d is not started", dev_id);
		return -EBUSY;
	}

	ret = (*dev->dev_ops->dev_stop)(dev);
	if (ret == 0)
		dev->data->dev_started = 0;

	return ret;
}
