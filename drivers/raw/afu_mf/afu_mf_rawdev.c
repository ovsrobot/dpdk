/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Intel Corporation
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>

#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_rawdev_pmd.h>

#include "afu_mf_rawdev.h"

#define AFU_MF_PMD_RAWDEV_NAME rawdev_afu_mf

static const struct rte_afu_uuid afu_uuid_map[] = {
	{ 0, 0 /* sentinel */ }
};

static struct afu_mf_drv *afu_table[] = {
	NULL
};

static inline int afu_mf_trylock(struct afu_mf_rawdev *dev)
{
	int32_t x = 0;

	if (!dev || !dev->shared)
		return -ENODEV;

	x = __atomic_load_n(&dev->shared->lock, __ATOMIC_RELAXED);

	if ((x != 0) || (__atomic_compare_exchange_n(&dev->shared->lock, &x, 1,
				1, __ATOMIC_ACQUIRE, __ATOMIC_RELAXED) == 0))
		return -EBUSY;

	return 0;
}

static inline void afu_mf_unlock(struct afu_mf_rawdev *dev)
{
	if (!dev || !dev->shared)
		return;

	__atomic_store_n(&dev->shared->lock, 0, __ATOMIC_RELEASE);
}

static int afu_mf_rawdev_configure(const struct rte_rawdev *rawdev,
	rte_rawdev_obj_t config, size_t config_size)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return -ENODEV;

	if (dev->ops && dev->ops->config)
		ret = (*dev->ops->config)(dev, config, config_size);

	return ret;
}

static int afu_mf_rawdev_start(struct rte_rawdev *rawdev)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return -ENODEV;

	ret = afu_mf_trylock(dev);
	if (ret) {
		AFU_MF_PMD_WARN("AFU is busy, please start it later");
		return ret;
	}

	if (dev->ops && dev->ops->start)
		ret = (*dev->ops->start)(dev);

	afu_mf_unlock(dev);

	return ret;
}

static void afu_mf_rawdev_stop(struct rte_rawdev *rawdev)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return;

	ret = afu_mf_trylock(dev);
	if (ret) {
		AFU_MF_PMD_WARN("AFU is busy, please stop it later");
		return;
	}

	if (dev->ops && dev->ops->stop)
		ret = (*dev->ops->stop)(dev);

	afu_mf_unlock(dev);
}

static int afu_mf_rawdev_close(struct rte_rawdev *rawdev)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return -ENODEV;

	if (dev->ops && dev->ops->close)
		ret = (*dev->ops->close)(dev);

	return ret;
}

static int afu_mf_rawdev_reset(struct rte_rawdev *rawdev)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return -ENODEV;

	ret = afu_mf_trylock(dev);
	if (ret) {
		AFU_MF_PMD_WARN("AFU is busy, please reset it later");
		return ret;
	}

	if (dev->ops && dev->ops->reset)
		ret = (*dev->ops->reset)(dev);

	afu_mf_unlock(dev);

	return ret;
}

static int afu_mf_rawdev_selftest(uint16_t dev_id)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	if (!rte_rawdev_pmd_is_valid_dev(dev_id))
		return -ENODEV;

	dev = afu_mf_rawdev_get_priv(&rte_rawdevs[dev_id]);
	if (!dev)
		return -ENOENT;

	ret = afu_mf_trylock(dev);
	if (ret) {
		AFU_MF_PMD_WARN("AFU is busy, please test it later");
		return ret;
	}

	if (dev->ops && dev->ops->test)
		ret = (*dev->ops->test)(dev);

	afu_mf_unlock(dev);

	return ret;
}

static int afu_mf_rawdev_dump(struct rte_rawdev *rawdev, FILE *f)
{
	struct afu_mf_rawdev *dev = NULL;
	int ret = 0;

	AFU_MF_PMD_FUNC_TRACE();

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		return -ENODEV;

	if (dev->ops && dev->ops->dump)
		ret = (*dev->ops->dump)(dev, f);

	return ret;
}

static const struct rte_rawdev_ops afu_mf_rawdev_ops = {
	.dev_info_get = NULL,
	.dev_configure = afu_mf_rawdev_configure,
	.dev_start = afu_mf_rawdev_start,
	.dev_stop = afu_mf_rawdev_stop,
	.dev_close = afu_mf_rawdev_close,
	.dev_reset = afu_mf_rawdev_reset,

	.queue_def_conf = NULL,
	.queue_setup = NULL,
	.queue_release = NULL,
	.queue_count = NULL,

	.attr_get = NULL,
	.attr_set = NULL,

	.enqueue_bufs = NULL,
	.dequeue_bufs = NULL,

	.dump = afu_mf_rawdev_dump,

	.xstats_get = NULL,
	.xstats_get_names = NULL,
	.xstats_get_by_name = NULL,
	.xstats_reset = NULL,

	.firmware_status_get = NULL,
	.firmware_version_get = NULL,
	.firmware_load = NULL,
	.firmware_unload = NULL,

	.dev_selftest = afu_mf_rawdev_selftest,
};

static int
afu_mf_shared_alloc(const char *name, struct afu_mf_shared **data,
	int socket_id)
{
	const struct rte_memzone *mz;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	struct afu_mf_shared *ptr = NULL;
	int init_mz = 0;

	if (!name || !data)
		return -EINVAL;

	/* name format is afu_?|??:??.? which is unique */
	snprintf(mz_name, sizeof(mz_name), "%s", name);

	mz = rte_memzone_lookup(mz_name);
	if (!mz) {
		mz = rte_memzone_reserve(mz_name,
				sizeof(struct afu_mf_shared),
				socket_id, 0);
		init_mz = 1;
	}

	if (!mz) {
		AFU_MF_PMD_ERR("Allocate memory zone %s failed!",
			mz_name);
		return -ENOMEM;
	}

	ptr = (struct afu_mf_shared *)mz->addr;

	if (init_mz)  /* initialize memory zone on the first time */
		ptr->lock = 0;

	*data = ptr;

	return 0;
}

static int afu_mf_rawdev_name_get(struct rte_afu_device *afu_dev, char *name,
	size_t size)
{
	int n = 0;

	if (!afu_dev || !name || !size)
		return -EINVAL;

	n = snprintf(name, size, "afu_%s", afu_dev->device.name);
	if (n >= (int)size) {
		AFU_MF_PMD_ERR("Name of AFU device is too long!");
		return -ENAMETOOLONG;
	}

	return 0;
}

static struct afu_mf_ops *afu_mf_ops_get(struct rte_afu_uuid *afu_id)
{
	struct afu_mf_drv *entry = NULL;
	int i = 0;

	if (!afu_id)
		return NULL;

	while ((entry = afu_table[i++])) {
		if ((entry->uuid.uuid_low == afu_id->uuid_low) &&
			(entry->uuid.uuid_high == afu_id->uuid_high))
			break;
	}

	return entry ? entry->ops : NULL;
}

static int afu_mf_rawdev_create(struct rte_afu_device *afu_dev, int socket_id)
{
	struct rte_rawdev *rawdev = NULL;
	struct afu_mf_rawdev *dev = NULL;
	char name[RTE_RAWDEV_NAME_MAX_LEN] = {0};
	int ret = 0;

	if (!afu_dev)
		return -EINVAL;

	ret = afu_mf_rawdev_name_get(afu_dev, name, sizeof(name));
	if (ret)
		return ret;

	AFU_MF_PMD_INFO("Create raw device %s on NUMA node %d",
		name, socket_id);

	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(name, sizeof(struct afu_mf_rawdev),
				socket_id);
	if (!rawdev) {
		AFU_MF_PMD_ERR("Unable to allocate raw device");
		return -ENOMEM;
	}

	rawdev->dev_ops = &afu_mf_rawdev_ops;
	rawdev->device = &afu_dev->device;
	rawdev->driver_name = afu_dev->driver->driver.name;

	dev = afu_mf_rawdev_get_priv(rawdev);
	if (!dev)
		goto cleanup;

	dev->rawdev = rawdev;
	dev->port = afu_dev->id.port;
	dev->addr = afu_dev->mem_resource[0].addr;
	dev->ops = afu_mf_ops_get(&afu_dev->id.uuid);
	if (dev->ops == NULL) {
		AFU_MF_PMD_ERR("Unsupported AFU device");
		goto cleanup;
	}

	if (dev->ops->init) {
		ret = (*dev->ops->init)(dev);
		if (ret) {
			AFU_MF_PMD_ERR("Failed to init %s", name);
			goto cleanup;
		}
	}

	ret = afu_mf_shared_alloc(name, &dev->shared, socket_id);
	if (ret)
		goto cleanup;

	return ret;

cleanup:
	rte_rawdev_pmd_release(rawdev);
	return ret;
}

static int afu_mf_rawdev_destroy(struct rte_afu_device *afu_dev)
{
	struct rte_rawdev *rawdev = NULL;
	char name[RTE_RAWDEV_NAME_MAX_LEN] = {0};
	int ret = 0;

	if (!afu_dev)
		return -EINVAL;

	ret = afu_mf_rawdev_name_get(afu_dev, name, sizeof(name));
	if (ret)
		return ret;

	AFU_MF_PMD_INFO("Destroy raw device %s", name);

	rawdev = rte_rawdev_pmd_get_named_dev(name);
	if (!rawdev) {
		AFU_MF_PMD_ERR("Raw device %s not found", name);
		return -EINVAL;
	}

	/* rte_rawdev_close is called by pmd_release */
	ret = rte_rawdev_pmd_release(rawdev);
	if (ret)
		AFU_MF_PMD_DEBUG("Device cleanup failed");

	return 0;
}

static int afu_mf_rawdev_probe(struct rte_afu_device *afu_dev)
{
	AFU_MF_PMD_FUNC_TRACE();
	return afu_mf_rawdev_create(afu_dev, rte_socket_id());
}

static int afu_mf_rawdev_remove(struct rte_afu_device *afu_dev)
{
	AFU_MF_PMD_FUNC_TRACE();
	return afu_mf_rawdev_destroy(afu_dev);
}

static struct rte_afu_driver afu_mf_pmd_drv = {
	.id_table = afu_uuid_map,
	.probe = afu_mf_rawdev_probe,
	.remove = afu_mf_rawdev_remove
};

RTE_PMD_REGISTER_AFU(AFU_MF_PMD_RAWDEV_NAME, afu_mf_pmd_drv);
RTE_LOG_REGISTER_DEFAULT(afu_mf_pmd_logtype, NOTICE);
