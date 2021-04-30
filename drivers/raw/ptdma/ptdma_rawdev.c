/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Advanced Micro Devices, Inc. All rights reserved.
 */

#include <rte_bus_pci.h>
#include <rte_rawdev_pmd.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>
#include <rte_dev.h>

#include "rte_ptdma_rawdev.h"
#include "ptdma_rawdev_spec.h"
#include "ptdma_pmd_private.h"

RTE_LOG_REGISTER(ptdma_pmd_logtype, rawdev.ptdma, INFO);

uint8_t ptdma_rawdev_driver_id;
static struct rte_pci_driver ptdma_pmd_drv;

#define AMD_VENDOR_ID		0x1022
#define PTDMA_DEVICE_ID		0x1498
#define COMPLETION_SZ sizeof(__m128i)

static const struct rte_pci_id pci_id_ptdma_map[] = {
	{ RTE_PCI_DEVICE(AMD_VENDOR_ID, PTDMA_DEVICE_ID) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const char * const xstat_names[] = {
	"failed_enqueues", "successful_enqueues",
	"copies_started", "copies_completed"
};

static int
ptdma_dev_configure(const struct rte_rawdev *dev, rte_rawdev_obj_t config,
		size_t config_size)
{
	struct rte_ptdma_rawdev_config *params = config;
	struct rte_ptdma_rawdev *ptdma = dev->dev_private;
	char mz_name[RTE_MEMZONE_NAMESIZE];

	if (dev->started)
		return -EBUSY;
	if (params == NULL || config_size != sizeof(*params))
		return -EINVAL;
	if (params->ring_size > 4096 || params->ring_size < 64 ||
			!rte_is_power_of_2(params->ring_size))
		return -EINVAL;
	ptdma->ring_size = params->ring_size;
	ptdma->hdls_disable = params->hdls_disable;

	snprintf(mz_name, sizeof(mz_name), "rawdev%u_hdls", dev->dev_id);
	ptdma->mz = rte_memzone_reserve(mz_name,
			(COMPLETION_SZ) * COMMANDS_PER_QUEUE,
			dev->device->numa_node, RTE_MEMZONE_IOVA_CONTIG);
	if (ptdma->mz == NULL)
		return -ENOMEM;
	ptdma->hdls = (void *)&ptdma->mz->addr[COMMANDS_PER_QUEUE];

	return 0;
}

static int
ptdma_rawdev_remove(struct rte_pci_device *dev);

int
ptdma_xstats_get(const struct rte_rawdev *dev, const unsigned int ids[],
		uint64_t values[], unsigned int n)
{
	const struct rte_ptdma_rawdev *ptdma = dev->dev_private;
	const uint64_t *stats = (const void *)&ptdma->xstats;
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (ids[i] > sizeof(ptdma->xstats)/sizeof(*stats))
			values[i] = 0;
		else
			values[i] = stats[ids[i]];
	}
	return n;
}

int
ptdma_xstats_get_names(const struct rte_rawdev *dev,
		struct rte_rawdev_xstats_name *names,
		unsigned int size)
{
	unsigned int i;

	RTE_SET_USED(dev);
	if (size < RTE_DIM(xstat_names))
		return RTE_DIM(xstat_names);
	for (i = 0; i < RTE_DIM(xstat_names); i++)
		strlcpy(names[i].name, xstat_names[i], sizeof(names[i]));
	return RTE_DIM(xstat_names);
}

int
ptdma_xstats_reset(struct rte_rawdev *dev, const uint32_t *ids,
		uint32_t nb_ids)
{
	struct rte_ptdma_rawdev *ptdma = dev->dev_private;
	uint64_t *stats = (void *)&ptdma->xstats;
	unsigned int i;

	if (!ids) {
		memset(&ptdma->xstats, 0, sizeof(ptdma->xstats));
		return 0;
	}
	for (i = 0; i < nb_ids; i++)
		if (ids[i] < sizeof(ptdma->xstats)/sizeof(*stats))
			stats[ids[i]] = 0;
	return 0;
}

static int
ptdma_dev_start(struct rte_rawdev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static void
ptdma_dev_stop(struct rte_rawdev *dev)
{
	RTE_SET_USED(dev);
}

static int
ptdma_dev_close(struct rte_rawdev *dev __rte_unused)
{
	return 0;
}

static int
ptdma_dev_info_get(struct rte_rawdev *dev, rte_rawdev_obj_t dev_info,
		size_t dev_info_size)
{
	struct rte_ptdma_rawdev_config *cfg = dev_info;
	struct rte_ptdma_rawdev *ptdma = dev->dev_private;

	if (dev_info == NULL || dev_info_size != sizeof(*cfg))
		return -EINVAL;
	cfg->ring_size = ptdma->ring_size;
	cfg->hdls_disable = ptdma->hdls_disable;
	return 0;
}

static int
ptdma_rawdev_create(const char *name, struct rte_pci_device *dev)
{
	static const struct rte_rawdev_ops ptdma_rawdev_ops = {
			.dev_configure = ptdma_dev_configure,
			.dev_start = ptdma_dev_start,
			.dev_stop = ptdma_dev_stop,
			.dev_close = ptdma_dev_close,
			.dev_info_get = ptdma_dev_info_get,
			.xstats_get = ptdma_xstats_get,
			.xstats_get_names = ptdma_xstats_get_names,
			.xstats_reset = ptdma_xstats_reset,
			.dev_selftest = ptdma_rawdev_test,
	};
	struct rte_rawdev *rawdev = NULL;
	struct rte_ptdma_rawdev *ptdma_priv = NULL;
	struct ptdma_device *ptdma_dev = NULL;
	const struct rte_memzone *mz = NULL;
	char mz_name[RTE_MEMZONE_NAMESIZE];
	int ret = 0;
	if (!name) {
		PTDMA_PMD_ERR("Invalid name of the device!");
		ret = -EINVAL;
		goto cleanup;
	}
	/* Allocate device structure */
	rawdev = rte_rawdev_pmd_allocate(name, sizeof(struct rte_rawdev),
						dev->device.numa_node);
	if (rawdev == NULL) {
		PTDMA_PMD_ERR("Unable to allocate raw device");
		ret = -ENOMEM;
		goto cleanup;
	}

	snprintf(mz_name, sizeof(mz_name), "rawdev%u_private", rawdev->dev_id);
	mz = rte_memzone_reserve(mz_name, sizeof(struct rte_ptdma_rawdev),
			dev->device.numa_node, RTE_MEMZONE_IOVA_CONTIG);
	if (mz == NULL) {
		PTDMA_PMD_ERR("Unable to reserve memzone for private data\n");
		ret = -ENOMEM;
		goto init_error;
	}

	ptdma_dev = rte_zmalloc_socket("ptdma_device", sizeof(*ptdma_dev),
			RTE_CACHE_LINE_SIZE, dev->device.numa_node);
	if (ptdma_dev == NULL)
		goto cleanup;

	ptdma_dev->pci = *dev;

	rawdev->dev_id = ptdma_rawdev_driver_id++;
	PTDMA_PMD_INFO("dev_id = %d", rawdev->dev_id);
	PTDMA_PMD_INFO("driver_name = %s", dev->device.driver->name);

	rawdev->dev_ops = &ptdma_rawdev_ops;
	rawdev->device = &dev->device;
	rawdev->driver_name = dev->device.driver->name;

	ptdma_priv	= mz->addr;
	rawdev->dev_private = ptdma_priv;
	ptdma_priv->rawdev = rawdev;
	ptdma_priv->ring_size = 0;
	ptdma_priv->ptdma_dev = ptdma_dev;

	/* device is valid, add queue details */
	if (ptdma_add_queue(ptdma_dev))
		goto init_error;

	return 0;

cleanup:
	if (rawdev)
		rte_rawdev_pmd_release(rawdev);
	return ret;
init_error:
	PTDMA_PMD_ERR("driver %s(): failed", __func__);
	ptdma_rawdev_remove(dev);
	return -EFAULT;
}

static int
ptdma_rawdev_destroy(const char *name)
{
	int ret;
	struct rte_rawdev *rdev;
	if (!name) {
		PTDMA_PMD_ERR("Invalid device name");
		return -EINVAL;
	}
	rdev = rte_rawdev_pmd_get_named_dev(name);
	if (!rdev) {
		PTDMA_PMD_ERR("Invalid device name (%s)", name);
		return -EINVAL;
	}

	if (rdev->dev_private != NULL) {
		struct rte_ptdma_rawdev *ptdma = rdev->dev_private;
		rdev->dev_private = NULL;
		rte_memzone_free(ptdma->mz);
	}

	/* rte_rawdev_close is called by pmd_release */
	ret = rte_rawdev_pmd_release(rdev);

	if (ret)
		PTDMA_PMD_DEBUG("Device cleanup failed");
	return 0;
}
static int
ptdma_rawdev_probe(struct rte_pci_driver *drv, struct rte_pci_device *dev)
{
	char name[32];
	int ret = 0;

	rte_pci_device_name(&dev->addr, name, sizeof(name));
	PTDMA_PMD_INFO("Init %s on NUMA node %d", name, dev->device.numa_node);

	dev->device.driver = &drv->driver;
	ret = ptdma_rawdev_create(name, dev);
	return ret;
}

static int
ptdma_rawdev_remove(struct rte_pci_device *dev)
{
	char name[32];
	int ret;

	rte_pci_device_name(&dev->addr, name, sizeof(name));
	PTDMA_PMD_INFO("Closing %s on NUMA node %d",
			name, dev->device.numa_node);
	ret = ptdma_rawdev_destroy(name);
	return ret;
}

static struct rte_pci_driver ptdma_pmd_drv = {
	.id_table = pci_id_ptdma_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING | RTE_PCI_DRV_INTR_LSC,
	.probe = ptdma_rawdev_probe,
	.remove = ptdma_rawdev_remove,
};

RTE_PMD_REGISTER_PCI(PTDMA_PMD_RAWDEV_NAME, ptdma_pmd_drv);
RTE_PMD_REGISTER_PCI_TABLE(PTDMA_PMD_RAWDEV_NAME, pci_id_ptdma_map);
RTE_PMD_REGISTER_KMOD_DEP(PTDMA_PMD_RAWDEV_NAME, "* igb_uio | uio_pci_generic");

