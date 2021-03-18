/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Intel Corporation
 */

#include <dirent.h>
#include <libgen.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <rte_bus.h>
#include <rte_log.h>
#include <rte_string_fns.h>
#include "ioat_private.h"

/* default value for DSA paths, but allow override in environment for testing */
#define DSA_DEV_PATH "/dev/dsa"
#define DSA_SYSFS_PATH "/sys/bus/dsa/devices"

/** a DSA device instance */
struct rte_dsa_device {
	TAILQ_ENTRY(rte_dsa_device) next;   /**< next dev in list */
	struct rte_device device;           /**< Inherit core device */
	char wq_name[32];                   /**< the workqueue name/number e.g. wq0.1 */
	uint16_t device_id;                 /**< the DSA instance number */
	uint16_t wq_id;                     /**< the queue on the DSA instance */
};

/* forward prototypes */
struct dsa_bus;
static int dsa_scan(void);
static int dsa_probe(void);
static struct rte_device *dsa_find_device(const struct rte_device *start,
		rte_dev_cmp_t cmp,  const void *data);

/** List of devices */
TAILQ_HEAD(dsa_device_list, rte_dsa_device);

/**
 * Structure describing the DSA bus
 */
struct dsa_bus {
	struct rte_bus bus;               /**< Inherit the generic class */
	struct rte_driver driver;         /**< Driver struct for devices to point to */
	struct dsa_device_list device_list;  /**< List of PCI devices */
};

struct dsa_bus dsa_bus = {
	.bus = {
		.scan = dsa_scan,
		.probe = dsa_probe,
		.find_device = dsa_find_device,
	},
	.driver = {
		.name = "rawdev_idxd"
	},
	.device_list = TAILQ_HEAD_INITIALIZER(dsa_bus.device_list),
};

static inline const char *
dsa_get_dev_path(void)
{
	const char *path = getenv("DSA_DEV_PATH");
	return path ? path : DSA_DEV_PATH;
}

static inline const char *
dsa_get_sysfs_path(void)
{
	const char *path = getenv("DSA_SYSFS_PATH");
	return path ? path : DSA_SYSFS_PATH;
}

static const struct rte_rawdev_ops idxd_vdev_ops = {
		.dev_close = idxd_rawdev_close,
		.dev_selftest = ioat_rawdev_test,
		.dump = idxd_dev_dump,
		.dev_configure = idxd_dev_configure,
		.dev_info_get = idxd_dev_info_get,
		.xstats_get = ioat_xstats_get,
		.xstats_get_names = ioat_xstats_get_names,
		.xstats_reset = ioat_xstats_reset,
};

static void *
idxd_vdev_mmap_wq(struct rte_dsa_device *dev)
{
	void *addr;
	char path[PATH_MAX];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dsa_get_dev_path(), dev->wq_name);
	fd = open(path, O_RDWR);
	if (fd < 0) {
		IOAT_PMD_ERR("Failed to open device path: %s", path);
		return NULL;
	}

	addr = mmap(NULL, 0x1000, PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		IOAT_PMD_ERR("Failed to mmap device %s", path);
		return NULL;
	}

	return addr;
}

static int
read_wq_string(struct rte_dsa_device *dev, const char *filename,
		char *value, size_t valuelen)
{
	char sysfs_node[PATH_MAX];
	int len;
	int fd;

	snprintf(sysfs_node, sizeof(sysfs_node), "%s/%s/%s",
			dsa_get_sysfs_path(), dev->wq_name, filename);
	if ((fd = open(sysfs_node, O_RDONLY)) < 0) {
		IOAT_PMD_ERR("%s(): opening file '%s' failed: %s",
				__func__, sysfs_node, strerror(errno));
		return -1;
	}

	len = read(fd, value, valuelen - 1);
	close(fd);
	if (len < 0) {
		IOAT_PMD_ERR("%s(): error reading file '%s': %s",
				__func__, sysfs_node, strerror(errno));
		return -1;
	}
	value[len] = '\0';
	return 0;
}

static int
read_wq_int(struct rte_dsa_device *dev, const char *filename,
		int *value)
{
	char sysfs_node[PATH_MAX];
	FILE *f;
	int ret = 0;

	snprintf(sysfs_node, sizeof(sysfs_node), "%s/%s/%s",
			dsa_get_sysfs_path(), dev->wq_name, filename);
	f = fopen(sysfs_node, "r");
	if (f == NULL) {
		IOAT_PMD_ERR("%s(): opening file '%s' failed: %s",
				__func__, sysfs_node, strerror(errno));
		return -1;
	}

	if (fscanf(f, "%d", value) != 1) {
		IOAT_PMD_ERR("%s(): error reading file '%s': %s",
				__func__, sysfs_node, strerror(errno));
		ret = -1;
	}

	fclose(f);
	return ret;
}

static int
read_device_int(struct rte_dsa_device *dev, const char *filename,
		int *value)
{
	char sysfs_node[PATH_MAX];
	FILE *f;
	int ret;

	snprintf(sysfs_node, sizeof(sysfs_node), "%s/dsa%d/%s",
			dsa_get_sysfs_path(), dev->device_id, filename);
	f = fopen(sysfs_node, "r");
	if (f == NULL) {
		IOAT_PMD_ERR("%s(): opening file '%s' failed: %s",
				__func__, sysfs_node, strerror(errno));
		return -1;
	}

	if (fscanf(f, "%d", value) != 1) {
		IOAT_PMD_ERR("%s(): error reading file '%s': %s",
				__func__, sysfs_node, strerror(errno));
		ret = -1;
	}

	fclose(f);
	return ret;
}

static int
idxd_rawdev_probe_dsa(struct rte_dsa_device *dev)
{
	struct idxd_rawdev idxd = {{0}}; /* double {} to avoid error on BSD12 */
	int ret = 0;

	IOAT_PMD_INFO("Probing device %s on numa node %d",
			dev->wq_name, dev->device.numa_node);
	if (read_wq_int(dev, "size", &ret) < 0)
		return -1;
	idxd.max_batches = ret;
	idxd.qid = dev->wq_id;
	idxd.u.vdev.dsa_id = dev->device_id;

	idxd.public.portal = idxd_vdev_mmap_wq(dev);
	if (idxd.public.portal == NULL) {
		IOAT_PMD_ERR("WQ mmap failed");
		return -ENOENT;
	}

	ret = idxd_rawdev_create(dev->wq_name, &dev->device, &idxd, &idxd_vdev_ops);
	if (ret) {
		IOAT_PMD_ERR("Failed to create rawdev %s", dev->wq_name);
		return ret;
	}

	return 0;
}

static int
is_for_this_process_use(const char *name)
{
	char *runtime_dir = strdup(rte_eal_get_runtime_dir());
	char *prefix = basename(runtime_dir);
	int prefixlen = strlen(prefix);
	int retval = 0;

	if (strncmp(name, "dpdk_", 5) == 0)
		retval = 1;
	if (strncmp(name, prefix, prefixlen) == 0 && name[prefixlen] == '_')
		retval = 1;

	free(runtime_dir);
	return retval;
}

static int
dsa_probe(void)
{
	struct rte_dsa_device *dev;

	TAILQ_FOREACH(dev, &dsa_bus.device_list, next) {
		char type[64], name[64];

		if (read_wq_string(dev, "type", type, sizeof(type)) < 0 ||
				read_wq_string(dev, "name", name, sizeof(name)) < 0)
			continue;

		if (strncmp(type, "user", 4) == 0 && is_for_this_process_use(name)) {
			dev->device.driver = &dsa_bus.driver;
			idxd_rawdev_probe_dsa(dev);
			continue;
		}
		IOAT_PMD_DEBUG("WQ '%s', not allocated to DPDK", dev->wq_name);
	}

	return 0;
}

static int
dsa_scan(void)
{
	const char *path = dsa_get_dev_path();
	struct dirent *wq;
	DIR *dev_dir;

	dev_dir = opendir(path);
	if (dev_dir == NULL) {
		if (errno == ENOENT)
			return 0; /* no bus, return witout error */
		IOAT_PMD_ERR("%s(): opendir '%s' failed: %s",
				__func__, path, strerror(errno));
		return -1;
	}

	while ((wq = readdir(dev_dir)) != NULL) {
		struct rte_dsa_device *dev;
		unsigned int device_id, wq_id;
		int numa_node = -1;

		if (strncmp(wq->d_name, "wq", 2) != 0)
			continue;
		if (strnlen(wq->d_name, sizeof(dev->wq_name)) == sizeof(dev->wq_name)) {
			IOAT_PMD_ERR("%s(): wq name too long: '%s', skipping",
					__func__, wq->d_name);
			continue;
		}
		IOAT_PMD_DEBUG("%s(): found %s/%s", __func__, path, wq->d_name);

		if (sscanf(wq->d_name, "wq%u.%u", &device_id, &wq_id) != 2) {
			IOAT_PMD_ERR("Error parsing WQ name: %s", wq->d_name);
			continue;
		}

		dev = malloc(sizeof(*dev));
		dev->device_id = device_id;
		dev->wq_id = wq_id;
		dev->device.bus = &dsa_bus.bus;
		strlcpy(dev->wq_name, wq->d_name, sizeof(dev->wq_name));
		TAILQ_INSERT_TAIL(&dsa_bus.device_list, dev, next);

		read_device_int(dev, "numa_node", &numa_node);
		dev->device.numa_node = numa_node;
	}

	return 0;
}

static struct rte_device *
dsa_find_device(const struct rte_device *start, rte_dev_cmp_t cmp,
			 const void *data)
{
	RTE_SET_USED(start);
	RTE_SET_USED(cmp);
	RTE_SET_USED(data);
	return NULL;
}

RTE_REGISTER_BUS(dsa, dsa_bus.bus);
