/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 * Copyright(c) 2021 Intel Corporation.
 */

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_string_fns.h>

#include "rte_dmadev.h"
#include "rte_dmadev_pmd.h"

struct rte_dmadev rte_dmadevices[RTE_DMADEV_MAX_DEVS];

static const char *mz_rte_dmadev_data = "rte_dmadev_data";
/* Shared memory between primary and secondary processes. */
static struct {
	struct rte_dmadev_data data[RTE_DMADEV_MAX_DEVS];
} *dmadev_shared_data;

RTE_LOG_REGISTER_DEFAULT(rte_dmadev_logtype, INFO);
#define RTE_DMADEV_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, rte_dmadev_logtype, "" __VA_ARGS__)

/* Macros to check for valid device id */
#define RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, retval) do { \
	if (!rte_dmadev_is_valid_dev(dev_id)) { \
		RTE_DMADEV_LOG(ERR, "Invalid dev_id=%u\n", dev_id); \
		return retval; \
	} \
} while (0)

static int
dmadev_check_name(const char *name)
{
	size_t name_len;

	if (name == NULL) {
		RTE_DMADEV_LOG(ERR, "Name can't be NULL\n");
		return -EINVAL;
	}

	name_len = strnlen(name, RTE_DMADEV_NAME_MAX_LEN);
	if (name_len == 0) {
		RTE_DMADEV_LOG(ERR, "Zero length DMA device name\n");
		return -EINVAL;
	}
	if (name_len >= RTE_DMADEV_NAME_MAX_LEN) {
		RTE_DMADEV_LOG(ERR, "DMA device name is too long\n");
		return -EINVAL;
	}

	return 0;
}

static uint16_t
dmadev_find_free_dev(void)
{
	uint16_t i;

	for (i = 0; i < RTE_DMADEV_MAX_DEVS; i++) {
		if (dmadev_shared_data->data[i].dev_name[0] == '\0')
			return i;
	}

	return RTE_DMADEV_MAX_DEVS;
}

static struct rte_dmadev*
dmadev_find(const char *name)
{
	uint16_t i;

	for (i = 0; i < RTE_DMADEV_MAX_DEVS; i++) {
		if ((rte_dmadevices[i].state == RTE_DMADEV_ATTACHED) &&
		    (!strcmp(name, rte_dmadevices[i].data->dev_name)))
			return &rte_dmadevices[i];
	}

	return NULL;
}

static int
dmadev_shared_data_prepare(void)
{
	const struct rte_memzone *mz;

	if (dmadev_shared_data == NULL) {
		if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
			/* Allocate port data and ownership shared memory. */
			mz = rte_memzone_reserve(mz_rte_dmadev_data,
					 sizeof(*dmadev_shared_data),
					 rte_socket_id(), 0);
		} else
			mz = rte_memzone_lookup(mz_rte_dmadev_data);
		if (mz == NULL)
			return -ENOMEM;

		dmadev_shared_data = mz->addr;
		if (rte_eal_process_type() == RTE_PROC_PRIMARY)
			memset(dmadev_shared_data->data, 0,
			       sizeof(dmadev_shared_data->data));
	}

	return 0;
}

static struct rte_dmadev *
dmadev_allocate(const char *name)
{
	struct rte_dmadev *dev;
	uint16_t dev_id;

	dev = dmadev_find(name);
	if (dev != NULL) {
		RTE_DMADEV_LOG(ERR, "DMA device already allocated\n");
		return NULL;
	}

	if (dmadev_shared_data_prepare() != 0) {
		RTE_DMADEV_LOG(ERR, "Cannot allocate DMA shared data\n");
		return NULL;
	}

	dev_id = dmadev_find_free_dev();
	if (dev_id == RTE_DMADEV_MAX_DEVS) {
		RTE_DMADEV_LOG(ERR, "Reached maximum number of DMA devices\n");
		return NULL;
	}

	dev = &rte_dmadevices[dev_id];
	dev->data = &dmadev_shared_data->data[dev_id];
	dev->data->dev_id = dev_id;
	rte_strscpy(dev->data->dev_name, name, sizeof(dev->data->dev_name));

	return dev;
}

static struct rte_dmadev *
dmadev_attach_secondary(const char *name)
{
	struct rte_dmadev *dev;
	uint16_t i;

	if (dmadev_shared_data_prepare() != 0) {
		RTE_DMADEV_LOG(ERR, "Cannot allocate DMA shared data\n");
		return NULL;
	}

	for (i = 0; i < RTE_DMADEV_MAX_DEVS; i++) {
		if (!strcmp(dmadev_shared_data->data[i].dev_name, name))
			break;
	}
	if (i == RTE_DMADEV_MAX_DEVS) {
		RTE_DMADEV_LOG(ERR,
			"Device %s is not driven by the primary process\n",
			name);
		return NULL;
	}

	dev = &rte_dmadevices[i];
	dev->data = &dmadev_shared_data->data[i];
	dev->dev_private = dev->data->dev_private;

	return dev;
}

struct rte_dmadev *
rte_dmadev_pmd_allocate(const char *name)
{
	struct rte_dmadev *dev;

	if (dmadev_check_name(name) != 0)
		return NULL;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		dev = dmadev_allocate(name);
	else
		dev = dmadev_attach_secondary(name);

	if (dev == NULL)
		return NULL;
	dev->state = RTE_DMADEV_ATTACHED;

	return dev;
}

int
rte_dmadev_pmd_release(struct rte_dmadev *dev)
{
	void *dev_private_tmp;

	if (dev == NULL)
		return -EINVAL;

	if (dev->state == RTE_DMADEV_UNUSED)
		return 0;

	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		memset(dev->data, 0, sizeof(struct rte_dmadev_data));

	dev_private_tmp = dev->dev_private;
	memset(dev, 0, sizeof(struct rte_dmadev));
	if (rte_eal_process_type() == RTE_PROC_PRIMARY)
		dev->dev_private = dev_private_tmp;
	dev->state = RTE_DMADEV_UNUSED;

	return 0;
}

struct rte_dmadev *
rte_dmadev_get_device_by_name(const char *name)
{
	if (dmadev_check_name(name) != 0)
		return NULL;
	return dmadev_find(name);
}

int
rte_dmadev_get_dev_id(const char *name)
{
	struct rte_dmadev *dev = rte_dmadev_get_device_by_name(name);
	if (dev != NULL)
		return dev->data->dev_id;
	return -EINVAL;
}

bool
rte_dmadev_is_valid_dev(uint16_t dev_id)
{
	return (dev_id < RTE_DMADEV_MAX_DEVS) &&
		rte_dmadevices[dev_id].state == RTE_DMADEV_ATTACHED;
}

uint16_t
rte_dmadev_count(void)
{
	uint16_t count = 0;
	uint16_t i;

	for (i = 0; i < RTE_DMADEV_MAX_DEVS; i++) {
		if (rte_dmadevices[i].state == RTE_DMADEV_ATTACHED)
			count++;
	}

	return count;
}

int
rte_dmadev_info_get(uint16_t dev_id, struct rte_dmadev_info *dev_info)
{
	const struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (dev_info == NULL)
		return -EINVAL;

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_info_get, -ENOTSUP);
	memset(dev_info, 0, sizeof(struct rte_dmadev_info));
	ret = (*dev->dev_ops->dev_info_get)(dev, dev_info,
					    sizeof(struct rte_dmadev_info));
	if (ret != 0)
		return ret;

	dev_info->device = dev->device;
	dev_info->nb_vchans = dev->data->dev_conf.max_vchans;

	return 0;
}

int
rte_dmadev_configure(uint16_t dev_id, const struct rte_dmadev_conf *dev_conf)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	struct rte_dmadev_info info;
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (dev_conf == NULL)
		return -EINVAL;

	if (dev->data->dev_started != 0) {
		RTE_DMADEV_LOG(ERR,
			"Device %u must be stopped to allow configuration\n",
			dev_id);
		return -EBUSY;
	}

	ret = rte_dmadev_info_get(dev_id, &info);
	if (ret != 0) {
		RTE_DMADEV_LOG(ERR, "Device %u get device info fail\n", dev_id);
		return -EINVAL;
	}
	if (dev_conf->max_vchans == 0) {
		RTE_DMADEV_LOG(ERR,
			"Device %u configure zero vchans\n", dev_id);
		return -EINVAL;
	}
	if (dev_conf->max_vchans > info.max_vchans) {
		RTE_DMADEV_LOG(ERR,
			"Device %u configure too many vchans\n", dev_id);
		return -EINVAL;
	}
	if (dev_conf->enable_silent &&
	    !(info.dev_capa & RTE_DMADEV_CAPA_SILENT)) {
		RTE_DMADEV_LOG(ERR, "Device %u don't support silent\n", dev_id);
		return -EINVAL;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_configure, -ENOTSUP);
	ret = (*dev->dev_ops->dev_configure)(dev, dev_conf);
	if (ret == 0)
		memcpy(&dev->data->dev_conf, dev_conf, sizeof(*dev_conf));

	return ret;
}

int
rte_dmadev_start(uint16_t dev_id)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);

	if (dev->data->dev_started != 0) {
		RTE_DMADEV_LOG(WARNING, "Device %u already started\n", dev_id);
		return 0;
	}

	if (dev->dev_ops->dev_start == NULL)
		goto mark_started;

	ret = (*dev->dev_ops->dev_start)(dev);
	if (ret != 0)
		return ret;

mark_started:
	dev->data->dev_started = 1;
	return 0;
}

int
rte_dmadev_stop(uint16_t dev_id)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);

	if (dev->data->dev_started == 0) {
		RTE_DMADEV_LOG(WARNING, "Device %u already stopped\n", dev_id);
		return 0;
	}

	if (dev->dev_ops->dev_stop == NULL)
		goto mark_stopped;

	ret = (*dev->dev_ops->dev_stop)(dev);
	if (ret != 0)
		return ret;

mark_stopped:
	dev->data->dev_started = 0;
	return 0;
}

int
rte_dmadev_close(uint16_t dev_id)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);

	/* Device must be stopped before it can be closed */
	if (dev->data->dev_started == 1) {
		RTE_DMADEV_LOG(ERR,
			"Device %u must be stopped before closing\n", dev_id);
		return -EBUSY;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_close, -ENOTSUP);
	return (*dev->dev_ops->dev_close)(dev);
}

int
rte_dmadev_vchan_setup(uint16_t dev_id,
		       const struct rte_dmadev_vchan_conf *conf)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	struct rte_dmadev_info info;
	bool src_is_dev, dst_is_dev;
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (conf == NULL)
		return -EINVAL;

	if (dev->data->dev_started != 0) {
		RTE_DMADEV_LOG(ERR,
			"Device %u must be stopped to allow configuration\n",
			dev_id);
		return -EBUSY;
	}

	ret = rte_dmadev_info_get(dev_id, &info);
	if (ret != 0) {
		RTE_DMADEV_LOG(ERR, "Device %u get device info fail\n", dev_id);
		return -EINVAL;
	}
	if (conf->direction != RTE_DMA_DIR_MEM_TO_MEM &&
	    conf->direction != RTE_DMA_DIR_MEM_TO_DEV &&
	    conf->direction != RTE_DMA_DIR_DEV_TO_MEM &&
	    conf->direction != RTE_DMA_DIR_DEV_TO_DEV) {
		RTE_DMADEV_LOG(ERR, "Device %u direction invalid!\n", dev_id);
		return -EINVAL;
	}
	if (conf->direction == RTE_DMA_DIR_MEM_TO_MEM &&
	    !(info.dev_capa & RTE_DMADEV_CAPA_MEM_TO_MEM)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u don't support mem2mem transfer\n", dev_id);
		return -EINVAL;
	}
	if (conf->direction == RTE_DMA_DIR_MEM_TO_DEV &&
	    !(info.dev_capa & RTE_DMADEV_CAPA_MEM_TO_DEV)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u don't support mem2dev transfer\n", dev_id);
		return -EINVAL;
	}
	if (conf->direction == RTE_DMA_DIR_DEV_TO_MEM &&
	    !(info.dev_capa & RTE_DMADEV_CAPA_DEV_TO_MEM)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u don't support dev2mem transfer\n", dev_id);
		return -EINVAL;
	}
	if (conf->direction == RTE_DMA_DIR_DEV_TO_DEV &&
	    !(info.dev_capa & RTE_DMADEV_CAPA_DEV_TO_DEV)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u don't support dev2dev transfer\n", dev_id);
		return -EINVAL;
	}
	if (conf->nb_desc < info.min_desc || conf->nb_desc > info.max_desc) {
		RTE_DMADEV_LOG(ERR,
			"Device %u number of descriptors invalid\n", dev_id);
		return -EINVAL;
	}
	src_is_dev = conf->direction == RTE_DMA_DIR_DEV_TO_MEM ||
		     conf->direction == RTE_DMA_DIR_DEV_TO_DEV;
	if ((conf->src_port.port_type == RTE_DMADEV_PORT_NONE && src_is_dev) ||
	    (conf->src_port.port_type != RTE_DMADEV_PORT_NONE && !src_is_dev)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u source port type invalid\n", dev_id);
		return -EINVAL;
	}
	dst_is_dev = conf->direction == RTE_DMA_DIR_MEM_TO_DEV ||
		     conf->direction == RTE_DMA_DIR_DEV_TO_DEV;
	if ((conf->dst_port.port_type == RTE_DMADEV_PORT_NONE && dst_is_dev) ||
	    (conf->dst_port.port_type != RTE_DMADEV_PORT_NONE && !dst_is_dev)) {
		RTE_DMADEV_LOG(ERR,
			"Device %u destination port type invalid\n", dev_id);
		return -EINVAL;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->vchan_setup, -ENOTSUP);
	return (*dev->dev_ops->vchan_setup)(dev, conf);
}

int
rte_dmadev_stats_get(uint16_t dev_id, uint16_t vchan,
		     struct rte_dmadev_stats *stats)
{
	const struct rte_dmadev *dev = &rte_dmadevices[dev_id];

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (stats == NULL)
		return -EINVAL;
	if (vchan >= dev->data->dev_conf.max_vchans &&
	    vchan != RTE_DMADEV_ALL_VCHAN) {
		RTE_DMADEV_LOG(ERR,
			"Device %u vchan %u out of range\n", dev_id, vchan);
		return -EINVAL;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->stats_get, -ENOTSUP);
	memset(stats, 0, sizeof(struct rte_dmadev_stats));
	return (*dev->dev_ops->stats_get)(dev, vchan, stats,
					  sizeof(struct rte_dmadev_stats));
}

int
rte_dmadev_stats_reset(uint16_t dev_id, uint16_t vchan)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (vchan >= dev->data->dev_conf.max_vchans &&
	    vchan != RTE_DMADEV_ALL_VCHAN) {
		RTE_DMADEV_LOG(ERR,
			"Device %u vchan %u out of range\n", dev_id, vchan);
		return -EINVAL;
	}

	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->stats_reset, -ENOTSUP);
	return (*dev->dev_ops->stats_reset)(dev, vchan);
}

int
rte_dmadev_dump(uint16_t dev_id, FILE *f)
{
	const struct rte_dmadev *dev = &rte_dmadevices[dev_id];
	struct rte_dmadev_info info;
	int ret;

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	if (f == NULL)
		return -EINVAL;

	ret = rte_dmadev_info_get(dev_id, &info);
	if (ret != 0) {
		RTE_DMADEV_LOG(ERR, "Device %u get device info fail\n", dev_id);
		return -EINVAL;
	}

	fprintf(f, "DMA Dev %u, '%s' [%s]\n",
		dev->data->dev_id,
		dev->data->dev_name,
		dev->data->dev_started ? "started" : "stopped");
	fprintf(f, "  dev_capa: 0x%" PRIx64 "\n", info.dev_capa);
	fprintf(f, "  max_vchans_supported: %u\n", info.max_vchans);
	fprintf(f, "  max_vchans_configured: %u\n", info.nb_vchans);
	fprintf(f, "  silent_mode: %s\n",
		dev->data->dev_conf.enable_silent ? "on" : "off");

	if (dev->dev_ops->dev_dump != NULL)
		return (*dev->dev_ops->dev_dump)(dev, f);

	return 0;
}

int
rte_dmadev_selftest(uint16_t dev_id)
{
	struct rte_dmadev *dev = &rte_dmadevices[dev_id];

	RTE_DMADEV_VALID_DEV_ID_OR_ERR_RET(dev_id, -EINVAL);
	RTE_FUNC_PTR_OR_ERR_RET(*dev->dev_ops->dev_selftest, -ENOTSUP);
	return (*dev->dev_ops->dev_selftest)(dev_id);
}
