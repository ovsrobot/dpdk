/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 HiSilicon Limited.
 */

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <rte_bus_vdev.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_kvargs.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_ring.h>

#include <rte_dmadev_pmd.h>

#include "skeleton_dmadev.h"

RTE_LOG_REGISTER_DEFAULT(skeldma_logtype, INFO);
#define SKELDMA_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, skeldma_logtype, "%s(): " fmt "\n", \
		__func__, ##args)

/* Count of instances */
static uint16_t skeldma_init_once;

static int
skeldma_info_get(const struct rte_dmadev *dev, struct rte_dmadev_info *dev_info,
		 uint32_t info_sz)
{
#define SKELDMA_MAX_DESC	8192
#define SKELDMA_MIN_DESC	128

	RTE_SET_USED(dev);
	RTE_SET_USED(info_sz);

	dev_info->dev_capa = RTE_DMADEV_CAPA_MEM_TO_MEM |
			     RTE_DMADEV_CAPA_SVA |
			     RTE_DMADEV_CAPA_OPS_COPY;
	dev_info->max_vchans = 1;
	dev_info->max_desc = SKELDMA_MAX_DESC;
	dev_info->min_desc = SKELDMA_MIN_DESC;

	return 0;
}

static int
skeldma_configure(struct rte_dmadev *dev, const struct rte_dmadev_conf *conf)
{
	RTE_SET_USED(dev);
	RTE_SET_USED(conf);
	return 0;
}

static void *
cpucopy_thread(void *param)
{
#define SLEEP_THRESHOLD		10000
#define SLEEP_US_VAL		10

	struct rte_dmadev *dev = (struct rte_dmadev *)param;
	struct skeldma_hw *hw = dev->dev_private;
	struct skeldma_desc *desc = NULL;
	int ret;

	while (!hw->exit_flag) {
		ret = rte_ring_dequeue(hw->desc_running, (void **)&desc);
		if (ret) {
			hw->zero_req_count++;
			if (hw->zero_req_count > SLEEP_THRESHOLD) {
				if (hw->zero_req_count == 0)
					hw->zero_req_count = SLEEP_THRESHOLD;
				rte_delay_us_sleep(SLEEP_US_VAL);
			}
			continue;
		}

		hw->zero_req_count = 0;
		rte_memcpy(desc->dst, desc->src, desc->len);
		hw->completed_count++;
		(void)rte_ring_enqueue(hw->desc_completed, (void *)desc);
	}

	return NULL;
}

static void
fflush_ring(struct skeldma_hw *hw, struct rte_ring *ring)
{
	struct skeldma_desc *desc = NULL;
	while (rte_ring_count(ring) > 0) {
		(void)rte_ring_dequeue(ring, (void **)&desc);
		(void)rte_ring_enqueue(hw->desc_empty, (void *)desc);
	}
}

static int
skeldma_start(struct rte_dmadev *dev)
{
	struct skeldma_hw *hw = dev->dev_private;
	rte_cpuset_t cpuset;
	int ret;

	if (hw->desc_mem == NULL) {
		SKELDMA_LOG(ERR, "Vchan was not setup, start fail!");
		return -EINVAL;
	}

	/* Reset the dmadev to a known state, include:
	 * 1) fflush pending/running/completed ring to empty ring.
	 * 2) init ring idx to zero.
	 * 3) init running statistics.
	 * 4) mark cpucopy task exit_flag to false.
	 */
	fflush_ring(hw, hw->desc_pending);
	fflush_ring(hw, hw->desc_running);
	fflush_ring(hw, hw->desc_completed);
	hw->ridx = 0;
	hw->submitted_count = 0;
	hw->zero_req_count = 0;
	hw->completed_count = 0;
	hw->exit_flag = false;

	rte_mb();

	ret = rte_ctrl_thread_create(&hw->thread, "dma_skeleton", NULL,
				     cpucopy_thread, dev);
	if (ret) {
		SKELDMA_LOG(ERR, "Start cpucopy thread fail!");
		return -EINVAL;
	}

	if (hw->lcore_id != -1) {
		cpuset = rte_lcore_cpuset(hw->lcore_id);
		ret = pthread_setaffinity_np(hw->thread, sizeof(cpuset),
					     &cpuset);
		if (ret)
			SKELDMA_LOG(WARNING,
				"Set thread affinity lcore = %u fail!",
				hw->lcore_id);
	}

	return 0;
}

static int
skeldma_stop(struct rte_dmadev *dev)
{
	struct skeldma_hw *hw = dev->dev_private;

	hw->exit_flag = true;
	rte_delay_ms(1);

	pthread_cancel(hw->thread);
	pthread_join(hw->thread, NULL);

	return 0;
}

static int
vchan_setup(struct skeldma_hw *hw, uint16_t nb_desc)
{
	struct skeldma_desc *desc;
	struct rte_ring *empty;
	struct rte_ring *pending;
	struct rte_ring *running;
	struct rte_ring *completed;
	uint16_t i;

	desc = rte_zmalloc_socket("dma_skelteon_desc",
				  nb_desc * sizeof(struct skeldma_desc),
				  RTE_CACHE_LINE_SIZE, hw->socket_id);
	if (desc == NULL) {
		SKELDMA_LOG(ERR, "Malloc dma skeleton desc fail!");
		return -ENOMEM;
	}

	empty = rte_ring_create("dma_skeleton_desc_empty", nb_desc,
				hw->socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
	pending = rte_ring_create("dma_skeleton_desc_pending", nb_desc,
				  hw->socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
	running = rte_ring_create("dma_skeleton_desc_running", nb_desc,
				  hw->socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
	completed = rte_ring_create("dma_skeleton_desc_completed", nb_desc,
				  hw->socket_id, RING_F_SP_ENQ | RING_F_SC_DEQ);
	if (empty == NULL || pending == NULL || running == NULL ||
	    completed == NULL) {
		SKELDMA_LOG(ERR, "Create dma skeleton desc ring fail!");
		rte_ring_free(empty);
		rte_ring_free(pending);
		rte_ring_free(running);
		rte_ring_free(completed);
		rte_free(desc);
		return -ENOMEM;
	}

	/* The real usable ring size is *count-1* instead of *count* to
	 * differentiate a free ring from an empty ring.
	 * @see rte_ring_create
	 */
	for (i = 0; i < nb_desc - 1; i++)
		(void)rte_ring_enqueue(empty, (void *)(desc + i));

	hw->desc_mem = desc;
	hw->desc_empty = empty;
	hw->desc_pending = pending;
	hw->desc_running = running;
	hw->desc_completed = completed;

	return 0;
}

static void
vchan_release(struct skeldma_hw *hw)
{
	if (hw->desc_mem == NULL)
		return;

	rte_free(hw->desc_mem);
	hw->desc_mem = NULL;
	rte_ring_free(hw->desc_empty);
	hw->desc_empty = NULL;
	rte_ring_free(hw->desc_pending);
	hw->desc_pending = NULL;
	rte_ring_free(hw->desc_running);
	hw->desc_running = NULL;
	rte_ring_free(hw->desc_completed);
	hw->desc_completed = NULL;
}

static int
skeldma_close(struct rte_dmadev *dev)
{
	/* The device already stopped */
	vchan_release(dev->dev_private);
	return 0;
}

static int
skeldma_vchan_setup(struct rte_dmadev *dev, uint16_t vchan,
		    const struct rte_dmadev_vchan_conf *conf)
{
	struct skeldma_hw *hw = dev->dev_private;

	RTE_SET_USED(vchan);

	if (!rte_is_power_of_2(conf->nb_desc)) {
		SKELDMA_LOG(ERR, "Number of desc must be power of 2!");
		return -EINVAL;
	}

	vchan_release(hw);
	return vchan_setup(hw, conf->nb_desc);
}

static int
skeldma_stats_get(const struct rte_dmadev *dev, uint16_t vchan,
		  struct rte_dmadev_stats *stats, uint32_t stats_sz)
{
	struct skeldma_hw *hw = dev->dev_private;

	RTE_SET_USED(vchan);
	RTE_SET_USED(stats_sz);

	stats->submitted = hw->submitted_count;
	stats->completed = hw->completed_count;
	stats->errors = 0;

	return 0;
}

static int
skeldma_stats_reset(struct rte_dmadev *dev, uint16_t vchan)
{
	struct skeldma_hw *hw = dev->dev_private;

	RTE_SET_USED(vchan);

	hw->submitted_count = 0;
	hw->completed_count = 0;

	return 0;
}

static int
skeldma_dump(const struct rte_dmadev *dev, FILE *f)
{
#define GET_RING_COUNT(ring)	((ring) ? (rte_ring_count(ring)) : 0)

	struct skeldma_hw *hw = dev->dev_private;

	fprintf(f,
		"  lcore_id: %d\n"
		"  socket_id: %d\n"
		"  desc_empty_ring_count: %u\n"
		"  desc_pending_ring_count: %u\n"
		"  desc_running_ring_count: %u\n"
		"  desc_completed_ring_count: %u\n",
		hw->lcore_id, hw->socket_id,
		GET_RING_COUNT(hw->desc_empty),
		GET_RING_COUNT(hw->desc_pending),
		GET_RING_COUNT(hw->desc_running),
		GET_RING_COUNT(hw->desc_completed));
	fprintf(f,
		"  next_ring_idx: %u\n"
		"  submitted_count: %" PRIu64 "\n"
		"  completed_count: %" PRIu64 "\n",
		hw->ridx, hw->submitted_count, hw->completed_count);

	return 0;
}

static inline void
submit(struct skeldma_hw *hw, struct skeldma_desc *desc)
{
	uint16_t count = rte_ring_count(hw->desc_pending);
	struct skeldma_desc *pend_desc = NULL;

	while (count > 0) {
		(void)rte_ring_dequeue(hw->desc_pending, (void **)&pend_desc);
		(void)rte_ring_enqueue(hw->desc_running, (void *)pend_desc);
		count--;
	}

	if (desc)
		(void)rte_ring_enqueue(hw->desc_running, (void *)desc);
}

static int
skeldma_copy(struct rte_dmadev *dev, uint16_t vchan,
	     rte_iova_t src, rte_iova_t dst,
	     uint32_t length, uint64_t flags)
{
	struct skeldma_hw *hw = dev->dev_private;
	struct skeldma_desc *desc;
	int ret;

	RTE_SET_USED(vchan);
	RTE_SET_USED(flags);

	ret = rte_ring_dequeue(hw->desc_empty, (void **)&desc);
	if (ret)
		return -ENOSPC;
	desc->src = (void *)(uintptr_t)src;
	desc->dst = (void *)(uintptr_t)dst;
	desc->len = length;
	desc->ridx = hw->ridx;
	if (flags & RTE_DMA_OP_FLAG_SUBMIT)
		submit(hw, desc);
	else
		(void)rte_ring_enqueue(hw->desc_pending, (void *)desc);
	hw->submitted_count++;

	return hw->ridx++;
}

static int
skeldma_submit(struct rte_dmadev *dev, uint16_t vchan)
{
	struct skeldma_hw *hw = dev->dev_private;
	RTE_SET_USED(vchan);
	submit(hw, NULL);
	return 0;
}

static uint16_t
skeldma_completed(struct rte_dmadev *dev,
		  uint16_t vchan, const uint16_t nb_cpls,
		  uint16_t *last_idx, bool *has_error)
{
	struct skeldma_hw *hw = dev->dev_private;
	struct skeldma_desc *desc = NULL;
	uint16_t index = 0;
	uint16_t count;

	RTE_SET_USED(vchan);
	RTE_SET_USED(has_error);

	count = RTE_MIN(nb_cpls, rte_ring_count(hw->desc_completed));
	while (index < count) {
		(void)rte_ring_dequeue(hw->desc_completed, (void **)&desc);
		if (index == count - 1)
			*last_idx = desc->ridx;
		index++;
		(void)rte_ring_enqueue(hw->desc_empty, (void *)desc);
	}

	return count;
}

static uint16_t
skeldma_completed_status(struct rte_dmadev *dev,
			 uint16_t vchan, const uint16_t nb_cpls,
			 uint16_t *last_idx, enum rte_dma_status_code *status)
{
	struct skeldma_hw *hw = dev->dev_private;
	struct skeldma_desc *desc = NULL;
	uint16_t index = 0;
	uint16_t count;

	RTE_SET_USED(vchan);

	count = RTE_MIN(nb_cpls, rte_ring_count(hw->desc_completed));
	while (index < count) {
		(void)rte_ring_dequeue(hw->desc_completed, (void **)&desc);
		if (index == count - 1)
			*last_idx = desc->ridx;
		status[index++] = RTE_DMA_STATUS_SUCCESSFUL;
		(void)rte_ring_enqueue(hw->desc_empty, (void *)desc);
	}

	return count;
}

static const struct rte_dmadev_ops skeldma_ops = {
	.dev_info_get = skeldma_info_get,
	.dev_configure = skeldma_configure,
	.dev_start = skeldma_start,
	.dev_stop = skeldma_stop,
	.dev_close = skeldma_close,

	.vchan_setup = skeldma_vchan_setup,

	.stats_get = skeldma_stats_get,
	.stats_reset = skeldma_stats_reset,

	.dev_dump = skeldma_dump,
};

static int
skeldma_create(const char *name, struct rte_vdev_device *vdev, int lcore_id)
{
	struct rte_dmadev *dev;
	struct skeldma_hw *hw;
	int socket_id;

	dev = rte_dmadev_pmd_allocate(name);
	if (dev == NULL) {
		SKELDMA_LOG(ERR, "Unable to allocate dmadev: %s", name);
		return -EINVAL;
	}

	socket_id = (lcore_id < 0) ? rte_socket_id() :
				     rte_lcore_to_socket_id(lcore_id);
	dev->dev_private = rte_zmalloc_socket("dmadev private",
					      sizeof(struct skeldma_hw),
					      RTE_CACHE_LINE_SIZE,
					      socket_id);
	if (!dev->dev_private) {
		SKELDMA_LOG(ERR, "Unable to allocate device private memory");
		(void)rte_dmadev_pmd_release(dev);
		return -ENOMEM;
	}

	dev->copy = skeldma_copy;
	dev->submit = skeldma_submit;
	dev->completed = skeldma_completed;
	dev->completed_status = skeldma_completed_status;
	dev->dev_ops = &skeldma_ops;
	dev->device = &vdev->device;

	hw = dev->dev_private;
	hw->lcore_id = lcore_id;
	hw->socket_id = socket_id;

	return dev->data->dev_id;
}

static int
skeldma_destroy(const char *name)
{
	struct rte_dmadev *dev;
	int ret;

	dev = rte_dmadev_get_device_by_name(name);
	if (!dev)
		return -EINVAL;

	ret = rte_dmadev_close(dev->data->dev_id);
	if (ret)
		return ret;

	rte_free(dev->dev_private);
	dev->dev_private = NULL;
	(void)rte_dmadev_pmd_release(dev);

	return 0;
}

static int
skeldma_parse_lcore(const char *key __rte_unused,
		    const char *value,
		    void *opaque)
{
	int lcore_id = atoi(value);
	if (lcore_id >= 0 && lcore_id < RTE_MAX_LCORE)
		*(int *)opaque = lcore_id;
	return 0;
}

static void
skeldma_parse_vdev_args(struct rte_vdev_device *vdev, int *lcore_id)
{
	static const char *const args[] = {
		SKELDMA_ARG_LCORE,
		NULL
	};

	struct rte_kvargs *kvlist;
	const char *params;

	params = rte_vdev_device_args(vdev);
	if (params == NULL || params[0] == '\0')
		return;

	kvlist = rte_kvargs_parse(params, args);
	if (!kvlist)
		return;

	(void)rte_kvargs_process(kvlist, SKELDMA_ARG_LCORE,
				 skeldma_parse_lcore, lcore_id);
	SKELDMA_LOG(INFO, "Parse lcore_id = %d", *lcore_id);

	rte_kvargs_free(kvlist);
}

static int
skeldma_probe(struct rte_vdev_device *vdev)
{
	const char *name;
	int lcore_id = -1;
	int ret;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		SKELDMA_LOG(ERR, "Multiple process not supported for %s", name);
		return -EINVAL;
	}

	/* More than one instance is not supported */
	if (skeldma_init_once) {
		SKELDMA_LOG(ERR, "Multiple instance not supported for %s",
			name);
		return -EINVAL;
	}

	skeldma_parse_vdev_args(vdev, &lcore_id);

	ret = skeldma_create(name, vdev, lcore_id);
	if (ret >= 0) {
		SKELDMA_LOG(INFO, "Create %s dmadev with lcore-id %d",
			name, lcore_id);
		/* Device instance created; Second instance not possible */
		skeldma_init_once = 1;
	}

	return ret < 0 ? ret : 0;
}

static int
skeldma_remove(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -1;

	ret = skeldma_destroy(name);
	if (!ret) {
		skeldma_init_once = 0;
		SKELDMA_LOG(INFO, "Remove %s dmadev", name);
	}

	return ret;
}

static struct rte_vdev_driver skeldma_pmd_drv = {
	.probe = skeldma_probe,
	.remove = skeldma_remove,
	.drv_flags = RTE_VDEV_DRV_NEED_IOVA_AS_VA,
};

RTE_PMD_REGISTER_VDEV(dma_skeleton, skeldma_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(dma_skeleton,
		SKELDMA_ARG_LCORE "=<uint16> ");
