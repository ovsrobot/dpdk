/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 *
 * Intel Hyperscan PMD for DPDK rte_regexdev
 *
 * This Poll Mode Driver wraps Intel Hyperscan behind the standard DPDK
 * regex device API (rte_regexdev). Applications use the enqueue/dequeue
 * burst interface with Hyperscan as the matching engine.
 *
 * Key design:
 *   - Synchronous scan in enqueue (hs_scan blocks until done)
 *   - Per-queue-pair scratch space for lock-free parallel scanning
 *   - HS_MODE_BLOCK: each buffer scanned independently
 *   - Runtime compilation via hs_compile_ext_multi()
 *   - Serialized database import/export via hs_deserialize_database()
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_errno.h>
#include <bus_vdev_driver.h>
#include <rte_regexdev.h>
#include <rte_regexdev_core.h>
#include <rte_regexdev_driver.h>
#include <rte_mbuf.h>

#include <hs/hs.h>

#include "hs_regex.h"

RTE_LOG_REGISTER_DEFAULT(hs_regex_logtype, NOTICE);
#define RTE_LOGTYPE_HS_REGEX hs_regex_logtype

#define HS_LOG(level, ...) \
	RTE_LOG_LINE(level, HS_REGEX, __VA_ARGS__)

/* Device Info */
static int
hs_regex_info_get(struct rte_regexdev *dev __rte_unused,
		  struct rte_regexdev_info *info)
{
	info->driver_name = HS_REGEX_DRIVER_NAME;
	info->dev = NULL;
	info->max_matches = UINT16_MAX;
	info->max_queue_pairs = HS_REGEX_MAX_QUEUE_PAIRS;
	info->max_payload_size = UINT16_MAX;
	info->max_rules_per_group = HS_REGEX_MAX_RULES;
	info->max_groups = HS_REGEX_MAX_GROUPS;
	info->regexdev_capa = RTE_REGEXDEV_CAPA_RUNTIME_COMPILATION_F;
	info->rule_flags = RTE_REGEX_PCRE_RULE_CASELESS_F |
			   RTE_REGEX_PCRE_RULE_DOTALL_F |
			   RTE_REGEX_PCRE_RULE_MULTILINE_F |
			   RTE_REGEX_PCRE_RULE_UTF_F;

	return 0;
}

/* Fast path stubs replaced by real implementations in later patches. */

static uint16_t
hs_regex_enqueue_burst(struct rte_regexdev *dev __rte_unused,
		       uint16_t qp_id __rte_unused,
		       struct rte_regex_ops **ops __rte_unused,
		       uint16_t nb_ops __rte_unused)
{
	return 0;
}

static uint16_t
hs_regex_dequeue_burst(struct rte_regexdev *dev __rte_unused,
		       uint16_t qp_id __rte_unused,
		       struct rte_regex_ops **ops __rte_unused,
		       uint16_t nb_ops __rte_unused)
{
	return 0;
}

static const struct rte_regexdev_ops hs_regexdev_ops = {
	.dev_info_get = hs_regex_info_get,
};

/* Device Lifecycle */

int
hs_regex_dev_create(const char *name, struct rte_device *device)
{
	struct hs_regex_priv *priv;
	struct rte_regexdev *dev;

	if (name == NULL || device == NULL)
		return -EINVAL;

	HS_LOG(INFO, "Creating Hyperscan regex device: %s", name);

	dev = rte_regexdev_register(name);
	if (!dev) {
		HS_LOG(ERR, "Failed to register regex device %s", name);
		return -EINVAL;
	}

	priv = rte_zmalloc("hs_regex_priv", sizeof(*priv),
			   RTE_CACHE_LINE_SIZE);
	if (!priv) {
		rte_regexdev_unregister(dev);
		return -ENOMEM;
	}

	dev->dev_ops = &hs_regexdev_ops;
	dev->enqueue = hs_regex_enqueue_burst;
	dev->dequeue = hs_regex_dequeue_burst;
	dev->device = device;
	dev->data->dev_private = priv;
	dev->state = RTE_REGEXDEV_READY;

	HS_LOG(INFO, "Hyperscan regex PMD created (dev_id=%u, hs=%s)",
	       dev->data->dev_id, hs_version());
	return dev->data->dev_id;
}

void
hs_regex_dev_destroy(const char *name)
{
	struct rte_regexdev *dev;
	struct hs_regex_priv *priv;

	if (name == NULL)
		return;

	dev = rte_regexdev_get_device_by_name(name);
	if (!dev)
		return;

	priv = dev->data->dev_private;
	if (priv) {
		rte_free(priv);
		dev->data->dev_private = NULL;
	}

	rte_regexdev_unregister(dev);
	HS_LOG(INFO, "Hyperscan regex PMD destroyed: %s", name);
}

static int
hs_regex_probe(struct rte_vdev_device *vdev)
{
	const char *name;
	int ret;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY) {
		HS_LOG(ERR, "Multi-process not supported for %s", name);
		return -EINVAL;
	}

	ret = hs_regex_dev_create(name, &vdev->device);
	return ret < 0 ? ret : 0;
}

static int
hs_regex_remove(struct rte_vdev_device *vdev)
{
	const char *name;

	name = rte_vdev_device_name(vdev);
	if (name == NULL)
		return -EINVAL;

	hs_regex_dev_destroy(name);
	return 0;
}

static struct rte_vdev_driver hs_regex_pmd_drv = {
	.probe = hs_regex_probe,
	.remove = hs_regex_remove,
};

RTE_PMD_REGISTER_VDEV(regex_hs, hs_regex_pmd_drv);
RTE_PMD_REGISTER_PARAM_STRING(regex_hs, "");
