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

/* Configure */
static int
hs_regex_configure(struct rte_regexdev *dev,
		   const struct rte_regexdev_config *cfg)
{
	struct hs_regex_priv *priv;

	if (dev == NULL || cfg == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (priv->dev_state == HS_REGEX_DEV_STARTED) {
		HS_LOG(ERR, "Cannot configure while device is started");
		return -EBUSY;
	}

	if (cfg->nb_queue_pairs > HS_REGEX_MAX_QUEUE_PAIRS) {
		HS_LOG(ERR, "Requested %u queue pairs exceeds max %u",
		       cfg->nb_queue_pairs, HS_REGEX_MAX_QUEUE_PAIRS);
		return -EINVAL;
	}

	priv->nb_queue_pairs = cfg->nb_queue_pairs;
	priv->max_matches = cfg->nb_max_matches ? cfg->nb_max_matches :
						  UINT16_MAX;
	priv->nb_groups = cfg->nb_groups ? cfg->nb_groups : 1;

	if (priv->rules) {
		uint32_t i;

		for (i = 0; i < priv->nb_rules; i++)
			rte_free(priv->rules[i].pattern);
		rte_free(priv->rules);
		priv->rules = NULL;
		priv->nb_rules = 0;
		priv->rules_cap = 0;
	}
	if (priv->db) {
		hs_free_database(priv->db);
		priv->db = NULL;
		priv->db_compiled = 0;
	}

	if (priv->qps) {
		rte_free(priv->qps);
		priv->qps = NULL;
	}

	priv->qps = rte_zmalloc("hs_regex_qps",
				sizeof(struct hs_regex_qp) *
				cfg->nb_queue_pairs,
				RTE_CACHE_LINE_SIZE);
	if (!priv->qps) {
		HS_LOG(ERR, "Failed to allocate queue pairs");
		/* Keep nb_queue_pairs in sync with the NULL qps array. */
		priv->nb_queue_pairs = 0;
		return -ENOMEM;
	}

	HS_LOG(INFO, "Configured: %u queue pairs, max_matches=%u",
	       priv->nb_queue_pairs, priv->max_matches);

	priv->dev_state = HS_REGEX_DEV_CONFIGURED;
	return 0;
}

/* Queue Pair Setup */
static int
hs_regex_qp_setup(struct rte_regexdev *dev, uint16_t qp_id,
		  const struct rte_regexdev_qp_conf *qp_conf)
{
	struct hs_regex_priv *priv;
	struct hs_regex_qp *qp;
	uint16_t nb_desc;
	hs_error_t err;

	if (dev == NULL)
		return -EINVAL;

	priv = dev->data->dev_private;
	if (priv == NULL)
		return -EINVAL;

	if (qp_id >= priv->nb_queue_pairs) {
		HS_LOG(ERR, "Invalid qp_id %u (max %u)", qp_id,
		       priv->nb_queue_pairs);
		return -EINVAL;
	}

	/* nb_queue_pairs must stay in sync with a live qps array. */
	if (priv->qps == NULL) {
		HS_LOG(ERR, "qp %u: queue pairs not allocated", qp_id);
		return -EINVAL;
	}

	qp = &priv->qps[qp_id];
	nb_desc = (qp_conf && qp_conf->nb_desc) ? qp_conf->nb_desc :
						   HS_REGEX_DEFAULT_NB_DESC;

	if (nb_desc == 0 || (nb_desc & (nb_desc - 1)) != 0) {
		uint16_t orig = nb_desc;
		uint32_t aligned = rte_align32pow2(nb_desc ? nb_desc : 1);

		if (aligned > HS_REGEX_MAX_NB_DESC)
			aligned = HS_REGEX_MAX_NB_DESC;
		nb_desc = aligned;
		HS_LOG(WARNING, "QP %u: nb_desc %u rounded up to %u (power of 2)",
		       qp_id, orig, nb_desc);
	}

	if (qp->ops) {
		rte_free(qp->ops);
		qp->ops = NULL;
	}

	if (qp->scratch) {
		hs_free_scratch(qp->scratch);
		qp->scratch = NULL;
	}

	qp->ops = rte_zmalloc("hs_regex_qp_ops",
			      sizeof(struct rte_regex_ops *) * nb_desc,
			      RTE_CACHE_LINE_SIZE);
	if (!qp->ops) {
		HS_LOG(ERR, "Failed to allocate ops ring for qp %u", qp_id);
		return -ENOMEM;
	}

	qp->nb_desc = nb_desc;
	qp->head = 0;
	qp->tail = 0;
	qp->count = 0;

	if (priv->db) {
		err = hs_alloc_scratch(priv->db, &qp->scratch);
		if (err != HS_SUCCESS) {
			HS_LOG(ERR, "Failed to alloc scratch for qp %u",
			       qp_id);
			rte_free(qp->ops);
			qp->ops = NULL;
			return -ENOMEM;
		}
	}

	HS_LOG(INFO, "QP %u setup: nb_desc=%u", qp_id, nb_desc);
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
	.dev_configure = hs_regex_configure,
	.dev_qp_setup = hs_regex_qp_setup,
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
