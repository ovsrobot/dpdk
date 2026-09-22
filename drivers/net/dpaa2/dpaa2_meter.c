/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <sys/queue.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>
#include <rte_mtr.h>
#include <rte_mtr_driver.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

static int
dpaa2_mtr_capabilities_get(struct rte_eth_dev *dev,
	struct rte_mtr_capabilities *capa,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (capa == NULL) {
		return -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
				"NULL input parameter");
	}

	memset(capa, 0, sizeof(*capa));
	capa->color_aware_trtcm_rfc2698_supported = true;
	capa->color_aware_trtcm_rfc4115_supported = true;
	capa->trtcm_rfc2698_byte_mode_supported = true;
	capa->trtcm_rfc2698_packet_mode_supported = true;
	capa->trtcm_rfc4115_byte_mode_supported = true;
	capa->trtcm_rfc4115_packet_mode_supported = true;

	rte_spinlock_lock(&priv->meter_lock);
	capa->n_max = priv->num_rx_tc;
	capa->n_shared_max = priv->num_rx_tc;
	capa->meter_trtcm_rfc2698_n_max = priv->num_rx_tc;
	capa->meter_trtcm_rfc4115_n_max = priv->num_rx_tc;
	capa->meter_policy_n_max = priv->num_rx_tc;
	capa->shared_n_flows_per_mtr_max = priv->fs_entries;
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static int
dpaa2_mtr_profile_add(struct rte_eth_dev *dev,
	uint32_t profile_id, struct rte_mtr_meter_profile *profile,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile;
	struct dpaa2_dev_meter_profile *curr;
	int ret = 0;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	while (curr != NULL) {
		if (curr->profile_id == profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return -rte_mtr_error_set(error, EEXIST,
				RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
				&profile_id,
				"Meter profile ID already exists.");
		}
		curr = LIST_NEXT(curr, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	dpaa2_profile = calloc(1, sizeof(struct dpaa2_dev_meter_profile));
	if (dpaa2_profile == NULL) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter profile memory alloc failed!");
	}
	if (profile->alg == RTE_MTR_NONE) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_PASS_THROUGH;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC2698) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_RFC_2698;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC4115) {
		dpaa2_profile->mode = DPNI_POLICER_MODE_RFC_4115;
	} else {
		DPAA2_PMD_ERR("Policer profile alg(%d) not supported!",
			profile->alg);
		rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"Policer profile alg not supported!");
		ret = -ENOTSUP;
		goto err;
	}

	if (profile->alg == RTE_MTR_TRTCM_RFC2698) {
		dpaa2_profile->cir = profile->trtcm_rfc2698.cir;
		dpaa2_profile->cbs = profile->trtcm_rfc2698.cbs;
		dpaa2_profile->pir = profile->trtcm_rfc2698.pir;
		dpaa2_profile->pbs = profile->trtcm_rfc2698.pbs;
	} else if (profile->alg == RTE_MTR_TRTCM_RFC4115) {
		dpaa2_profile->cir = profile->trtcm_rfc4115.cir;
		dpaa2_profile->cbs = profile->trtcm_rfc4115.cbs;
		dpaa2_profile->pir = profile->trtcm_rfc4115.eir;
		dpaa2_profile->pbs = profile->trtcm_rfc4115.ebs;
	}

	if (!profile->packet_mode)
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_BYTES_L3;
	else
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_FRAMES;

	dpaa2_profile->profile_id = profile_id;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	if (curr == NULL) {
		LIST_INSERT_HEAD(&priv->profiles, dpaa2_profile, next);
	} else {
		while (LIST_NEXT(curr, next) != NULL)
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, dpaa2_profile, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

err:
	if (ret != 0)
		free(dpaa2_profile);

	return ret;
}

static int
dpaa2_mtr_policy_add(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_meter_policy_params *policy,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy;
	struct dpaa2_dev_meter_policy *curr;
	const struct rte_flow_action *red_action;
	bool red_drop = false;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	while (curr != NULL) {
		if (curr->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return -rte_mtr_error_set(error, EEXIST,
				RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
				NULL,
				"Meter policy ID already exists.");
		}
		curr = LIST_NEXT(curr, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	if (policy->actions[RTE_COLOR_GREEN] != NULL) {
		return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_GREEN, NULL,
				"Meter green policy action not supported!");
	}
	if (policy->actions[RTE_COLOR_YELLOW] != NULL) {
		return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_YELLOW, NULL,
				"Meter yellow policy action not supported!");
	}

	red_action = policy->actions[RTE_COLOR_RED];

	if (red_action != NULL) {
		if (red_action->type == RTE_FLOW_ACTION_TYPE_DROP) {
			red_drop = true;
		} else if (red_action->type != RTE_FLOW_ACTION_TYPE_PASSTHRU) {
			return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_RED, NULL,
				"Meter red policy action not supported");
		}
	}

	dpaa2_policy = calloc(1, sizeof(struct dpaa2_dev_meter_policy));
	if (dpaa2_policy == NULL) {
		return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter policy memory alloc failed!");
	}

	dpaa2_policy->policy_id = policy_id;
	dpaa2_policy->red_drop = red_drop;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	if (curr == NULL) {
		LIST_INSERT_HEAD(&priv->policies, dpaa2_policy, next);
	} else {
		while (LIST_NEXT(curr, next) != NULL)
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, dpaa2_policy, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static struct rte_flow_meter_profile *
dpaa2_mtr_profile_get(struct rte_eth_dev *dev,
	uint32_t meter_profile_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile;

	RTE_SET_USED(error);

	rte_spinlock_lock(&priv->meter_lock);
	dpaa2_profile = LIST_FIRST(&priv->profiles);
	while (dpaa2_profile != NULL) {
		if (dpaa2_profile->profile_id == meter_profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return (struct rte_flow_meter_profile *)dpaa2_profile;
		}
		dpaa2_profile = LIST_NEXT(dpaa2_profile, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return NULL;
}

static struct rte_flow_meter_policy *
dpaa2_mtr_policy_get(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy;

	RTE_SET_USED(error);

	rte_spinlock_lock(&priv->meter_lock);
	dpaa2_policy = LIST_FIRST(&priv->policies);
	while (dpaa2_policy != NULL) {
		if (dpaa2_policy->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return (struct rte_flow_meter_policy *)dpaa2_policy;
		}
		dpaa2_policy = LIST_NEXT(dpaa2_policy, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);

	return NULL;
}

static int
dpaa2_mtr_profile_delete(struct rte_eth_dev *dev,
	uint32_t profile_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *dpaa2_profile = NULL, *curr;
	struct dpaa2_dev_meter *meter;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	while (curr != NULL) {
		if (curr->profile_id == profile_id) {
			dpaa2_profile = curr;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}
	if (dpaa2_profile == NULL) {
		rte_spinlock_unlock(&priv->meter_lock);
		return -rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
			&profile_id, "Meter profile is invalid.");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->profile_id == profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return -rte_mtr_error_set(error, EBUSY,
				RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
				&profile_id, "Meter profile is in use.");
		}
		meter = LIST_NEXT(meter, next);
	}

	LIST_REMOVE(dpaa2_profile, next);
	free(dpaa2_profile);
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static int
dpaa2_mtr_policy_delete(struct rte_eth_dev *dev,
	uint32_t policy_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *dpaa2_policy = NULL, *curr;
	struct dpaa2_dev_meter *meter;

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	while (curr != NULL) {
		if (curr->policy_id == policy_id) {
			dpaa2_policy = curr;
			break;
		}
		curr = LIST_NEXT(curr, next);
	}
	if (dpaa2_policy == NULL) {
		rte_spinlock_unlock(&priv->meter_lock);
		return -rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
			NULL, "Meter policy is invalid.");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return -rte_mtr_error_set(error, EBUSY,
				RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
				NULL, "Meter policy is in use.");
		}
		meter = LIST_NEXT(meter, next);
	}

	LIST_REMOVE(dpaa2_policy, next);
	free(dpaa2_policy);
	rte_spinlock_unlock(&priv->meter_lock);

	return 0;
}

static int
dpaa2_mtr_meter_create(struct rte_eth_dev *dev,
	uint32_t mtr_id, struct rte_mtr_params *params,
	int shared, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter, *curr;
	struct dpni_rx_tc_policing_cfg pol_cfg;
	uint32_t profile_id, policy_id;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
	const char *err_msg = NULL;
	bool found = false;
	int ret = 0;

	RTE_SET_USED(shared);
	profile_id = params->meter_profile_id;
	policy_id = params->meter_policy_id;

	rte_spinlock_lock(&priv->meter_lock);
	profile = LIST_FIRST(&priv->profiles);
	while (profile != NULL) {
		if (profile->profile_id == profile_id) {
			found = true;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		err_msg = "Meter profile ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}

	found = false;
	policy = LIST_FIRST(&priv->policies);
	while (policy != NULL) {
		if (policy->policy_id == policy_id) {
			found = true;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		err_msg = "Meter policy ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			err_msg = "Meter ID already exists";
			ret = EEXIST;
			err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
			goto quit;
		}
		meter = LIST_NEXT(meter, next);
	}
	meter = calloc(1, sizeof(struct dpaa2_dev_meter));
	if (meter == NULL) {
		err_msg = "Meter memory alloc failed";
		ret = ENOMEM;
		err_type = RTE_MTR_ERROR_TYPE_UNSPECIFIED;
		goto quit;
	}
	meter->meter_id = mtr_id;
	meter->profile_id = profile_id;
	meter->policy_id = policy_id;

	curr = LIST_FIRST(&priv->meters);
	if (curr == NULL) {
		LIST_INSERT_HEAD(&priv->meters, meter, next);
	} else {
		while (LIST_NEXT(curr, next) != NULL)
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, meter, next);
	}

	memset(&pol_cfg, 0, sizeof(pol_cfg));
	pol_cfg.mode = profile->mode;
	pol_cfg.units = profile->policer_unit;
	pol_cfg.cir = (uint32_t)(profile->cir / 1000);
	pol_cfg.cbs = (uint32_t)profile->cbs;
	pol_cfg.eir = (uint32_t)(profile->pir / 1000);
	pol_cfg.ebs = (uint32_t)profile->pbs;
	if (policy->red_drop)
		pol_cfg.options |= DPNI_POLICER_OPT_DISCARD_RED;
	ret = dpni_set_rx_tc_policing(priv->hw, CMD_PRI_LOW,
				      priv->token, (uint8_t)mtr_id, &pol_cfg);
	if (ret != 0) {
		LIST_REMOVE(meter, next);
		free(meter);
		err_msg = "Meter HW programming failed";
		err_type = RTE_MTR_ERROR_TYPE_UNSPECIFIED;
		goto quit;
	}

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0)
		return -rte_mtr_error_set(error, ret, err_type, NULL, err_msg);

	return 0;
}

static int
dpaa2_mtr_meter_destroy(struct rte_eth_dev *dev,
	uint32_t mtr_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter *meter;
	struct dpni_rx_tc_policing_cfg pol_cfg;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			LIST_REMOVE(meter, next);
			free(meter);
			memset(&pol_cfg, 0, sizeof(pol_cfg));
			pol_cfg.mode = DPNI_POLICER_MODE_NONE;
			dpni_set_rx_tc_policing(priv->hw, CMD_PRI_LOW,
						priv->token,
						(uint8_t)mtr_id, &pol_cfg);
			rte_spinlock_unlock(&priv->meter_lock);

			return 0;
		}
		meter = LIST_NEXT(meter, next);
	}
	rte_spinlock_unlock(&priv->meter_lock);
	return -rte_mtr_error_set(error, ENOENT,
		RTE_MTR_ERROR_TYPE_MTR_ID, NULL, "Meter ID does not exist");
}

static int
dpaa2_mtr_meter_profile_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t profile_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter *meter;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
	const char *err_msg = NULL;
	bool found = false;
	int ret = 0;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			found = true;
			break;
		}
		meter = LIST_NEXT(meter, next);
	}
	if (!found) {
		err_msg = "Meter ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
		goto quit;
	}

	found = false;
	profile = LIST_FIRST(&priv->profiles);
	while (profile != NULL) {
		if (profile->profile_id == profile_id) {
			found = true;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		err_msg = "Meter profile ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}
	meter->profile_id = profile_id;

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0)
		return -rte_mtr_error_set(error, ret, err_type, NULL, err_msg);

	return 0;
}

static int
dpaa2_mtr_meter_policy_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t policy_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
	const char *err_msg = NULL;
	bool found = false;
	int ret = 0;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			found = true;
			break;
		}
		meter = LIST_NEXT(meter, next);
	}
	if (!found) {
		err_msg = "Meter ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
		goto quit;
	}

	found = false;
	policy = LIST_FIRST(&priv->policies);
	while (policy != NULL) {
		if (policy->policy_id == policy_id) {
			found = true;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		err_msg = "Meter policy ID not found";
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}
	meter->policy_id = policy_id;

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0)
		return -rte_mtr_error_set(error, ret, err_type, NULL, err_msg);

	return 0;
}

static const struct rte_mtr_ops dpaa2_meter_ops = {
	.capabilities_get = dpaa2_mtr_capabilities_get,
	.meter_profile_add = dpaa2_mtr_profile_add,
	.meter_profile_delete = dpaa2_mtr_profile_delete,
	.meter_policy_add = dpaa2_mtr_policy_add,
	.meter_policy_delete = dpaa2_mtr_policy_delete,
	.meter_profile_get = dpaa2_mtr_profile_get,
	.meter_policy_get = dpaa2_mtr_policy_get,
	.create = dpaa2_mtr_meter_create,
	.destroy = dpaa2_mtr_meter_destroy,
	.meter_profile_update = dpaa2_mtr_meter_profile_update,
	.meter_policy_update = dpaa2_mtr_meter_policy_update,
};

int
dpaa2_mtr_ops_get(struct rte_eth_dev *dev, void *ops)
{
	RTE_SET_USED(dev);

	*(const void **)ops = &dpaa2_meter_ops;
	return 0;
}

void
dpaa2_meter_clean(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter;

	while ((meter = LIST_FIRST(&priv->meters)) != NULL) {
		LIST_REMOVE(meter, next);
		free(meter);
	}
	while ((profile = LIST_FIRST(&priv->profiles)) != NULL) {
		LIST_REMOVE(profile, next);
		free(profile);
	}
	while ((policy = LIST_FIRST(&priv->policies)) != NULL) {
		LIST_REMOVE(policy, next);
		free(policy);
	}
}
