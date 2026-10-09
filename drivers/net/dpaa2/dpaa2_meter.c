/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025-2026 NXP
 */

#include <sys/queue.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/mman.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_flow_driver.h>
#include <rte_tailq.h>
#include <rte_mtr.h>
#include <rte_mtr_driver.h>

#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#include <dpaa2_ethdev.h>
#include <dpaa2_pmd_logs.h>

static char s_err_msg[128];

/*
 * color_aware mode is not yet implemented: the firmware color input from
 * FD[DROPP] is not read or acted upon.  Advertise only blind (non-aware)
 * trTCM variants until color-aware handling is added.
 */
static struct rte_mtr_capabilities s_dpaa2_mtr_capa = {
	.color_aware_trtcm_rfc2698_supported = false,
	.color_aware_trtcm_rfc4115_supported = false,
	.trtcm_rfc2698_byte_mode_supported = true,
	.trtcm_rfc2698_packet_mode_supported = true,
	.trtcm_rfc4115_byte_mode_supported = true,
	.trtcm_rfc4115_packet_mode_supported = true
};

/*
 * Program the DPNI policing HW for the given TC.
 * profile->cir and profile->pir are stored in the rte_mtr units:
 *   byte mode:   bytes/s  -> convert to Kbps (divide by 125)
 *   packet mode: packets/s -> pass through unchanged
 * cbs/pbs are in bytes or packets and fit in uint32_t; the caller must
 * verify this before storing in the profile.
 */
static int
dpaa2_mtr_hw_program(struct rte_eth_dev *dev,
	uint32_t mtr_id,
	const struct dpaa2_dev_meter_profile *profile,
	const struct dpaa2_dev_meter_policy *policy)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct fsl_mc_io *dpni = priv->hw;
	struct dpni_rx_tc_policing_cfg cfg;
	int ret;

	memset(&cfg, 0, sizeof(cfg));
	cfg.mode = profile->mode;
	cfg.units = profile->policer_unit;
	cfg.default_color = DPNI_POLICER_COLOR_GREEN;

	if (policy->red_drop)
		cfg.options |= DPNI_POLICER_OPT_DISCARD_RED;

	if (profile->policer_unit == DPNI_POLICER_UNIT_BYTES_L3) {
		/* rte_mtr rates are bytes/s; DPNI expects Kbps (1 Kbps = 125 B/s). */
		cfg.cir = (uint32_t)(profile->cir / 125);
		cfg.eir = (uint32_t)(profile->pir / 125);
	} else {
		/* Packet mode: rates are packets/s, passed directly. */
		cfg.cir = (uint32_t)profile->cir;
		cfg.eir = (uint32_t)profile->pir;
	}
	cfg.cbs = (uint32_t)profile->cbs;
	cfg.ebs = (uint32_t)profile->pbs;

	ret = dpni_set_rx_tc_policing(dpni, CMD_PRI_LOW, priv->token,
				      (uint8_t)mtr_id, &cfg);
	if (ret) {
		DPAA2_PMD_ERR("TC[%u] policing set failed (%d)", mtr_id, ret);
		return ret;
	}

	return 0;
}

static int
dpaa2_mtr_capabilities_get(struct rte_eth_dev *dev,
	struct rte_mtr_capabilities *capa,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;

	if (capa == NULL) {
		return rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
				"NULL input parameter");
	}

	if (!(priv->options & DPNI_OPT_HAS_POLICING))
		return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"policing not enabled in DPNI");

	rte_spinlock_lock(&priv->meter_lock);
	s_dpaa2_mtr_capa.n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.n_shared_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_trtcm_rfc2698_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_trtcm_rfc4115_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.meter_policy_n_max = priv->num_rx_tc;
	s_dpaa2_mtr_capa.shared_n_flows_per_mtr_max = priv->fs_entries;
	rte_spinlock_unlock(&priv->meter_lock);

	*capa = s_dpaa2_mtr_capa;

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

	dpaa2_profile = rte_zmalloc(NULL,
		sizeof(struct dpaa2_dev_meter_profile), 0);
	if (dpaa2_profile == NULL) {
		return rte_mtr_error_set(error, ENOMEM,
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

	/* Align with DPNI policy. */
	if (!profile->packet_mode)
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_BYTES_L3;
	else
		dpaa2_profile->policer_unit = DPNI_POLICER_UNIT_FRAMES;

	/* Reject burst sizes that do not fit in the HW uint32_t fields. */
	if (dpaa2_profile->cbs > UINT32_MAX ||
	    dpaa2_profile->pbs > UINT32_MAX) {
		rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"burst size too large");
		ret = -EINVAL;
		goto err;
	}

	/* Reject burst sizes that do not fit in the HW uint32_t fields. */
	if (dpaa2_profile->cbs > UINT32_MAX ||
	    dpaa2_profile->pbs > UINT32_MAX) {
		rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"burst size too large");
		ret = -EINVAL;
		goto err;
	}

	dpaa2_profile->profile_id = profile_id;

	/* Check for duplicate ID and insert under lock to prevent TOCTOU. */
	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->profiles);
	while (curr != NULL) {
		if (curr->profile_id == profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			rte_mtr_error_set(error, EEXIST,
				RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
				NULL, "Meter profile ID already exists!");
			ret = -EEXIST;
			goto err;
		}
		curr = LIST_NEXT(curr, next);
	}

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
		rte_free(dpaa2_profile);

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

	if (policy->actions[RTE_COLOR_GREEN] != NULL) {
		return rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_GREEN, NULL,
				"Meter green policy action not supported!");
	}
	if (policy->actions[RTE_COLOR_YELLOW] != NULL) {
		return rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_YELLOW, NULL,
				"Meter yellow policy action not supported!");
	}

	red_action = policy->actions[RTE_COLOR_RED];

	if (red_action != NULL) {
		if (red_action->type == RTE_FLOW_ACTION_TYPE_DROP) {
			red_drop = true;
		} else if (red_action->type != RTE_FLOW_ACTION_TYPE_PASSTHRU) {
			snprintf(s_err_msg, sizeof(s_err_msg),
				"Meter red policy action(%d) NOT supported!",
				red_action->type);
			return rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_POLICER_ACTION_RED, NULL,
				s_err_msg);
		}
	}

	dpaa2_policy = rte_zmalloc(NULL,
		sizeof(struct dpaa2_dev_meter_policy), 0);
	if (dpaa2_policy == NULL) {
		return rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter policy memory alloc failed!");
	}

	dpaa2_policy->policy_id = policy_id;
	dpaa2_policy->red_drop = red_drop;

	/* Check for duplicate ID and insert under lock to prevent TOCTOU. */
	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->policies);
	while (curr != NULL) {
		if (curr->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			rte_free(dpaa2_policy);
			return rte_mtr_error_set(error, EEXIST,
				RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
				NULL, "Meter policy ID already exists!");
		}
		curr = LIST_NEXT(curr, next);
	}

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
		return rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
			&profile_id, "Meter profile is invalid.");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->profile_id == profile_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return rte_mtr_error_set(error, EBUSY,
				RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
				&profile_id, "Meter profile is in use.");
		}
		meter = LIST_NEXT(meter, next);
	}

	LIST_REMOVE(dpaa2_profile, next);
	rte_free(dpaa2_profile);
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
		return rte_mtr_error_set(error, ENOENT,
			RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
			NULL, "Meter policy is invalid.");
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->policy_id == policy_id) {
			rte_spinlock_unlock(&priv->meter_lock);
			return rte_mtr_error_set(error, EBUSY,
				RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
				NULL, "Meter policy is in use.");
		}
		meter = LIST_NEXT(meter, next);
	}

	LIST_REMOVE(dpaa2_policy, next);
	rte_free(dpaa2_policy);
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
	uint32_t profile_id, policy_id;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
	bool found = false;
	int ret = 0;

	RTE_SET_USED(shared);

	if (!(priv->options & DPNI_OPT_HAS_POLICING))
		return -rte_mtr_error_set(error, ENOTSUP,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"policing not enabled in DPNI");

	/* mtr_id maps 1:1 to an Rx TC; validate the range. */
	if (mtr_id >= priv->num_rx_tc) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter ID(%u) >= num_rx_tc(%u)!", mtr_id,
			priv->num_rx_tc);
		return rte_mtr_error_set(error, EINVAL,
			RTE_MTR_ERROR_TYPE_MTR_ID, NULL, s_err_msg);
	}

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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter profile ID(%d) not exist!", profile_id);
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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter policy ID(%d) not exist!", policy_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}

	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			snprintf(s_err_msg, sizeof(s_err_msg),
				"Meter ID(%d) exist!", mtr_id);
			ret = EEXIST;
			err_type = RTE_MTR_ERROR_TYPE_MTR_ID;
			goto quit;
		}
		meter = LIST_NEXT(meter, next);
	}
	meter = rte_zmalloc(NULL, sizeof(struct dpaa2_dev_meter), 0);
	if (meter == NULL) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter memory alloc failed!");
		ret = ENOMEM;
		err_type = RTE_MTR_ERROR_TYPE_UNSPECIFIED;
		goto quit;
	}
	meter->meter_id = mtr_id;
	meter->profile_id = profile_id;
	meter->policy_id = policy_id;

	rte_spinlock_unlock(&priv->meter_lock);

	/* Program the hardware policing configuration for this TC. */
	ret = dpaa2_mtr_hw_program(dev, mtr_id, profile, policy);
	if (ret) {
		rte_free(meter);
		snprintf(s_err_msg, sizeof(s_err_msg),
			"TC[%u] HW policing set failed (%d)!", mtr_id, ret);
		return rte_mtr_error_set(error, -ret,
			RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL, s_err_msg);
	}

	rte_spinlock_lock(&priv->meter_lock);
	curr = LIST_FIRST(&priv->meters);
	if (curr == NULL) {
		LIST_INSERT_HEAD(&priv->meters, meter, next);
	} else {
		while (LIST_NEXT(curr, next) != NULL)
			curr = LIST_NEXT(curr, next);
		LIST_INSERT_AFTER(curr, meter, next);
	}

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0) {
		if (meter != NULL && ret == ENOMEM)
			rte_free(meter);
		return rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);
	}

	return 0;
}

static int
dpaa2_mtr_meter_destroy(struct rte_eth_dev *dev,
	uint32_t mtr_id, struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_priv *priv_dev = dev->data->dev_private;
	struct fsl_mc_io *dpni = priv_dev->hw;
	struct dpaa2_dev_meter *meter;
	struct dpni_rx_tc_policing_cfg cfg;
	int ret;

	rte_spinlock_lock(&priv->meter_lock);
	meter = LIST_FIRST(&priv->meters);
	while (meter != NULL) {
		if (meter->meter_id == mtr_id) {
			LIST_REMOVE(meter, next);
			rte_free(meter);
			rte_spinlock_unlock(&priv->meter_lock);

			/* Disable policing for this TC. */
			memset(&cfg, 0, sizeof(cfg));
			cfg.mode = DPNI_POLICER_MODE_NONE;
			ret = dpni_set_rx_tc_policing(dpni, CMD_PRI_LOW,
						      priv->token,
						      (uint8_t)mtr_id, &cfg);
			if (ret)
				DPAA2_PMD_ERR("TC[%u] policing disable failed (%d)",
					mtr_id, ret);

			return 0;
		}
		meter = LIST_NEXT(meter, next);
	}
	snprintf(s_err_msg, sizeof(s_err_msg),
		"Meter ID(%d) does not exist!", mtr_id);
	rte_spinlock_unlock(&priv->meter_lock);
	return rte_mtr_error_set(error, ENOENT,
		RTE_MTR_ERROR_TYPE_MTR_ID, NULL, s_err_msg);
}

static int
dpaa2_mtr_meter_profile_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t profile_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter *meter;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter ID(%d) not found!", mtr_id);
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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Profile ID(%d) not found!", profile_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}

	/* Find the current policy so we can reprogram HW. */
	found = false;
	policy = LIST_FIRST(&priv->policies);
	while (policy != NULL) {
		if (policy->policy_id == meter->policy_id) {
			found = true;
			break;
		}
		policy = LIST_NEXT(policy, next);
	}
	if (!found) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Current policy ID(%d) not found!", meter->policy_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0)
		return rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);

	/* Reprogram hardware with the new profile. */
	ret = dpaa2_mtr_hw_program(dev, mtr_id, profile, policy);
	if (ret) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"TC[%u] HW reprogram failed (%d)!", mtr_id, ret);
		return rte_mtr_error_set(error, -ret,
			RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL, s_err_msg);
	}

	/* Commit the new profile id only after HW succeeded. */
	meter->profile_id = profile_id;

	return 0;
}

static int
dpaa2_mtr_meter_policy_update(struct rte_eth_dev *dev,
	uint32_t mtr_id, uint32_t policy_id,
	struct rte_mtr_error *error)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter_policy *policy;
	struct dpaa2_dev_meter_profile *profile;
	struct dpaa2_dev_meter *meter;
	enum rte_mtr_error_type err_type = RTE_MTR_ERROR_TYPE_NONE;
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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Meter ID(%d) not found!", mtr_id);
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
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Policy ID(%d) not found!", policy_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_POLICY_ID;
		goto quit;
	}

	/* Find the current profile so we can reprogram HW. */
	found = false;
	profile = LIST_FIRST(&priv->profiles);
	while (profile != NULL) {
		if (profile->profile_id == meter->profile_id) {
			found = true;
			break;
		}
		profile = LIST_NEXT(profile, next);
	}
	if (!found) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"Current profile ID(%d) not found!", meter->profile_id);
		ret = ENOENT;
		err_type = RTE_MTR_ERROR_TYPE_METER_PROFILE_ID;
		goto quit;
	}

quit:
	rte_spinlock_unlock(&priv->meter_lock);
	if (ret != 0)
		return rte_mtr_error_set(error, ret, err_type, NULL, s_err_msg);

	/* Reprogram hardware with the new policy. */
	ret = dpaa2_mtr_hw_program(dev, mtr_id, profile, policy);
	if (ret) {
		snprintf(s_err_msg, sizeof(s_err_msg),
			"TC[%u] HW reprogram failed (%d)!", mtr_id, ret);
		return rte_mtr_error_set(error, -ret,
			RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL, s_err_msg);
	}

	/* Commit the new policy id only after HW succeeded. */
	meter->policy_id = policy_id;

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

void
dpaa2_mtr_deinit(struct rte_eth_dev *dev)
{
	struct dpaa2_dev_priv *priv = dev->data->dev_private;
	struct dpaa2_dev_meter *m;
	struct dpaa2_dev_meter_policy *p;
	struct dpaa2_dev_meter_profile *pf;

	rte_spinlock_lock(&priv->meter_lock);
	while ((m = LIST_FIRST(&priv->meters)) != NULL) {
		LIST_REMOVE(m, next);
		rte_free(m);
	}
	while ((p = LIST_FIRST(&priv->policies)) != NULL) {
		LIST_REMOVE(p, next);
		rte_free(p);
	}
	while ((pf = LIST_FIRST(&priv->profiles)) != NULL) {
		LIST_REMOVE(pf, next);
		rte_free(pf);
	}
	rte_spinlock_unlock(&priv->meter_lock);
}

int
dpaa2_mtr_ops_get(struct rte_eth_dev *dev, void *ops)
{
	RTE_SET_USED(dev);

	*(const void **)ops = &dpaa2_meter_ops;
	return 0;
}
