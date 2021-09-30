/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "cn10k_ethdev.h"
#include <rte_mtr_driver.h>

#define NIX_MTR_COUNT_MAX      73 /* 64(leaf) + 8(mid) + 1(top) */
#define NIX_MTR_COUNT_PER_FLOW 3  /* 1(leaf) + 1(mid) + 1(top) */

static const enum roc_nix_bpf_level_flag lvl_map[] = {ROC_NIX_BPF_LEVEL_F_LEAF,
						      ROC_NIX_BPF_LEVEL_F_MID,
						      ROC_NIX_BPF_LEVEL_F_TOP};

static struct rte_mtr_capabilities mtr_capa = {
	.n_max = NIX_MTR_COUNT_MAX,
	.n_shared_max = NIX_MTR_COUNT_PER_FLOW,
	/* .identical = , */
	.shared_identical = true,
	/* .shared_n_flows_per_mtr_max = ,*/
	.chaining_n_mtrs_per_flow_max = NIX_MTR_COUNT_PER_FLOW,
	.chaining_use_prev_mtr_color_supported = true,
	.chaining_use_prev_mtr_color_enforced = true,
	.meter_srtcm_rfc2697_n_max = NIX_MTR_COUNT_MAX,
	.meter_trtcm_rfc2698_n_max = NIX_MTR_COUNT_MAX,
	.meter_trtcm_rfc4115_n_max = NIX_MTR_COUNT_MAX,
	.meter_rate_max = NIX_BPF_RATE_MAX / 8, /* Bytes per second */
	.meter_policy_n_max = NIX_MTR_COUNT_MAX,
	.color_aware_srtcm_rfc2697_supported = true,
	.color_aware_trtcm_rfc2698_supported = true,
	.color_aware_trtcm_rfc4115_supported = true,
	.srtcm_rfc2697_byte_mode_supported = true,
	.srtcm_rfc2697_packet_mode_supported = true,
	.trtcm_rfc2698_byte_mode_supported = true,
	.trtcm_rfc2698_packet_mode_supported = true,
	.trtcm_rfc4115_byte_mode_supported = true,
	.trtcm_rfc4115_packet_mode_supported = true,
	.stats_mask = RTE_MTR_STATS_N_PKTS_GREEN | RTE_MTR_STATS_N_PKTS_YELLOW |
		      RTE_MTR_STATS_N_PKTS_RED | RTE_MTR_STATS_N_PKTS_DROPPED |
		      RTE_MTR_STATS_N_BYTES_GREEN |
		      RTE_MTR_STATS_N_BYTES_YELLOW | RTE_MTR_STATS_N_BYTES_RED |
		      RTE_MTR_STATS_N_BYTES_DROPPED};

static struct cnxk_meter_node *
nix_mtr_find(struct cnxk_eth_dev *dev, uint32_t meter_id)
{
	struct cnxk_mtr *fms = &dev->mtr;
	struct cnxk_meter_node *fm;

	TAILQ_FOREACH(fm, fms, next)
		if (meter_id == fm->id)
			return fm;
	return NULL;
}

static struct cnxk_mtr_profile_node *
nix_mtr_profile_find(struct cnxk_eth_dev *dev, uint32_t profile_id)
{
	struct cnxk_mtr_profiles *fmps = &dev->mtr_profiles;
	struct cnxk_mtr_profile_node *fmp;

	TAILQ_FOREACH(fmp, fmps, next)
		if (profile_id == fmp->id)
			return fmp;

	return NULL;
}

static struct cnxk_mtr_policy_node *
nix_mtr_policy_find(struct cnxk_eth_dev *dev, uint32_t meter_policy_id)
{
	struct cnxk_mtr_policy *fmps = &dev->mtr_policy;
	struct cnxk_mtr_policy_node *fmp;

	TAILQ_FOREACH(fmp, fmps, next)
		if (meter_policy_id == fmp->id)
			return fmp;
	return NULL;
}

static int
nix_mtr_profile_validate(struct cnxk_eth_dev *dev, uint32_t profile_id,
			 struct rte_mtr_meter_profile *profile,
			 struct rte_mtr_error *error)
{
	int rc = 0;

	PLT_SET_USED(dev);

	if (profile == NULL)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE,
					  NULL, "Meter profile is null.");

	if (profile_id == UINT32_MAX)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id not valid.");

	switch (profile->alg) {
	case RTE_MTR_SRTCM_RFC2697:
		if (profile->srtcm_rfc2697.cir > mtr_capa.meter_rate_max)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"CIR exceeds max meter rate");

		if (profile->srtcm_rfc2697.cbs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"CBS exceeds max meter burst size");

		if (profile->srtcm_rfc2697.ebs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"EBS exceeds max meter burst size");
		break;

	case RTE_MTR_TRTCM_RFC2698:
		if (profile->trtcm_rfc2698.cir > mtr_capa.meter_rate_max)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"CIR exceeds max meter rate");

		if (profile->trtcm_rfc2698.pir > mtr_capa.meter_rate_max)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"PIR exceeds max meter rate");

		if (profile->trtcm_rfc2698.cbs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"CBS exceeds max meter burst size");

		if (profile->trtcm_rfc2698.pbs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"PBS exceeds max meter burst size");
		break;

	case RTE_MTR_TRTCM_RFC4115:
		if ((profile->trtcm_rfc4115.cir + profile->trtcm_rfc4115.eir) >
		    mtr_capa.meter_rate_max)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"PIR + EIR exceeds max rate");

		if (profile->trtcm_rfc4115.cbs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"CBS exceeds max meter burst size");

		if (profile->trtcm_rfc4115.ebs > NIX_BPF_BURST_MAX)
			rc = -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
				"PBS exceeds max meter burst size");
		break;

	default:
		rc = -rte_mtr_error_set(error, EINVAL,
					RTE_MTR_ERROR_TYPE_METER_PROFILE, NULL,
					"alg is invalid");
		break;
	}

	return rc;
}

static int
cn10k_nix_mtr_capabilities_get(struct rte_eth_dev *dev,
			       struct rte_mtr_capabilities *capa,
			       struct rte_mtr_error *error)
{
	RTE_SET_USED(dev);

	if (!capa)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "NULL input parameter");
	*capa = mtr_capa;
	return 0;
}

static int
cn10k_nix_mtr_profile_add(struct rte_eth_dev *eth_dev, uint32_t profile_id,
			  struct rte_mtr_meter_profile *profile,
			  struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mtr_profiles *fmps = &dev->mtr_profiles;
	struct cnxk_mtr_profile_node *fmp;
	int ret;

	/* Check input params. */
	ret = nix_mtr_profile_validate(dev, profile_id, profile, error);
	if (ret)
		return ret;

	fmp = nix_mtr_profile_find(dev, profile_id);
	if (fmp) {
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Profile already exist");
	}

	fmp = plt_zmalloc(sizeof(struct cnxk_mtr_profile_node), ROC_ALIGN);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  "Meter profile memory "
					  "alloc failed.");

	fmp->id = profile_id;
	fmp->profile = *profile;

	TAILQ_INSERT_TAIL(fmps, fmp, next);

	return 0;
}

static int
cn10k_nix_mtr_profile_delete(struct rte_eth_dev *eth_dev, uint32_t profile_id,
			     struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mtr_profile_node *fmp;

	if (profile_id == UINT32_MAX)
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile id not valid.");

	fmp = nix_mtr_profile_find(dev, profile_id);
	if (fmp == NULL)
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  &profile_id,
					  "Meter profile is invalid.");

	if (fmp->ref_cnt)
		return -rte_mtr_error_set(error, EBUSY,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  NULL, "Meter profile is in use.");

	TAILQ_REMOVE(&dev->mtr_profiles, fmp, next);
	plt_free(fmp);
	return 0;
}

static int
cn10k_nix_mtr_policy_validate(struct rte_eth_dev *dev,
			      struct rte_mtr_meter_policy_params *policy,
			      struct rte_mtr_error *error)
{
	static const char *const action_color[] = {"Green", "Yellow", "Red"};
	bool supported[RTE_COLORS] = {false, false, false};
	const struct rte_flow_action *action;
	char message[1024];
	uint32_t i;

	RTE_SET_USED(dev);

	if (!policy)
		return 0; /* Nothing to be validated */

	for (i = 0; i < RTE_COLORS; i++) {
		if (policy->actions[i]) {
			for (action = policy->actions[i];
			     action->type != RTE_FLOW_ACTION_TYPE_END;
			     action++) {
				if (action->type == RTE_FLOW_ACTION_TYPE_METER)
					supported[i] = true;

				if (action->type == RTE_FLOW_ACTION_TYPE_DROP)
					supported[i] = true;

				if (!supported[i]) {
					sprintf(message,
						"%s action is not valid",
						action_color[i]);
					return -rte_mtr_error_set(error,
					  ENOTSUP,
					  RTE_MTR_ERROR_TYPE_METER_POLICY, NULL,
					  message);
				}
			}
		} else {
			sprintf(message, "%s action is null", action_color[i]);
			return -rte_mtr_error_set(error, EINVAL,
				RTE_MTR_ERROR_TYPE_METER_POLICY, NULL,
				message);
		}
	}

	return 0;
}

static void
cn10k_fill_policy_actions(struct cnxk_mtr_policy_node *fmp,
			  struct rte_mtr_meter_policy_params *policy)

{
	const struct rte_flow_action_meter *mtr;
	const struct rte_flow_action *action;
	int i;

	for (i = 0; i < RTE_COLORS; i++) {
		if (policy->actions[i]) {
			for (action = policy->actions[i];
			     action->type != RTE_FLOW_ACTION_TYPE_END;
			     action++) {
				if (action->type ==
				    RTE_FLOW_ACTION_TYPE_METER) {
					fmp->actions[i].action_fate =
						action->type;
					mtr = (const struct
					       rte_flow_action_meter *)
						      action->conf;
					fmp->actions[i].mtr_id = mtr->mtr_id;
				}

				if (action->type == RTE_FLOW_ACTION_TYPE_DROP) {
					fmp->actions[i].action_fate =
						action->type;
				}
			}
		}
	}
}

static int
cn10k_nix_mtr_policy_add(struct rte_eth_dev *eth_dev, uint32_t policy_id,
			 struct rte_mtr_meter_policy_params *policy,
			 struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mtr_policy *fmps = &dev->mtr_policy;
	struct cnxk_mtr_policy_node *fmp;
	int rc;

	fmp = nix_mtr_policy_find(dev, policy_id);
	if (fmp) {
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "Policy already exist");
	}

	fmp = plt_zmalloc(sizeof(struct cnxk_mtr_policy_node), ROC_ALIGN);
	if (fmp == NULL) {
		return -rte_mtr_error_set(error, ENOMEM,
					  RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
					  "Memory allocation failure");
	} else {
		rc = cn10k_nix_mtr_policy_validate(eth_dev, policy, error);
		if (rc)
			goto exit;
	}

	fmp->id = policy_id;
	cn10k_fill_policy_actions(fmp, policy);
	TAILQ_INSERT_TAIL(fmps, fmp, next);
	return 0;

exit:
	plt_free(fmp);
	return rc;
}

static int
cn10k_nix_mtr_policy_delete(struct rte_eth_dev *eth_dev, uint32_t policy_id,
			    struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mtr_policy_node *fmp;

	fmp = nix_mtr_policy_find(dev, policy_id);
	if (fmp == NULL) {
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "No policy found");
	}

	if (fmp->ref_cnt)
		return -rte_mtr_error_set(error, EBUSY,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  NULL, "Meter policy is in use.");

	TAILQ_REMOVE(&dev->mtr_policy, fmp, next);
	plt_free(fmp);

	return 0;
}

static int
cn10k_nix_mtr_create(struct rte_eth_dev *eth_dev, uint32_t mtr_id,
		     struct rte_mtr_params *params, int shared,
		     struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct cnxk_mtr_profile_node *profile;
	struct cnxk_mtr_policy_node *policy;
	struct cnxk_mtr *fm = &dev->mtr;
	struct cnxk_meter_node *mtr;
	int i;

	RTE_SET_USED(shared);

	if (params == NULL)
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_MTR_PARAMS, NULL,
					  "Meter params are invalid.");

	profile = nix_mtr_profile_find(dev, params->meter_profile_id);
	if (profile == NULL)
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_METER_PROFILE_ID,
					  &params->meter_profile_id,
					  "Meter profile is invalid.");

	policy = nix_mtr_policy_find(dev, params->meter_policy_id);
	if (policy == NULL)
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_METER_POLICY_ID,
					  &params->meter_policy_id,
					  "Meter policy is invalid.");

	mtr = nix_mtr_find(dev, mtr_id);
	if (mtr == NULL) {
		mtr = plt_zmalloc(sizeof(struct cnxk_meter_node), ROC_ALIGN);
		if (mtr == NULL) {
			return -rte_mtr_error_set(error, ENOMEM,
				RTE_MTR_ERROR_TYPE_UNSPECIFIED, NULL,
				"Meter memory alloc failed.");
		} else {
			mtr->id = mtr_id;
			mtr->profile = profile;
			mtr->policy = policy;
			mtr->params = *params;
			mtr->bpf_id = ROC_NIX_BPF_ID_INVALID;
			mtr->prev_cnt = 0;
			for (i = 0; i < MAX_PRV_MTR_NODES; i++)
				mtr->prev_id[i] = ROC_NIX_BPF_ID_INVALID;
			mtr->next_id = ROC_NIX_BPF_ID_INVALID;
			mtr->is_prev = false;
			mtr->is_next = false;
			mtr->level = ROC_NIX_BPF_LEVEL_IDX_INVALID;

			if (params->dscp_table) {
				mtr->params.dscp_table =
					plt_zmalloc(ROC_NIX_BPF_PRE_COLOR_MAX,
						    ROC_ALIGN);
				if (mtr->params.dscp_table == NULL) {
					plt_free(mtr);
					return -rte_mtr_error_set(error, ENOMEM,
						RTE_MTR_ERROR_TYPE_UNSPECIFIED,
						NULL, "Memory alloc failed.");
				}

				for (i = 0; i < ROC_NIX_BPF_PRE_COLOR_MAX;
				     i++) {
					mtr->params.dscp_table[i] =
						params->dscp_table[i];
				}
			}
		}
	} else {
		return -rte_mtr_error_set(error, EEXIST,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter already exist");
	}

	profile->ref_cnt++;
	policy->ref_cnt++;
	TAILQ_INSERT_TAIL(fm, mtr, next);
	return 0;
}

static int
cn10k_nix_mtr_destroy(struct rte_eth_dev *eth_dev, uint32_t mtr_id,
		      struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct roc_nix_bpf_objs profs = {0};
	struct cnxk_mtr *fm = &dev->mtr;
	struct roc_nix *nix = &dev->nix;
	struct cnxk_meter_node *mtr;
	int rc = 0;

	mtr = nix_mtr_find(dev, mtr_id);
	if (mtr == NULL) {
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_MTR_ID, &mtr_id,
					  "Meter id is invalid.");
	}

	if (mtr->ref_cnt) {
		return -rte_mtr_error_set(error, EADDRINUSE,
					  RTE_MTR_ERROR_TYPE_MTR_ID, &mtr_id,
					  "Meter id in use.");
	}

	switch (lvl_map[mtr->level]) {
	case ROC_NIX_BPF_LEVEL_F_LEAF:
		if (mtr->is_next) {
			rc = roc_nix_bpf_connect(nix, ROC_NIX_BPF_LEVEL_F_LEAF,
						 mtr_id,
						 ROC_NIX_BPF_ID_INVALID);
		}
		break;
	case ROC_NIX_BPF_LEVEL_F_MID:
		while (mtr->prev_cnt) {
			rc = roc_nix_bpf_connect(nix, ROC_NIX_BPF_LEVEL_F_LEAF,
						 mtr->prev_id[mtr->prev_cnt],
						 ROC_NIX_BPF_ID_INVALID);
			mtr->prev_cnt--;
		}
		if (mtr->is_next) {
			rc = roc_nix_bpf_connect(nix, ROC_NIX_BPF_LEVEL_F_MID,
						 mtr_id,
						 ROC_NIX_BPF_ID_INVALID);
		}
		break;
	case ROC_NIX_BPF_LEVEL_F_TOP:
		while (mtr->prev_cnt) {
			rc = roc_nix_bpf_connect(nix, ROC_NIX_BPF_LEVEL_F_MID,
						 mtr->prev_id[mtr->prev_cnt],
						 ROC_NIX_BPF_ID_INVALID);
			mtr->prev_cnt--;
		}
		break;
	default:
		return -rte_mtr_error_set(error, EINVAL,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Invalid meter level");
	}

	if (rc)
		goto exit;

	profs.level = mtr->level;
	profs.count = 1;
	profs.ids[0] = mtr->bpf_id;
	rc = roc_nix_bpf_free(nix, &profs, 1);
	if (rc)
		goto exit;

	TAILQ_REMOVE(fm, mtr, next);
	plt_free(mtr->params.dscp_table);
	plt_free(mtr);

exit:
	return rc;
}

static int
cn10k_nix_mtr_enable(struct rte_eth_dev *eth_dev, uint32_t mtr_id,
		     struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct roc_nix *nix = &dev->nix;
	struct cnxk_meter_node *mtr;
	struct roc_nix_rq *rq;
	uint32_t i;
	int rc = 0;

	mtr = nix_mtr_find(dev, mtr_id);
	if (mtr == NULL) {
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id is invalid.");
	}

	if (mtr->level != 0)
		return 0;

	for (i = 0; i < mtr->rq_num; i++) {
		rq = &dev->rqs[mtr->rq_id[i]];
		rc |= roc_nix_bpf_ena_dis(nix, mtr->bpf_id, rq, true);
	}

	return rc;
}

static int
cn10k_nix_mtr_disable(struct rte_eth_dev *eth_dev, uint32_t mtr_id,
		      struct rte_mtr_error *error)
{
	struct cnxk_eth_dev *dev = cnxk_eth_pmd_priv(eth_dev);
	struct roc_nix *nix = &dev->nix;
	struct cnxk_meter_node *mtr;
	struct roc_nix_rq *rq;
	uint32_t i;
	int rc = 0;

	mtr = nix_mtr_find(dev, mtr_id);
	if (mtr == NULL) {
		return -rte_mtr_error_set(error, ENOENT,
					  RTE_MTR_ERROR_TYPE_MTR_ID, NULL,
					  "Meter id is invalid.");
	}

	if (mtr->level != 0)
		return 0;

	for (i = 0; i < mtr->rq_num; i++) {
		rq = &dev->rqs[mtr->rq_id[i]];
		rc |= roc_nix_bpf_ena_dis(nix, mtr->bpf_id, rq, false);
	}

	return rc;
}

const struct rte_mtr_ops nix_mtr_ops = {
	.capabilities_get = cn10k_nix_mtr_capabilities_get,
	.meter_profile_add = cn10k_nix_mtr_profile_add,
	.meter_profile_delete = cn10k_nix_mtr_profile_delete,
	.meter_policy_validate = cn10k_nix_mtr_policy_validate,
	.meter_policy_add = cn10k_nix_mtr_policy_add,
	.meter_policy_delete = cn10k_nix_mtr_policy_delete,
	.create = cn10k_nix_mtr_create,
	.destroy = cn10k_nix_mtr_destroy,
	.meter_enable = cn10k_nix_mtr_enable,
	.meter_disable = cn10k_nix_mtr_disable,
};

int
cn10k_nix_mtr_ops_get(struct rte_eth_dev *dev, void *ops)
{
	RTE_SET_USED(dev);

	*(const void **)ops = &nix_mtr_ops;
	return 0;
}
