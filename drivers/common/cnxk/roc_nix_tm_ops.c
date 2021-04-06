/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_nix_tm_sq_aura_fc(struct roc_nix_sq *sq, bool enable)
{
	struct npa_aq_enq_req *req;
	struct npa_aq_enq_rsp *rsp;
	uint64_t aura_handle;
	struct npa_lf *lf;
	struct mbox *mbox;
	int rc = -ENOSPC;

	plt_tm_dbg("Setting SQ %u SQB aura FC to %s", sq->qid,
		   enable ? "enable" : "disable");

	lf = idev_npa_obj_get();
	if (!lf)
		return NPA_ERR_DEVICE_NOT_BOUNDED;

	mbox = lf->mbox;
	/* Set/clear sqb aura fc_ena */
	aura_handle = sq->aura_handle;
	req = mbox_alloc_msg_npa_aq_enq(mbox);
	if (req == NULL)
		return rc;

	req->aura_id = roc_npa_aura_handle_to_aura(aura_handle);
	req->ctype = NPA_AQ_CTYPE_AURA;
	req->op = NPA_AQ_INSTOP_WRITE;
	/* Below is not needed for aura writes but AF driver needs it */
	/* AF will translate to associated poolctx */
	req->aura.pool_addr = req->aura_id;

	req->aura.fc_ena = enable;
	req->aura_mask.fc_ena = 1;

	rc = mbox_process(mbox);
	if (rc)
		return rc;

	/* Read back npa aura ctx */
	req = mbox_alloc_msg_npa_aq_enq(mbox);
	if (req == NULL)
		return -ENOSPC;

	req->aura_id = roc_npa_aura_handle_to_aura(aura_handle);
	req->ctype = NPA_AQ_CTYPE_AURA;
	req->op = NPA_AQ_INSTOP_READ;

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		return rc;

	/* Init when enabled as there might be no triggers */
	if (enable)
		*(volatile uint64_t *)sq->fc = rsp->aura.count;
	else
		*(volatile uint64_t *)sq->fc = sq->nb_sqb_bufs;
	/* Sync write barrier */
	plt_wmb();
	return 0;
}

int
roc_nix_tm_free_resources(struct roc_nix *roc_nix, bool hw_only)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);

	if (nix->tm_flags & NIX_TM_HIERARCHY_ENA)
		return -EBUSY;

	return nix_tm_free_resources(roc_nix, BIT(ROC_NIX_TM_USER), hw_only);
}

static int
nix_tm_shaper_profile_add(struct roc_nix *roc_nix,
			  struct nix_tm_shaper_profile *profile, int skip_ins)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	uint64_t commit_rate, commit_sz;
	uint64_t peak_rate, peak_sz;
	uint32_t id;

	id = profile->id;
	commit_rate = profile->commit.rate;
	commit_sz = profile->commit.size;
	peak_rate = profile->peak.rate;
	peak_sz = profile->peak.size;

	if (nix_tm_shaper_profile_search(nix, id) && !skip_ins)
		return NIX_ERR_TM_SHAPER_PROFILE_EXISTS;

	if (profile->pkt_len_adj < NIX_TM_LENGTH_ADJUST_MIN ||
	    profile->pkt_len_adj > NIX_TM_LENGTH_ADJUST_MAX)
		return NIX_ERR_TM_SHAPER_PKT_LEN_ADJUST;

	/* We cannot support both pkt length adjust and pkt mode */
	if (profile->pkt_mode && profile->pkt_len_adj)
		return NIX_ERR_TM_SHAPER_PKT_LEN_ADJUST;

	/* commit rate and burst size can be enabled/disabled */
	if (commit_rate || commit_sz) {
		if (commit_sz < NIX_TM_MIN_SHAPER_BURST ||
		    commit_sz > NIX_TM_MAX_SHAPER_BURST)
			return NIX_ERR_TM_INVALID_COMMIT_SZ;
		else if (!nix_tm_shaper_rate_conv(commit_rate, NULL, NULL,
						  NULL))
			return NIX_ERR_TM_INVALID_COMMIT_RATE;
	}

	/* Peak rate and burst size can be enabled/disabled */
	if (peak_sz || peak_rate) {
		if (peak_sz < NIX_TM_MIN_SHAPER_BURST ||
		    peak_sz > NIX_TM_MAX_SHAPER_BURST)
			return NIX_ERR_TM_INVALID_PEAK_SZ;
		else if (!nix_tm_shaper_rate_conv(peak_rate, NULL, NULL, NULL))
			return NIX_ERR_TM_INVALID_PEAK_RATE;
	}

	if (!skip_ins)
		TAILQ_INSERT_TAIL(&nix->shaper_profile_list, profile, shaper);

	plt_tm_dbg("Added TM shaper profile %u, "
		   " pir %" PRIu64 " , pbs %" PRIu64 ", cir %" PRIu64
		   ", cbs %" PRIu64 " , adj %u, pkt_mode %u",
		   id, profile->peak.rate, profile->peak.size,
		   profile->commit.rate, profile->commit.size,
		   profile->pkt_len_adj, profile->pkt_mode);

	/* Always use PIR for single rate shaping */
	if (!peak_rate && commit_rate) {
		profile->peak.rate = profile->commit.rate;
		profile->peak.size = profile->commit.size;
		profile->commit.rate = 0;
		profile->commit.size = 0;
	}

	/* update min rate */
	nix->tm_rate_min = nix_tm_shaper_profile_rate_min(nix);
	return 0;
}

int
roc_nix_tm_shaper_profile_add(struct roc_nix *roc_nix,
			      struct roc_nix_tm_shaper_profile *roc_profile)
{
	struct nix_tm_shaper_profile *profile;

	profile = (struct nix_tm_shaper_profile *)roc_profile->reserved;

	profile->ref_cnt = 0;
	profile->id = roc_profile->id;
	if (roc_profile->pkt_mode) {
		/* Each packet accomulate single count, whereas HW
		 * considers each unit as Byte, so we need convert
		 * user pps to bps
		 */
		profile->commit.rate = roc_profile->commit_rate * 8;
		profile->peak.rate = roc_profile->peak_rate * 8;
	} else {
		profile->commit.rate = roc_profile->commit_rate;
		profile->peak.rate = roc_profile->peak_rate;
	}
	profile->commit.size = roc_profile->commit_sz;
	profile->peak.size = roc_profile->peak_sz;
	profile->pkt_len_adj = roc_profile->pkt_len_adj;
	profile->pkt_mode = roc_profile->pkt_mode;
	profile->free_fn = roc_profile->free_fn;

	return nix_tm_shaper_profile_add(roc_nix, profile, 0);
}

int
roc_nix_tm_shaper_profile_update(struct roc_nix *roc_nix,
				 struct roc_nix_tm_shaper_profile *roc_profile)
{
	struct nix_tm_shaper_profile *profile;

	profile = (struct nix_tm_shaper_profile *)roc_profile->reserved;

	if (roc_profile->pkt_mode) {
		/* Each packet accomulate single count, whereas HW
		 * considers each unit as Byte, so we need convert
		 * user pps to bps
		 */
		profile->commit.rate = roc_profile->commit_rate * 8;
		profile->peak.rate = roc_profile->peak_rate * 8;
	} else {
		profile->commit.rate = roc_profile->commit_rate;
		profile->peak.rate = roc_profile->peak_rate;
	}
	profile->commit.size = roc_profile->commit_sz;
	profile->peak.size = roc_profile->peak_sz;

	return nix_tm_shaper_profile_add(roc_nix, profile, 1);
}

int
roc_nix_tm_shaper_profile_delete(struct roc_nix *roc_nix, uint32_t id)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct nix_tm_shaper_profile *profile;

	profile = nix_tm_shaper_profile_search(nix, id);
	if (!profile)
		return NIX_ERR_TM_INVALID_SHAPER_PROFILE;

	if (profile->ref_cnt)
		return NIX_ERR_TM_SHAPER_PROFILE_IN_USE;

	plt_tm_dbg("Removing TM shaper profile %u", id);
	TAILQ_REMOVE(&nix->shaper_profile_list, profile, shaper);
	nix_tm_shaper_profile_free(profile);

	/* update min rate */
	nix->tm_rate_min = nix_tm_shaper_profile_rate_min(nix);
	return 0;
}

int
roc_nix_tm_node_add(struct roc_nix *roc_nix, struct roc_nix_tm_node *roc_node)
{
	struct nix_tm_node *node;

	node = (struct nix_tm_node *)&roc_node->reserved;
	node->id = roc_node->id;
	node->priority = roc_node->priority;
	node->weight = roc_node->weight;
	node->lvl = roc_node->lvl;
	node->parent_id = roc_node->parent_id;
	node->shaper_profile_id = roc_node->shaper_profile_id;
	node->pkt_mode = roc_node->pkt_mode;
	node->pkt_mode_set = roc_node->pkt_mode_set;
	node->free_fn = roc_node->free_fn;
	node->tree = ROC_NIX_TM_USER;

	return nix_tm_node_add(roc_nix, node);
}

int
roc_nix_tm_node_pkt_mode_update(struct roc_nix *roc_nix, uint32_t node_id,
				bool pkt_mode)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct nix_tm_node *node, *child;
	struct nix_tm_node_list *list;
	int num_children = 0;

	node = nix_tm_node_search(nix, node_id, ROC_NIX_TM_USER);
	if (!node)
		return NIX_ERR_TM_INVALID_NODE;

	if (node->pkt_mode == pkt_mode) {
		node->pkt_mode_set = true;
		return 0;
	}

	/* Check for any existing children, if there are any,
	 * then we cannot update the pkt mode as children's quantum
	 * are already taken in.
	 */
	list = nix_tm_node_list(nix, ROC_NIX_TM_USER);
	TAILQ_FOREACH(child, list, node) {
		if (child->parent == node)
			num_children++;
	}

	/* Cannot update mode if it has children or tree is enabled */
	if ((nix->tm_flags & NIX_TM_HIERARCHY_ENA) && num_children)
		return -EBUSY;

	if (node->pkt_mode_set && num_children)
		return NIX_ERR_TM_PKT_MODE_MISMATCH;

	node->pkt_mode = pkt_mode;
	node->pkt_mode_set = true;

	return 0;
}

int
roc_nix_tm_node_name_get(struct roc_nix *roc_nix, uint32_t node_id, char *buf,
			 size_t buflen)
{
	struct nix *nix = roc_nix_to_nix_priv(roc_nix);
	struct nix_tm_node *node;

	node = nix_tm_node_search(nix, node_id, ROC_NIX_TM_USER);
	if (!node) {
		plt_strlcpy(buf, "???", buflen);
		return NIX_ERR_TM_INVALID_NODE;
	}

	if (node->hw_lvl == NIX_TXSCH_LVL_CNT)
		snprintf(buf, buflen, "SQ_%d", node->id);
	else
		snprintf(buf, buflen, "%s_%d", nix_tm_hwlvl2str(node->hw_lvl),
			 node->hw_id);
	return 0;
}

int
roc_nix_tm_node_delete(struct roc_nix *roc_nix, uint32_t node_id, bool free)
{
	return nix_tm_node_delete(roc_nix, node_id, ROC_NIX_TM_USER, free);
}
