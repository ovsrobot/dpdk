/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2022 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

struct mcs_event_cb {
	TAILQ_ENTRY(mcs_event_cb) next;
	enum roc_mcs_event_type event;
	roc_mcs_dev_cb_fn cb_fn;
	void *cb_arg;
	void *ret_param;
	uint32_t active;
};
TAILQ_HEAD(mcs_event_cb_list, mcs_event_cb);

PLT_STATIC_ASSERT(ROC_MCS_MEM_SZ >= (sizeof(struct mcs_priv) + sizeof(struct mcs_event_cb_list)));

TAILQ_HEAD(roc_mcs_head, roc_mcs);
/* Local mcs tailq list */
static struct roc_mcs_head roc_mcs_head = TAILQ_HEAD_INITIALIZER(roc_mcs_head);

int
roc_mcs_hw_info_get(struct roc_mcs_hw_info *hw_info)
{
	struct mcs_hw_info *hw;
	struct npa_lf *npa;
	int rc;

	MCS_SUPPORT_CHECK;

	if (hw_info == NULL)
		return -EINVAL;

	/* Use mbox handler of first probed pci_func for
	 * initial mcs mbox communication.
	 */
	npa = idev_npa_obj_get();
	if (!npa)
		return MCS_ERR_DEVICE_NOT_FOUND;

	mbox_alloc_msg_mcs_get_hw_info(npa->mbox);
	rc = mbox_process_msg(npa->mbox, (void *)&hw);
	if (rc)
		return rc;

	hw_info->num_mcs_blks = hw->num_mcs_blks;
	hw_info->tcam_entries = hw->tcam_entries;
	hw_info->secy_entries = hw->secy_entries;
	hw_info->sc_entries = hw->sc_entries;
	hw_info->sa_entries = hw->sa_entries;

	return rc;
}

int
roc_mcs_active_lmac_set(struct roc_mcs *mcs, struct roc_mcs_set_active_lmac *lmac)
{
	struct mcs_set_active_lmac *req;
	struct msg_rsp *rsp;

	/* Only needed for 105N */
	if (!roc_model_is_cnf10kb())
		return 0;

	if (lmac == NULL)
		return -EINVAL;

	MCS_SUPPORT_CHECK;

	req = mbox_alloc_msg_mcs_set_active_lmac(mcs->mbox);
	if (req == NULL)
		return -ENOMEM;

	req->lmac_bmap = lmac->lmac_bmap;
	req->channel_base = lmac->channel_base;
	req->mcs_id = mcs->idx;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_lmac_mode_set(struct roc_mcs *mcs, struct roc_mcs_set_lmac_mode *port)
{
	struct mcs_set_lmac_mode *req;
	struct msg_rsp *rsp;

	if (port == NULL)
		return -EINVAL;

	MCS_SUPPORT_CHECK;

	req = mbox_alloc_msg_mcs_set_lmac_mode(mcs->mbox);
	if (req == NULL)
		return -ENOMEM;

	req->lmac_id = port->lmac_id;
	req->mcs_id = mcs->idx;
	req->mode = port->mode;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_intr_configure(struct roc_mcs *mcs, struct roc_mcs_intr_cfg *config)
{
	struct mcs_intr_cfg *req;
	struct msg_rsp *rsp;

	if (config == NULL)
		return -EINVAL;

	MCS_SUPPORT_CHECK;

	req = mbox_alloc_msg_mcs_intr_cfg(mcs->mbox);
	if (req == NULL)
		return -ENOMEM;

	req->intr_mask = config->intr_mask;
	req->mcs_id = mcs->idx;

	return mbox_process_msg(mcs->mbox, (void *)&rsp);
}

int
roc_mcs_event_cb_register(struct roc_mcs *mcs, enum roc_mcs_event_type event,
			  roc_mcs_dev_cb_fn cb_fn, void *cb_arg, void *userdata)
{
	struct mcs_event_cb_list *cb_list = (struct mcs_event_cb_list *)roc_mcs_to_mcs_cb_list(mcs);
	struct mcs_event_cb *cb;

	if (cb_fn == NULL || cb_arg == NULL || userdata == NULL)
		return -EINVAL;

	MCS_SUPPORT_CHECK;

	TAILQ_FOREACH(cb, cb_list, next) {
		if (cb->cb_fn == cb_fn && cb->cb_arg == cb_arg && cb->event == event)
			break;
	}

	if (cb == NULL) {
		cb = plt_zmalloc(sizeof(struct mcs_event_cb), 0);
		if (!cb)
			return -ENOMEM;

		cb->cb_fn = cb_fn;
		cb->cb_arg = cb_arg;
		cb->event = event;
		mcs->userdata = userdata;
		TAILQ_INSERT_TAIL(cb_list, cb, next);
	}

	return 0;
}

int
roc_mcs_event_cb_unregister(struct roc_mcs *mcs, enum roc_mcs_event_type event)
{
	struct mcs_event_cb_list *cb_list = (struct mcs_event_cb_list *)roc_mcs_to_mcs_cb_list(mcs);
	struct mcs_event_cb *cb, *next;

	MCS_SUPPORT_CHECK;

	for (cb = TAILQ_FIRST(cb_list); cb != NULL; cb = next) {
		next = TAILQ_NEXT(cb, next);

		if (cb->event != event)
			continue;

		if (cb->active == 0) {
			TAILQ_REMOVE(cb_list, cb, next);
			plt_free(cb);
		} else {
			return -EAGAIN;
		}
	}

	return 0;
}

int
mcs_event_cb_process(struct roc_mcs *mcs, struct roc_mcs_event_desc *desc)
{
	struct mcs_event_cb_list *cb_list = (struct mcs_event_cb_list *)roc_mcs_to_mcs_cb_list(mcs);
	struct mcs_event_cb mcs_cb;
	struct mcs_event_cb *cb;
	int rc = 0;

	TAILQ_FOREACH(cb, cb_list, next) {
		if (cb->cb_fn == NULL || cb->event != desc->type)
			continue;

		mcs_cb = *cb;
		cb->active = 1;
		mcs_cb.ret_param = desc;

		rc = mcs_cb.cb_fn(mcs->userdata, mcs_cb.ret_param, mcs_cb.cb_arg);
		cb->active = 0;
	}

	return rc;
}

static int
mcs_alloc_bmap(uint16_t entries, void **mem, struct plt_bitmap **bmap)
{
	size_t bmap_sz;
	int rc = 0;

	bmap_sz = plt_bitmap_get_memory_footprint(entries);
	*mem = plt_zmalloc(bmap_sz, PLT_CACHE_LINE_SIZE);
	if (*mem == NULL)
		rc = -ENOMEM;

	*bmap = plt_bitmap_init(entries, *mem, bmap_sz);
	if (!*bmap) {
		plt_free(*mem);
		*mem = NULL;
		rc = -ENOMEM;
	}

	return rc;
}

static int
mcs_alloc_rsrc_bmap(struct roc_mcs *mcs)
{
	struct mcs_priv *priv = roc_mcs_to_mcs_priv(mcs);
	struct mcs_hw_info *hw;
	int rc;

	mbox_alloc_msg_mcs_get_hw_info(mcs->mbox);
	rc = mbox_process_msg(mcs->mbox, (void *)&hw);
	if (rc)
		return rc;

	priv->num_mcs_blks = hw->num_mcs_blks;
	priv->tcam_entries = hw->tcam_entries;
	priv->secy_entries = hw->secy_entries;
	priv->sc_entries = hw->sc_entries;
	priv->sa_entries = hw->sa_entries;

	/* Allocate double the resources to accommodate both Tx & Rx */
	rc = mcs_alloc_bmap(priv->tcam_entries << 1, &priv->tcam_bmap_mem, &priv->tcam_bmap);
	if (rc)
		goto exit;

	rc = mcs_alloc_bmap(priv->secy_entries << 1, &priv->secy_bmap_mem, &priv->secy_bmap);
	if (rc)
		goto exit;

	rc = mcs_alloc_bmap(priv->sc_entries << 1, &priv->sc_bmap_mem, &priv->sc_bmap);
	if (rc)
		goto exit;

	rc = mcs_alloc_bmap(priv->sa_entries << 1, &priv->sa_bmap_mem, &priv->sa_bmap);
	if (rc)
		goto exit;

	return rc;

exit:
	plt_bitmap_free(priv->tcam_bmap);
	plt_free(priv->tcam_bmap_mem);
	plt_bitmap_free(priv->secy_bmap);
	plt_free(priv->secy_bmap_mem);
	plt_bitmap_free(priv->sc_bmap);
	plt_free(priv->sc_bmap_mem);
	plt_bitmap_free(priv->sa_bmap);
	plt_free(priv->sa_bmap_mem);

	return rc;
}

struct roc_mcs *
roc_mcs_dev_get(uint8_t mcs_idx)
{
	struct roc_mcs *mcs = NULL;

	TAILQ_FOREACH (mcs, &roc_mcs_head, next) {
		if (mcs->idx == mcs_idx)
			break;
	}

	return mcs;
}

struct roc_mcs *
roc_mcs_dev_init(uint8_t mcs_idx)
{
	struct mcs_event_cb_list *cb_list;
	struct roc_mcs *mcs;
	struct npa_lf *npa;

	mcs = plt_zmalloc(sizeof(struct roc_mcs), PLT_CACHE_LINE_SIZE);
	if (!mcs)
		return NULL;

	if (roc_model_is_cnf10kb()) {
		npa = idev_npa_obj_get();
		if (!npa)
			goto exit;

		mcs->mbox = npa->mbox;
	} else {
		/* Retrieve mbox handler for other roc models */
		;
	}

	mcs->idx = mcs_idx;

	/* Add any per mcsv initialization */
	if (mcs_alloc_rsrc_bmap(mcs))
		goto exit;

	TAILQ_INSERT_TAIL(&roc_mcs_head, mcs, next);

	cb_list = (struct mcs_event_cb_list *)roc_mcs_to_mcs_cb_list(mcs);
	TAILQ_INIT(cb_list);

	return mcs;

exit:
	plt_free(mcs);
	return NULL;
}

void
roc_mcs_dev_fini(struct roc_mcs *mcs)
{
	struct mcs_priv *priv = roc_mcs_to_mcs_priv(mcs);

	TAILQ_REMOVE(&roc_mcs_head, mcs, next);

	plt_bitmap_free(priv->tcam_bmap);
	plt_free(priv->tcam_bmap_mem);
	plt_bitmap_free(priv->secy_bmap);
	plt_free(priv->secy_bmap_mem);
	plt_bitmap_free(priv->sc_bmap);
	plt_free(priv->sc_bmap_mem);
	plt_bitmap_free(priv->sa_bmap);
	plt_free(priv->sa_bmap_mem);

	plt_free(mcs);
}
