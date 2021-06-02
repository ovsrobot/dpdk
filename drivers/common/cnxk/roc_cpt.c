/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2021 Marvell.
 */

#include "roc_api.h"
#include "roc_priv.h"

int
roc_cpt_rxc_time_cfg(struct roc_cpt *roc_cpt, struct roc_cpt_rxc_time_cfg *cfg)
{
	struct cpt *cpt = roc_cpt_to_cpt_priv(roc_cpt);
	struct cpt_rxc_time_cfg_req *req;
	struct dev *dev = &cpt->dev;

	req = mbox_alloc_msg_cpt_rxc_time_cfg(dev->mbox);
	if (req == NULL)
		return -ENOSPC;

	req->blkaddr = 0;

	/* The step value is in microseconds. */
	req->step = cfg->step;

	/* The timeout will be: limit * step microseconds */
	req->zombie_limit = cfg->zombie_limit;
	req->zombie_thres = cfg->zombie_thres;

	/* The timeout will be: limit * step microseconds */
	req->active_limit = cfg->active_limit;
	req->active_thres = cfg->active_thres;

	return mbox_process(dev->mbox);
}

static int
cpt_get_msix_offset(struct dev *dev, struct msix_offset_rsp **msix_rsp)
{
	struct mbox *mbox = dev->mbox;
	int rc;

	/* Get MSIX vector offsets */
	mbox_alloc_msg_msix_offset(mbox);
	rc = mbox_process_msg(mbox, (void *)msix_rsp);

	return rc;
}

static int
cpt_lfs_attach(struct dev *dev, int nb_lf)
{
	struct mbox *mbox;
	struct rsrc_attach_req *req;

	mbox = dev->mbox;
	/* Attach CPT(lf) */
	req = mbox_alloc_msg_attach_resources(mbox);
	if (req == NULL)
		return -ENOSPC;

	req->cptlfs = nb_lf;

	return mbox_process(mbox);
}

static int
cpt_lfs_detach(struct dev *dev)
{
	struct mbox *mbox = dev->mbox;
	struct rsrc_detach_req *req;

	req = mbox_alloc_msg_detach_resources(mbox);
	if (req == NULL)
		return -ENOSPC;

	req->cptlfs = 1;
	req->partial = 1;

	return mbox_process(mbox);
}

static int
cpt_available_lfs_get(struct dev *dev, uint16_t *nb_lf)
{
	struct mbox *mbox = dev->mbox;
	struct free_rsrcs_rsp *rsp;
	int rc;

	mbox_alloc_msg_free_rsrc_cnt(mbox);

	rc = mbox_process_msg(mbox, (void *)&rsp);
	if (rc)
		return -EIO;

	*nb_lf = rsp->cpt;
	return 0;
}

static int
cpt_lfs_alloc(struct dev *dev, uint8_t eng_grpmsk)
{
	struct cpt_lf_alloc_req_msg *req;
	struct mbox *mbox = dev->mbox;

	req = mbox_alloc_msg_cpt_lf_alloc(mbox);
	req->nix_pf_func = 0;
	req->sso_pf_func = idev_sso_pffunc_get();
	req->eng_grpmsk = eng_grpmsk;

	return mbox_process(mbox);
}

static int
cpt_lfs_free(struct dev *dev)
{
	mbox_alloc_msg_cpt_lf_free(dev->mbox);

	return mbox_process(dev->mbox);
}

static int
cpt_hardware_caps_get(struct dev *dev, union cpt_eng_caps *hw_caps)
{
	struct cpt_caps_rsp_msg *rsp;
	int ret;

	mbox_alloc_msg_cpt_caps_get(dev->mbox);

	ret = mbox_process_msg(dev->mbox, (void *)&rsp);
	if (ret)
		return -EIO;

	mbox_memcpy(hw_caps, rsp->eng_caps,
		    sizeof(union cpt_eng_caps) * CPT_MAX_ENG_TYPES);

	return 0;
}

int
roc_cpt_dev_configure(struct roc_cpt *roc_cpt, int nb_lf)
{
	struct cpt *cpt = roc_cpt_to_cpt_priv(roc_cpt);
	struct msix_offset_rsp *rsp;
	uint8_t eng_grpmsk;
	int rc, i;

	/* Request LF resources */
	rc = cpt_lfs_attach(&cpt->dev, nb_lf);
	if (rc)
		return rc;

	eng_grpmsk = (1 << roc_cpt->eng_grp[CPT_ENG_TYPE_AE]) |
		     (1 << roc_cpt->eng_grp[CPT_ENG_TYPE_SE]) |
		     (1 << roc_cpt->eng_grp[CPT_ENG_TYPE_IE]);

	rc = cpt_lfs_alloc(&cpt->dev, eng_grpmsk);
	if (rc)
		goto lfs_detach;

	rc = cpt_get_msix_offset(&cpt->dev, &rsp);
	if (rc)
		goto lfs_free;

	for (i = 0; i < nb_lf; i++)
		cpt->lf_msix_off[i] =
			(cpt->lf_blkaddr[i] == RVU_BLOCK_ADDR_CPT1) ?
				rsp->cpt1_lf_msixoff[i] :
				rsp->cptlf_msixoff[i];

	roc_cpt->nb_lf = nb_lf;

	return 0;

lfs_free:
	cpt_lfs_free(&cpt->dev);
lfs_detach:
	cpt_lfs_detach(&cpt->dev);
	return rc;
}

int
roc_cpt_dev_init(struct roc_cpt *roc_cpt)
{
	struct plt_pci_device *pci_dev;
	uint16_t nb_lf_avail;
	struct dev *dev;
	struct cpt *cpt;
	int rc;

	if (roc_cpt == NULL || roc_cpt->pci_dev == NULL)
		return -EINVAL;

	PLT_STATIC_ASSERT(sizeof(struct cpt) <= ROC_CPT_MEM_SZ);

	cpt = roc_cpt_to_cpt_priv(roc_cpt);
	memset(cpt, 0, sizeof(*cpt));
	pci_dev = roc_cpt->pci_dev;
	dev = &cpt->dev;

	/* Initialize device  */
	rc = dev_init(dev, pci_dev);
	if (rc) {
		plt_err("Failed to init roc device");
		goto fail;
	}

	cpt->pci_dev = pci_dev;
	roc_cpt->lmt_base = dev->lmt_base;

	rc = cpt_hardware_caps_get(dev, roc_cpt->hw_caps);
	if (rc) {
		plt_err("Could not determine hardware capabilities");
		goto fail;
	}

	rc = cpt_available_lfs_get(&cpt->dev, &nb_lf_avail);
	if (rc) {
		plt_err("Could not get available lfs");
		goto fail;
	}

	roc_cpt->nb_lf_avail = nb_lf_avail;

	dev->roc_cpt = roc_cpt;

	return 0;

fail:
	return rc;
}

int
roc_cpt_dev_fini(struct roc_cpt *roc_cpt)
{
	struct cpt *cpt = roc_cpt_to_cpt_priv(roc_cpt);

	if (cpt == NULL)
		return -EINVAL;

	roc_cpt->nb_lf_avail = 0;

	roc_cpt->lmt_base = 0;

	return dev_fini(&cpt->dev, cpt->pci_dev);
}

void
roc_cpt_dev_clear(struct roc_cpt *roc_cpt)
{
	struct cpt *cpt = roc_cpt_to_cpt_priv(roc_cpt);
	int i;

	if (cpt == NULL)
		return;

	for (i = 0; i < roc_cpt->nb_lf; i++)
		cpt->lf_msix_off[i] = 0;

	roc_cpt->nb_lf = 0;

	cpt_lfs_free(&cpt->dev);

	cpt_lfs_detach(&cpt->dev);
}

int
roc_cpt_eng_grp_add(struct roc_cpt *roc_cpt, enum cpt_eng_type eng_type)
{
	struct cpt *cpt = roc_cpt_to_cpt_priv(roc_cpt);
	struct dev *dev = &cpt->dev;
	struct cpt_eng_grp_req *req;
	struct cpt_eng_grp_rsp *rsp;
	int ret;

	req = mbox_alloc_msg_cpt_eng_grp_get(dev->mbox);
	if (req == NULL)
		return -EIO;

	switch (eng_type) {
	case CPT_ENG_TYPE_AE:
	case CPT_ENG_TYPE_SE:
	case CPT_ENG_TYPE_IE:
		break;
	default:
		return -EINVAL;
	}

	req->eng_type = eng_type;
	ret = mbox_process_msg(dev->mbox, (void *)&rsp);
	if (ret)
		return -EIO;

	if (rsp->eng_grp_num > 8) {
		plt_err("Invalid CPT engine group");
		return -ENOTSUP;
	}

	roc_cpt->eng_grp[eng_type] = rsp->eng_grp_num;

	return rsp->eng_grp_num;
}
