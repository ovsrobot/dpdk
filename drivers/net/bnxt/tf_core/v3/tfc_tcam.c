/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2021 Broadcom
 * All rights reserved.
 */
#include <stdio.h>
#include "tfc.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "tfc.h"
#include "tfc_msg.h"
#include "tfc_util.h"

int tfc_tcam_alloc(struct tfc *tfcp, uint16_t fid, enum cfa_track_type tt,
		   uint16_t priority, uint8_t key_sz_in_bytes,
		   struct tfc_tcam_info *tcam_info)
{
	int rc = 0;
	struct bnxt *bp;
	uint16_t sid;

	if (tfcp == NULL) {
		PMD_DRV_LOG(ERR, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}

	if (tfcp->bp == NULL || tfcp->tfo == NULL) {
		PMD_DRV_LOG(ERR, "%s: tfcp not initialized\n", __func__);
		return -EINVAL;
	}
	bp = tfcp->bp;

	if (tcam_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_info->rsubtype >= CFA_RSUBTYPE_TCAM_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid tcam subtype: %d\n", __func__,
			    tcam_info->rsubtype);
		return -EINVAL;
	}

	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		PMD_DRV_LOG(ERR, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		PMD_DRV_LOG(ERR, "%s: Failed to retrieve SID, rc:%s\n",
			    __func__, strerror(-rc));
		return rc;
	}

	rc = tfc_msg_tcam_alloc(tfcp, fid, sid, tcam_info->dir,
				tcam_info->rsubtype, tt, priority,
				key_sz_in_bytes, &tcam_info->id);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: alloc failed %s:%s %s\n", __func__,
			    tfc_dir_2_str(tcam_info->dir),
			    tfc_tcam_2_str(tcam_info->rsubtype), strerror(-rc));

	return rc;
}

int tfc_tcam_alloc_set(struct tfc *tfcp, uint16_t fid, enum cfa_track_type tt,
		       uint16_t priority, struct tfc_tcam_info *tcam_info,
		       const struct tfc_tcam_data *tcam_data)
{
	int rc = 0;
	struct bnxt *bp;
	uint16_t sid;

	if (tfcp == NULL) {
		PMD_DRV_LOG(ERR, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}

	if (tfcp->bp == NULL || tfcp->tfo == NULL) {
		PMD_DRV_LOG(ERR, "%s: tfcp not initialized\n", __func__);
		return -EINVAL;
	}
	bp = tfcp->bp;

	if (tcam_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_data == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_data is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_info->rsubtype >= CFA_RSUBTYPE_TCAM_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid tcam subtype: %d\n", __func__,
			    tcam_info->rsubtype);
		return -EINVAL;
	}

	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		PMD_DRV_LOG(ERR, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		PMD_DRV_LOG(ERR, "%s: Failed to retrieve SID, rc:%s\n",
			    __func__, strerror(-rc));
		return rc;
	}

	rc = tfc_msg_tcam_alloc_set(tfcp, fid, sid, tcam_info->dir,
				    tcam_info->rsubtype, tt, &tcam_info->id,
				    priority, tcam_data->key,
				    tcam_data->key_sz_in_bytes,
				    tcam_data->mask,
				    tcam_data->remap,
				    tcam_data->remap_sz_in_bytes);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: alloc_set failed: %s:%s %s\n", __func__,
			    tfc_dir_2_str(tcam_info->dir),
			    tfc_tcam_2_str(tcam_info->rsubtype), strerror(-rc));

	return rc;
}

int tfc_tcam_set(struct tfc *tfcp, uint16_t fid,
		 const struct tfc_tcam_info *tcam_info,
		 const struct tfc_tcam_data *tcam_data)
{
	int rc = 0;
	struct bnxt *bp;
	uint16_t sid;

	if (tfcp == NULL) {
		PMD_DRV_LOG(ERR, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}

	if (tfcp->bp == NULL || tfcp->tfo == NULL) {
		PMD_DRV_LOG(ERR, "%s: tfcp not initialized\n", __func__);
		return -EINVAL;
	}
	bp = tfcp->bp;

	if (tcam_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_data == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_data is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_info->rsubtype >= CFA_RSUBTYPE_TCAM_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid tcam subtype: %d\n", __func__,
			    tcam_info->rsubtype);
		return -EINVAL;
	}

	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		PMD_DRV_LOG(ERR, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		PMD_DRV_LOG(ERR, "%s: Failed to retrieve SID, rc:%s\n",
			    __func__, strerror(-rc));
		return rc;
	}

	rc = tfc_msg_tcam_set(tfcp, fid, sid, tcam_info->dir,
			      tcam_info->rsubtype, tcam_info->id,
			      tcam_data->key,
			      tcam_data->key_sz_in_bytes,
			      tcam_data->mask, tcam_data->remap,
			      tcam_data->remap_sz_in_bytes);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: set failed: %s:%s %d %s\n", __func__,
			    tfc_dir_2_str(tcam_info->dir),
			    tfc_tcam_2_str(tcam_info->rsubtype), tcam_info->id,
			    strerror(-rc));

	return rc;
}

int tfc_tcam_get(struct tfc *tfcp, uint16_t fid,
		 const struct tfc_tcam_info *tcam_info,
		 struct tfc_tcam_data *tcam_data)
{
	int rc = 0;
	struct bnxt *bp;
	uint16_t sid;

	if (tfcp == NULL) {
		PMD_DRV_LOG(ERR, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}

	if (tfcp->bp == NULL || tfcp->tfo == NULL) {
		PMD_DRV_LOG(ERR, "%s: tfcp not initialized\n", __func__);
		return -EINVAL;
	}
	bp = tfcp->bp;

	if (tcam_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_data == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_data is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_info->rsubtype >= CFA_RSUBTYPE_TCAM_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid tcam subtype: %d\n", __func__,
			    tcam_info->rsubtype);
		return -EINVAL;
	}

	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		PMD_DRV_LOG(ERR, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		PMD_DRV_LOG(ERR, "%s: Failed to retrieve SID, rc:%s\n",
			    __func__, strerror(-rc));
		return rc;
	}

	rc = tfc_msg_tcam_get(tfcp, fid, sid, tcam_info->dir,
			      tcam_info->rsubtype, tcam_info->id,
			      tcam_data->key, &tcam_data->key_sz_in_bytes,
			      tcam_data->mask, tcam_data->remap,
			      &tcam_data->remap_sz_in_bytes);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: get failed: %s:%s %d %s\n", __func__,
			    tfc_dir_2_str(tcam_info->dir),
			    tfc_tcam_2_str(tcam_info->rsubtype), tcam_info->id,
			    strerror(-rc));

	return rc;
}

int tfc_tcam_free(struct tfc *tfcp, uint16_t fid, const struct tfc_tcam_info *tcam_info)
{
	int rc = 0;
	struct bnxt *bp;
	uint16_t sid;

	if (tfcp == NULL) {
		PMD_DRV_LOG(ERR, "%s: Invalid tfcp pointer\n", __func__);
		return -EINVAL;
	}

	if (tfcp->bp == NULL || tfcp->tfo == NULL) {
		PMD_DRV_LOG(ERR, "%s: tfcp not initialized\n", __func__);
		return -EINVAL;
	}

	if (tcam_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tcam_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tcam_info->rsubtype >= CFA_RSUBTYPE_TCAM_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid tcam subtype: %d\n", __func__,
			    tcam_info->rsubtype);
		return -EINVAL;
	}

	bp = tfcp->bp;
	if (!BNXT_PF(bp) && !BNXT_VF_IS_TRUSTED(bp)) {
		PMD_DRV_LOG(ERR, "%s: bp not PF or trusted VF\n", __func__);
		return -EINVAL;
	}

	rc = tfo_sid_get(tfcp->tfo, &sid);
	if (rc) {
		PMD_DRV_LOG(ERR, "%s: Failed to retrieve SID, rc:%s\n",
			    __func__, strerror(-rc));
		return rc;
	}

	rc = tfc_msg_tcam_free(tfcp, fid, sid, tcam_info->dir,
			       tcam_info->rsubtype, tcam_info->id);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: free failed: %s:%s:%d %s\n", __func__,
			    tfc_dir_2_str(tcam_info->dir),
			    tfc_tcam_2_str(tcam_info->rsubtype), tcam_info->id,
			    strerror(-rc));
	return rc;
}
