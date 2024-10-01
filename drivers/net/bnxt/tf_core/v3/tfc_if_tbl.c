/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2021 Broadcom
 * All rights reserved.
 */
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "rte_malloc.h"
#include "hsi_struct_def_dpdk.h"
#include "bnxt.h"
#include "bnxt_hwrm.h"
#include "tfc.h"
#include "tfc_msg.h"
#include "tfc_util.h"

int tfc_if_tbl_set(struct tfc *tfcp, uint16_t fid,
		   const struct tfc_if_tbl_info *tbl_info,
		   const uint8_t *data, uint8_t data_sz_in_bytes)
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

	if (tbl_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tbl_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tbl_info->dir >= CFA_DIR_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid cfa dir: %d\n", __func__, tbl_info->dir);
		return -EINVAL;
	}

	if (tbl_info->rsubtype >= CFA_RSUBTYPE_IF_TBL_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid if tbl subtype: %d\n", __func__,
			    tbl_info->rsubtype);
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

	rc = tfc_msg_if_tbl_set(tfcp, fid, sid, tbl_info->dir,
				tbl_info->rsubtype, tbl_info->id,
				data_sz_in_bytes, data);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: hwrm failed: %s:%s %d %s\n", __func__,
			    tfc_dir_2_str(tbl_info->dir),
			    tfc_if_tbl_2_str(tbl_info->rsubtype), tbl_info->id,
			    strerror(-rc));

	return rc;
}

int tfc_if_tbl_get(struct tfc *tfcp, uint16_t fid,
		   const struct tfc_if_tbl_info *tbl_info,
		   uint8_t *data, uint8_t *data_sz_in_bytes)
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

	if (tbl_info == NULL) {
		PMD_DRV_LOG(ERR, "%s: tbl_info is NULL\n", __func__);
		return -EINVAL;
	}

	if (tbl_info->dir >= CFA_DIR_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid cfa dir: %d\n", __func__, tbl_info->dir);
		return -EINVAL;
	}

	if (tbl_info->rsubtype >= CFA_RSUBTYPE_IF_TBL_MAX) {
		PMD_DRV_LOG(ERR, "%s: Invalid if tbl subtype: %d\n", __func__,
			    tbl_info->rsubtype);
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

	rc = tfc_msg_if_tbl_get(tfcp, fid, sid, tbl_info->dir,
				tbl_info->rsubtype, tbl_info->id,
				data_sz_in_bytes, data);
	if (rc)
		PMD_DRV_LOG(ERR, "%s: hwrm failed: %s:%s %d %s\n", __func__,
			    tfc_dir_2_str(tbl_info->dir),
			    tfc_if_tbl_2_str(tbl_info->rsubtype), tbl_info->id,
			    strerror(-rc));
	return rc;
}
