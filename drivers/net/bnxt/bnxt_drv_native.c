/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2026 Broadcom
 * All rights reserved.
 */

/**
 * Native Driver Implementation
 * =============================
 *
 * This file contains wrapper functions that call the native implementations
 * of HWRM and doorbell operations. The actual implementations remain in
 * their original files (bnxt_hwrm.c, bnxt_ring.c, bnxt_ring.h).
 */

#include <rte_common.h>

#include "bnxt.h"
#include "bnxt_drv_map.h"
#include "bnxt_hwrm.h"
#include "bnxt_ring.h"
#include "bnxt_cpr.h"

/**
 * Wrapper Functions
 * These simply call the native implementations in their original locations
 */

static int bnxt_drv_native_hwrm_send_msg(struct bnxt *bp, void *msg,
					 uint32_t msg_len, bool use_kong_mb)
{
	return bnxt_native_hwrm_send_message(bp, msg, msg_len, use_kong_mb);
}

static int bnxt_drv_native_map_fw_status_reg(struct bnxt *bp)
{
	return bnxt_native_map_fw_status_reg(bp);
}

static void bnxt_drv_native_set_db(struct bnxt *bp,
				   struct bnxt_db_info *db,
				   uint32_t ring_type,
				   uint32_t map_idx,
				   uint32_t fid,
				   uint32_t ring_mask,
				   uint16_t dpi)
{
	bnxt_native_set_db(bp, db, ring_type, map_idx, fid, ring_mask, dpi);
}

static void bnxt_drv_native_db_write(struct bnxt_db_info *db, uint32_t idx)
{
	bnxt_native_db_write(db, idx);
}

static void bnxt_drv_native_db_epoch_write(struct bnxt_db_info *db,
					   uint32_t idx, uint32_t epoch)
{
	bnxt_native_db_epoch_write(db, idx, epoch);
}

static void bnxt_drv_native_db_mpc_write(struct bnxt_db_info *db,
					 uint32_t idx, uint32_t epoch)
{
	bnxt_native_db_mpc_write(db, idx, epoch);
}

static void bnxt_drv_native_db_nq(struct bnxt_cp_ring_info *cpr)
{
	bnxt_native_db_nq(cpr);
}

static void bnxt_drv_native_db_nq_arm(struct bnxt_cp_ring_info *cpr)
{
	bnxt_native_db_nq_arm(cpr);
}

static void bnxt_drv_native_db_cq(struct bnxt_cp_ring_info *cpr)
{
	bnxt_native_db_cq(cpr);
}

static void bnxt_drv_native_db_mpc_cq(struct bnxt_cp_ring_info *cpr)
{
	bnxt_native_db_mpc_cq(cpr);
}

/**
 * Native Driver API Operations Table
 */
const struct bnxt_drv_api_ops bnxt_drv_native_ops = {
	.hwrm_send_msg = bnxt_drv_native_hwrm_send_msg,
	.map_fw_status_reg = bnxt_drv_native_map_fw_status_reg,
	.set_db = bnxt_drv_native_set_db,
	.db_write = bnxt_drv_native_db_write,
	.db_epoch_write = bnxt_drv_native_db_epoch_write,
	.db_mpc_write = bnxt_drv_native_db_mpc_write,
	.db_nq = bnxt_drv_native_db_nq,
	.db_nq_arm = bnxt_drv_native_db_nq_arm,
	.db_cq = bnxt_drv_native_db_cq,
	.db_mpc_cq = bnxt_drv_native_db_mpc_cq,
};
