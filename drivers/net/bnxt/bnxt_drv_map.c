/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2026 Broadcom
 * All rights reserved.
 */

/**
 * Driver Mapping Layer Dispatcher
 * ================================
 *
 * This file implements the dispatcher that selects between native and
 * bifurcated driver implementations based on the configured mode. Only
 * the native backend is wired up so far.
 */

#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include "bnxt.h"
#include "bnxt_drv_map.h"

/*
 * Macro to validate driver mapping context and operations.
 * "op" is used as a struct member name after "->", not as an
 * expression, so it must stay unparenthesized here.
 */
#define BNXT_DRV_MAP_INVALID(bp, op) \
	(!(bp) || !(bp)->drv_map_ctx || !(bp)->drv_map_ctx->ops || \
	 !(bp)->drv_map_ctx->ops->op)

/**
 * Initialize driver mapping layer
 */
int bnxt_drv_map_init(struct bnxt *bp, enum bnxt_drv_mode mode)
{
	if (!bp)
		return -EINVAL;

	/* Allocate drv_map context if not already allocated */
	if (!bp->drv_map_ctx) {
		bp->drv_map_ctx = rte_zmalloc("bnxt_drv_map_ctx",
					      sizeof(struct bnxt_drv_map_ctx),
					      RTE_CACHE_LINE_SIZE);
		if (!bp->drv_map_ctx) {
			PMD_DRV_LOG_LINE(ERR, "Failed to allocate drv_map context");
			return -ENOMEM;
		}
	}

	/* Set the mode and operations table */
	bp->drv_map_ctx->mode = mode;

	switch (mode) {
	case BNXT_DRV_MODE_NATIVE:
		bp->drv_map_ctx->ops = &bnxt_drv_native_ops;
		PMD_DRV_LOG_LINE(INFO, "Initialized native driver mode");
		break;

	default:
		PMD_DRV_LOG_LINE(ERR, "Invalid driver mode: %d", mode);
		rte_free(bp->drv_map_ctx);
		bp->drv_map_ctx = NULL;
		return -EINVAL;
	}

	bp->drv_map_ctx->priv_data = NULL;

	return 0;
}

/**
 * Cleanup driver mapping layer
 */
void bnxt_drv_map_cleanup(struct bnxt *bp)
{
	if (!bp)
		return;

	if (bp->drv_map_ctx) {
		rte_free(bp->drv_map_ctx);
		bp->drv_map_ctx = NULL;
	}
}

/**
 * Driver Map API Implementations - HWRM Operations
 */
int bnxt_drv_hwrm_send_msg(struct bnxt *bp, void *msg,
			   uint32_t msg_len, bool use_kong_mb)
{
	if (BNXT_DRV_MAP_INVALID(bp, hwrm_send_msg))
		return -EINVAL;

	return bp->drv_map_ctx->ops->hwrm_send_msg(bp, msg, msg_len, use_kong_mb);
}

/**
 * Driver Map API Implementations - FW Status Register Mapping
 */
int bnxt_drv_map_fw_status_reg(struct bnxt *bp)
{
	if (BNXT_DRV_MAP_INVALID(bp, map_fw_status_reg))
		return -EINVAL;

	return bp->drv_map_ctx->ops->map_fw_status_reg(bp);
}

/**
 * Driver Map API Implementations - Doorbell Setup
 */
void bnxt_drv_set_db(struct bnxt *bp,
		     struct bnxt_db_info *db,
		     uint32_t ring_type,
		     uint32_t map_idx,
		     uint32_t fid,
		     uint32_t ring_mask,
		     uint16_t dpi)
{
	if (BNXT_DRV_MAP_INVALID(bp, set_db))
		return;

	bp->drv_map_ctx->ops->set_db(bp, db, ring_type, map_idx, fid, ring_mask, dpi);
}

/**
 * Driver Map API Implementations - Doorbell Write Operations
 */
void bnxt_drv_db_write(struct bnxt *bp, struct bnxt_db_info *db, uint32_t idx)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_write))
		return;

	bp->drv_map_ctx->ops->db_write(db, idx);
}

void bnxt_drv_db_epoch_write(struct bnxt *bp, struct bnxt_db_info *db,
			     uint32_t idx, uint32_t epoch)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_epoch_write))
		return;

	bp->drv_map_ctx->ops->db_epoch_write(db, idx, epoch);
}

void bnxt_drv_db_mpc_write(struct bnxt *bp, struct bnxt_db_info *db,
			   uint32_t idx, uint32_t epoch)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_mpc_write))
		return;

	bp->drv_map_ctx->ops->db_mpc_write(db, idx, epoch);
}

void bnxt_drv_db_nq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_nq))
		return;

	bp->drv_map_ctx->ops->db_nq(cpr);
}

void bnxt_drv_db_nq_arm(struct bnxt *bp, struct bnxt_cp_ring_info *cpr)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_nq_arm))
		return;

	bp->drv_map_ctx->ops->db_nq_arm(cpr);
}

void bnxt_drv_db_cq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_cq))
		return;

	bp->drv_map_ctx->ops->db_cq(cpr);
}

void bnxt_drv_db_mpc_cq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr)
{
	if (BNXT_DRV_MAP_INVALID(bp, db_mpc_cq))
		return;

	bp->drv_map_ctx->ops->db_mpc_cq(cpr);
}
