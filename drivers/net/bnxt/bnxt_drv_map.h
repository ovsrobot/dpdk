/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2014-2026 Broadcom
 * All rights reserved.
 */

#ifndef _BNXT_DRV_MAP_H_
#define _BNXT_DRV_MAP_H_

#include <inttypes.h>
#include <stdbool.h>

struct bnxt;
struct bnxt_db_info;
struct bnxt_cp_ring_info;

/**
 * BNXT Driver Mapping Layer
 * ==========================
 *
 * This layer abstracts HWRM and doorbell operations to support multiple
 * backend implementations (native vs bifurcated driver). Only the native
 * backend is implemented so far; the bifurcated backend is added in a
 * follow-up patch.
 */

/* Driver mode enumeration */
enum bnxt_drv_mode {
	BNXT_DRV_MODE_NATIVE = 0,      /* Native DPDK with direct MMIO */
};

/**
 * HWRM API Function Pointers
 */
typedef int (*bnxt_drv_hwrm_send_msg_t)(struct bnxt *bp, void *msg,
					uint32_t msg_len, bool use_kong_mb);

/**
 * FW Status Register Mapping API Function Pointer
 */
typedef int (*bnxt_drv_map_fw_status_reg_t)(struct bnxt *bp);

/**
 * Doorbell Setup API Function Pointers
 */
typedef void (*bnxt_drv_set_db_t)(struct bnxt *bp,
				  struct bnxt_db_info *db,
				  uint32_t ring_type,
				  uint32_t map_idx,
				  uint32_t fid,
				  uint32_t ring_mask,
				  uint16_t dpi);

/**
 * Doorbell Write API Function Pointers
 */
typedef void (*bnxt_drv_db_write_t)(struct bnxt_db_info *db, uint32_t idx);

typedef void (*bnxt_drv_db_epoch_write_t)(struct bnxt_db_info *db,
					  uint32_t idx,
					  uint32_t epoch);

typedef void (*bnxt_drv_db_mpc_write_t)(struct bnxt_db_info *db,
					uint32_t idx,
					uint32_t epoch);

typedef void (*bnxt_drv_db_nq_t)(struct bnxt_cp_ring_info *cpr);

typedef void (*bnxt_drv_db_nq_arm_t)(struct bnxt_cp_ring_info *cpr);

typedef void (*bnxt_drv_db_cq_t)(struct bnxt_cp_ring_info *cpr);

typedef void (*bnxt_drv_db_mpc_cq_t)(struct bnxt_cp_ring_info *cpr);

/**
 * Driver API Operations Table
 */
struct bnxt_drv_api_ops {
	/* HWRM operations */
	bnxt_drv_hwrm_send_msg_t	hwrm_send_msg;

	/* FW status register mapping */
	bnxt_drv_map_fw_status_reg_t	map_fw_status_reg;

	/* Doorbell setup operations */
	bnxt_drv_set_db_t		set_db;

	/* Doorbell write operations */
	bnxt_drv_db_write_t		db_write;
	bnxt_drv_db_epoch_write_t	db_epoch_write;
	bnxt_drv_db_mpc_write_t		db_mpc_write;
	bnxt_drv_db_nq_t		db_nq;
	bnxt_drv_db_nq_arm_t		db_nq_arm;
	bnxt_drv_db_cq_t		db_cq;
	bnxt_drv_db_mpc_cq_t		db_mpc_cq;
};

/**
 * Driver Mapping Context
 */
struct bnxt_drv_map_ctx {
	enum bnxt_drv_mode mode;
	const struct bnxt_drv_api_ops *ops;
	void *priv_data;  /* Mode-specific private data */
};

/**
 * Driver Map Initialization and Cleanup
 */
int bnxt_drv_map_init(struct bnxt *bp, enum bnxt_drv_mode mode);
void bnxt_drv_map_cleanup(struct bnxt *bp);

/**
 * Driver Map API - HWRM Operations
 */
int bnxt_drv_hwrm_send_msg(struct bnxt *bp, void *msg,
			   uint32_t msg_len, bool use_kong_mb);

/**
 * Driver Map API - FW Status Register Mapping
 */
int bnxt_drv_map_fw_status_reg(struct bnxt *bp);

/**
 * Driver Map API - Doorbell Setup
 */
void bnxt_drv_set_db(struct bnxt *bp,
		     struct bnxt_db_info *db,
		     uint32_t ring_type,
		     uint32_t map_idx,
		     uint32_t fid,
		     uint32_t ring_mask,
		     uint16_t dpi);

/**
 * Driver Map API - Doorbell Write Operations
 */
void bnxt_drv_db_write(struct bnxt *bp, struct bnxt_db_info *db, uint32_t idx);

void bnxt_drv_db_epoch_write(struct bnxt *bp, struct bnxt_db_info *db,
			     uint32_t idx, uint32_t epoch);

void bnxt_drv_db_mpc_write(struct bnxt *bp, struct bnxt_db_info *db,
			   uint32_t idx, uint32_t epoch);

void bnxt_drv_db_nq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr);

void bnxt_drv_db_nq_arm(struct bnxt *bp, struct bnxt_cp_ring_info *cpr);

void bnxt_drv_db_cq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr);

void bnxt_drv_db_mpc_cq(struct bnxt *bp, struct bnxt_cp_ring_info *cpr);

/**
 * Native Driver API Operations (exported for direct use if needed)
 */
extern const struct bnxt_drv_api_ops bnxt_drv_native_ops;

#endif /* _BNXT_DRV_MAP_H_ */
