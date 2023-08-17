/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "flow_api_backend.h"

#define _MOD_ "RMC"
#define _VER_ be->rmc.ver

bool hw_mod_rmc_present(struct flow_api_backend_s *be)
{
	return be->iface->get_rmc_present(be->be_dev);
}

int hw_mod_rmc_alloc(struct flow_api_backend_s *be)
{
	_VER_ = be->iface->get_rmc_version(be->be_dev);
	NT_LOG(DBG, FILTER, "RMC MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	switch (_VER_) {
	case 0x10003:
		if (!callocate_mod(CAST_COMMON(&be->rmc), 1,
			&be->rmc.v1_3.ctrl, 1, sizeof(struct rmc_v1_3_ctrl_s)))
			return -1;
		break;
	/* end case 1_3 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_rmc_free(struct flow_api_backend_s *be)
{
	if (be->rmc.base) {
		free(be->rmc.base);
		be->rmc.base = NULL;
	}
}

int hw_mod_rmc_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->rmc);

	NT_LOG(DBG, FILTER, "INIT RMC CTRL\n");
	/* disable block stat, block keep alive */
	hw_mod_rmc_ctrl_set(be, HW_RMC_BLOCK_STATT, 1);
	hw_mod_rmc_ctrl_set(be, HW_RMC_BLOCK_KEEPA, 1);
	hw_mod_rmc_ctrl_set(be, HW_RMC_BLOCK_MAC_PORT,
			    0xff); /* initially block all ports */
	hw_mod_rmc_ctrl_set(be, HW_RMC_BLOCK_STATT, 1);
	hw_mod_rmc_ctrl_set(be, HW_RMC_BLOCK_RPP_SLICE, 0xf);
	return hw_mod_rmc_ctrl_flush(be);
}

int hw_mod_rmc_ctrl_flush(struct flow_api_backend_s *be)
{
	return be->iface->rmc_ctrl_flush(be->be_dev, &be->rmc);
}

static int hw_mod_rmc_ctrl_mod(struct flow_api_backend_s *be,
			       enum hw_rmc_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 0x10003:
		switch (field) {
		case HW_RMC_BLOCK_STATT:
			get_set(&be->rmc.v1_3.ctrl->block_statt, value, get);
			break;
		case HW_RMC_BLOCK_KEEPA:
			get_set(&be->rmc.v1_3.ctrl->block_keepa, value, get);
			break;
		case HW_RMC_BLOCK_RPP_SLICE:
			get_set(&be->rmc.v1_3.ctrl->block_rpp_slice, value, get);
			break;
		case HW_RMC_BLOCK_MAC_PORT:
			get_set(&be->rmc.v1_3.ctrl->block_mac_port, value, get);
			break;
		case HW_RMC_LAG_PHY_ODD_EVEN:
			get_set(&be->rmc.v1_3.ctrl->lag_phy_odd_even, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 1.3 */

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_rmc_ctrl_set(struct flow_api_backend_s *be, enum hw_rmc_e field,
			uint32_t value)
{
	return hw_mod_rmc_ctrl_mod(be, field, &value, 0);
}

int hw_mod_rmc_ctrl_get(struct flow_api_backend_s *be, enum hw_rmc_e field,
			uint32_t *value)
{
	return hw_mod_rmc_ctrl_mod(be, field, value, 1);
}
