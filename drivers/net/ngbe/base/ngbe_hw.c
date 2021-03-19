/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2020
 */

#include "ngbe_hw.h"

void ngbe_map_device_id(struct ngbe_hw *hw)
{
	u16 oem = hw->sub_system_id & NGBE_OEM_MASK;
	u16 internal = hw->sub_system_id & NGBE_INTERNAL_MASK;
	hw->is_pf = true;

	/* move subsystem_device_id to device_id */
	switch (hw->device_id) {
	case NGBE_DEV_ID_EM_WX1860AL_W_VF:
	case NGBE_DEV_ID_EM_WX1860A2_VF:
	case NGBE_DEV_ID_EM_WX1860A2S_VF:
	case NGBE_DEV_ID_EM_WX1860A4_VF:
	case NGBE_DEV_ID_EM_WX1860A4S_VF:
	case NGBE_DEV_ID_EM_WX1860AL2_VF:
	case NGBE_DEV_ID_EM_WX1860AL2S_VF:
	case NGBE_DEV_ID_EM_WX1860AL4_VF:
	case NGBE_DEV_ID_EM_WX1860AL4S_VF:
	case NGBE_DEV_ID_EM_WX1860NCSI_VF:
	case NGBE_DEV_ID_EM_WX1860A1_VF:
	case NGBE_DEV_ID_EM_WX1860A1L_VF:
		hw->device_id = NGBE_DEV_ID_EM_VF;
		hw->sub_device_id = NGBE_SUB_DEV_ID_EM_VF;
		hw->is_pf = false;
		break;
	case NGBE_DEV_ID_EM_WX1860AL_W:
	case NGBE_DEV_ID_EM_WX1860A2:
	case NGBE_DEV_ID_EM_WX1860A2S:
	case NGBE_DEV_ID_EM_WX1860A4:
	case NGBE_DEV_ID_EM_WX1860A4S:
	case NGBE_DEV_ID_EM_WX1860AL2:
	case NGBE_DEV_ID_EM_WX1860AL2S:
	case NGBE_DEV_ID_EM_WX1860AL4:
	case NGBE_DEV_ID_EM_WX1860AL4S:
	case NGBE_DEV_ID_EM_WX1860NCSI:
	case NGBE_DEV_ID_EM_WX1860A1:
	case NGBE_DEV_ID_EM_WX1860A1L:
		hw->device_id = NGBE_DEV_ID_EM;
		if (oem == NGBE_LY_M88E1512_SFP ||
				internal == NGBE_INTERNAL_SFP)
			hw->sub_device_id = NGBE_SUB_DEV_ID_EM_MVL_SFP;
		else if (hw->sub_system_id == NGBE_SUB_DEV_ID_EM_M88E1512_RJ45)
			hw->sub_device_id = NGBE_SUB_DEV_ID_EM_MVL_RGMII;
		else if (oem == NGBE_YT8521S_SFP ||
				oem == NGBE_LY_YT8521S_SFP)
			hw->sub_device_id = NGBE_SUB_DEV_ID_EM_YT8521S_SFP;
		else
			hw->sub_device_id = NGBE_SUB_DEV_ID_EM_RTL_SGMII;
		break;
	default:
		break;
	}
}

