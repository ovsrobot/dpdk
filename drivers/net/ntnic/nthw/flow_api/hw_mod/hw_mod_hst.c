/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "flow_api_backend.h"

#define _MOD_ "HST"
#define _VER_ be->hst.ver

bool hw_mod_hst_present(struct flow_api_backend_s *be)
{
	return be->iface->get_hst_present(be->be_dev);
}

int hw_mod_hst_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_hst_version(be->be_dev);
	NT_LOG(DBG, FILTER, "HST MODULE VERSION %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_hst_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "hst_categories", _MOD_, _VER_);
	be->hst.nb_hst_rcp_categories = (uint32_t)nb;

	switch (_VER_) {
	case 2:
		if (!callocate_mod(CAST_COMMON(&be->hst), 1,
			&be->hst.v2.rcp,
			be->hst.nb_hst_rcp_categories,
			sizeof(struct hst_v2_rcp_s)))
			return -1;
		break;
	/* end case 2 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_hst_free(struct flow_api_backend_s *be)
{
	if (be->hst.base) {
		free(be->hst.base);
		be->hst.base = NULL;
	}
}

int hw_mod_hst_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->hst);

	NT_LOG(DBG, FILTER, "INIT HST RCP\n");
	return hw_mod_hst_rcp_flush(be, 0, ALL_ENTRIES);
}

int hw_mod_hst_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->hst.nb_hst_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->hst.nb_hst_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->hst_rcp_flush(be->be_dev, &be->hst, start_idx, count);
}

static int hw_mod_hst_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_hst_e field, uint32_t index,
			      uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->hst.nb_hst_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 2:
		switch (field) {
		case HW_HST_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->hst.v2.rcp[index], (uint8_t)*value,
			       sizeof(struct hst_v2_rcp_s));
			break;
		case HW_HST_RCP_FIND:
			find_equal_index(be->hst.v2.rcp,
				sizeof(struct hst_v2_rcp_s), index, *value,
				be->hst.nb_hst_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_HST_RCP_COMPARE:
			rv = do_compare_indexes(be->hst.v2.rcp,
				sizeof(struct hst_v2_rcp_s), index, *value,
				be->hst.nb_hst_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_HST_RCP_STRIP_MODE:
			get_set(&be->hst.v2.rcp[index].strip_mode, value, get);
			break;
		case HW_HST_RCP_START_DYN:
			get_set(&be->hst.v2.rcp[index].start_dyn, value, get);
			break;
		case HW_HST_RCP_START_OFS:
			get_set(&be->hst.v2.rcp[index].start_ofs, value, get);
			break;
		case HW_HST_RCP_END_DYN:
			get_set(&be->hst.v2.rcp[index].end_dyn, value, get);
			break;
		case HW_HST_RCP_END_OFS:
			get_set(&be->hst.v2.rcp[index].end_ofs, value, get);
			break;
		case HW_HST_RCP_MODIF0_CMD:
			get_set(&be->hst.v2.rcp[index].modif0_cmd, value, get);
			break;
		case HW_HST_RCP_MODIF0_DYN:
			get_set(&be->hst.v2.rcp[index].modif0_dyn, value, get);
			break;
		case HW_HST_RCP_MODIF0_OFS:
			get_set(&be->hst.v2.rcp[index].modif0_ofs, value, get);
			break;
		case HW_HST_RCP_MODIF0_VALUE:
			get_set(&be->hst.v2.rcp[index].modif0_value, value, get);
			break;
		case HW_HST_RCP_MODIF1_CMD:
			get_set(&be->hst.v2.rcp[index].modif1_cmd, value, get);
			break;
		case HW_HST_RCP_MODIF1_DYN:
			get_set(&be->hst.v2.rcp[index].modif1_dyn, value, get);
			break;
		case HW_HST_RCP_MODIF1_OFS:
			get_set(&be->hst.v2.rcp[index].modif1_ofs, value, get);
			break;
		case HW_HST_RCP_MODIF1_VALUE:
			get_set(&be->hst.v2.rcp[index].modif1_value, value, get);
			break;
		case HW_HST_RCP_MODIF2_CMD:
			get_set(&be->hst.v2.rcp[index].modif2_cmd, value, get);
			break;
		case HW_HST_RCP_MODIF2_DYN:
			get_set(&be->hst.v2.rcp[index].modif2_dyn, value, get);
			break;
		case HW_HST_RCP_MODIF2_OFS:
			get_set(&be->hst.v2.rcp[index].modif2_ofs, value, get);
			break;
		case HW_HST_RCP_MODIF2_VALUE:
			get_set(&be->hst.v2.rcp[index].modif2_value, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 2 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_hst_rcp_set(struct flow_api_backend_s *be, enum hw_hst_e field,
		       int index, uint32_t value)
{
	return hw_mod_hst_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_hst_rcp_get(struct flow_api_backend_s *be, enum hw_hst_e field,
		       int index, uint32_t *value)
{
	return hw_mod_hst_rcp_mod(be, field, index, value, 1);
}
