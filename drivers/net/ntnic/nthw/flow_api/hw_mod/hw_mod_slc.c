/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "flow_api_backend.h"

#define _MOD_ "SLC"
#define _VER_ be->slc.ver

bool hw_mod_slc_present(struct flow_api_backend_s *be)
{
	return be->iface->get_slc_present(be->be_dev);
}

int hw_mod_slc_alloc(struct flow_api_backend_s *be)
{
	_VER_ = be->iface->get_slc_version(be->be_dev);
	NT_LOG(DBG, FILTER, "SLC MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	switch (_VER_) {
	case 1:
		if (!callocate_mod(CAST_COMMON(&be->slc), 1,
			&be->slc.v1.rcp,
			be->max_categories,
			sizeof(struct slc_v1_rcp_s)))
			return -1;
		break;
	/* end case 1 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_slc_free(struct flow_api_backend_s *be)
{
	if (be->slc.base) {
		free(be->slc.base);
		be->slc.base = NULL;
	}
}

int hw_mod_slc_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->slc);

	NT_LOG(DBG, FILTER, "INIT SLC RCP\n");
	return hw_mod_slc_rcp_flush(be, 0, be->max_categories);
}

int hw_mod_slc_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->max_categories;
	if ((unsigned int)(start_idx + count) > be->max_categories)
		return error_index_too_large(__func__);
	return be->iface->slc_rcp_flush(be->be_dev, &be->slc, start_idx, count);
}

static int hw_mod_slc_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_slc_e field, uint32_t index,
			      uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->max_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
		switch (field) {
		case HW_SLC_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->slc.v1.rcp[index], (uint8_t)*value,
			       sizeof(struct hw_mod_slc_v1_s));
			break;
		case HW_SLC_RCP_FIND:
			rv = find_equal_index(be->slc.v1.rcp,
				sizeof(struct hw_mod_slc_v1_s), index, *value,
				be->max_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_SLC_RCP_COMPARE:
			rv = do_compare_indexes(be->slc.v1.rcp,
				sizeof(struct hw_mod_slc_v1_s), index, *value,
				be->max_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_SLC_RCP_SLC_EN:
			get_set(&be->slc.v1.rcp[index].tail_slc_en, value, get);
			break;
		case HW_SLC_RCP_DYN:
			get_set(&be->slc.v1.rcp[index].tail_dyn, value, get);
			break;
		case HW_SLC_RCP_OFS:
			get_set_signed(&be->slc.v1.rcp[index].tail_ofs, value, get);
			break;
		case HW_SLC_RCP_PCAP:
			get_set(&be->slc.v1.rcp[index].pcap, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 1 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_slc_rcp_set(struct flow_api_backend_s *be, enum hw_slc_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_slc_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_slc_rcp_get(struct flow_api_backend_s *be, enum hw_slc_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_slc_rcp_mod(be, field, index, value, 1);
}
