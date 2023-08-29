/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "IOA"
#define _VER_ be->ioa.ver

bool hw_mod_ioa_present(struct flow_api_backend_s *be)
{
	return be->iface->get_ioa_present(be->be_dev);
}

int hw_mod_ioa_alloc(struct flow_api_backend_s *be)
{
	_VER_ = be->iface->get_ioa_version(be->be_dev);
	NT_LOG(DBG, FILTER, "IOA MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	int nb = be->iface->get_nb_ioa_categories(be->be_dev);

	if (nb <= 0)
		return error_resource_count(__func__, "ioa_categories", _MOD_, _VER_);
	be->ioa.nb_rcp_categories = (uint32_t)nb;

	/* NOTE: ROA number of categories are called here. FPGA uses a cross-indexing here - bad! */
	nb = be->iface->get_nb_roa_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "roa_epp_entries", _MOD_, _VER_);
	be->ioa.nb_roa_epp_entries = (uint32_t)nb;

	switch (_VER_) {
	case 4:
		if (!callocate_mod(CAST_COMMON(&be->ioa), 3,
			&be->ioa.v4.rcp, be->ioa.nb_rcp_categories,
			sizeof(struct ioa_v4_rcp_s),
			&be->ioa.v4.tpid, 1,
			sizeof(struct ioa_v4_special_tpid_s),
			&be->ioa.v4.roa_epp, be->ioa.nb_roa_epp_entries,
			sizeof(struct ioa_v4_roa_epp_s)))
			return -1;
		break;
	/* end case 4 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

void hw_mod_ioa_free(struct flow_api_backend_s *be)
{
	if (be->ioa.base) {
		free(be->ioa.base);
		be->ioa.base = NULL;
	}
}

int hw_mod_ioa_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->ioa);

	NT_LOG(DBG, FILTER, "INIT IOA RCP\n");
	hw_mod_ioa_rcp_flush(be, 0, ALL_ENTRIES);
	NT_LOG(DBG, FILTER, "INIT IOA SPECIAL TPID\n");
	hw_mod_ioa_config_set(be, HW_IOA_CONFIG_CUST_TPID_0, 0x8200);
	hw_mod_ioa_config_set(be, HW_IOA_CONFIG_CUST_TPID_1, 0x8300);
	hw_mod_ioa_config_flush(be);
	NT_LOG(DBG, FILTER, "INIT IOA ROA EPP\n");
	hw_mod_ioa_roa_epp_flush(be, 0, ALL_ENTRIES);
	return 0;
}

int hw_mod_ioa_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->ioa.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->ioa.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->ioa_rcp_flush(be->be_dev, &be->ioa, start_idx, count);
}

static int hw_mod_ioa_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_ioa_e field, uint32_t index,
			      uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->ioa.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 4:
		switch (field) {
		case HW_IOA_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->ioa.v4.rcp[index], (uint8_t)*value,
			       sizeof(struct ioa_v4_rcp_s));
			break;
		case HW_IOA_RCP_FIND:
			rv = find_equal_index(be->ioa.v4.rcp,
				sizeof(struct ioa_v4_rcp_s), index, *value,
				be->ioa.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_IOA_RCP_COMPARE:
			rv = do_compare_indexes(be->ioa.v4.rcp,
				sizeof(struct ioa_v4_rcp_s), index, *value,
				be->ioa.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_IOA_RCP_TUNNEL_POP:
			get_set(&be->ioa.v4.rcp[index].tunnel_pop, value, get);
			break;
		case HW_IOA_RCP_VLAN_POP:
			get_set(&be->ioa.v4.rcp[index].vlan_pop, value, get);
			break;
		case HW_IOA_RCP_VLAN_PUSH:
			get_set(&be->ioa.v4.rcp[index].vlan_push, value, get);
			break;
		case HW_IOA_RCP_VLAN_VID:
			get_set(&be->ioa.v4.rcp[index].vlan_vid, value, get);
			break;
		case HW_IOA_RCP_VLAN_DEI:
			get_set(&be->ioa.v4.rcp[index].vlan_dei, value, get);
			break;
		case HW_IOA_RCP_VLAN_PCP:
			get_set(&be->ioa.v4.rcp[index].vlan_pcp, value, get);
			break;
		case HW_IOA_RCP_VLAN_TPID_SEL:
			get_set(&be->ioa.v4.rcp[index].vlan_tpid_sel, value, get);
			break;
		case HW_IOA_RCP_QUEUE_OVERRIDE_EN:
			get_set(&be->ioa.v4.rcp[index].queue_override_en, value, get);
			break;
		case HW_IOA_RCP_QUEUE_ID:
			get_set(&be->ioa.v4.rcp[index].queue_id, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 4 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_ioa_rcp_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_ioa_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_ioa_rcp_get(struct flow_api_backend_s *be, enum hw_ioa_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_ioa_rcp_mod(be, field, index, value, 1);
}

int hw_mod_ioa_config_flush(struct flow_api_backend_s *be)
{
	return be->iface->ioa_special_tpid_flush(be->be_dev, &be->ioa);
}

int hw_mod_ioa_config_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
			  uint32_t value)
{
	switch (_VER_) {
	case 4:
		switch (field) {
		case HW_IOA_CONFIG_CUST_TPID_0:
			be->ioa.v4.tpid->cust_tpid_0 = value;
			break;
		case HW_IOA_CONFIG_CUST_TPID_1:
			be->ioa.v4.tpid->cust_tpid_1 = value;
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 4 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_ioa_roa_epp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->ioa.nb_roa_epp_entries;
	if ((unsigned int)(start_idx + count) > be->ioa.nb_roa_epp_entries)
		return error_index_too_large(__func__);
	return be->iface->ioa_roa_epp_flush(be->be_dev, &be->ioa, start_idx,
					    count);
}

static int hw_mod_ioa_roa_epp_mod(struct flow_api_backend_s *be,
				  enum hw_ioa_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->ioa.nb_roa_epp_entries)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 4:
		switch (field) {
		case HW_IOA_ROA_EPP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->ioa.v4.roa_epp[index], (uint8_t)*value,
			       sizeof(struct ioa_v4_roa_epp_s));
			break;
		case HW_IOA_ROA_EPP_FIND:
			rv = find_equal_index(be->ioa.v4.roa_epp,
				sizeof(struct ioa_v4_roa_epp_s), index, *value,
				be->ioa.nb_roa_epp_entries, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_IOA_ROA_EPP_COMPARE:
			rv = do_compare_indexes(be->ioa.v4.roa_epp,
				sizeof(struct ioa_v4_roa_epp_s), index, *value,
				be->ioa.nb_roa_epp_entries, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_IOA_ROA_EPP_PUSH_TUNNEL:
			get_set(&be->ioa.v4.roa_epp[index].push_tunnel, value, get);
			break;
		case HW_IOA_ROA_EPP_TX_PORT:
			get_set(&be->ioa.v4.roa_epp[index].tx_port, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 4 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_ioa_roa_epp_set(struct flow_api_backend_s *be, enum hw_ioa_e field,
			   uint32_t index, uint32_t value)
{
	return hw_mod_ioa_roa_epp_mod(be, field, index, &value, 0);
}

int hw_mod_ioa_roa_epp_get(struct flow_api_backend_s *be, enum hw_ioa_e field,
			   uint32_t index, uint32_t *value)
{
	return hw_mod_ioa_roa_epp_mod(be, field, index, value, 1);
}
