/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "HSH"
#define _VER_ be->hsh.ver

#define HSH_RCP_ENTRIES_V4 16
#define HSH_RCP_ENTRIES_V5 32
#define HSH_RCP_MAC_PORT_MASK_SIZE 4
#define HSH_RCP_WORD_MASK_SIZE 10

bool hw_mod_hsh_present(struct flow_api_backend_s *be)
{
	return be->iface->get_hsh_present(be->be_dev);
}

int hw_mod_hsh_alloc(struct flow_api_backend_s *be)
{
	_VER_ = be->iface->get_hsh_version(be->be_dev);
	NT_LOG(DBG, FILTER, "HSH MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	switch (_VER_) {
	case 5:
		be->hsh.nb_rcp = HSH_RCP_ENTRIES_V5;
		if (!callocate_mod(CAST_COMMON(&be->hsh), 1,
			&be->hsh.v5.rcp,
			be->hsh.nb_rcp,
			sizeof(struct hsh_v5_rcp_s)))
			return -1;
		break;
	/* end case 5 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

void hw_mod_hsh_free(struct flow_api_backend_s *be)
{
	if (be->hsh.base) {
		free(be->hsh.base);
		be->hsh.base = NULL;
	}
}

int hw_mod_hsh_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->hsh);

	NT_LOG(DBG, FILTER, "INIT HSH RCP\n");
	return hw_mod_hsh_rcp_flush(be, 0, be->hsh.nb_rcp);
}

int hw_mod_hsh_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->hsh.nb_rcp;
	if ((start_idx + count) > (int)be->hsh.nb_rcp)
		return error_index_too_large(__func__);
	return be->iface->hsh_rcp_flush(be->be_dev, &be->hsh, start_idx, count);
}

static int hw_mod_hsh_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_hsh_e field, uint32_t index,
			      uint32_t word_off, uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->hsh.nb_rcp)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 5:
		switch (field) {
		case HW_HSH_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->hsh.v5.rcp[index], (uint8_t)*value,
			       sizeof(struct hsh_v5_rcp_s));
			break;
		case HW_HSH_RCP_COMPARE:
			rv = do_compare_indexes(be->hsh.v5.rcp,
				sizeof(struct hsh_v5_rcp_s), index, word_off,
				be->hsh.nb_rcp, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_HSH_RCP_FIND:
			rv = find_equal_index(be->hsh.v5.rcp,
				sizeof(struct hsh_v5_rcp_s), index, word_off,
				be->hsh.nb_rcp, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_HSH_RCP_LOAD_DIST_TYPE:
			get_set(&be->hsh.v5.rcp[index].load_dist_type, value, get);
			break;
		case HW_HSH_RCP_MAC_PORT_MASK:
			if (word_off > HSH_RCP_MAC_PORT_MASK_SIZE)
				return error_word_off_too_large(__func__);
			get_set(&be->hsh.v5.rcp[index].mac_port_mask[word_off],
				value, get);
			break;
		case HW_HSH_RCP_SORT:
			get_set(&be->hsh.v5.rcp[index].sort, value, get);
			break;
		case HW_HSH_RCP_QW0_PE:
			get_set(&be->hsh.v5.rcp[index].qw0_pe, value, get);
			break;
		case HW_HSH_RCP_QW0_OFS:
			get_set_signed(&be->hsh.v5.rcp[index].qw0_ofs, value, get);
			break;
		case HW_HSH_RCP_QW4_PE:
			get_set(&be->hsh.v5.rcp[index].qw4_pe, value, get);
			break;
		case HW_HSH_RCP_QW4_OFS:
			get_set_signed(&be->hsh.v5.rcp[index].qw4_ofs, value, get);
			break;
		case HW_HSH_RCP_W8_PE:
			get_set(&be->hsh.v5.rcp[index].w8_pe, value, get);
			break;
		case HW_HSH_RCP_W8_OFS:
			get_set_signed(&be->hsh.v5.rcp[index].w8_ofs, value, get);
			break;
		case HW_HSH_RCP_W8_SORT:
			get_set(&be->hsh.v5.rcp[index].w8_sort, value, get);
			break;
		case HW_HSH_RCP_W9_PE:
			get_set(&be->hsh.v5.rcp[index].w9_pe, value, get);
			break;
		case HW_HSH_RCP_W9_OFS:
			get_set_signed(&be->hsh.v5.rcp[index].w9_ofs, value, get);
			break;
		case HW_HSH_RCP_W9_SORT:
			get_set(&be->hsh.v5.rcp[index].w9_sort, value, get);
			break;
		case HW_HSH_RCP_W9_P:
			get_set(&be->hsh.v5.rcp[index].w9_p, value, get);
			break;
		case HW_HSH_RCP_P_MASK:
			get_set(&be->hsh.v5.rcp[index].p_mask, value, get);
			break;
		case HW_HSH_RCP_WORD_MASK:
			if (word_off > HSH_RCP_WORD_MASK_SIZE)
				return error_word_off_too_large(__func__);
			get_set(&be->hsh.v5.rcp[index].word_mask[word_off],
				value, get);
			break;
		case HW_HSH_RCP_SEED:
			get_set(&be->hsh.v5.rcp[index].seed, value, get);
			break;
		case HW_HSH_RCP_TNL_P:
			get_set(&be->hsh.v5.rcp[index].tnl_p, value, get);
			break;
		case HW_HSH_RCP_HSH_VALID:
			get_set(&be->hsh.v5.rcp[index].hsh_valid, value, get);
			break;
		case HW_HSH_RCP_HSH_TYPE:
			get_set(&be->hsh.v5.rcp[index].hsh_type, value, get);
			break;
		case HW_HSH_RCP_AUTO_IPV4_MASK:
			get_set(&be->hsh.v5.rcp[index].auto_ipv4_mask, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 5 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_hsh_rcp_set(struct flow_api_backend_s *be, enum hw_hsh_e field,
		       uint32_t index, uint32_t word_off, uint32_t value)
{
	return hw_mod_hsh_rcp_mod(be, field, index, word_off, &value, 0);
}

int hw_mod_hsh_rcp_get(struct flow_api_backend_s *be, enum hw_hsh_e field,
		       uint32_t index, uint32_t word_off, uint32_t *value)
{
	return hw_mod_hsh_rcp_mod(be, field, index, word_off, value, 1);
}
