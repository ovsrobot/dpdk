/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "flow_api_backend.h"

#define _MOD_ "TPE"
#define _VER_ be->tpe.ver

bool hw_mod_tpe_present(struct flow_api_backend_s *be)
{
	return be->iface->get_tpe_present(be->be_dev);
}

int hw_mod_tpe_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_tpe_version(be->be_dev);
	NT_LOG(DBG, FILTER, _MOD_ " MODULE VERSION %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_tpe_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tpe_categories", _MOD_, _VER_);
	be->tpe.nb_rcp_categories = (uint32_t)nb;

	be->tpe.nb_ifr_categories = 0;
	if (_VER_ > 1) {
		nb = be->iface->get_nb_tpe_ifr_categories(be->be_dev);
		if (nb <= 0)
			return error_resource_count(__func__, "tpe_ifr_categories", _MOD_, _VER_);
		be->tpe.nb_ifr_categories = (uint32_t)nb;
	}

	nb = be->iface->get_nb_tx_cpy_writers(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tx_cpy_writers", _MOD_, _VER_);
	be->tpe.nb_cpy_writers = (uint32_t)nb;

	nb = be->iface->get_nb_tx_rpl_depth(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tx_rpl_depth", _MOD_, _VER_);
	be->tpe.nb_rpl_depth = (uint32_t)nb;

	nb = be->iface->get_nb_tx_rpl_ext_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tx_rpl_ext_categories", _MOD_, _VER_);
	be->tpe.nb_rpl_ext_categories = (uint32_t)nb;

	switch (_VER_) {
	case 1:
		if (!callocate_mod(CAST_COMMON(&be->tpe), 8,
			&be->tpe.v1.rpp_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_rpp_v0_rcp_s),
			&be->tpe.v1.ins_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_ins_v1_rcp_s),
			&be->tpe.v1.rpl_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_rpl_v2_rcp_s),
			&be->tpe.v1.rpl_ext, be->tpe.nb_rpl_ext_categories,
			sizeof(struct tpe_v1_rpl_v2_ext_s),
			&be->tpe.v1.rpl_rpl, be->tpe.nb_rpl_depth,
			sizeof(struct tpe_v1_rpl_v2_rpl_s),
			&be->tpe.v1.cpy_rcp,
			be->tpe.nb_cpy_writers * be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_cpy_v1_rcp_s),
			&be->tpe.v1.hfu_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_hfu_v1_rcp_s),
			&be->tpe.v1.csu_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_csu_v0_rcp_s)))
			return -1;
		break;
	case 2:
		if (!callocate_mod(CAST_COMMON(&be->tpe), 10,
			&be->tpe.v2.rpp_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_rpp_v0_rcp_s),
			&be->tpe.v2.rpp_ifr_rcp, be->tpe.nb_ifr_categories,
			sizeof(struct tpe_v2_rpp_v1_ifr_rcp_s),
			&be->tpe.v2.ifr_rcp, be->tpe.nb_ifr_categories,
			sizeof(struct tpe_v2_ifr_v1_rcp_s),
			&be->tpe.v2.ins_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_ins_v1_rcp_s),
			&be->tpe.v2.rpl_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_rpl_v2_rcp_s),
			&be->tpe.v2.rpl_ext, be->tpe.nb_rpl_ext_categories,
			sizeof(struct tpe_v1_rpl_v2_ext_s),
			&be->tpe.v2.rpl_rpl, be->tpe.nb_rpl_depth,
			sizeof(struct tpe_v1_rpl_v2_rpl_s),
			&be->tpe.v2.cpy_rcp,
			be->tpe.nb_cpy_writers * be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_cpy_v1_rcp_s),
			&be->tpe.v2.hfu_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_hfu_v1_rcp_s),
			&be->tpe.v2.csu_rcp, be->tpe.nb_rcp_categories,
			sizeof(struct tpe_v1_csu_v0_rcp_s)))
			return -1;
		break;
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_tpe_free(struct flow_api_backend_s *be)
{
	if (be->tpe.base) {
		free(be->tpe.base);
		be->tpe.base = NULL;
	}
}

int hw_mod_tpe_reset(struct flow_api_backend_s *be)
{
	int err = 0;

	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->tpe);

	NT_LOG(DBG, FILTER, "INIT TPE\n");
	err |= hw_mod_tpe_rpp_rcp_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_ins_rcp_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_rpl_rcp_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_rpl_ext_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_rpl_rpl_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_cpy_rcp_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_hfu_rcp_flush(be, 0, ALL_ENTRIES);
	err |= hw_mod_tpe_csu_rcp_flush(be, 0, ALL_ENTRIES);

	if (_VER_ == 2) {
		err |= hw_mod_tpe_rpp_ifr_rcp_flush(be, 0, ALL_ENTRIES);
		err |= hw_mod_tpe_ifr_rcp_flush(be, 0, ALL_ENTRIES);
	}

	return err;
}

/*
 * RPP_IFR_RCP
 */

int hw_mod_tpe_rpp_ifr_rcp_flush(struct flow_api_backend_s *be, int start_idx,
				 int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_ifr_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_ifr_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_rpp_ifr_rcp_flush(be->be_dev, &be->tpe, start_idx,
						count);
}

static int hw_mod_tpe_rpp_ifr_rcp_mod(struct flow_api_backend_s *be,
				      enum hw_tpe_e field, uint32_t index,
				      uint32_t *value, int get)
{
	if (index >= be->tpe.nb_ifr_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 2:
		switch (field) {
		case HW_TPE_IFR_RCP_EN:
			get_set(&be->tpe.v2.rpp_ifr_rcp[index].en, value, get);
			break;

		case HW_TPE_IFR_RCP_MTU:
			get_set(&be->tpe.v2.rpp_ifr_rcp[index].mtu, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_tpe_rpp_ifr_rcp_set(struct flow_api_backend_s *be,
			       enum hw_tpe_e field, int index, uint32_t value)
{
	return hw_mod_tpe_rpp_ifr_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_rpp_ifr_rcp_get(struct flow_api_backend_s *be,
			       enum hw_tpe_e field, int index, uint32_t *value)
{
	return hw_mod_tpe_rpp_ifr_rcp_mod(be, field, index, value, 1);
}

/*
 * RPP_RCP
 */

int hw_mod_tpe_rpp_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_rpp_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_rpp_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.rpp_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_rpp_v0_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.rpp_rcp,
				sizeof(struct tpe_v1_rpp_v0_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.rpp_rcp,
				sizeof(struct tpe_v1_rpp_v0_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_RPP_RCP_EXP:
			get_set(&be->tpe.v1.rpp_rcp[index].exp, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_tpe_rpp_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_rpp_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_rpp_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_rpp_rcp_mod(be, field, index, value, 1);
}

/*
 * IFR_RCP
 */

int hw_mod_tpe_ifr_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_ifr_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_ifr_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_ifr_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_ifr_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	if (index >= be->tpe.nb_ifr_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 2:
		switch (field) {
		case HW_TPE_IFR_RCP_EN:
			get_set(&be->tpe.v2.ifr_rcp[index].en, value, get);
			break;

		case HW_TPE_IFR_RCP_MTU:
			get_set(&be->tpe.v2.ifr_rcp[index].mtu, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_tpe_ifr_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_ifr_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_ifr_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_ifr_rcp_mod(be, field, index, value, 1);
}

/*
 * INS_RCP
 */

int hw_mod_tpe_ins_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_ins_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_ins_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.ins_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_ins_v1_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.ins_rcp,
				sizeof(struct tpe_v1_ins_v1_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.ins_rcp,
				sizeof(struct tpe_v1_ins_v1_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_INS_RCP_DYN:
			get_set(&be->tpe.v1.ins_rcp[index].dyn, value, get);
			break;
		case HW_TPE_INS_RCP_OFS:
			get_set(&be->tpe.v1.ins_rcp[index].ofs, value, get);
			break;
		case HW_TPE_INS_RCP_LEN:
			get_set(&be->tpe.v1.ins_rcp[index].len, value, get);
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

int hw_mod_tpe_ins_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_ins_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_ins_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_ins_rcp_mod(be, field, index, value, 1);
}

/*
 * RPL_RCP
 */

int hw_mod_tpe_rpl_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_rpl_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_rpl_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.rpl_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_rpl_v2_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.rpl_rcp,
				sizeof(struct tpe_v1_rpl_v2_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.rpl_rcp,
				sizeof(struct tpe_v1_rpl_v2_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_RPL_RCP_DYN:
			get_set(&be->tpe.v1.rpl_rcp[index].dyn, value, get);
			break;
		case HW_TPE_RPL_RCP_OFS:
			get_set(&be->tpe.v1.rpl_rcp[index].ofs, value, get);
			break;
		case HW_TPE_RPL_RCP_LEN:
			get_set(&be->tpe.v1.rpl_rcp[index].len, value, get);
			break;
		case HW_TPE_RPL_RCP_RPL_PTR:
			get_set(&be->tpe.v1.rpl_rcp[index].rpl_ptr, value, get);
			break;
		case HW_TPE_RPL_RCP_EXT_PRIO:
			get_set(&be->tpe.v1.rpl_rcp[index].ext_prio, value, get);
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

int hw_mod_tpe_rpl_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_rpl_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_rpl_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_rpl_rcp_mod(be, field, index, value, 1);
}

/*
 * RPL_EXT
 */

int hw_mod_tpe_rpl_ext_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rpl_ext_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rpl_ext_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_rpl_ext_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_rpl_ext_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rpl_ext_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.rpl_ext[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_rpl_v2_ext_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.rpl_ext,
				sizeof(struct tpe_v1_rpl_v2_ext_s), index, *value,
				be->tpe.nb_rpl_ext_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.rpl_ext,
				sizeof(struct tpe_v1_rpl_v2_ext_s), index, *value,
				be->tpe.nb_rpl_ext_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_RPL_EXT_RPL_PTR:
			get_set(&be->tpe.v1.rpl_ext[index].rpl_ptr, value, get);
			break;
		case HW_TPE_RPL_EXT_META_RPL_LEN:
			get_set(&be->tpe.v1.rpl_ext[index].meta_rpl_len, value, get);
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

int hw_mod_tpe_rpl_ext_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_rpl_ext_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_rpl_ext_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_rpl_ext_mod(be, field, index, value, 1);
}

/*
 * RPL_RPL
 */

int hw_mod_tpe_rpl_rpl_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rpl_depth;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rpl_depth)
		return error_index_too_large(__func__);
	return be->iface->tpe_rpl_rpl_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_rpl_rpl_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rpl_depth)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.rpl_rpl[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_rpl_v2_rpl_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.rpl_rpl,
				sizeof(struct tpe_v1_rpl_v2_rpl_s), index, *value,
				be->tpe.nb_rpl_depth, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.rpl_rpl,
				sizeof(struct tpe_v1_rpl_v2_rpl_s), index, *value,
				be->tpe.nb_rpl_depth, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_RPL_RPL_VALUE:
			if (get)
				memcpy(value, be->tpe.v1.rpl_rpl[index].value,
				       sizeof(uint32_t) * 4);
			else
				memcpy(be->tpe.v1.rpl_rpl[index].value, value,
				       sizeof(uint32_t) * 4);
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

int hw_mod_tpe_rpl_rpl_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_rpl_rpl_mod(be, field, index, value, 0);
}

int hw_mod_tpe_rpl_rpl_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_rpl_rpl_mod(be, field, index, value, 1);
}

/*
 * CPY_RCP
 */

int hw_mod_tpe_cpy_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	const uint32_t cpy_size =
		be->tpe.nb_cpy_writers * be->tpe.nb_rcp_categories;
	if (count == ALL_ENTRIES)
		count = cpy_size;
	if ((unsigned int)(start_idx + count) > cpy_size)
		return error_index_too_large(__func__);
	return be->iface->tpe_cpy_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_cpy_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	const uint32_t cpy_size =
		be->tpe.nb_cpy_writers * be->tpe.nb_rcp_categories;
	int rv = 0;
	if (index >= cpy_size)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.cpy_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_cpy_v1_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.cpy_rcp,
				sizeof(struct tpe_v1_cpy_v1_rcp_s), index, *value,
				cpy_size, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.cpy_rcp,
				sizeof(struct tpe_v1_cpy_v1_rcp_s), index, *value,
				cpy_size, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_CPY_RCP_READER_SELECT:
			get_set(&be->tpe.v1.cpy_rcp[index].reader_select, value, get);
			break;
		case HW_TPE_CPY_RCP_DYN:
			get_set(&be->tpe.v1.cpy_rcp[index].dyn, value, get);
			break;
		case HW_TPE_CPY_RCP_OFS:
			get_set(&be->tpe.v1.cpy_rcp[index].ofs, value, get);
			break;
		case HW_TPE_CPY_RCP_LEN:
			get_set(&be->tpe.v1.cpy_rcp[index].len, value, get);
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

int hw_mod_tpe_cpy_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_cpy_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_cpy_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_cpy_rcp_mod(be, field, index, value, 1);
}

/*
 * HFU_RCP
 */

int hw_mod_tpe_hfu_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_hfu_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_hfu_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.hfu_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_hfu_v1_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.hfu_rcp,
				sizeof(struct tpe_v1_hfu_v1_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.hfu_rcp,
				sizeof(struct tpe_v1_hfu_v1_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_HFU_RCP_LEN_A_WR:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_wr, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_OUTER_L4_LEN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_outer_l4_len,
				value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_POS_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_pos_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_POS_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_pos_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_ADD_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_add_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_ADD_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_add_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_A_SUB_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_a_sub_dyn, value, get);
			break;

		case HW_TPE_HFU_RCP_LEN_B_WR:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_wr, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_B_POS_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_pos_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_B_POS_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_pos_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_B_ADD_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_add_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_B_ADD_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_add_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_B_SUB_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_b_sub_dyn, value, get);
			break;

		case HW_TPE_HFU_RCP_LEN_C_WR:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_wr, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_C_POS_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_pos_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_C_POS_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_pos_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_C_ADD_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_add_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_C_ADD_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_add_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_LEN_C_SUB_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].len_c_sub_dyn, value, get);
			break;

		case HW_TPE_HFU_RCP_TTL_WR:
			get_set(&be->tpe.v1.hfu_rcp[index].ttl_wr, value, get);
			break;
		case HW_TPE_HFU_RCP_TTL_POS_DYN:
			get_set(&be->tpe.v1.hfu_rcp[index].ttl_pos_dyn, value, get);
			break;
		case HW_TPE_HFU_RCP_TTL_POS_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].ttl_pos_ofs, value, get);
			break;

		case HW_TPE_HFU_RCP_CS_INF:
			get_set(&be->tpe.v1.hfu_rcp[index].cs_inf, value, get);
			break;
		case HW_TPE_HFU_RCP_L3_PRT:
			get_set(&be->tpe.v1.hfu_rcp[index].l3_prt, value, get);
			break;
		case HW_TPE_HFU_RCP_L3_FRAG:
			get_set(&be->tpe.v1.hfu_rcp[index].l3_frag, value, get);
			break;
		case HW_TPE_HFU_RCP_TUNNEL:
			get_set(&be->tpe.v1.hfu_rcp[index].tunnel, value, get);
			break;
		case HW_TPE_HFU_RCP_L4_PRT:
			get_set(&be->tpe.v1.hfu_rcp[index].l4_prt, value, get);
			break;
		case HW_TPE_HFU_RCP_OUTER_L3_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].outer_l3_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_OUTER_L4_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].outer_l4_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_INNER_L3_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].inner_l3_ofs, value, get);
			break;
		case HW_TPE_HFU_RCP_INNER_L4_OFS:
			get_set(&be->tpe.v1.hfu_rcp[index].inner_l4_ofs, value, get);
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

int hw_mod_tpe_hfu_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_hfu_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_hfu_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_hfu_rcp_mod(be, field, index, value, 1);
}

/*
 * CSU_RCP
 */

int hw_mod_tpe_csu_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			     int count)
{
	if (count == ALL_ENTRIES)
		count = be->tpe.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->tpe_csu_rcp_flush(be->be_dev, &be->tpe, start_idx,
					    count);
}

static int hw_mod_tpe_csu_rcp_mod(struct flow_api_backend_s *be,
				  enum hw_tpe_e field, uint32_t index,
				  uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->tpe.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 1:
	case 2:
		switch (field) {
		case HW_TPE_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->tpe.v1.csu_rcp[index], (uint8_t)*value,
			       sizeof(struct tpe_v1_csu_v0_rcp_s));
			break;
		case HW_TPE_FIND:
			rv = find_equal_index(be->tpe.v1.csu_rcp,
				sizeof(struct tpe_v1_csu_v0_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_COMPARE:
			rv = do_compare_indexes(be->tpe.v1.csu_rcp,
				sizeof(struct tpe_v1_csu_v0_rcp_s), index, *value,
				be->tpe.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_TPE_CSU_RCP_OUTER_L3_CMD:
			get_set(&be->tpe.v1.csu_rcp[index].ol3_cmd, value, get);
			break;
		case HW_TPE_CSU_RCP_OUTER_L4_CMD:
			get_set(&be->tpe.v1.csu_rcp[index].ol4_cmd, value, get);
			break;
		case HW_TPE_CSU_RCP_INNER_L3_CMD:
			get_set(&be->tpe.v1.csu_rcp[index].il3_cmd, value, get);
			break;
		case HW_TPE_CSU_RCP_INNER_L4_CMD:
			get_set(&be->tpe.v1.csu_rcp[index].il4_cmd, value, get);
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

int hw_mod_tpe_csu_rcp_set(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t value)
{
	return hw_mod_tpe_csu_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_tpe_csu_rcp_get(struct flow_api_backend_s *be, enum hw_tpe_e field,
			   int index, uint32_t *value)
{
	return hw_mod_tpe_csu_rcp_mod(be, field, index, value, 1);
}
