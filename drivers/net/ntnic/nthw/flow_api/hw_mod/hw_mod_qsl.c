/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "QSL"
#define _VER_ be->qsl.ver

#define QSL_QEN_ENTRIES 32
#define QSL_QNMQ_ENTRIES 256

bool hw_mod_qsl_present(struct flow_api_backend_s *be)
{
	return be->iface->get_qsl_present(be->be_dev);
}

int hw_mod_qsl_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_qsl_version(be->be_dev);
	NT_LOG(DBG, FILTER, "QSL MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_qsl_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "qsl_categories", _MOD_, _VER_);
	be->qsl.nb_rcp_categories = (uint32_t)nb;

	nb = be->iface->get_nb_qsl_qst_entries(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "qsl_qst_entries", _MOD_, _VER_);
	be->qsl.nb_qst_entries = (uint32_t)nb;

	switch (_VER_) {
	case 7:
		if (!callocate_mod(CAST_COMMON(&be->qsl), 4,
			&be->qsl.v7.rcp,
			be->qsl.nb_rcp_categories,
			sizeof(struct qsl_v7_rcp_s),
			&be->qsl.v7.qst,
			be->qsl.nb_qst_entries,
			sizeof(struct qsl_v7_qst_s),
			&be->qsl.v7.qen,
			QSL_QEN_ENTRIES,
			sizeof(struct qsl_v7_qen_s),
			&be->qsl.v7.unmq,
			QSL_QNMQ_ENTRIES,
			sizeof(struct qsl_v7_unmq_s)))
			return -1;
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

void hw_mod_qsl_free(struct flow_api_backend_s *be)
{
	if (be->qsl.base) {
		free(be->qsl.base);
		be->qsl.base = NULL;
	}
}

int hw_mod_qsl_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->qsl);

	NT_LOG(DBG, FILTER, "INIT QSL RCP\n");
	hw_mod_qsl_rcp_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL QST\n");
	hw_mod_qsl_qst_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL QEN\n");
	hw_mod_qsl_qen_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT QSL UNMQ\n");
	be->iface->qsl_unmq_flush(be->be_dev, &be->qsl, 0, 256);

	return 0;
}

int hw_mod_qsl_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->qsl.nb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->qsl.nb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->qsl_rcp_flush(be->be_dev, &be->qsl, start_idx, count);
}

static int hw_mod_qsl_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_qsl_e field, uint32_t index,
			      uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->qsl.nb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_QSL_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->qsl.v7.rcp[index], (uint8_t)*value,
			       sizeof(struct qsl_v7_rcp_s));
			break;
		case HW_QSL_RCP_FIND:
			rv = find_equal_index(be->qsl.v7.rcp,
				sizeof(struct qsl_v7_rcp_s), index, *value,
				be->qsl.nb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_QSL_RCP_COMPARE:
			rv = do_compare_indexes(be->qsl.v7.rcp,
				sizeof(struct qsl_v7_rcp_s), index, *value,
				be->qsl.nb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_QSL_RCP_DISCARD:
			get_set(&be->qsl.v7.rcp[index].discard, value, get);
			break;
		case HW_QSL_RCP_DROP:
			get_set(&be->qsl.v7.rcp[index].drop, value, get);
			break;
		case HW_QSL_RCP_TBL_LO:
			get_set(&be->qsl.v7.rcp[index].tbl_lo, value, get);
			break;
		case HW_QSL_RCP_TBL_HI:
			get_set(&be->qsl.v7.rcp[index].tbl_hi, value, get);
			break;
		case HW_QSL_RCP_TBL_IDX:
			get_set(&be->qsl.v7.rcp[index].tbl_idx, value, get);
			break;
		case HW_QSL_RCP_TBL_MSK:
			get_set(&be->qsl.v7.rcp[index].tbl_msk, value, get);
			break;
		case HW_QSL_RCP_LR:
			get_set(&be->qsl.v7.rcp[index].lr, value, get);
			break;
		case HW_QSL_RCP_TSA:
			get_set(&be->qsl.v7.rcp[index].tsa, value, get);
			break;
		case HW_QSL_RCP_VLI:
			get_set(&be->qsl.v7.rcp[index].vli, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_qsl_rcp_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_qsl_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_qsl_rcp_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_qsl_rcp_mod(be, field, index, value, 1);
}

int hw_mod_qsl_qst_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->qsl.nb_qst_entries;
	if ((unsigned int)(start_idx + count) > be->qsl.nb_qst_entries)
		return error_index_too_large(__func__);
	return be->iface->qsl_qst_flush(be->be_dev, &be->qsl, start_idx, count);
}

static int hw_mod_qsl_qst_mod(struct flow_api_backend_s *be,
			      enum hw_qsl_e field, uint32_t index,
			      uint32_t *value, int get)
{
	if (index >= be->qsl.nb_qst_entries)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_QSL_QST_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->qsl.v7.qst[index], (uint8_t)*value,
			       sizeof(struct qsl_v7_qst_s));
			break;
		case HW_QSL_QST_QUEUE:
			get_set(&be->qsl.v7.qst[index].queue, value, get);
			break;
		case HW_QSL_QST_EN:
			get_set(&be->qsl.v7.qst[index].en, value, get);
			break;
		case HW_QSL_QST_TX_PORT:
			get_set(&be->qsl.v7.qst[index].tx_port, value, get);
			break;
		case HW_QSL_QST_LRE:
			get_set(&be->qsl.v7.qst[index].lre, value, get);
			break;
		case HW_QSL_QST_TCI:
			get_set(&be->qsl.v7.qst[index].tci, value, get);
			break;
		case HW_QSL_QST_VEN:
			get_set(&be->qsl.v7.qst[index].ven, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_qsl_qst_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_qsl_qst_mod(be, field, index, &value, 0);
}

int hw_mod_qsl_qst_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_qsl_qst_mod(be, field, index, value, 1);
}

int hw_mod_qsl_qen_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = QSL_QEN_ENTRIES;
	if ((start_idx + count) > QSL_QEN_ENTRIES)
		return error_index_too_large(__func__);
	return be->iface->qsl_qen_flush(be->be_dev, &be->qsl, start_idx, count);
}

static int hw_mod_qsl_qen_mod(struct flow_api_backend_s *be,
			      enum hw_qsl_e field, uint32_t index,
			      uint32_t *value, int get)
{
	if (index >= QSL_QEN_ENTRIES)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_QSL_QEN_EN:
			get_set(&be->qsl.v7.qen[index].en, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_qsl_qen_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_qsl_qen_mod(be, field, index, &value, 0);
}

int hw_mod_qsl_qen_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_qsl_qen_mod(be, field, index, value, 1);
}

int hw_mod_qsl_unmq_flush(struct flow_api_backend_s *be, int start_idx,
			  int count)
{
	if (count == ALL_ENTRIES)
		count = QSL_QNMQ_ENTRIES;
	if ((start_idx + count) > QSL_QNMQ_ENTRIES)
		return error_index_too_large(__func__);
	return be->iface->qsl_unmq_flush(be->be_dev, &be->qsl, start_idx,
					 count);
}

static int hw_mod_qsl_unmq_mod(struct flow_api_backend_s *be,
			       enum hw_qsl_e field, uint32_t index,
			       uint32_t *value, int get)
{
	if (index >= QSL_QNMQ_ENTRIES)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_QSL_UNMQ_DEST_QUEUE:
			get_set(&be->qsl.v7.unmq[index].dest_queue, value, get);
			break;
		case HW_QSL_UNMQ_EN:
			get_set(&be->qsl.v7.unmq[index].en, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_qsl_unmq_set(struct flow_api_backend_s *be, enum hw_qsl_e field,
			uint32_t index, uint32_t value)
{
	return hw_mod_qsl_unmq_mod(be, field, index, &value, 0);
}

int hw_mod_qsl_unmq_get(struct flow_api_backend_s *be, enum hw_qsl_e field,
			uint32_t index, uint32_t *value)
{
	return hw_mod_qsl_unmq_mod(be, field, index, value, 1);
}
