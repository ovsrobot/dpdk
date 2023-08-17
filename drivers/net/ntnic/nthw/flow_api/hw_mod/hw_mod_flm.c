/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "FLM"
#define _VER_ be->flm.ver

bool hw_mod_flm_present(struct flow_api_backend_s *be)
{
	return be->iface->get_flm_present(be->be_dev);
}

int hw_mod_flm_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_flm_version(be->be_dev);
	NT_LOG(DBG, FILTER, "FLM MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_flm_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_categories", _MOD_, _VER_);
	be->flm.nb_categories = (uint32_t)nb;

	nb = be->iface->get_nb_flm_size_mb(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_size_mb", _MOD_, _VER_);
	be->flm.nb_size_mb = (uint32_t)nb;

	nb = be->iface->get_nb_flm_entry_size(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_entry_size", _MOD_, _VER_);
	be->flm.nb_entry_size = (uint32_t)nb;

	nb = be->iface->get_nb_flm_variant(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_variant", _MOD_, _VER_);
	be->flm.nb_variant = (uint32_t)nb;

	nb = be->iface->get_nb_flm_prios(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_prios", _MOD_, _VER_);
	be->flm.nb_prios = (uint32_t)nb;

	nb = be->iface->get_nb_flm_pst_profiles(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "flm_variant", _MOD_, _VER_);
	be->flm.nb_pst_profiles = (uint32_t)nb;

	switch (_VER_) {
	case 17:
		if (!callocate_mod(CAST_COMMON(&be->flm), 26,
			&be->flm.v17.control, 1,
			sizeof(struct flm_v17_control_s),
			&be->flm.v17.status, 1,
			sizeof(struct flm_v17_status_s),
			&be->flm.v17.timeout, 1,
			sizeof(struct flm_v17_timeout_s),
			&be->flm.v17.scrub, 1,
			sizeof(struct flm_v17_scrub_s),
			&be->flm.v17.load_bin, 1,
			sizeof(struct flm_v17_load_bin_s),
			&be->flm.v17.load_pps, 1,
			sizeof(struct flm_v17_load_pps_s),
			&be->flm.v17.load_lps, 1,
			sizeof(struct flm_v17_load_lps_s),
			&be->flm.v17.load_aps, 1,
			sizeof(struct flm_v17_load_aps_s),
			&be->flm.v17.prio, 1,
			sizeof(struct flm_v17_prio_s),
			&be->flm.v17.pst, be->flm.nb_pst_profiles,
			sizeof(struct flm_v17_pst_s),
			&be->flm.v17.rcp, be->flm.nb_categories,
			sizeof(struct flm_v17_rcp_s),
			&be->flm.v17.buf_ctrl, 1,
			sizeof(struct flm_v17_buf_ctrl_s),
			&be->flm.v17.lrn_done, 1,
			sizeof(struct flm_v17_stat_lrn_done_s),
			&be->flm.v17.lrn_ignore, 1,
			sizeof(struct flm_v17_stat_lrn_ignore_s),
			&be->flm.v17.lrn_fail, 1,
			sizeof(struct flm_v17_stat_lrn_fail_s),
			&be->flm.v17.unl_done, 1,
			sizeof(struct flm_v17_stat_unl_done_s),
			&be->flm.v17.unl_ignore, 1,
			sizeof(struct flm_v17_stat_unl_ignore_s),
			&be->flm.v17.rel_done, 1,
			sizeof(struct flm_v17_stat_rel_done_s),
			&be->flm.v17.rel_ignore, 1,
			sizeof(struct flm_v17_stat_rel_ignore_s),
			&be->flm.v17.aul_done, 1,
			sizeof(struct flm_v17_stat_aul_done_s),
			&be->flm.v17.aul_ignore, 1,
			sizeof(struct flm_v17_stat_aul_ignore_s),
			&be->flm.v17.aul_fail, 1,
			sizeof(struct flm_v17_stat_aul_fail_s),
			&be->flm.v17.tul_done, 1,
			sizeof(struct flm_v17_stat_tul_done_s),
			&be->flm.v17.flows, 1,
			sizeof(struct flm_v17_stat_flows_s),
			&be->flm.v17.prb_done, 1,
			sizeof(struct flm_v17_stat_prb_done_s),
			&be->flm.v17.prb_ignore, 1,
			sizeof(struct flm_v17_stat_prb_ignore_s)))
			return -1;
		break;

	case 20:
		if (!callocate_mod(CAST_COMMON(&be->flm), 38,
			&be->flm.v17.control, 1,
			sizeof(struct flm_v17_control_s),
			&be->flm.v17.status, 1,
			sizeof(struct flm_v17_status_s),
			&be->flm.v17.timeout, 1,
			sizeof(struct flm_v17_timeout_s),
			&be->flm.v17.scrub, 1,
			sizeof(struct flm_v17_scrub_s),
			&be->flm.v17.load_bin, 1,
			sizeof(struct flm_v17_load_bin_s),
			&be->flm.v17.load_pps, 1,
			sizeof(struct flm_v17_load_pps_s),
			&be->flm.v17.load_lps, 1,
			sizeof(struct flm_v17_load_lps_s),
			&be->flm.v17.load_aps, 1,
			sizeof(struct flm_v17_load_aps_s),
			&be->flm.v17.prio, 1,
			sizeof(struct flm_v17_prio_s),
			&be->flm.v17.pst, be->flm.nb_pst_profiles,
			sizeof(struct flm_v17_pst_s),
			&be->flm.v17.rcp, be->flm.nb_categories,
			sizeof(struct flm_v17_rcp_s),
			&be->flm.v17.buf_ctrl, 1,
			sizeof(struct flm_v17_buf_ctrl_s),
			&be->flm.v17.lrn_done, 1,
			sizeof(struct flm_v17_stat_lrn_done_s),
			&be->flm.v17.lrn_ignore, 1,
			sizeof(struct flm_v17_stat_lrn_ignore_s),
			&be->flm.v17.lrn_fail, 1,
			sizeof(struct flm_v17_stat_lrn_fail_s),
			&be->flm.v17.unl_done, 1,
			sizeof(struct flm_v17_stat_unl_done_s),
			&be->flm.v17.unl_ignore, 1,
			sizeof(struct flm_v17_stat_unl_ignore_s),
			&be->flm.v17.rel_done, 1,
			sizeof(struct flm_v17_stat_rel_done_s),
			&be->flm.v17.rel_ignore, 1,
			sizeof(struct flm_v17_stat_rel_ignore_s),
			&be->flm.v17.aul_done, 1,
			sizeof(struct flm_v17_stat_aul_done_s),
			&be->flm.v17.aul_ignore, 1,
			sizeof(struct flm_v17_stat_aul_ignore_s),
			&be->flm.v17.aul_fail, 1,
			sizeof(struct flm_v17_stat_aul_fail_s),
			&be->flm.v17.tul_done, 1,
			sizeof(struct flm_v17_stat_tul_done_s),
			&be->flm.v17.flows, 1,
			sizeof(struct flm_v17_stat_flows_s),
			&be->flm.v17.prb_done, 1,
			sizeof(struct flm_v17_stat_prb_done_s),
			&be->flm.v17.prb_ignore, 1,
			sizeof(struct flm_v17_stat_prb_ignore_s),
			&be->flm.v20.sta_done, 1,
			sizeof(struct flm_v20_stat_sta_done_s),
			&be->flm.v20.inf_done, 1,
			sizeof(struct flm_v20_stat_inf_done_s),
			&be->flm.v20.inf_skip, 1,
			sizeof(struct flm_v20_stat_inf_skip_s),
			&be->flm.v20.pck_hit, 1,
			sizeof(struct flm_v20_stat_pck_hit_s),
			&be->flm.v20.pck_miss, 1,
			sizeof(struct flm_v20_stat_pck_miss_s),
			&be->flm.v20.pck_unh, 1,
			sizeof(struct flm_v20_stat_pck_unh_s),
			&be->flm.v20.pck_dis, 1,
			sizeof(struct flm_v20_stat_pck_dis_s),
			&be->flm.v20.csh_hit, 1,
			sizeof(struct flm_v20_stat_csh_hit_s),
			&be->flm.v20.csh_miss, 1,
			sizeof(struct flm_v20_stat_csh_miss_s),
			&be->flm.v20.csh_unh, 1,
			sizeof(struct flm_v20_stat_csh_unh_s),
			&be->flm.v20.cuc_start, 1,
			sizeof(struct flm_v20_stat_cuc_start_s),
			&be->flm.v20.cuc_move, 1,
			sizeof(struct flm_v20_stat_cuc_move_s)))
			return -1;
		break;

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_flm_free(struct flow_api_backend_s *be)
{
	if (be->flm.base) {
		free(be->flm.base);
		be->flm.base = NULL;
	}
}

int hw_mod_flm_reset(struct flow_api_backend_s *be)
{
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->flm);

	NT_LOG(DBG, FILTER, "INIT FLM\n");
	hw_mod_flm_control_set(be, HW_FLM_CONTROL_SPLIT_SDRAM_USAGE, 0x10);

	hw_mod_flm_control_flush(be);
	hw_mod_flm_timeout_flush(be);
	hw_mod_flm_scrub_flush(be);
	hw_mod_flm_rcp_flush(be, 0, ALL_ENTRIES);

	return 0;
}

int hw_mod_flm_control_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_control_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_control_mod(struct flow_api_backend_s *be,
				  enum hw_flm_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_CONTROL_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(be->flm.v17.control, (uint8_t)*value,
			       sizeof(struct flm_v17_control_s));
			break;
		case HW_FLM_CONTROL_ENABLE:
			get_set(&be->flm.v17.control->enable, value, get);
			break;
		case HW_FLM_CONTROL_INIT:
			get_set(&be->flm.v17.control->init, value, get);
			break;
		case HW_FLM_CONTROL_LDS:
			get_set(&be->flm.v17.control->lds, value, get);
			break;
		case HW_FLM_CONTROL_LFS:
			get_set(&be->flm.v17.control->lfs, value, get);
			break;
		case HW_FLM_CONTROL_LIS:
			get_set(&be->flm.v17.control->lis, value, get);
			break;
		case HW_FLM_CONTROL_UDS:
			get_set(&be->flm.v17.control->uds, value, get);
			break;
		case HW_FLM_CONTROL_UIS:
			get_set(&be->flm.v17.control->uis, value, get);
			break;
		case HW_FLM_CONTROL_RDS:
			get_set(&be->flm.v17.control->rds, value, get);
			break;
		case HW_FLM_CONTROL_RIS:
			get_set(&be->flm.v17.control->ris, value, get);
			break;
		case HW_FLM_CONTROL_PDS:
			get_set(&be->flm.v17.control->pds, value, get);
			break;
		case HW_FLM_CONTROL_PIS:
			get_set(&be->flm.v17.control->pis, value, get);
			break;
		case HW_FLM_CONTROL_CRCWR:
			get_set(&be->flm.v17.control->crcwr, value, get);
			break;
		case HW_FLM_CONTROL_CRCRD:
			get_set(&be->flm.v17.control->crcrd, value, get);
			break;
		case HW_FLM_CONTROL_RBL:
			get_set(&be->flm.v17.control->rbl, value, get);
			break;
		case HW_FLM_CONTROL_EAB:
			get_set(&be->flm.v17.control->eab, value, get);
			break;
		case HW_FLM_CONTROL_SPLIT_SDRAM_USAGE:
			get_set(&be->flm.v17.control->split_sdram_usage, value, get);
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

int hw_mod_flm_control_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t value)
{
	return hw_mod_flm_control_mod(be, field, &value, 0);
}

int hw_mod_flm_control_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t *value)
{
	return hw_mod_flm_control_mod(be, field, value, 1);
}

int hw_mod_flm_status_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_status_flush(be->be_dev, &be->flm);
}

int hw_mod_flm_status_update(struct flow_api_backend_s *be)
{
	return be->iface->flm_status_update(be->be_dev, &be->flm);
}

static int hw_mod_flm_status_mod(struct flow_api_backend_s *be,
				 enum hw_flm_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_STATUS_CALIBDONE:
			get_set(&be->flm.v17.status->calibdone, value, get);
			break;
		case HW_FLM_STATUS_INITDONE:
			get_set(&be->flm.v17.status->initdone, value, get);
			break;
		case HW_FLM_STATUS_IDLE:
			get_set(&be->flm.v17.status->idle, value, get);
			break;
		case HW_FLM_STATUS_CRITICAL:
			get_set(&be->flm.v17.status->critical, value, get);
			break;
		case HW_FLM_STATUS_PANIC:
			get_set(&be->flm.v17.status->panic, value, get);
			break;
		case HW_FLM_STATUS_CRCERR:
			get_set(&be->flm.v17.status->crcerr, value, get);
			break;
		case HW_FLM_STATUS_EFT_BP:
			get_set(&be->flm.v17.status->eft_bp, value, get);
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

int hw_mod_flm_status_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			  uint32_t value)
{
	return hw_mod_flm_status_mod(be, field, &value, 0);
}

int hw_mod_flm_status_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			  uint32_t *value)
{
	return hw_mod_flm_status_mod(be, field, value, 1);
}

int hw_mod_flm_timeout_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_timeout_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_timeout_mod(struct flow_api_backend_s *be,
				  enum hw_flm_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_TIMEOUT_T:
			get_set(&be->flm.v17.timeout->t, value, get);
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

int hw_mod_flm_timeout_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t value)
{
	return hw_mod_flm_timeout_mod(be, field, &value, 0);
}

int hw_mod_flm_timeout_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			   uint32_t *value)
{
	return hw_mod_flm_timeout_mod(be, field, value, 1);
}

int hw_mod_flm_scrub_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_scrub_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_scrub_mod(struct flow_api_backend_s *be,
				enum hw_flm_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_SCRUB_I:
			get_set(&be->flm.v17.scrub->i, value, get);
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

int hw_mod_flm_scrub_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			 uint32_t value)
{
	return hw_mod_flm_scrub_mod(be, field, &value, 0);
}

int hw_mod_flm_scrub_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			 uint32_t *value)
{
	return hw_mod_flm_scrub_mod(be, field, value, 1);
}

int hw_mod_flm_load_bin_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_load_bin_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_load_bin_mod(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_LOAD_BIN:
			get_set(&be->flm.v17.load_bin->bin, value, get);
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

int hw_mod_flm_load_bin_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value)
{
	return hw_mod_flm_load_bin_mod(be, field, &value, 0);
}

int hw_mod_flm_load_bin_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value)
{
	return hw_mod_flm_load_bin_mod(be, field, value, 1);
}

int hw_mod_flm_load_pps_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_load_pps_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_load_pps_mod(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_LOAD_PPS:
			get_set(&be->flm.v17.load_pps->pps, value, get);
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

int hw_mod_flm_load_pps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value)
{
	return hw_mod_flm_load_pps_mod(be, field, &value, 0);
}

int hw_mod_flm_load_pps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value)
{
	return hw_mod_flm_load_pps_mod(be, field, value, 1);
}

int hw_mod_flm_load_lps_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_load_lps_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_load_lps_mod(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_LOAD_LPS:
			get_set(&be->flm.v17.load_lps->lps, value, get);
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

int hw_mod_flm_load_lps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value)
{
	return hw_mod_flm_load_lps_mod(be, field, &value, 0);
}

int hw_mod_flm_load_lps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value)
{
	return hw_mod_flm_load_lps_mod(be, field, value, 1);
}

int hw_mod_flm_load_aps_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_load_aps_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_load_aps_mod(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_LOAD_APS:
			get_set(&be->flm.v17.load_aps->aps, value, get);
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

int hw_mod_flm_load_aps_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t value)
{
	return hw_mod_flm_load_aps_mod(be, field, &value, 0);
}

int hw_mod_flm_load_aps_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value)
{
	return hw_mod_flm_load_aps_mod(be, field, value, 1);
}

int hw_mod_flm_prio_flush(struct flow_api_backend_s *be)
{
	return be->iface->flm_prio_flush(be->be_dev, &be->flm);
}

static int hw_mod_flm_prio_mod(struct flow_api_backend_s *be,
			       enum hw_flm_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_PRIO_LIMIT0:
			get_set(&be->flm.v17.prio->limit0, value, get);
			break;
		case HW_FLM_PRIO_FT0:
			get_set(&be->flm.v17.prio->ft0, value, get);
			break;
		case HW_FLM_PRIO_LIMIT1:
			get_set(&be->flm.v17.prio->limit1, value, get);
			break;
		case HW_FLM_PRIO_FT1:
			get_set(&be->flm.v17.prio->ft1, value, get);
			break;
		case HW_FLM_PRIO_LIMIT2:
			get_set(&be->flm.v17.prio->limit2, value, get);
			break;
		case HW_FLM_PRIO_FT2:
			get_set(&be->flm.v17.prio->ft2, value, get);
			break;
		case HW_FLM_PRIO_LIMIT3:
			get_set(&be->flm.v17.prio->limit3, value, get);
			break;
		case HW_FLM_PRIO_FT3:
			get_set(&be->flm.v17.prio->ft3, value, get);
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

int hw_mod_flm_prio_set(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t value)
{
	return hw_mod_flm_prio_mod(be, field, &value, 0);
}

int hw_mod_flm_prio_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t *value)
{
	return hw_mod_flm_prio_mod(be, field, value, 1);
}

int hw_mod_flm_pst_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->flm.nb_pst_profiles;
	if ((unsigned int)(start_idx + count) > be->flm.nb_pst_profiles)
		return error_index_too_large(__func__);
	return be->iface->flm_pst_flush(be->be_dev, &be->flm, start_idx, count);
}

static int hw_mod_flm_pst_mod(struct flow_api_backend_s *be,
			      enum hw_flm_e field, int index, uint32_t *value,
			      int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_PST_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->flm.v17.pst[index], (uint8_t)*value,
			       sizeof(struct flm_v17_pst_s));
			break;
		case HW_FLM_PST_BP:
			get_set(&be->flm.v17.pst[index].bp, value, get);
			break;
		case HW_FLM_PST_PP:
			get_set(&be->flm.v17.pst[index].pp, value, get);
			break;
		case HW_FLM_PST_TP:
			get_set(&be->flm.v17.pst[index].tp, value, get);
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

int hw_mod_flm_pst_set(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t value)
{
	return hw_mod_flm_pst_mod(be, field, index, &value, 0);
}

int hw_mod_flm_pst_get(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t *value)
{
	return hw_mod_flm_pst_mod(be, field, index, value, 1);
}

int hw_mod_flm_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->flm.nb_categories;
	if ((unsigned int)(start_idx + count) > be->flm.nb_categories)
		return error_index_too_large(__func__);
	return be->iface->flm_rcp_flush(be->be_dev, &be->flm, start_idx, count);
}

static int hw_mod_flm_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_flm_e field, int index, uint32_t *value,
			      int get)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->flm.v17.rcp[index], (uint8_t)*value,
			       sizeof(struct flm_v17_rcp_s));
			break;
		case HW_FLM_RCP_LOOKUP:
			get_set(&be->flm.v17.rcp[index].lookup, value, get);
			break;
		case HW_FLM_RCP_QW0_DYN:
			get_set(&be->flm.v17.rcp[index].qw0_dyn, value, get);
			break;
		case HW_FLM_RCP_QW0_OFS:
			get_set(&be->flm.v17.rcp[index].qw0_ofs, value, get);
			break;
		case HW_FLM_RCP_QW0_SEL:
			get_set(&be->flm.v17.rcp[index].qw0_sel, value, get);
			break;
		case HW_FLM_RCP_QW4_DYN:
			get_set(&be->flm.v17.rcp[index].qw4_dyn, value, get);
			break;
		case HW_FLM_RCP_QW4_OFS:
			get_set(&be->flm.v17.rcp[index].qw4_ofs, value, get);
			break;
		case HW_FLM_RCP_SW8_DYN:
			get_set(&be->flm.v17.rcp[index].sw8_dyn, value, get);
			break;
		case HW_FLM_RCP_SW8_OFS:
			get_set(&be->flm.v17.rcp[index].sw8_ofs, value, get);
			break;
		case HW_FLM_RCP_SW8_SEL:
			get_set(&be->flm.v17.rcp[index].sw8_sel, value, get);
			break;
		case HW_FLM_RCP_SW9_DYN:
			get_set(&be->flm.v17.rcp[index].sw9_dyn, value, get);
			break;
		case HW_FLM_RCP_SW9_OFS:
			get_set(&be->flm.v17.rcp[index].sw9_ofs, value, get);
			break;
		case HW_FLM_RCP_MASK:
			if (get) {
				memcpy(value, be->flm.v17.rcp[index].mask,
				       sizeof(((struct flm_v17_rcp_s *)0)
					      ->mask));
			} else {
				memcpy(be->flm.v17.rcp[index].mask, value,
				       sizeof(((struct flm_v17_rcp_s *)0)
					      ->mask));
			}
			break;
		case HW_FLM_RCP_KID:
			get_set(&be->flm.v17.rcp[index].kid, value, get);
			break;
		case HW_FLM_RCP_OPN:
			get_set(&be->flm.v17.rcp[index].opn, value, get);
			break;
		case HW_FLM_RCP_IPN:
			get_set(&be->flm.v17.rcp[index].ipn, value, get);
			break;
		case HW_FLM_RCP_BYT_DYN:
			get_set(&be->flm.v17.rcp[index].byt_dyn, value, get);
			break;
		case HW_FLM_RCP_BYT_OFS:
			get_set(&be->flm.v17.rcp[index].byt_ofs, value, get);
			break;
		case HW_FLM_RCP_TXPLM:
			get_set(&be->flm.v17.rcp[index].txplm, value, get);
			break;
		case HW_FLM_RCP_AUTO_IPV4_MASK:
			get_set(&be->flm.v17.rcp[index].auto_ipv4_mask, value, get);
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

int hw_mod_flm_rcp_set_mask(struct flow_api_backend_s *be, enum hw_flm_e field,
			    int index, uint32_t *value)
{
	if (field != HW_FLM_RCP_MASK)
		return error_unsup_ver(__func__, _MOD_, _VER_);
	return hw_mod_flm_rcp_mod(be, field, index, value, 0);
}

int hw_mod_flm_rcp_set(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t value)
{
	if (field == HW_FLM_RCP_MASK)
		return error_unsup_ver(__func__, _MOD_, _VER_);
	return hw_mod_flm_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_flm_rcp_get(struct flow_api_backend_s *be, enum hw_flm_e field,
		       int index, uint32_t *value)
{
	return hw_mod_flm_rcp_mod(be, field, index, value, 1);
}

int hw_mod_flm_buf_ctrl_update(struct flow_api_backend_s *be)
{
	return be->iface->flm_buf_ctrl_update(be->be_dev, &be->flm);
}

static int hw_mod_flm_buf_ctrl_mod_get(struct flow_api_backend_s *be,
				       enum hw_flm_e field, uint32_t *value)
{
	int get = 1; /* Only get supported */

	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_BUF_CTRL_LRN_FREE:
			get_set(&be->flm.v17.buf_ctrl->lrn_free, value, get);
			break;
		case HW_FLM_BUF_CTRL_INF_AVAIL:
			get_set(&be->flm.v17.buf_ctrl->inf_avail, value, get);
			break;
		case HW_FLM_BUF_CTRL_STA_AVAIL:
			get_set(&be->flm.v17.buf_ctrl->sta_avail, value, get);
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

int hw_mod_flm_buf_ctrl_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			    uint32_t *value)
{
	return hw_mod_flm_buf_ctrl_mod_get(be, field, value);
}

int hw_mod_flm_stat_update(struct flow_api_backend_s *be)
{
	return be->iface->flm_stat_update(be->be_dev, &be->flm);
}

int hw_mod_flm_stat_get(struct flow_api_backend_s *be, enum hw_flm_e field,
			uint32_t *value)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_STAT_LRN_DONE:
			*value = be->flm.v17.lrn_done->cnt;
			break;
		case HW_FLM_STAT_LRN_IGNORE:
			*value = be->flm.v17.lrn_ignore->cnt;
			break;
		case HW_FLM_STAT_LRN_FAIL:
			*value = be->flm.v17.lrn_fail->cnt;
			break;
		case HW_FLM_STAT_UNL_DONE:
			*value = be->flm.v17.unl_done->cnt;
			break;
		case HW_FLM_STAT_UNL_IGNORE:
			*value = be->flm.v17.unl_ignore->cnt;
			break;
		case HW_FLM_STAT_REL_DONE:
			*value = be->flm.v17.rel_done->cnt;
			break;
		case HW_FLM_STAT_REL_IGNORE:
			*value = be->flm.v17.rel_ignore->cnt;
			break;
		case HW_FLM_STAT_PRB_DONE:
			*value = be->flm.v17.prb_done->cnt;
			break;
		case HW_FLM_STAT_PRB_IGNORE:
			*value = be->flm.v17.prb_ignore->cnt;
			break;
		case HW_FLM_STAT_AUL_DONE:
			*value = be->flm.v17.aul_done->cnt;
			break;
		case HW_FLM_STAT_AUL_IGNORE:
			*value = be->flm.v17.aul_ignore->cnt;
			break;
		case HW_FLM_STAT_AUL_FAIL:
			*value = be->flm.v17.aul_fail->cnt;
			break;
		case HW_FLM_STAT_TUL_DONE:
			*value = be->flm.v17.tul_done->cnt;
			break;
		case HW_FLM_STAT_FLOWS:
			*value = be->flm.v17.flows->cnt;
			break;

		default: {
			if (_VER_ < 18)
				return error_unsup_field(__func__);

			switch (field) {
			case HW_FLM_STAT_STA_DONE:
				*value = be->flm.v20.sta_done->cnt;
				break;
			case HW_FLM_STAT_INF_DONE:
				*value = be->flm.v20.inf_done->cnt;
				break;
			case HW_FLM_STAT_INF_SKIP:
				*value = be->flm.v20.inf_skip->cnt;
				break;
			case HW_FLM_STAT_PCK_HIT:
				*value = be->flm.v20.pck_hit->cnt;
				break;
			case HW_FLM_STAT_PCK_MISS:
				*value = be->flm.v20.pck_miss->cnt;
				break;
			case HW_FLM_STAT_PCK_UNH:
				*value = be->flm.v20.pck_unh->cnt;
				break;
			case HW_FLM_STAT_PCK_DIS:
				*value = be->flm.v20.pck_dis->cnt;
				break;
			case HW_FLM_STAT_CSH_HIT:
				*value = be->flm.v20.csh_hit->cnt;
				break;
			case HW_FLM_STAT_CSH_MISS:
				*value = be->flm.v20.csh_miss->cnt;
				break;
			case HW_FLM_STAT_CSH_UNH:
				*value = be->flm.v20.csh_unh->cnt;
				break;
			case HW_FLM_STAT_CUC_START:
				*value = be->flm.v20.cuc_start->cnt;
				break;
			case HW_FLM_STAT_CUC_MOVE:
				*value = be->flm.v20.cuc_move->cnt;
				break;

			default:
				return error_unsup_field(__func__);
			}
		}
		break;
		}
		break;

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_flm_lrn_data_set_flush(struct flow_api_backend_s *be,
				  enum hw_flm_e field, const uint32_t *value)
{
	int ret = 0;

	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_FLOW_LRN_DATA_V17:
			ret = be->iface->flm_lrn_data_flush(be->be_dev,
				&be->flm, value,
				sizeof(struct flm_v17_lrn_data_s) /
				sizeof(uint32_t));
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;

	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return ret;
}

int hw_mod_flm_inf_data_update_get(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value,
				   uint32_t word_cnt)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_FLOW_INF_DATA_V17:
			be->iface->flm_inf_data_update(be->be_dev, &be->flm,
						       value, word_cnt);
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

int hw_mod_flm_sta_data_update_get(struct flow_api_backend_s *be,
				   enum hw_flm_e field, uint32_t *value)
{
	switch (_VER_) {
	case 17:
	case 20:
		switch (field) {
		case HW_FLM_FLOW_STA_DATA_V17:
			be->iface->flm_sta_data_update(be->be_dev,
				&be->flm, value,
				sizeof(struct flm_v17_sta_data_s) /
				sizeof(uint32_t));
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
