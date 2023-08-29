/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "KM"
#define _VER_ be->km.ver

#define KM_TCQ_ENTRIES 2048
#define KM_RCP_MASK_A_SIZE 11
#define KM_RCP_MASK_D_A_SIZE \
	12 /* Mask for double size word extractors for DW8/DW10 */
#define KM_RCP_MASK_B_SIZE 6

bool hw_mod_km_present(struct flow_api_backend_s *be)
{
	return be->iface->get_km_present(be->be_dev);
}

int hw_mod_km_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_km_version(be->be_dev);
	NT_LOG(DBG, FILTER, "KM  MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_km_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "km_categories", _MOD_, _VER_);
	be->km.nb_categories = (uint32_t)nb;

	nb = be->iface->get_nb_km_cam_banks(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "cam_banks", _MOD_, _VER_);
	be->km.nb_cam_banks = (uint32_t)nb;

	nb = be->iface->get_nb_km_cam_records(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "cam_records", _MOD_, _VER_);
	be->km.nb_cam_records = (uint32_t)nb;

	nb = be->iface->get_nb_km_cam_record_words(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "cam_record_words", _MOD_, _VER_);
	be->km.nb_cam_record_words = (uint32_t)nb;

	nb = be->iface->get_nb_km_tcam_banks(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tcam_banks", _MOD_, _VER_);
	be->km.nb_tcam_banks = (uint32_t)nb;

	nb = be->iface->get_nb_km_tcam_bank_width(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "tcam_bank_width", _MOD_, _VER_);
	be->km.nb_tcam_bank_width = (uint32_t)nb;

	switch (_VER_) {
	case 7:
		be->km.nb_km_rcp_mask_a_word_size = 12;
		be->km.nb_km_rcp_mask_b_word_size = 6;
		if (!callocate_mod(CAST_COMMON(&be->km), 5,
			&be->km.v7.rcp,
			be->km.nb_categories,
			sizeof(struct km_v7_rcp_s),
			&be->km.v7.cam,
			be->km.nb_cam_banks * be->km.nb_cam_records,
			sizeof(struct km_v7_cam_s),
			&be->km.v7.tcam,
			be->km.nb_tcam_banks * 4 * 256,
			sizeof(struct km_v7_tcam_s),
			&be->km.v7.tci,
			be->km.nb_tcam_banks * be->km.nb_tcam_bank_width,
			sizeof(struct km_v7_tci_s),
			&be->km.v7.tcq,
			KM_TCQ_ENTRIES,
			sizeof(struct km_v7_tcq_s)))
			return -1;
		break;
	/* end case 7 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

void hw_mod_km_free(struct flow_api_backend_s *be)
{
	if (be->km.base) {
		free(be->km.base);
		be->km.base = NULL;
	}
}

int hw_mod_km_reset(struct flow_api_backend_s *be)
{
	uint32_t tcam_v_set[3] = { 0x00000000, 0x00000000, 0x00000000 };
	/*  int err = 0; */

	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->km);

	NT_LOG(DBG, FILTER, "INIT KM RCP\n");
	hw_mod_km_rcp_flush(be, 0, ALL_ENTRIES);

	/* init CAM - all zero */
	NT_LOG(DBG, FILTER, "INIT KM CAM\n");
	hw_mod_km_cam_flush(be, 0, 0, ALL_ENTRIES);

	/* init TCAM - all zero */
	NT_LOG(DBG, FILTER, "INIT KM TCAM\n");
	for (unsigned int i = 0; i < be->km.nb_tcam_banks; i++) {
		/*
		 * TCAM entries are cache controlled, thus need to hard reset initially to sync
		 * cache with HW
		 */
		hw_mod_km_tcam_set(be, HW_KM_TCAM_BANK_RESET, i, 0, 0,
				   tcam_v_set);
	}
	hw_mod_km_tcam_flush(be, 0, ALL_ENTRIES);

	/* init TCI - all zero */
	NT_LOG(DBG, FILTER, "INIT KM TCI\n");
	hw_mod_km_tci_flush(be, 0, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT KM TCQ\n");
	for (unsigned int i = 0; i < be->km.nb_tcam_bank_width; i++)
		hw_mod_km_tcq_flush(be, 0, i, be->km.nb_tcam_banks);

	return 0;
}

int hw_mod_km_rcp_flush(struct flow_api_backend_s *be, int start_idx, int count)
{
	if (count == ALL_ENTRIES)
		count = be->km.nb_categories;
	if ((unsigned int)(start_idx + count) > be->km.nb_categories)
		return error_index_too_large(__func__);
	return be->iface->km_rcp_flush(be->be_dev, &be->km, start_idx, count);
}

static int hw_mod_km_rcp_mod(struct flow_api_backend_s *be, enum hw_km_e field,
			     int index, int word_off, uint32_t *value, int get)
{
	if ((unsigned int)index >= be->km.nb_categories)
		return error_index_too_large(__func__);

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_KM_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->km.v7.rcp[index], (uint8_t)*value,
			       sizeof(struct km_v7_rcp_s));
			break;
		case HW_KM_RCP_QW0_DYN:
			get_set(&be->km.v7.rcp[index].qw0_dyn, value, get);
			break;
		case HW_KM_RCP_QW0_OFS:
			get_set_signed(&be->km.v7.rcp[index].qw0_ofs, value, get);
			break;
		case HW_KM_RCP_QW0_SEL_A:
			get_set(&be->km.v7.rcp[index].qw0_sel_a, value, get);
			break;
		case HW_KM_RCP_QW0_SEL_B:
			get_set(&be->km.v7.rcp[index].qw0_sel_b, value, get);
			break;
		case HW_KM_RCP_QW4_DYN:
			get_set(&be->km.v7.rcp[index].qw4_dyn, value, get);
			break;
		case HW_KM_RCP_QW4_OFS:
			get_set_signed(&be->km.v7.rcp[index].qw4_ofs, value, get);
			break;
		case HW_KM_RCP_QW4_SEL_A:
			get_set(&be->km.v7.rcp[index].qw4_sel_a, value, get);
			break;
		case HW_KM_RCP_QW4_SEL_B:
			get_set(&be->km.v7.rcp[index].qw4_sel_b, value, get);
			break;
		case HW_KM_RCP_DW8_DYN:
			get_set(&be->km.v7.rcp[index].dw8_dyn, value, get);
			break;
		case HW_KM_RCP_DW8_OFS:
			get_set_signed(&be->km.v7.rcp[index].dw8_ofs, value, get);
			break;
		case HW_KM_RCP_DW8_SEL_A:
			get_set(&be->km.v7.rcp[index].dw8_sel_a, value, get);
			break;
		case HW_KM_RCP_DW8_SEL_B:
			get_set(&be->km.v7.rcp[index].dw8_sel_b, value, get);
			break;
		case HW_KM_RCP_DW10_DYN:
			get_set(&be->km.v7.rcp[index].dw10_dyn, value, get);
			break;
		case HW_KM_RCP_DW10_OFS:
			get_set_signed(&be->km.v7.rcp[index].dw10_ofs, value, get);
			break;
		case HW_KM_RCP_DW10_SEL_A:
			get_set(&be->km.v7.rcp[index].dw10_sel_a, value, get);
			break;
		case HW_KM_RCP_DW10_SEL_B:
			get_set(&be->km.v7.rcp[index].dw10_sel_b, value, get);
			break;
		case HW_KM_RCP_SWX_CCH:
			get_set(&be->km.v7.rcp[index].swx_cch, value, get);
			break;
		case HW_KM_RCP_SWX_SEL_A:
			get_set(&be->km.v7.rcp[index].swx_sel_a, value, get);
			break;
		case HW_KM_RCP_SWX_SEL_B:
			get_set(&be->km.v7.rcp[index].swx_sel_b, value, get);
			break;
		case HW_KM_RCP_MASK_A:
			if (word_off > KM_RCP_MASK_D_A_SIZE)
				return error_word_off_too_large(__func__);
			get_set(&be->km.v7.rcp[index].mask_d_a[word_off], value, get);
			break;
		case HW_KM_RCP_MASK_B:
			if (word_off > KM_RCP_MASK_B_SIZE)
				return error_word_off_too_large(__func__);
			get_set(&be->km.v7.rcp[index].mask_b[word_off], value, get);
			break;
		case HW_KM_RCP_DUAL:
			get_set(&be->km.v7.rcp[index].dual, value, get);
			break;
		case HW_KM_RCP_PAIRED:
			get_set(&be->km.v7.rcp[index].paired, value, get);
			break;
		case HW_KM_RCP_EL_A:
			get_set(&be->km.v7.rcp[index].el_a, value, get);
			break;
		case HW_KM_RCP_EL_B:
			get_set(&be->km.v7.rcp[index].el_b, value, get);
			break;
		case HW_KM_RCP_INFO_A:
			get_set(&be->km.v7.rcp[index].info_a, value, get);
			break;
		case HW_KM_RCP_INFO_B:
			get_set(&be->km.v7.rcp[index].info_b, value, get);
			break;
		case HW_KM_RCP_FTM_A:
			get_set(&be->km.v7.rcp[index].ftm_a, value, get);
			break;
		case HW_KM_RCP_FTM_B:
			get_set(&be->km.v7.rcp[index].ftm_b, value, get);
			break;
		case HW_KM_RCP_BANK_A:
			get_set(&be->km.v7.rcp[index].bank_a, value, get);
			break;
		case HW_KM_RCP_BANK_B:
			get_set(&be->km.v7.rcp[index].bank_b, value, get);
			break;
		case HW_KM_RCP_KL_A:
			get_set(&be->km.v7.rcp[index].kl_a, value, get);
			break;
		case HW_KM_RCP_KL_B:
			get_set(&be->km.v7.rcp[index].kl_b, value, get);
			break;
		case HW_KM_RCP_KEYWAY_A:
			get_set(&be->km.v7.rcp[index].keyway_a, value, get);
			break;
		case HW_KM_RCP_KEYWAY_B:
			get_set(&be->km.v7.rcp[index].keyway_b, value, get);
			break;
		case HW_KM_RCP_SYNERGY_MODE:
			get_set(&be->km.v7.rcp[index].synergy_mode, value, get);
			break;
		case HW_KM_RCP_DW0_B_DYN:
			get_set(&be->km.v7.rcp[index].dw0_b_dyn, value, get);
			break;
		case HW_KM_RCP_DW0_B_OFS:
			get_set_signed(&be->km.v7.rcp[index].dw0_b_ofs, value, get);
			break;
		case HW_KM_RCP_DW2_B_DYN:
			get_set(&be->km.v7.rcp[index].dw2_b_dyn, value, get);
			break;
		case HW_KM_RCP_DW2_B_OFS:
			get_set_signed(&be->km.v7.rcp[index].dw2_b_ofs, value, get);
			break;
		case HW_KM_RCP_SW4_B_DYN:
			get_set(&be->km.v7.rcp[index].sw4_b_dyn, value, get);
			break;
		case HW_KM_RCP_SW4_B_OFS:
			get_set_signed(&be->km.v7.rcp[index].sw4_b_ofs, value, get);
			break;
		case HW_KM_RCP_SW5_B_DYN:
			get_set(&be->km.v7.rcp[index].sw5_b_dyn, value, get);
			break;
		case HW_KM_RCP_SW5_B_OFS:
			get_set_signed(&be->km.v7.rcp[index].sw5_b_ofs, value, get);
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

int hw_mod_km_rcp_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int index, int word_off, uint32_t value)
{
	return hw_mod_km_rcp_mod(be, field, index, word_off, &value, 0);
}

int hw_mod_km_rcp_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int index, int word_off, uint32_t *value)
{
	return hw_mod_km_rcp_mod(be, field, index, word_off, value, 1);
}

int hw_mod_km_cam_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count)
{
	if (count == ALL_ENTRIES)
		count = be->km.nb_cam_records * be->km.nb_cam_banks;

	unsigned int end =
		start_bank * be->km.nb_cam_records + start_record + count;
	if (end > (be->km.nb_cam_banks * be->km.nb_cam_records))
		return error_index_too_large(__func__);

	return be->iface->km_cam_flush(be->be_dev, &be->km, start_bank,
				       start_record, count);
}

static int hw_mod_km_cam_mod(struct flow_api_backend_s *be, enum hw_km_e field,
			     int bank, int record, uint32_t *value, int get)
{
	if ((unsigned int)bank >= be->km.nb_cam_banks)
		return error_index_too_large(__func__);
	if ((unsigned int)record >= be->km.nb_cam_records)
		return error_index_too_large(__func__);

	unsigned int index = bank * be->km.nb_cam_records + record;

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_KM_CAM_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->km.v7.cam[index], (uint8_t)*value,
			       sizeof(struct km_v7_cam_s));
			break;
		case HW_KM_CAM_W0:
			get_set(&be->km.v7.cam[index].w0, value, get);
			break;
		case HW_KM_CAM_W1:
			get_set(&be->km.v7.cam[index].w1, value, get);
			break;
		case HW_KM_CAM_W2:
			get_set(&be->km.v7.cam[index].w2, value, get);
			break;
		case HW_KM_CAM_W3:
			get_set(&be->km.v7.cam[index].w3, value, get);
			break;
		case HW_KM_CAM_W4:
			get_set(&be->km.v7.cam[index].w4, value, get);
			break;
		case HW_KM_CAM_W5:
			get_set(&be->km.v7.cam[index].w5, value, get);
			break;
		case HW_KM_CAM_FT0:
			get_set(&be->km.v7.cam[index].ft0, value, get);
			break;
		case HW_KM_CAM_FT1:
			get_set(&be->km.v7.cam[index].ft1, value, get);
			break;
		case HW_KM_CAM_FT2:
			get_set(&be->km.v7.cam[index].ft2, value, get);
			break;
		case HW_KM_CAM_FT3:
			get_set(&be->km.v7.cam[index].ft3, value, get);
			break;
		case HW_KM_CAM_FT4:
			get_set(&be->km.v7.cam[index].ft4, value, get);
			break;
		case HW_KM_CAM_FT5:
			get_set(&be->km.v7.cam[index].ft5, value, get);
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

int hw_mod_km_cam_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t value)
{
	return hw_mod_km_cam_mod(be, field, bank, record, &value, 0);
}

int hw_mod_km_cam_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value)
{
	return hw_mod_km_cam_mod(be, field, bank, record, value, 1);
}

int hw_mod_km_tcam_flush(struct flow_api_backend_s *be, int start_bank,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->km.nb_tcam_banks * 4 * 256;
	else if (count == ALL_BANK_ENTRIES)
		count = 4 * 256;

	unsigned int end = start_bank * 4 * 256 + count;

	if (end > (be->km.nb_tcam_banks * 4 * 256))
		return error_index_too_large(__func__);

	return be->iface->km_tcam_flush(be->be_dev, &be->km, start_bank, 0, 0,
					count);
}

static int hw_mod_km_tcam_mod(struct flow_api_backend_s *be, enum hw_km_e field,
			      int bank, int byte, int byte_val,
			      uint32_t *value_set, int get)
{
	unsigned int start_index = bank * 4 * 256 + (int)byte * 256 + byte_val;

	if (start_index >= (be->km.nb_tcam_banks * 4 * 256))
		return error_index_too_large(__func__);

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_KM_TCAM_BANK_RESET:
			if (get)
				return error_unsup_field(__func__);
			{
				int start_idx = bank * 4 * 256;

				for (int i = 0; i < 4 * 256; i++) {
					be->km.v7.tcam[start_idx + i].t[0] =
						value_set[0];
					be->km.v7.tcam[start_idx + i].t[1] =
						value_set[1];
					be->km.v7.tcam[start_idx + i].t[2] =
						value_set[2];
					be->km.v7.tcam[start_idx + i].dirty = 1;
				}
			}
			break;
		case HW_KM_TCAM_T: {
			int index = bank * 4 * 256 + byte * 256 + byte_val;

			if (get) {
				value_set[0] = be->km.v7.tcam[index].t[0];
				value_set[1] = be->km.v7.tcam[index].t[1];
				value_set[2] = be->km.v7.tcam[index].t[2];
			} else {
				/* only change if any bits has to be changed */
				if (be->km.v7.tcam[index].t[0] !=
						value_set[0] ||
						be->km.v7.tcam[index].t[1] !=
						value_set[1] ||
						be->km.v7.tcam[index].t[2] !=
						value_set[2]) {
					be->km.v7.tcam[index].t[0] =
						value_set[0];
					be->km.v7.tcam[index].t[1] =
						value_set[1];
					be->km.v7.tcam[index].t[2] =
						value_set[2];
					be->km.v7.tcam[index].dirty = 1;
				}
			}
		}
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

int hw_mod_km_tcam_set(struct flow_api_backend_s *be, enum hw_km_e field,
		       int bank, int byte, int byte_val, uint32_t *value_set)
{
	return hw_mod_km_tcam_mod(be, field, bank, byte, byte_val, value_set,
				  0);
}

int hw_mod_km_tcam_get(struct flow_api_backend_s *be, enum hw_km_e field,
		       int bank, int byte, int byte_val, uint32_t *value_set)
{
	return hw_mod_km_tcam_mod(be, field, bank, byte, byte_val, value_set,
				  1);
}

int hw_mod_km_tci_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count)
{
	if (count == ALL_ENTRIES)
		count = be->km.nb_tcam_banks * be->km.nb_tcam_bank_width;

	unsigned int end = (int)start_bank * be->km.nb_tcam_bank_width +
			   start_record + count;

	if (end > (be->km.nb_tcam_banks * be->km.nb_tcam_bank_width))
		return error_index_too_large(__func__);

	return be->iface->km_tci_flush(be->be_dev, &be->km, start_bank,
				       start_record, count);
}

static int hw_mod_km_tci_mod(struct flow_api_backend_s *be, enum hw_km_e field,
			     int bank, int record, uint32_t *value, int get)
{
	unsigned int index = bank * be->km.nb_tcam_bank_width + record;

	if (index >= (be->km.nb_tcam_banks * be->km.nb_tcam_bank_width))
		return error_index_too_large(__func__);

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_KM_TCI_COLOR:
			get_set(&be->km.v7.tci[index].color, value, get);
			break;
		case HW_KM_TCI_FT:
			get_set(&be->km.v7.tci[index].ft, value, get);
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

int hw_mod_km_tci_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t value)
{
	return hw_mod_km_tci_mod(be, field, bank, record, &value, 0);
}

int hw_mod_km_tci_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value)
{
	return hw_mod_km_tci_mod(be, field, bank, record, value, 1);
}

int hw_mod_km_tcq_flush(struct flow_api_backend_s *be, int start_bank,
			int start_record, int count)
{
	if (count == ALL_ENTRIES)
		count = be->km.nb_tcam_banks * be->km.nb_tcam_bank_width;

	unsigned int end = (int)start_bank * be->km.nb_tcam_bank_width +
			   start_record + count;

	if (end > (be->km.nb_tcam_banks * be->km.nb_tcam_bank_width))
		return error_index_too_large(__func__);

	return be->iface->km_tcq_flush(be->be_dev, &be->km, start_bank,
				       start_record, count);
}

static int hw_mod_km_tcq_mod(struct flow_api_backend_s *be, enum hw_km_e field,
			     int bank, int record, uint32_t *value, int get)
{
	unsigned int index = bank * be->km.nb_tcam_bank_width + record;

	if (index >= (be->km.nb_tcam_banks * be->km.nb_tcam_bank_width))
		return error_index_too_large(__func__);

	switch (_VER_) {
	case 7:
		switch (field) {
		case HW_KM_TCQ_BANK_MASK:
			get_set(&be->km.v7.tcq[index].bank_mask, value, get);
			break;
		case HW_KM_TCQ_QUAL:
			get_set(&be->km.v7.tcq[index].qual, value, get);
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

int hw_mod_km_tcq_set(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value)
{
	return hw_mod_km_tcq_mod(be, field, bank, record, value, 0);
}

int hw_mod_km_tcq_get(struct flow_api_backend_s *be, enum hw_km_e field,
		      int bank, int record, uint32_t *value)
{
	return hw_mod_km_tcq_mod(be, field, bank, record, value, 1);
}
