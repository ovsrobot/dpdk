/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "ROA"
#define _VER_ be->roa.ver

#define ROA_LAGCFG_ENTRIES 512

bool hw_mod_roa_present(struct flow_api_backend_s *be)
{
	return be->iface->get_roa_present(be->be_dev);
}

int hw_mod_roa_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_roa_version(be->be_dev);
	NT_LOG(DBG, FILTER, "ROA MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_roa_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "roa_categories", _MOD_, _VER_);
	be->roa.nb_tun_categories = (uint32_t)nb;

	be->roa.nb_tun_categories /= 4;

	switch (_VER_) {
	case 6:
		be->roa.nb_lag_entries = ROA_LAGCFG_ENTRIES;
		if (!callocate_mod(CAST_COMMON(&be->roa), 4,
			&be->roa.v6.tunhdr,
			be->roa.nb_tun_categories,
			sizeof(struct roa_v6_tunhdr_s),
			&be->roa.v6.tuncfg,
			be->roa.nb_tun_categories,
			sizeof(struct roa_v6_tuncfg_s),
			&be->roa.v6.config,
			1,
			sizeof(struct roa_v6_config_s),
			&be->roa.v6.lagcfg,
			be->roa.nb_lag_entries,
			sizeof(struct roa_v6_lagcfg_s)))
			return -1;
		break;
	/* end case 6 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

void hw_mod_roa_free(struct flow_api_backend_s *be)
{
	if (be->roa.base) {
		free(be->roa.base);
		be->roa.base = NULL;
	}
}

int hw_mod_roa_reset(struct flow_api_backend_s *be)
{
	int err = 0;

	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->roa);

	NT_LOG(DBG, FILTER, "INIT ROA TUNHDR\n");
	err = hw_mod_roa_tunhdr_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT ROA TUNCFG\n");
	hw_mod_roa_tuncfg_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT ROA CONFIG\n");
	hw_mod_roa_config_set(be, HW_ROA_CONFIG_FWD_RECIRCULATE, 1);
	hw_mod_roa_config_set(be, HW_ROA_CONFIG_FWD_NORMAL_PCKS, 1);
	hw_mod_roa_config_set(be, HW_ROA_CONFIG_FWD_TXPORT0, 1);
	hw_mod_roa_config_set(be, HW_ROA_CONFIG_FWD_TXPORT1, 1);
	hw_mod_roa_config_flush(be);

	NT_LOG(DBG, FILTER, "INIT ROA LAGCFG\n");
	hw_mod_roa_lagcfg_flush(be, 0, ALL_ENTRIES);

	return err;
}

int hw_mod_roa_tunhdr_flush(struct flow_api_backend_s *be, int start_idx,
			    int count)
{
	if (count == ALL_ENTRIES)
		count = be->roa.nb_tun_categories;
	if ((unsigned int)(start_idx + count) > be->roa.nb_tun_categories)
		return error_index_too_large(__func__);
	return be->iface->roa_tunhdr_flush(be->be_dev, &be->roa, start_idx,
					   count);
}

static int hw_mod_roa_tunhdr_mod(struct flow_api_backend_s *be,
				 enum hw_roa_e field, uint32_t index,
				 uint32_t word_off, uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->roa.nb_tun_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 6:
		switch (field) {
		case HW_ROA_TUNHDR_COMPARE:
			rv = do_compare_indexes(be->roa.v6.tunhdr,
				sizeof(struct roa_v6_tunhdr_s), index, word_off,
				be->roa.nb_tun_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_ROA_TUNHDR:
			get_set(&be->roa.v6.tunhdr[index].tunnel_hdr[word_off],
				value, get);
			break;
		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 6 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_roa_tunhdr_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t word_off, uint32_t value)
{
	return hw_mod_roa_tunhdr_mod(be, field, index, word_off, &value, 0);
}

int hw_mod_roa_tunhdr_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t word_off, uint32_t *value)
{
	return hw_mod_roa_tunhdr_mod(be, field, index, word_off, value, 1);
}

int hw_mod_roa_tuncfg_flush(struct flow_api_backend_s *be, int start_idx,
			    int count)
{
	if (count == ALL_ENTRIES)
		count = be->roa.nb_tun_categories;
	if ((unsigned int)(start_idx + count) > be->roa.nb_tun_categories)
		return error_index_too_large(__func__);
	return be->iface->roa_tuncfg_flush(be->be_dev, &be->roa, start_idx,
					   count);
}

static int hw_mod_roa_tuncfg_mod(struct flow_api_backend_s *be,
				 enum hw_roa_e field, uint32_t index,
				 uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->roa.nb_tun_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 6:
		switch (field) {
		case HW_ROA_TUNCFG_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->roa.v6.tuncfg[index], (uint8_t)*value,
			       sizeof(struct roa_v6_tuncfg_s));
			break;
		case HW_ROA_TUNCFG_FIND:
			rv = find_equal_index(be->roa.v6.tuncfg,
				sizeof(struct roa_v6_tuncfg_s), index, *value,
				be->roa.nb_tun_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_ROA_TUNCFG_COMPARE:
			rv = do_compare_indexes(be->roa.v6.tuncfg,
				sizeof(struct roa_v6_tuncfg_s), index, *value,
				be->roa.nb_tun_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_ROA_TUNCFG_TUN_LEN:
			get_set(&be->roa.v6.tuncfg[index].tun_len, value, get);
			break;
		case HW_ROA_TUNCFG_TUN_TYPE:
			get_set(&be->roa.v6.tuncfg[index].tun_type, value, get);
			break;
		case HW_ROA_TUNCFG_TUN_VLAN:
			get_set(&be->roa.v6.tuncfg[index].tun_vlan, value, get);
			break;
		case HW_ROA_TUNCFG_IP_TYPE:
			get_set(&be->roa.v6.tuncfg[index].ip_type, value, get);
			break;
		case HW_ROA_TUNCFG_IPCS_UPD:
			get_set(&be->roa.v6.tuncfg[index].ipcs_upd, value, get);
			break;
		case HW_ROA_TUNCFG_IPCS_PRECALC:
			get_set(&be->roa.v6.tuncfg[index].ipcs_precalc, value, get);
			break;
		case HW_ROA_TUNCFG_IPTL_UPD:
			get_set(&be->roa.v6.tuncfg[index].iptl_upd, value, get);
			break;
		case HW_ROA_TUNCFG_IPTL_PRECALC:
			get_set(&be->roa.v6.tuncfg[index].iptl_precalc, value, get);
			break;
		case HW_ROA_TUNCFG_VXLAN_UDP_LEN_UPD:
			get_set(&be->roa.v6.tuncfg[index].vxlan_udp_len_upd,
				value, get);
			break;
		case HW_ROA_TUNCFG_TX_LAG_IX:
			get_set(&be->roa.v6.tuncfg[index].tx_lag_ix, value, get);
			break;
		case HW_ROA_TUNCFG_RECIRCULATE:
			get_set(&be->roa.v6.tuncfg[index].recirculate, value, get);
			break;
		case HW_ROA_TUNCFG_PUSH_TUNNEL:
			get_set(&be->roa.v6.tuncfg[index].push_tunnel, value, get);
			break;
		case HW_ROA_TUNCFG_RECIRC_PORT:
			get_set(&be->roa.v6.tuncfg[index].recirc_port, value, get);
			break;
		case HW_ROA_TUNCFG_RECIRC_BYPASS:
			get_set(&be->roa.v6.tuncfg[index].recirc_bypass, value, get);
			break;
		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 6 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_roa_tuncfg_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t value)
{
	return hw_mod_roa_tuncfg_mod(be, field, index, &value, 0);
}

int hw_mod_roa_tuncfg_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t *value)
{
	return hw_mod_roa_tuncfg_mod(be, field, index, value, 1);
}

int hw_mod_roa_config_flush(struct flow_api_backend_s *be)
{
	return be->iface->roa_config_flush(be->be_dev, &be->roa);
}

static int hw_mod_roa_config_mod(struct flow_api_backend_s *be,
				 enum hw_roa_e field, uint32_t *value, int get)
{
	switch (_VER_) {
	case 6:
		switch (field) {
		case HW_ROA_CONFIG_FWD_RECIRCULATE:
			get_set(&be->roa.v6.config->fwd_recirculate, value, get);
			break;
		case HW_ROA_CONFIG_FWD_NORMAL_PCKS:
			get_set(&be->roa.v6.config->fwd_normal_pcks, value, get);
			break;
		case HW_ROA_CONFIG_FWD_TXPORT0:
			get_set(&be->roa.v6.config->fwd_txport0, value, get);
			break;
		case HW_ROA_CONFIG_FWD_TXPORT1:
			get_set(&be->roa.v6.config->fwd_txport1, value, get);
			break;
		case HW_ROA_CONFIG_FWD_CELLBUILDER_PCKS:
			get_set(&be->roa.v6.config->fwd_cellbuilder_pcks, value, get);
			break;
		case HW_ROA_CONFIG_FWD_NON_NORMAL_PCKS:
			get_set(&be->roa.v6.config->fwd_non_normal_pcks, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 6 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_roa_config_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t value)
{
	return hw_mod_roa_config_mod(be, field, &value, 0);
}

int hw_mod_roa_config_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t *value)
{
	return hw_mod_roa_config_mod(be, field, value, 1);
}

int hw_mod_roa_lagcfg_flush(struct flow_api_backend_s *be, int start_idx,
			    int count)
{
	if (count == ALL_ENTRIES)
		count = be->roa.nb_lag_entries;
	if ((unsigned int)(start_idx + count) > be->roa.nb_lag_entries)
		return error_index_too_large(__func__);
	return be->iface->roa_lagcfg_flush(be->be_dev, &be->roa, start_idx,
					   count);
}

static int hw_mod_roa_lagcfg_mod(struct flow_api_backend_s *be,
				 enum hw_roa_e field, uint32_t index,
				 uint32_t *value, int get)
{
	if (index >= be->roa.nb_lag_entries)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 6:
		switch (field) {
		case HW_ROA_LAGCFG_TXPHY_PORT:
			get_set(&be->roa.v6.lagcfg[index].txphy_port, value, get);
			break;
		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 6 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_roa_lagcfg_set(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t value)
{
	return hw_mod_roa_lagcfg_mod(be, field, index, &value, 0);
}

int hw_mod_roa_lagcfg_get(struct flow_api_backend_s *be, enum hw_roa_e field,
			  uint32_t index, uint32_t *value)
{
	return hw_mod_roa_lagcfg_mod(be, field, index, value, 1);
}
