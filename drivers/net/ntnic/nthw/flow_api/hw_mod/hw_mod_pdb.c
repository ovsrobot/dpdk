/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "flow_api_backend.h"

#define _MOD_ "PDB"
#define _VER_ be->pdb.ver

bool hw_mod_pdb_present(struct flow_api_backend_s *be)
{
	return be->iface->get_pdb_present(be->be_dev);
}

int hw_mod_pdb_alloc(struct flow_api_backend_s *be)
{
	int nb;

	_VER_ = be->iface->get_pdb_version(be->be_dev);
	NT_LOG(DBG, FILTER, "PDB MODULE VERSION  %i.%i\n", VER_MAJOR(_VER_),
	       VER_MINOR(_VER_));

	nb = be->iface->get_nb_pdb_categories(be->be_dev);
	if (nb <= 0)
		return error_resource_count(__func__, "pdb_categories", _MOD_, _VER_);
	be->pdb.nb_pdb_rcp_categories = (uint32_t)nb;

	switch (_VER_) {
	case 9:
		if (!callocate_mod(CAST_COMMON(&be->pdb), 2,
			&be->pdb.v9.rcp,
			be->pdb.nb_pdb_rcp_categories,
			sizeof(struct pdb_v9_rcp_s),
			&be->pdb.v9.config,
			1,
			sizeof(struct pdb_v9_config_s)))
			return -1;
		break;
	/* end case 9 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}
	return 0;
}

void hw_mod_pdb_free(struct flow_api_backend_s *be)
{
	if (be->pdb.base) {
		free(be->pdb.base);
		be->pdb.base = NULL;
	}
}

int hw_mod_pdb_reset(struct flow_api_backend_s *be)
{
	int err = 0;
	/* Zero entire cache area */
	ZERO_MOD_CACHE(&be->pdb);

	NT_LOG(DBG, FILTER, "INIT PDB RCP\n");
	err |= hw_mod_pdb_rcp_flush(be, 0, ALL_ENTRIES);

	NT_LOG(DBG, FILTER, "INIT PDB CONFIG\n");
	err |= hw_mod_pdb_config_flush(be);
	return err;
}

int hw_mod_pdb_rcp_flush(struct flow_api_backend_s *be, int start_idx,
			 int count)
{
	if (count == ALL_ENTRIES)
		count = be->pdb.nb_pdb_rcp_categories;
	if ((unsigned int)(start_idx + count) > be->pdb.nb_pdb_rcp_categories)
		return error_index_too_large(__func__);
	return be->iface->pdb_rcp_flush(be->be_dev, &be->pdb, start_idx, count);
}

static int hw_mod_pdb_rcp_mod(struct flow_api_backend_s *be,
			      enum hw_pdb_e field, uint32_t index,
			      uint32_t *value, int get)
{
	int rv = 0;
	if (index >= be->pdb.nb_pdb_rcp_categories)
		return error_index_too_large(__func__);
	switch (_VER_) {
	case 9:
		switch (field) {
		case HW_PDB_RCP_PRESET_ALL:
			if (get)
				return error_unsup_field(__func__);
			memset(&be->pdb.v9.rcp[index], (uint8_t)*value,
			       sizeof(struct pdb_v9_rcp_s));
			break;
		case HW_PDB_RCP_FIND:
			rv = find_equal_index(be->pdb.v9.rcp,
				sizeof(struct pdb_v9_rcp_s), index, *value,
				be->pdb.nb_pdb_rcp_categories, value, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_PDB_RCP_COMPARE:
			rv = do_compare_indexes(be->pdb.v9.rcp,
				sizeof(struct pdb_v9_rcp_s), index, *value,
				be->pdb.nb_pdb_rcp_categories, get, __func__);
			if (rv != 0)
				return rv;
			break;
		case HW_PDB_RCP_DESCRIPTOR:
			get_set(&be->pdb.v9.rcp[index].descriptor, value, get);
			break;
		case HW_PDB_RCP_DESC_LEN:
			get_set(&be->pdb.v9.rcp[index].desc_len, value, get);
			break;
		case HW_PDB_RCP_TX_PORT:
			get_set(&be->pdb.v9.rcp[index].tx_port, value, get);
			break;
		case HW_PDB_RCP_TX_IGNORE:
			get_set(&be->pdb.v9.rcp[index].tx_ignore, value, get);
			break;
		case HW_PDB_RCP_TX_NOW:
			get_set(&be->pdb.v9.rcp[index].tx_now, value, get);
			break;
		case HW_PDB_RCP_CRC_OVERWRITE:
			get_set(&be->pdb.v9.rcp[index].crc_overwrite, value, get);
			break;
		case HW_PDB_RCP_ALIGN:
			get_set(&be->pdb.v9.rcp[index].align, value, get);
			break;
		case HW_PDB_RCP_OFS0_DYN:
			get_set(&be->pdb.v9.rcp[index].ofs0_dyn, value, get);
			break;
		case HW_PDB_RCP_OFS0_REL:
			get_set_signed(&be->pdb.v9.rcp[index].ofs0_rel, value, get);
			break;
		case HW_PDB_RCP_OFS1_DYN:
			get_set(&be->pdb.v9.rcp[index].ofs1_dyn, value, get);
			break;
		case HW_PDB_RCP_OFS1_REL:
			get_set_signed(&be->pdb.v9.rcp[index].ofs1_rel, value, get);
			break;
		case HW_PDB_RCP_OFS2_DYN:
			get_set(&be->pdb.v9.rcp[index].ofs2_dyn, value, get);
			break;
		case HW_PDB_RCP_OFS2_REL:
			get_set_signed(&be->pdb.v9.rcp[index].ofs2_rel, value, get);
			break;
		case HW_PDB_RCP_IP_PROT_TNL:
			get_set(&be->pdb.v9.rcp[index].ip_prot_tnl, value, get);
			break;
		case HW_PDB_RCP_PPC_HSH:
			get_set(&be->pdb.v9.rcp[index].ppc_hsh, value, get);
			break;
		case HW_PDB_RCP_DUPLICATE_EN:
			get_set(&be->pdb.v9.rcp[index].duplicate_en, value, get);
			break;
		case HW_PDB_RCP_DUPLICATE_BIT:
			get_set(&be->pdb.v9.rcp[index].duplicate_bit, value, get);
			break;
		case HW_PDB_RCP_PCAP_KEEP_FCS:
			get_set(&be->pdb.v9.rcp[index].pcap_keep_fcs, value, get);
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 9 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}

int hw_mod_pdb_rcp_set(struct flow_api_backend_s *be, enum hw_pdb_e field,
		       uint32_t index, uint32_t value)
{
	return hw_mod_pdb_rcp_mod(be, field, index, &value, 0);
}

int hw_mod_pdb_rcp_get(struct flow_api_backend_s *be, enum hw_pdb_e field,
		       uint32_t index, uint32_t *value)
{
	return hw_mod_pdb_rcp_mod(be, field, index, value, 1);
}

int hw_mod_pdb_config_flush(struct flow_api_backend_s *be)
{
	return be->iface->pdb_config_flush(be->be_dev, &be->pdb);
}

int hw_mod_pdb_config_set(struct flow_api_backend_s *be, enum hw_pdb_e field,
			  uint32_t value)
{
	switch (_VER_) {
	case 9:
		switch (field) {
		case HW_PDB_CONFIG_TS_FORMAT:
			be->pdb.v9.config->ts_format = value;
			break;
		case HW_PDB_CONFIG_PORT_OFS:
			be->pdb.v9.config->port_ofs = value;
			break;

		default:
			return error_unsup_field(__func__);
		}
		break;
	/* end case 9 */
	default:
		return error_unsup_ver(__func__, _MOD_, _VER_);
	}

	return 0;
}
