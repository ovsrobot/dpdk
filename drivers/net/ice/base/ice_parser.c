/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2021 Intel Corporation
 */

#include "ice_common.h"
#include "ice_parser_util.h"

#define ICE_SEC_DATA_OFFSET				4
#define ICE_SID_RXPARSER_IMEM_ENTRY_SIZE		48
#define ICE_SID_RXPARSER_METADATA_INIT_ENTRY_SIZE	24
#define ICE_SID_RXPARSER_CAM_ENTRY_SIZE			16
#define ICE_SID_RXPARSER_PG_SPILL_ENTRY_SIZE		17
#define ICE_SID_RXPARSER_NOMATCH_CAM_ENTRY_SIZE		12
#define ICE_SID_RXPARSER_NOMATCH_SPILL_ENTRY_SIZE	13
#define ICE_SID_RXPARSER_BOOST_TCAM_ENTRY_SIZE		88
#define ICE_SID_RXPARSER_MARKER_TYPE_ENTRY_SIZE		24
#define ICE_SID_RXPARSER_MARKER_GRP_ENTRY_SIZE		8
#define ICE_SID_RXPARSER_PROTO_GRP_ENTRY_SIZE		24
#define ICE_SID_RXPARSER_FLAG_REDIR_ENTRY_SIZE		1

#define ICE_SEC_LBL_DATA_OFFSET				2
#define ICE_SID_LBL_ENTRY_SIZE				66

void ice_lbl_dump(struct ice_hw *hw, struct ice_lbl_item *item)
{
	ice_info(hw, "index = %d\n", item->idx);
	ice_info(hw, "label = %s\n", item->label);
}

void ice_parse_item_dflt(struct ice_hw *hw, u16 idx, void *item,
			 void *data, int size)
{
	ice_memcpy(item, data, size, ICE_DMA_TO_NONDMA);
}

/**
 * ice_parser_sect_item_get - parse a item from a section
 * @sect_type: section type
 * @section: section object
 * @index: index of the item to get
 * @offset: dummy as prototype of ice_pkg_enum_entry's last parameter
 */
void *ice_parser_sect_item_get(u32 sect_type, void *section,
			       u32 index, u32 *offset)
{
	struct ice_pkg_sect_hdr *hdr;
	int data_off = ICE_SEC_DATA_OFFSET;
	int size;

	if (!section)
		return NULL;

	switch (sect_type) {
	case ICE_SID_RXPARSER_IMEM:
		size = ICE_SID_RXPARSER_IMEM_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_METADATA_INIT:
		size = ICE_SID_RXPARSER_METADATA_INIT_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_CAM:
		size = ICE_SID_RXPARSER_CAM_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_PG_SPILL:
		size = ICE_SID_RXPARSER_PG_SPILL_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_NOMATCH_CAM:
		size = ICE_SID_RXPARSER_NOMATCH_CAM_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_NOMATCH_SPILL:
		size = ICE_SID_RXPARSER_NOMATCH_SPILL_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_BOOST_TCAM:
		size = ICE_SID_RXPARSER_BOOST_TCAM_ENTRY_SIZE;
		break;
	case ICE_SID_LBL_RXPARSER_TMEM:
		data_off = ICE_SEC_LBL_DATA_OFFSET;
		size = ICE_SID_LBL_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_MARKER_PTYPE:
		size = ICE_SID_RXPARSER_MARKER_TYPE_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_MARKER_GRP:
		size = ICE_SID_RXPARSER_MARKER_GRP_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_PROTO_GRP:
		size = ICE_SID_RXPARSER_PROTO_GRP_ENTRY_SIZE;
		break;
	case ICE_SID_RXPARSER_FLAG_REDIR:
		size = ICE_SID_RXPARSER_FLAG_REDIR_ENTRY_SIZE;
		break;
	default:
		return NULL;
	}

	hdr = (struct ice_pkg_sect_hdr *)section;
	if (index >= LE16_TO_CPU(hdr->count))
		return NULL;

	return (void *)((uintptr_t)section + data_off + index * size);
}

/**
 * ice_parser_create_table - create a item table from a section
 * @hw: pointer to the hardware structure
 * @sect_type: section type
 * @item_size: item size in byte
 * @length: number of items in the table to create
 * @item_get: the function will be parsed to ice_pkg_enum_entry
 * @parser_item: the function to parse the item
 * @no_offset: ignore header offset, calculate index from 0
 */
void *ice_parser_create_table(struct ice_hw *hw, u32 sect_type,
			      u32 item_size, u32 length,
			      void *(*item_get)(u32 sect_type, void *section,
						u32 index, u32 *offset),
			      void (*parse_item)(struct ice_hw *hw, u16 idx,
						 void *item, void *data,
						 int size),
			      bool no_offset)
{
	struct ice_seg *seg = hw->seg;
	struct ice_pkg_enum state;
	u16 idx = 0xffff;
	void *table;
	void *data;

	if (!seg)
		return NULL;

	table = ice_malloc(hw, item_size * length);
	if (!table) {
		ice_debug(hw, ICE_DBG_PARSER, "failed to allocate memory for table type %d.\n",
			  sect_type);
		return NULL;
	}

	ice_memset(&state, 0, sizeof(state), ICE_NONDMA_MEM);
	do {
		data = ice_pkg_enum_entry(seg, &state, sect_type, NULL,
					  item_get);
		seg = NULL;
		if (data) {
			struct ice_pkg_sect_hdr *hdr =
				(struct ice_pkg_sect_hdr *)state.sect;

			if (no_offset)
				idx++;
			else
				idx = hdr->offset + state.entry_idx;
			parse_item(hw, idx,
				   (void *)((uintptr_t)table + idx * item_size),
				   data, item_size);
		}
	} while (data);

	return table;
}

/**
 * ice_parser_create - create a parser instance
 * @hw: pointer to the hardware structure
 * @psr: output parameter for a new parser instance be created
 */
enum ice_status ice_parser_create(struct ice_hw *hw, struct ice_parser **psr)
{
	enum ice_status status;
	struct ice_parser *p;

	p = (struct ice_parser *)ice_malloc(hw, sizeof(struct ice_parser));
	p->hw = hw;
	p->rt.psr = p;

	if (!p)
		return ICE_ERR_NO_MEMORY;

	p->hw = hw;

	p->imem_table = ice_imem_table_get(hw);
	if (!p->imem_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->mi_table = ice_metainit_table_get(hw);
	if (!p->mi_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->pg_cam_table = ice_pg_cam_table_get(hw);
	if (!p->pg_cam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->pg_sp_cam_table = ice_pg_sp_cam_table_get(hw);
	if (!p->pg_sp_cam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->pg_nm_cam_table = ice_pg_nm_cam_table_get(hw);
	if (!p->pg_nm_cam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->pg_nm_sp_cam_table = ice_pg_nm_sp_cam_table_get(hw);
	if (!p->pg_nm_sp_cam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->bst_tcam_table = ice_bst_tcam_table_get(hw);
	if (!p->bst_tcam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->bst_lbl_table = ice_bst_lbl_table_get(hw);
	if (!p->bst_lbl_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->ptype_mk_tcam_table = ice_ptype_mk_tcam_table_get(hw);
	if (!p->ptype_mk_tcam_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->mk_grp_table = ice_mk_grp_table_get(hw);
	if (!p->mk_grp_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->proto_grp_table = ice_proto_grp_table_get(hw);
	if (!p->proto_grp_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->flg_rd_table = ice_flg_rd_table_get(hw);
	if (!p->flg_rd_table) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->xlt_kb_sw = ice_xlt_kb_get_sw(hw);
	if (!p->xlt_kb_sw) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->xlt_kb_acl = ice_xlt_kb_get_acl(hw);
	if (!p->xlt_kb_acl) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->xlt_kb_fd = ice_xlt_kb_get_fd(hw);
	if (!p->xlt_kb_fd) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	p->xlt_kb_rss = ice_xlt_kb_get_rss(hw);
	if (!p->xlt_kb_rss) {
		status = ICE_ERR_PARAM;
		goto err;
	}

	*psr = p;
	return ICE_SUCCESS;
err:
	ice_parser_destroy(p);
	return status;
}

/**
 * ice_parser_destroy - destroy a parser instance
 * @psr: pointer to a parser instance
 */
void ice_parser_destroy(struct ice_parser *psr)
{
	ice_free(psr->hw, psr->imem_table);
	ice_free(psr->hw, psr->mi_table);
	ice_free(psr->hw, psr->pg_cam_table);
	ice_free(psr->hw, psr->pg_sp_cam_table);
	ice_free(psr->hw, psr->pg_nm_cam_table);
	ice_free(psr->hw, psr->pg_nm_sp_cam_table);
	ice_free(psr->hw, psr->bst_tcam_table);
	ice_free(psr->hw, psr->bst_lbl_table);
	ice_free(psr->hw, psr->ptype_mk_tcam_table);
	ice_free(psr->hw, psr->mk_grp_table);
	ice_free(psr->hw, psr->proto_grp_table);
	ice_free(psr->hw, psr->flg_rd_table);
	ice_free(psr->hw, psr->xlt_kb_sw);
	ice_free(psr->hw, psr->xlt_kb_acl);
	ice_free(psr->hw, psr->xlt_kb_fd);
	ice_free(psr->hw, psr->xlt_kb_rss);

	ice_free(psr->hw, psr);
}

/**
 * ice_parser_run - parse on a packet in binary and return the result
 * @psr: pointer to a parser instance
 * @pkt_buf: packet data
 * @pkt_len: packet length
 * @rslt: input/output parameter to save parser result.
 */
enum ice_status ice_parser_run(struct ice_parser *psr, const u8 *pkt_buf,
			       int pkt_len, struct ice_parser_result *rslt)
{
	ice_parser_rt_reset(&psr->rt);
	ice_parser_rt_pktbuf_set(&psr->rt, pkt_buf, pkt_len);

	return ice_parser_rt_execute(&psr->rt, rslt);
}

/**
 * ice_parser_result_dump - dump a parser result info
 * @hw: pointer to the hardware structure
 * @rslt: parser result info to dump
 */
void ice_parser_result_dump(struct ice_hw *hw, struct ice_parser_result *rslt)
{
	int i;

	ice_info(hw, "ptype = %d\n", rslt->ptype);
	for (i = 0; i < rslt->po_num; i++)
		ice_info(hw, "proto = %d, offset = %d\n",
			 rslt->po[i].proto_id, rslt->po[i].offset);

	ice_info(hw, "flags_psr = 0x%016" PRIx64 "\n", rslt->flags_psr);
	ice_info(hw, "flags_pkt = 0x%016" PRIx64 "\n", rslt->flags_pkt);
	ice_info(hw, "flags_sw = 0x%04x\n", rslt->flags_sw);
	ice_info(hw, "flags_fd = 0x%04x\n", rslt->flags_fd);
	ice_info(hw, "flags_rss = 0x%04x\n", rslt->flags_rss);
}

static void _bst_vm_set(struct ice_parser *psr, const char *prefix, bool on)
{
	struct ice_bst_tcam_item *item;
	u16 i = 0;

	while (true) {
		item = ice_bst_tcam_search(psr->bst_tcam_table,
					   psr->bst_lbl_table,
					   prefix, &i);
		if (!item)
			break;
		item->key[0] = (u8)(on ? 0xff : 0xfe);
		item->key_inv[0] = (u8)(on ? 0xff : 0xfe);
		i++;
	}
}

/**
 * ice_parser_dvm_set - configure double vlan mode for parser
 * @psr: pointer to a parser instance
 */
void ice_parser_dvm_set(struct ice_parser *psr, bool on)
{
	_bst_vm_set(psr, "BOOST_MAC_VLAN_DVM", on);
	_bst_vm_set(psr, "BOOST_MAC_VLAN_SVM", !on);
}
