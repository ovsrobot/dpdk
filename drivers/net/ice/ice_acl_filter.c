/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_eth_ctrl.h>
#include <rte_tailq.h>
#include <rte_flow_driver.h>
#include <rte_flow.h>
#include "base/ice_type.h"
#include "base/ice_acl.h"
#include "ice_logs.h"
#include "ice_ethdev.h"
#include "ice_generic_flow.h"
#include "base/ice_flow.h"

#define ICE_ACL_INSET_ETH_IPV4 ( \
	ICE_INSET_SMAC | ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST)
#define ICE_ACL_INSET_ETH_IPV4_UDP ( \
	ICE_INSET_SMAC | ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_UDP_SRC_PORT | ICE_INSET_UDP_DST_PORT)
#define ICE_ACL_INSET_ETH_IPV4_TCP ( \
	ICE_INSET_SMAC | ICE_INSET_IPV4_SRC | ICE_INSET_IPV4_DST | \
	ICE_INSET_TCP_SRC_PORT | ICE_INSET_TCP_DST_PORT)

enum ice_fd_stat_idx {
	ICE_FD_STAT_SB,
};

#define ICE_FD_STAT_CTR_BLOCK_COUNT	256
#define ICE_FD_STAT_PF_IDX(base_idx) \
	((base_idx) * ICE_FD_STAT_CTR_BLOCK_COUNT)
#define ICE_FD_SB_STAT_IDX(base_idx) \
	(ICE_FD_STAT_PF_IDX(base_idx) + ICE_FD_STAT_SB)

static struct ice_flow_parser ice_acl_parser;

static struct
ice_pattern_match_item ice_acl_pattern[] = {
	{pattern_eth_ipv4,     ICE_ACL_INSET_ETH_IPV4,     ICE_INSET_NONE},
	{pattern_eth_ipv4_udp, ICE_ACL_INSET_ETH_IPV4_UDP, ICE_INSET_NONE},
	{pattern_eth_ipv4_tcp, ICE_ACL_INSET_ETH_IPV4_TCP, ICE_INSET_NONE},
};

static int
ice_acl_prof_alloc(struct ice_hw *hw)
{
	enum ice_fltr_ptype ptype, fltr_ptype;

	if (!hw->acl_prof) {
		hw->acl_prof = (struct ice_fd_hw_prof **)
			ice_malloc(hw, ICE_FLTR_PTYPE_MAX *
				   sizeof(*hw->acl_prof));
		if (!hw->acl_prof)
			return -ENOMEM;
	}

	for (ptype = ICE_FLTR_PTYPE_NONF_NONE + 1;
	     ptype < ICE_FLTR_PTYPE_MAX; ptype++) {
		if (!hw->acl_prof[ptype]) {
			hw->acl_prof[ptype] = (struct ice_fd_hw_prof *)
				ice_malloc(hw, sizeof(**hw->acl_prof));
			if (!hw->acl_prof[ptype])
				goto fail_mem;
		}
	}

	return 0;

fail_mem:
	for (fltr_ptype = ICE_FLTR_PTYPE_NONF_IPV4_UDP;
	     fltr_ptype < ptype; fltr_ptype++) {
		rte_free(hw->acl_prof[fltr_ptype]);
		hw->acl_prof[fltr_ptype] = NULL;
	}

	rte_free(hw->acl_prof);
	return -ENOMEM;
}

/**
 * ice_acl_setup - Reserve and initialize the ACL resources
 * @pf: board private structure
 */
static int
ice_acl_setup(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->adapter->hw;
	u32 pf_num = hw->dev_caps.num_funcs;
	struct ice_acl_tbl_params params;
	int acl_ipv4_rules = 0;
	u16 scen_id;
	int err = 0;

	if (pf->adapter->devargs.acl_ipv4_rules_num)
		acl_ipv4_rules = pf->adapter->devargs.acl_ipv4_rules_num;
	else
		acl_ipv4_rules = ICE_AQC_ACL_TCAM_DEPTH;

	memset(&params, 0, sizeof(params));

	/* create for IPV4 table */
	if (acl_ipv4_rules) {
		if (pf_num < 4)
			params.width = ICE_AQC_ACL_KEY_WIDTH_BYTES * 5;
		else
			params.width = ICE_AQC_ACL_KEY_WIDTH_BYTES * 3;

		params.depth = acl_ipv4_rules;
		params.entry_act_pairs = 1;
		params.concurr = false;

		err = ice_acl_create_tbl(hw, &params);
		if (err)
			return err;

		err = ice_acl_create_scen(hw, params.width, params.depth,
					  &scen_id);
		if (err)
			return err;
	}

	return 0;
}

/**
 * ice_deinit_acl - Unroll the initialization of the ACL block
 * @pf: ptr to PF device
 *
 * returns 0 on success, negative on error
 */
static void ice_deinit_acl(struct ice_pf *pf)
{
	struct ice_hw *hw = &pf->adapter->hw;

	ice_acl_destroy_tbl(hw);
}

/**
 * ice_del_acl_entry - Delete an ACL rule entry
 * @hw: pointer to HW instance
 * @fltr: filter structure
 *
 * returns 0 on success and negative value on error
 */
static int
ice_del_acl_entry(struct ice_hw *hw, struct ice_fdir_fltr *fltr)
{
	uint64_t entry;

	entry = ice_flow_find_entry(hw, ICE_BLK_ACL, fltr->fltr_id);
	return ice_flow_rem_entry(hw, ICE_BLK_ACL, entry);
}

/**
 * ice_acl_erase_flow_from_hw - Remove a flow from the HW profile tables
 * @hw: hardware structure containing the filter list
 * @flow_type: flow type to release
 */
static void
ice_acl_erase_flow_from_hw(struct ice_hw *hw, enum ice_fltr_ptype flow_type)
{
	int tun;

	if (!hw->acl_prof || !hw->acl_prof[flow_type])
		return;

	struct ice_fd_hw_prof *prof = hw->acl_prof[flow_type];
	for (tun = 0; tun < ICE_FD_HW_SEG_TUN; tun++) {
		uint64_t prof_id;
		int j;

		prof_id = flow_type + tun * ICE_FLTR_PTYPE_MAX;
		for (j = 0; j < prof->cnt; j++) {
			uint16_t vsi_num;

			if (!prof->entry_h[j][tun] && !prof->vsi_h[j])
				continue;
			vsi_num = ice_get_hw_vsi_num(hw, prof->vsi_h[j]);
			ice_rem_prof_id_flow(hw, ICE_BLK_ACL, vsi_num, prof_id);
			ice_flow_rem_entry(hw, ICE_BLK_ACL,
					   prof->entry_h[j][tun]);
			prof->entry_h[j][tun] = 0;
		}
		ice_flow_rem_prof(hw, ICE_BLK_ACL, prof_id);
	}
}

/**
 * ice_acl_rem_flow - Release the ice_flow structures for a filter type
 * @hw: hardware structure containing the filter list
 * @flow_type: flow type to release
 */
static void ice_acl_rem_flow(struct ice_hw *hw, enum ice_fltr_ptype flow_type)
{
	struct ice_fd_hw_prof *prof;
	int tun, i;

	if (!hw->acl_prof || !hw->acl_prof[flow_type])
		return;

	prof = hw->acl_prof[flow_type];

	ice_acl_erase_flow_from_hw(hw, flow_type);
	for (i = 0; i < prof->cnt; i++)
		prof->vsi_h[i] = 0;
	for (tun = 0; tun < ICE_FD_HW_SEG_MAX; tun++) {
		if (!prof->fdir_seg[tun])
			continue;
		ice_free(hw, prof->fdir_seg[tun]);
		prof->fdir_seg[tun] = NULL;
	}
	prof->cnt = 0;
}

/**
 * ice_acl_update_list_entry - Add or delete a filter from the filter list
 * @pf: PF structure
 * @input: filter structure
 * @fltr_idx: index of filter to modify
 *
 * returns 0 on success and negative on errors
 */
static int
ice_acl_update_list_entry(struct ice_pf *pf, struct ice_fdir_fltr *input,
			   int fltr_idx)
{
	struct ice_fdir_fltr *old_fltr;
	int err = 0;
	struct ice_hw *hw;

	hw = &pf->adapter->hw;
	old_fltr = ice_fdir_find_fltr_by_idx(hw, fltr_idx);
	if (old_fltr) {
		if (old_fltr->acl_fltr) {
			/* ACL filter */
			if (!input) {
				err = ice_del_acl_entry(hw, old_fltr);
				if (err)
					return err;
			}
		}
		ice_fdir_update_cntrs(hw, old_fltr->flow_type,
				      old_fltr->acl_fltr, false);
		/* we just deleted the last filter of flow_type so we
		 * should also delete the HW filter info.
		 */
		if (old_fltr->acl_fltr && !input &&
		    !hw->acl_fltr_cnt[old_fltr->flow_type])
			ice_acl_rem_flow(hw, old_fltr->flow_type);

		LIST_DEL(&old_fltr->fltr_node);
		ice_free(hw, old_fltr);
	}

	if (!input)
		return err;

	ice_fdir_list_add_fltr(hw, input);
	ice_fdir_update_cntrs(hw, input->flow_type, input->acl_fltr, true);

	return 0;
}

/**
 * ice_acl_check_input_set - Check that a given ACL input set is valid
 * @pf: ice PF structure
 * @filter: pointer to ACL info
 *
 * Returns 0 on success.
 */
static int
ice_acl_check_input_set(struct ice_pf *pf, struct ice_acl_info *filter)
{
	struct ice_fd_hw_prof *hw_prof = NULL;
	struct ice_flow_prof *prof = NULL;
	struct ice_flow_seg_info *old_seg;
	struct ice_flow_seg_info *seg;
	enum ice_fltr_ptype fltr_type = filter->input.flow_type;
	struct ice_hw *hw = &pf->adapter->hw;
	enum ice_status status;
	u16 val_loc, mask_loc;
	struct ice_fdir_v4 *ip4_mask;
	uint64_t prof_id;

	seg = (struct ice_flow_seg_info *)
		ice_malloc(hw, sizeof(*seg));
	if (!seg) {
		PMD_DRV_LOG(ERR, "No memory can be allocated");
		return -ENOMEM;
	}

	switch (fltr_type) {
	case ICE_FLTR_PTYPE_NONF_IPV4_TCP:
	case ICE_FLTR_PTYPE_NONF_IPV4_UDP:
		ip4_mask = &filter->input.mask.v4;

		/* make sure we don't have any empty rule */
		if (!ip4_mask->src_ip && !ip4_mask->src_port &&
		    !ip4_mask->dst_ip && !ip4_mask->dst_port) {
			goto err_exit;

			/* filtering on TOS not supported */
			if (ip4_mask->tos)
				goto err_exit;
		}

		if (hw->dev_caps.num_funcs < 4) {
			/* mac source address */
			val_loc = offsetof(struct ice_fdir_fltr,
					   ext_data.src_mac);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    ext_mask.src_mac);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_SA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);

			/* mac destination address */
			val_loc = offsetof(struct ice_fdir_fltr,
					   ext_data.dst_mac);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    ext_mask.dst_mac);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_DA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		}

		/* IP source address */
		val_loc = offsetof(struct ice_fdir_fltr, ip.v4.src_ip);
		mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.src_ip);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA, val_loc,
				 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);

		/* IP destination address */
		val_loc = offsetof(struct ice_fdir_fltr, ip.v4.dst_ip);
		mask_loc = offsetof(struct ice_fdir_fltr, mask.v4.dst_ip);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA, val_loc,
				 mask_loc, ICE_FLOW_FLD_OFF_INVAL, false);
		break;
	case ICE_FLTR_PTYPE_NONF_IPV4_OTHER:
		ip4_mask = &filter->input.mask.v4;

		if (ip4_mask->tos)
			goto err_exit;
		if (ip4_mask->ip_ver)
			goto err_exit;
		/* Filtering on Layer 4 protocol not supported */
		if (ip4_mask->proto)
			goto err_exit;
		/* empty rules are not valid */
		if (!ip4_mask->src_ip && !ip4_mask->dst_ip)
			goto err_exit;

		if (hw->dev_caps.num_funcs < 4) {
			/* mac source address */
			val_loc = offsetof(struct ice_fdir_fltr,
					   ext_data.src_mac);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    ext_mask.src_mac);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_SA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);

			/* mac destination address */
			val_loc = offsetof(struct ice_fdir_fltr,
					   ext_data.dst_mac);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    ext_mask.dst_mac);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_ETH_DA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		}

		if (ip4_mask->src_ip != 0) {
			/* IP source address */
			val_loc = offsetof(struct ice_fdir_fltr,
					   ip.v4.src_ip);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    mask.v4.src_ip);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_SA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		}

		if (ip4_mask->dst_ip != 0) {
			/* IP destination address */
			val_loc = offsetof(struct ice_fdir_fltr, ip.v4.dst_ip);
			mask_loc = offsetof(struct ice_fdir_fltr,
					    mask.v4.dst_ip);

			ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_IPV4_DA,
					 val_loc, mask_loc,
					 ICE_FLOW_FLD_OFF_INVAL, false);
		}
		break;
	default:
		goto err_exit;
	}

	switch (fltr_type) {
	case ICE_FLTR_PTYPE_NONF_IPV4_TCP:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_TCP |
				  ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_ETH);
		ip4_mask = &filter->input.mask.v4;

		/* Layer 4 source port */
		val_loc = offsetof(struct ice_fdir_fltr,
				   ip.v4.src_port);
		mask_loc = offsetof(struct ice_fdir_fltr,
				    mask.v4.src_port);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_SRC_PORT,
				 val_loc, mask_loc,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		val_loc = offsetof(struct ice_fdir_fltr,
				   ip.v4.dst_port);
		mask_loc = offsetof(struct ice_fdir_fltr,
				    mask.v4.dst_port);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_TCP_DST_PORT,
				 val_loc, mask_loc,
				 ICE_FLOW_FLD_OFF_INVAL, false);
		break;
	case ICE_FLTR_PTYPE_NONF_IPV4_UDP:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_UDP |
				  ICE_FLOW_SEG_HDR_IPV4 | ICE_FLOW_SEG_HDR_ETH);
		ip4_mask = &filter->input.mask.v4;

		/* Layer 4 source port */
		val_loc = offsetof(struct ice_fdir_fltr,
				   ip.v4.src_port);
		mask_loc = offsetof(struct ice_fdir_fltr,
				    mask.v4.src_port);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_SRC_PORT,
				 val_loc, mask_loc,
				 ICE_FLOW_FLD_OFF_INVAL, false);

		/* Layer 4 destination port */
		val_loc = offsetof(struct ice_fdir_fltr,
				   ip.v4.dst_port);
		mask_loc = offsetof(struct ice_fdir_fltr,
				    mask.v4.dst_port);

		ice_flow_set_fld(seg, ICE_FLOW_FIELD_IDX_UDP_DST_PORT,
				 val_loc, mask_loc,
				 ICE_FLOW_FLD_OFF_INVAL, false);
		break;
	case ICE_FLTR_PTYPE_NONF_IPV4_OTHER:
		ICE_FLOW_SET_HDRS(seg, ICE_FLOW_SEG_HDR_IPV4 |
				  ICE_FLOW_SEG_HDR_ETH);
		break;
	default:
		goto err_exit;
	}

	hw_prof = hw->acl_prof[fltr_type];
	old_seg = hw_prof->fdir_seg[0];
	if (old_seg) {
		/* This flow_type already has an input set.
		 * If it matches the requested input set then we are
		 * done. If it's different then it's an error.
		 */
		if (!memcmp(old_seg, seg, sizeof(*seg))) {
			PMD_DRV_LOG(ERR, "Rule already exists!");
			goto err_exit;
		}

		/* remove HW filter definition */
		ice_acl_rem_flow(hw, fltr_type);

		goto err_exit;
	}

	/* Adding a profile for the given flow specification with no
	 * actions (NULL) and zero actions 0.
	 */
	prof_id = fltr_type;
	status = ice_flow_add_prof(hw, ICE_BLK_ACL, ICE_FLOW_RX, prof_id,
				   seg, 1, NULL, 0, &prof);
	if (status)
		goto err_exit;

	hw_prof->fdir_seg[0] = seg;
	return 0;

err_exit:
	ice_free(hw, seg);
	return -EINVAL;
}

/**
 * ice_acl_set_input_set - Helper function to set the input set for ACL
 * @hw: pointer to HW instance
 * @filter: pointer to ACL info
 * @input: filter structure
 *
 * Return error value or 0 on success.
 */
static int
ice_acl_set_input_set(struct ice_hw *hw, struct ice_acl_info *filter,
		      struct ice_fdir_fltr *input)
{
	if (!input)
		return ICE_ERR_BAD_PTR;

	input->fltr_id = filter->input.fltr_id;
	input->q_index = filter->input.q_index;
	input->dest_vsi = filter->input.dest_vsi;
	input->dest_ctl = filter->input.dest_ctl;
	input->fltr_status = ICE_FLTR_PRGM_DESC_FD_STATUS_FD_ID;
	input->cnt_index = ICE_FD_SB_STAT_IDX(hw->fd_ctr_base);
	input->flow_type = filter->input.flow_type;

	switch (input->flow_type) {
	case ICE_FLTR_PTYPE_NONF_IPV4_TCP:
	case ICE_FLTR_PTYPE_NONF_IPV4_UDP:
		input->ip.v4.dst_port = filter->input.ip.v4.dst_port;
		input->ip.v4.src_port = filter->input.ip.v4.src_port;
		input->ip.v4.dst_ip = filter->input.ip.v4.dst_ip;
		input->ip.v4.src_ip = filter->input.ip.v4.src_ip;

		input->mask.v4.dst_port = filter->input.mask.v4.dst_port;
		input->mask.v4.src_port = filter->input.mask.v4.src_port;
		input->mask.v4.dst_ip = filter->input.mask.v4.dst_ip;
		input->mask.v4.src_ip = filter->input.mask.v4.src_ip;

		rte_memcpy(&input->ext_data.src_mac,
			   &filter->input.ext_data.src_mac,
			   RTE_ETHER_ADDR_LEN);
		rte_memcpy(&input->ext_mask.src_mac,
			   &filter->input.ext_mask.src_mac,
			   RTE_ETHER_ADDR_LEN);

		rte_memcpy(&input->ext_data.dst_mac,
			   &filter->input.ext_data.dst_mac,
			   RTE_ETHER_ADDR_LEN);
		rte_memcpy(&input->ext_mask.dst_mac,
			   &filter->input.ext_mask.dst_mac,
			   RTE_ETHER_ADDR_LEN);

		break;
	case ICE_FLTR_PTYPE_NONF_IPV4_OTHER:
		rte_memcpy(&input->ip.v4, &filter->input.ip.v4,
			   sizeof(struct ice_fdir_v4));
		rte_memcpy(&input->mask.v4, &filter->input.mask.v4,
			   sizeof(struct ice_fdir_v4));

		rte_memcpy(&input->ext_data.src_mac,
			   &filter->input.ext_data.src_mac,
			   RTE_ETHER_ADDR_LEN);
		rte_memcpy(&input->ext_mask.src_mac,
			   &filter->input.ext_mask.src_mac,
			   RTE_ETHER_ADDR_LEN);

		rte_memcpy(&input->ext_data.dst_mac,
			   &filter->input.ext_data.dst_mac,
			   RTE_ETHER_ADDR_LEN);
		rte_memcpy(&input->ext_mask.dst_mac,
			   &filter->input.ext_mask.dst_mac,
			   RTE_ETHER_ADDR_LEN);

		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int
ice_acl_create_filter(struct ice_adapter *ad,
		struct rte_flow *flow,
		void *meta,
		struct rte_flow_error *error)
{
	struct ice_pf *pf = &ad->pf;
	struct ice_hw *hw = &ad->hw;
	struct ice_acl_info *filter = meta;
	struct ice_fdir_fltr *input;
	struct ice_flow_action acts[1];
	int act_cnt;
	struct ice_fd_hw_prof *hw_prof = NULL;
	enum ice_block blk = ICE_BLK_ACL;
	enum ice_fltr_ptype flow_type = filter->input.flow_type;
	int ret;
	u64 entry_h = 0;
	uint64_t prof_id;
	int i;

	input = rte_zmalloc("acl_entry", sizeof(*input), 0);
	if (!input) {
		rte_flow_error_set(error, ENOMEM,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Failed to allocate memory");
		return -rte_errno;
	}

	ret = ice_acl_check_input_set(pf, filter);
	if (ret) {
		rte_flow_error_set(error, -ret,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Profile configure failed.");
		goto free_input;
	}

	ret = ice_acl_set_input_set(hw, filter, input);
	if (ret) {
		rte_flow_error_set(error, -ret,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "failed to set input set.");
		goto free_input;
	}

	act_cnt = 1;
	if (filter->input.dest_ctl == ICE_FLTR_PRGM_DESC_DEST_DROP_PKT) {
		acts[0].type = ICE_FLOW_ACT_DROP;
		acts[0].data.acl_act.mdid = ICE_MDID_RX_PKT_DROP;
		acts[0].data.acl_act.prio = 0x3;
		acts[0].data.acl_act.value = CPU_TO_LE16(0x1);
	}

	hw_prof = hw->acl_prof[flow_type];
	prof_id = flow_type;

	for (i = 0; i < pf->main_vsi->idx; i++) {
		ret = ice_flow_add_entry(hw, blk, prof_id, input->fltr_id, i,
					 ICE_FLOW_PRIO_NORMAL, input, acts,
					 act_cnt, &entry_h);
		if (ret) {
			rte_flow_error_set(error, -ret,
				   RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				   "Flow add entry error.");
			goto free_input;
		}
	}

	if (!hw_prof->cnt || 0 != hw_prof->vsi_h[hw_prof->cnt - 1]) {
		hw_prof->vsi_h[hw_prof->cnt] = 0;
		hw_prof->entry_h[hw_prof->cnt++][0] = entry_h;
	}

	input->acl_fltr = true;
	/* input struct is added to the HW filter list */
	ice_acl_update_list_entry(pf, input, input->fltr_id);

	flow->rule = input;

	return 0;

free_input:
	rte_free(input);
	return -rte_errno;
}

static int
ice_acl_destroy_filter(struct ice_adapter *ad,
		struct rte_flow *flow,
		struct rte_flow_error *error __rte_unused)
{
	struct ice_fdir_fltr *filter = (struct ice_fdir_fltr *)flow->rule;
	int ret;

	ret = ice_acl_update_list_entry(&ad->pf, NULL, filter->fltr_id);

	flow->rule = NULL;
	rte_free(filter);

	return ret;
}

static void
ice_acl_filter_free(struct rte_flow *flow)
{
	rte_free(flow->rule);
}

static int
ice_acl_parse_action(__rte_unused struct ice_adapter *ad,
		      const struct rte_flow_action actions[],
		      struct rte_flow_error *error,
		      struct ice_acl_info *filter)
{
	uint32_t dest_num = 0;

	for (; actions->type != RTE_FLOW_ACTION_TYPE_END; actions++) {
		switch (actions->type) {
		case RTE_FLOW_ACTION_TYPE_VOID:
			break;
		case RTE_FLOW_ACTION_TYPE_DROP:
			dest_num++;

			filter->input.dest_ctl =
				ICE_FLTR_PRGM_DESC_DEST_DROP_PKT;
			break;
		default:
			rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ACTION, actions,
				   "Invalid action.");
			return -rte_errno;
		}
	}

	if (dest_num == 0 || dest_num >= 2) {
		rte_flow_error_set(error, EINVAL,
			   RTE_FLOW_ERROR_TYPE_ACTION, actions,
			   "Unsupported action combination");
		return -rte_errno;
	}

	return 0;
}

static int
ice_acl_parse_pattern(__rte_unused struct ice_adapter *ad,
		       const struct rte_flow_item pattern[],
		       struct rte_flow_error *error,
		       struct ice_acl_info *filter)
{
	const struct rte_flow_item *item = pattern;
	enum rte_flow_item_type item_type;
	enum rte_flow_item_type l3 = RTE_FLOW_ITEM_TYPE_END;
	const struct rte_flow_item_eth *eth_spec, *eth_mask;
	const struct rte_flow_item_ipv4 *ipv4_spec, *ipv4_mask;
	const struct rte_flow_item_tcp *tcp_spec, *tcp_mask;
	const struct rte_flow_item_udp *udp_spec, *udp_mask;
	uint64_t input_set = ICE_INSET_NONE;
	uint8_t flow_type = ICE_FLTR_PTYPE_NONF_NONE;

	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		item_type = item->type;

		switch (item_type) {
		case RTE_FLOW_ITEM_TYPE_ETH:
			eth_spec = item->spec;
			eth_mask = item->mask;

			if (eth_spec && eth_mask) {
				if (rte_is_broadcast_ether_addr(&eth_mask->dst) ||
				    rte_is_broadcast_ether_addr(&eth_mask->src)) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid mac addr mask");
					return -rte_errno;
				}

				if (!rte_is_zero_ether_addr(&eth_spec->src) &&
				    !rte_is_zero_ether_addr(&eth_mask->src)) {
					input_set |= ICE_INSET_SMAC;
					rte_memcpy(&filter->input.ext_data.src_mac,
						   &eth_spec->src,
						   RTE_ETHER_ADDR_LEN);
					rte_memcpy(&filter->input.ext_mask.src_mac,
						   &eth_mask->src,
						   RTE_ETHER_ADDR_LEN);
				}

				if (!rte_is_zero_ether_addr(&eth_spec->dst) &&
				    !rte_is_zero_ether_addr(&eth_mask->dst)) {
					input_set |= ICE_INSET_DMAC;
					rte_memcpy(&filter->input.ext_data.dst_mac,
						   &eth_spec->dst,
						   RTE_ETHER_ADDR_LEN);
					rte_memcpy(&filter->input.ext_mask.dst_mac,
						   &eth_mask->dst,
						   RTE_ETHER_ADDR_LEN);
				}
			}
			break;
		case RTE_FLOW_ITEM_TYPE_IPV4:
			l3 = RTE_FLOW_ITEM_TYPE_IPV4;
			ipv4_spec = item->spec;
			ipv4_mask = item->mask;

			if (ipv4_spec && ipv4_mask) {
				/* Check IPv4 mask and update input set */
				if (ipv4_mask->hdr.version_ihl ||
				    ipv4_mask->hdr.total_length ||
				    ipv4_mask->hdr.packet_id ||
				    ipv4_mask->hdr.fragment_offset ||
				    ipv4_mask->hdr.hdr_checksum) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid IPv4 mask.");
					return -rte_errno;
				}

				if ((ipv4_mask->hdr.src_addr == UINT32_MAX) ||
				    (ipv4_mask->hdr.dst_addr == UINT32_MAX)) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid IPv4 mask.");
					return -rte_errno;
				}

				if ((ipv4_spec->hdr.src_addr != 0) &&
				    (ipv4_mask->hdr.src_addr != 0)) {
					filter->input.ip.v4.src_ip =
						ipv4_spec->hdr.src_addr;
					filter->input.mask.v4.src_ip =
						ipv4_mask->hdr.src_addr;

					input_set |= ICE_INSET_IPV4_SRC;
				}

				if ((ipv4_spec->hdr.dst_addr != 0) &&
				    (ipv4_mask->hdr.dst_addr != 0)) {
					filter->input.ip.v4.dst_ip =
						ipv4_spec->hdr.dst_addr;
					filter->input.mask.v4.dst_ip =
						ipv4_mask->hdr.dst_addr;

					input_set |= ICE_INSET_IPV4_DST;
				}
			}

			flow_type = ICE_FLTR_PTYPE_NONF_IPV4_OTHER;
			break;
		case RTE_FLOW_ITEM_TYPE_TCP:
			tcp_spec = item->spec;
			tcp_mask = item->mask;

			if (tcp_spec && tcp_mask) {
				/* Check TCP mask and update input set */
				if (tcp_mask->hdr.sent_seq ||
				    tcp_mask->hdr.recv_ack ||
				    tcp_mask->hdr.data_off ||
				    tcp_mask->hdr.tcp_flags ||
				    tcp_mask->hdr.rx_win ||
				    tcp_mask->hdr.cksum ||
				    tcp_mask->hdr.tcp_urp) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid TCP mask");
					return -rte_errno;
				}

				if ((tcp_mask->hdr.src_port == UINT16_MAX) ||
				    (tcp_mask->hdr.dst_port == UINT16_MAX)) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid TCP mask");
					return -rte_errno;
				}

				if ((tcp_mask->hdr.src_port == UINT16_MAX) ||
				    (tcp_mask->hdr.dst_port == UINT16_MAX)) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid TCP mask");
					return -rte_errno;
				}

				if ((l3 == RTE_FLOW_ITEM_TYPE_IPV4) &&
				    (tcp_spec->hdr.src_port != 0)) {
					input_set |= ICE_INSET_TCP_SRC_PORT;
					filter->input.ip.v4.src_port =
						tcp_spec->hdr.src_port;
					filter->input.mask.v4.src_port =
						tcp_mask->hdr.src_port;
				}

				if ((l3 == RTE_FLOW_ITEM_TYPE_IPV4) &&
				    (tcp_spec->hdr.dst_port != 0)) {
					input_set |= ICE_INSET_TCP_DST_PORT;
					filter->input.ip.v4.dst_port =
						tcp_spec->hdr.dst_port;
					filter->input.mask.v4.dst_port =
						tcp_mask->hdr.dst_port;
				}

				if (l3 == RTE_FLOW_ITEM_TYPE_IPV4)
					flow_type =
						ICE_FLTR_PTYPE_NONF_IPV4_TCP;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_UDP:
			udp_spec = item->spec;
			udp_mask = item->mask;

			if (udp_spec && udp_mask) {
				/* Check UDP mask and update input set*/
				if (udp_mask->hdr.dgram_len ||
				    udp_mask->hdr.dgram_cksum) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid UDP mask");
					return -rte_errno;
				}

				if ((udp_mask->hdr.src_port == UINT16_MAX) ||
				    (udp_mask->hdr.dst_port == UINT16_MAX)) {
					rte_flow_error_set(error, EINVAL,
						RTE_FLOW_ERROR_TYPE_ITEM,
						item,
						"Invalid UDP mask");
					return -rte_errno;
				}

				/* Get filter info */
				if ((l3 == RTE_FLOW_ITEM_TYPE_IPV4) &&
				    (udp_spec->hdr.src_port != 0)) {
					input_set |= ICE_INSET_UDP_SRC_PORT;
					filter->input.ip.v4.src_port =
						udp_spec->hdr.src_port;
					filter->input.mask.v4.src_port =
						udp_mask->hdr.src_port;
				}

				if ((l3 == RTE_FLOW_ITEM_TYPE_IPV4) &&
				    (udp_spec->hdr.dst_port != 0)) {
					input_set |= ICE_INSET_UDP_DST_PORT;
					filter->input.ip.v4.dst_port =
						udp_spec->hdr.dst_port;
					filter->input.mask.v4.dst_port =
						udp_mask->hdr.dst_port;
				}

				if (l3 == RTE_FLOW_ITEM_TYPE_IPV4)
					flow_type =
						ICE_FLTR_PTYPE_NONF_IPV4_UDP;
			}
			break;
		case RTE_FLOW_ITEM_TYPE_VOID:
			break;
		default:
			rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"Invalid pattern item.");
			return -rte_errno;
		}
	}

	filter->input.flow_type = flow_type;
	filter->input_set = input_set;

	return 0;
}

static int
ice_acl_parse(struct ice_adapter *ad,
	       struct ice_pattern_match_item *array,
	       uint32_t array_len,
	       const struct rte_flow_item pattern[],
	       const struct rte_flow_action actions[],
	       void **meta,
	       struct rte_flow_error *error)
{
	struct ice_pf *pf = &ad->pf;
	struct ice_acl_info *filter = &pf->acl;
	struct ice_pattern_match_item *item = NULL;
	uint64_t input_set;
	int ret;

	memset(filter, 0, sizeof(*filter));
	item = ice_search_pattern_match_item(pattern, array, array_len, error);
	if (!item)
		return -rte_errno;

	ret = ice_acl_parse_pattern(ad, pattern, error, filter);
	if (ret)
		return ret;
	input_set = filter->input_set;
	if (!input_set || input_set & ~item->input_set_mask) {
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM_SPEC,
				   pattern,
				   "Invalid input set");
		return -rte_errno;
	}

	ret = ice_acl_parse_action(ad, actions, error, filter);
	if (ret)
		return ret;

	*meta = filter;

	return 0;
}

static int
ice_acl_init(struct ice_adapter *ad)
{
	int ret = 0;
	struct ice_pf *pf = &ad->pf;
	struct ice_flow_parser *parser = &ice_acl_parser;

	ret = ice_acl_prof_alloc(&ad->hw);
	if (ret) {
		PMD_DRV_LOG(ERR, "Cannot allocate memory for "
			    "ACL profile.");
		ret = -ENOMEM;
	}

	ret = ice_acl_setup(pf);
	if (ret)
		return ret;

	return ice_register_parser(parser, ad);
}

static void
ice_acl_prof_free(struct ice_hw *hw)
{
	enum ice_fltr_ptype ptype;

	for (ptype = ICE_FLTR_PTYPE_NONF_NONE + 1;
	     ptype < ICE_FLTR_PTYPE_MAX;
	     ptype++) {
		rte_free(hw->acl_prof[ptype]);
		hw->acl_prof[ptype] = NULL;
	}

	rte_free(hw->acl_prof);
	hw->acl_prof = NULL;
}

static void
ice_acl_uninit(struct ice_adapter *ad)
{
	struct ice_pf *pf = &ad->pf;
	struct ice_flow_parser *parser = &ice_acl_parser;

	ice_unregister_parser(parser, ad);

	ice_deinit_acl(pf);
	ice_acl_prof_free(&ad->hw);
}

static struct
ice_flow_engine ice_acl_engine = {
	.init = ice_acl_init,
	.uninit = ice_acl_uninit,
	.create = ice_acl_create_filter,
	.destroy = ice_acl_destroy_filter,
	.free = ice_acl_filter_free,
	.type = ICE_FLOW_ENGINE_ACL,
};

static struct
ice_flow_parser ice_acl_parser = {
	.engine = &ice_acl_engine,
	.array = ice_acl_pattern,
	.array_len = RTE_DIM(ice_acl_pattern),
	.parse_pattern_action = ice_acl_parse,
	.stage = ICE_FLOW_STAGE_DISTRIBUTOR,
};

RTE_INIT(ice_acl_engine_init)
{
	struct ice_flow_engine *engine = &ice_acl_engine;
	ice_register_flow_engine(engine);
}
