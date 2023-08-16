/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h> /* sleep() */
#include <arpa/inet.h> /* htons, htonl, ntohs */
#include <stdatomic.h>

#include <inttypes.h>

#include "ntlog.h"

#include "flow_api_nic_setup.h"
#include "stream_binary_flow_api.h"
#include "flow_api.h"
#include "flow_api_actions.h"
#include "flow_api_backend.h"
#include "flow_api_engine.h"
#include "flow_api_profile_inline.h"

#include <rte_spinlock.h>

#define UNUSED __rte_unused

/*
 * lookup refers to key A/B/C/D, and can have values 0, 1, 2, and 3.
 */
static int set_flow_type_km(struct flow_nic_dev *ndev, int cfn_index,
			    int flow_type, int lookup, int enable)
{
	const int max_lookups = 4;
	const int cat_funcs = (int)ndev->be.cat.nb_cat_funcs / 8;

	int fte_index =
		(8 * flow_type + cfn_index / cat_funcs) * max_lookups + lookup;
	int fte_field = cfn_index % cat_funcs;

	uint32_t current_bm = 0;
	uint32_t fte_field_bm = 1 << fte_field;

	hw_mod_cat_fte_km_get(&ndev->be, HW_CAT_FTE_ENABLE_BM, KM_FLM_IF_FIRST,
			      fte_index, &current_bm);

	uint32_t final_bm = enable ? (fte_field_bm | current_bm) :
			    (~fte_field_bm & current_bm);

	if (current_bm != final_bm) {
		hw_mod_cat_fte_km_set(&ndev->be, HW_CAT_FTE_ENABLE_BM,
				      KM_FLM_IF_FIRST, fte_index, final_bm);
		hw_mod_cat_fte_km_flush(&ndev->be, KM_FLM_IF_FIRST, fte_index,
					1);
	}

	return 0;
}

/*
 * lookup refers to key A/B/C/D, and can have values 0, 1, 2, and 3.
 */
static int set_flow_type_flm(struct flow_nic_dev *ndev, int cfn_index,
			     int flow_type, int lookup, int enable)
{
	const int max_lookups = 4;
	const int cat_funcs = (int)ndev->be.cat.nb_cat_funcs / 8;

	int fte_index =
		(8 * flow_type + cfn_index / cat_funcs) * max_lookups + lookup;
	int fte_field = cfn_index % cat_funcs;

	uint32_t current_bm = 0;
	uint32_t fte_field_bm = 1 << fte_field;

	hw_mod_cat_fte_flm_get(&ndev->be, HW_CAT_FTE_ENABLE_BM, KM_FLM_IF_FIRST,
			       fte_index, &current_bm);

	uint32_t final_bm = enable ? (fte_field_bm | current_bm) :
			    (~fte_field_bm & current_bm);

	if (current_bm != final_bm) {
		hw_mod_cat_fte_flm_set(&ndev->be, HW_CAT_FTE_ENABLE_BM,
				       KM_FLM_IF_FIRST, fte_index, final_bm);
		hw_mod_cat_fte_flm_flush(&ndev->be, KM_FLM_IF_FIRST, fte_index,
					 1);
	}

	return 0;
}

static int rx_queue_idx_to_hw_id(struct flow_eth_dev *dev, int id)
{
	for (int i = 0; i < dev->num_queues; ++i) {
		if (dev->rx_queue[i].id == id)
			return dev->rx_queue[i].hw_id;
	}
	return -1;
}

/*
 * Flow Matcher functionality
 */

static int flm_sdram_calibrate(struct flow_nic_dev *ndev)
{
	int success = 0;

	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_PRESET_ALL, 0x0);
	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_SPLIT_SDRAM_USAGE,
			       0x10);
	hw_mod_flm_control_flush(&ndev->be);

	/* Wait for ddr4 calibration/init done */
	for (uint32_t i = 0; i < 1000000; ++i) {
		uint32_t value = 0;

		hw_mod_flm_status_update(&ndev->be);
		hw_mod_flm_status_get(&ndev->be, HW_FLM_STATUS_CALIBDONE,
				      &value);
		if (value) {
			success = 1;
			break;
		}
		usleep(1);
	}

	if (!success) {
		/* "Flow matcher initialization failed - SDRAM calibration failed"; */
		return -1;
	}

	/* Set the flow scrubber and timeout settings */
	hw_mod_flm_timeout_set(&ndev->be, HW_FLM_TIMEOUT_T, 0);
	hw_mod_flm_timeout_flush(&ndev->be);

	hw_mod_flm_scrub_set(&ndev->be, HW_FLM_SCRUB_I, 100);
	hw_mod_flm_scrub_flush(&ndev->be);

	return 0;
}

static int flm_sdram_reset(struct flow_nic_dev *ndev, int enable)
{
	int success = 0;

	/*
	 * Make sure no lookup is performed during init, i.e.
	 * disable every category and disable FLM
	 */
	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_ENABLE, 0x0);
	hw_mod_flm_control_flush(&ndev->be);

	for (uint32_t i = 1; i < ndev->be.flm.nb_categories; ++i)
		hw_mod_flm_rcp_set(&ndev->be, HW_FLM_RCP_PRESET_ALL, i, 0x0);
	hw_mod_flm_rcp_flush(&ndev->be, 1, ndev->be.flm.nb_categories - 1);

	/* Wait for FLM to enter Idle state */
	for (uint32_t i = 0; i < 1000000; ++i) {
		uint32_t value = 0;

		hw_mod_flm_status_update(&ndev->be);
		hw_mod_flm_status_get(&ndev->be, HW_FLM_STATUS_IDLE, &value);
		if (value) {
			success = 1;
			break;
		}
		usleep(1);
	}

	if (!success) {
		/* "Flow matcher initialization failed - never idle"; */
		return -1;
	}

	success = 0;

	/* Start SDRAM initialization */
	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_INIT, 0x1);
	hw_mod_flm_control_flush(&ndev->be);

	for (uint32_t i = 0; i < 1000000; ++i) {
		uint32_t value = 0;

		hw_mod_flm_status_update(&ndev->be);
		hw_mod_flm_status_get(&ndev->be, HW_FLM_STATUS_INITDONE,
				      &value);
		if (value) {
			success = 1;
			break;
		}
		usleep(1);
	}

	if (!success) {
		/* "Flow matcher initialization failed - SDRAM initialization incomplete"; */
		return -1;
	}

	/* Set the INIT value back to zero to clear the bit in the SW register cache */
	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_INIT, 0x0);
	hw_mod_flm_control_flush(&ndev->be);

	/* Enable FLM */
	hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_ENABLE, enable);
	hw_mod_flm_control_flush(&ndev->be);

	return 0;
}

#define FLM_FLOW_RCP_MAX 32
#define FLM_FLOW_FT_MAX 16

struct flm_flow_ft_ident_s {
	union {
		struct {
			uint64_t in_use : 1;
			uint64_t drop : 1;
			uint64_t ltx_en : 1;
			uint64_t ltx_port : 1;
			uint64_t queue_en : 1;
			uint64_t queue : 8;
			uint64_t encap_len : 8;
			uint64_t encap_vlans : 2;
			uint64_t encap_ip : 1;
			uint64_t decap_end : 5;
			uint64_t jump_to_group : 8;
			uint64_t pad : 27;
		};
		uint64_t data;
	};
};

struct flm_flow_key_def_s {
	union {
		struct {
			uint64_t qw0_dyn : 7;
			uint64_t qw0_ofs : 8;
			uint64_t qw4_dyn : 7;
			uint64_t qw4_ofs : 8;
			uint64_t sw8_dyn : 7;
			uint64_t sw8_ofs : 8;
			uint64_t sw9_dyn : 7;
			uint64_t sw9_ofs : 8;
			uint64_t outer_proto : 1;
			uint64_t inner_proto : 1;
			uint64_t pad : 2;
		};
		uint64_t data;
	};
};

static struct flm_flow_ft_ident_s flow_def_to_ft_ident(struct nic_flow_def *fd)
{
	struct flm_flow_ft_ident_s ft_ident;

	assert(sizeof(struct flm_flow_ft_ident_s) == sizeof(uint64_t));

	memset(&ft_ident, 0x0, sizeof(struct flm_flow_ft_ident_s));
	ft_ident.in_use = 1;

	if (fd->dst_num_avail == 0) {
		ft_ident.drop = 1;
	} else {
		for (int i = 0; i < fd->dst_num_avail; ++i) {
			if (fd->dst_id[i].type == PORT_PHY) {
				ft_ident.ltx_en = 1;
				ft_ident.ltx_port = fd->dst_id[i].id;
			} else if (fd->dst_id[i].type == PORT_VIRT) {
				ft_ident.queue_en = 1;
				ft_ident.queue = fd->dst_id[i].id;
			}
		}
	}

	if (fd->tun_hdr.len > 0) {
		ft_ident.encap_len = fd->tun_hdr.len;
		ft_ident.encap_vlans = fd->tun_hdr.nb_vlans & 0x3;
		ft_ident.encap_ip = fd->tun_hdr.ip_version == 4 ? 0 : 1;
	}

	ft_ident.decap_end = fd->header_strip_end_dyn & 0x1f;

	if (fd->jump_to_group != UINT32_MAX)
		ft_ident.jump_to_group = fd->jump_to_group & 0xff;

	return ft_ident;
}

static inline void set_key_def_qw(struct flm_flow_key_def_s *key_def,
				  unsigned int qw, unsigned int dyn,
				  unsigned int ofs)
{
	assert(qw < 2);
	if (qw == 0) {
		key_def->qw0_dyn = dyn & 0x7f;
		key_def->qw0_ofs = ofs & 0xff;
	} else {
		key_def->qw4_dyn = dyn & 0x7f;
		key_def->qw4_ofs = ofs & 0xff;
	}
}

static inline void set_key_def_sw(struct flm_flow_key_def_s *key_def,
				  unsigned int sw, unsigned int dyn,
				  unsigned int ofs)
{
	assert(sw < 2);
	if (sw == 0) {
		key_def->sw8_dyn = dyn & 0x7f;
		key_def->sw8_ofs = ofs & 0xff;
	} else {
		key_def->sw9_dyn = dyn & 0x7f;
		key_def->sw9_ofs = ofs & 0xff;
	}
}

struct flm_flow_group_s {
	int cfn_group0;
	int km_ft_group0;
	struct flow_handle *fh_group0;

	struct flm_flow_key_def_s key_def;

	int miss_enabled;

	struct flm_flow_group_ft_s {
		struct flm_flow_ft_ident_s ident;
		struct flow_handle *fh;
	} ft[FLM_FLOW_FT_MAX];

	uint32_t cashed_ft_index;
};

struct flm_flow_handle_s {
	struct flm_flow_group_s groups[FLM_FLOW_RCP_MAX];
};

static void flm_flow_handle_create(void **handle)
{
	struct flm_flow_handle_s *flm_handle;

	if (!*handle)
		*handle = calloc(1, sizeof(struct flm_flow_handle_s));

	else
		memset(*handle, 0x0, sizeof(struct flm_flow_handle_s));

	flm_handle = (struct flm_flow_handle_s *)*handle;

	for (int i = 0; i < FLM_FLOW_RCP_MAX; ++i) {
		flm_handle->groups[i].cfn_group0 = -1;
		flm_handle->groups[i].fh_group0 = NULL;
	}
}

static void flm_flow_handle_remove(void **handle)
{
	free(*handle);
	*handle = NULL;
}

static int flm_flow_setup_group(struct flow_eth_dev *dev, uint32_t group_index,
				int cfn, int km_ft, struct flow_handle *fh)
{
	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;
	struct flm_flow_group_s *flm_group;

	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	flm_group = &flm_handle->groups[group_index];

	flm_group->cfn_group0 = cfn;
	flm_group->km_ft_group0 = km_ft;
	flm_group->fh_group0 = fh;
	flm_group->miss_enabled = 0;

	return 0;
}

static int flm_flow_destroy_group(struct flow_eth_dev *dev,
				  uint32_t group_index)
{
	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;
	struct flm_flow_group_s *flm_group;

	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	flm_group = &flm_handle->groups[group_index];

	memset(flm_group, 0x0, sizeof(struct flm_flow_group_s));
	flm_group->cfn_group0 = -1;

	return 0;
}

static int flm_flow_get_group_miss_fh(struct flow_eth_dev *dev,
				      uint32_t group_index,
				      struct flow_handle **fh_miss)
{
	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;

	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	*fh_miss = flm_handle->groups[group_index].fh_group0;

	return 0;
}

static int flm_flow_setup_rcp(struct flow_eth_dev *dev,
			      struct flm_flow_key_def_s *key_def,
			      uint32_t *packet_mask, uint32_t group_index)
{
	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	uint32_t flm_mask[10] = {
		packet_mask[0], /* SW9 */
		packet_mask[1], /* SW8 */
		packet_mask[5], packet_mask[4],
		packet_mask[3], packet_mask[2], /* QW4 */
		packet_mask[9], packet_mask[8],
		packet_mask[7], packet_mask[6], /* QW0 */
	};

	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_LOOKUP, group_index, 1);

	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_QW0_DYN, group_index,
			   key_def->qw0_dyn);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_QW0_OFS, group_index,
			   key_def->qw0_ofs);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_QW0_SEL, group_index, 0);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_QW4_DYN, group_index,
			   key_def->qw4_dyn);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_QW4_OFS, group_index,
			   key_def->qw4_ofs);

	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_SW8_DYN, group_index,
			   key_def->sw8_dyn);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_SW8_OFS, group_index,
			   key_def->sw8_ofs);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_SW8_SEL, group_index, 0);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_SW9_DYN, group_index,
			   key_def->sw9_dyn);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_SW9_OFS, group_index,
			   key_def->sw9_ofs);

	hw_mod_flm_rcp_set_mask(&dev->ndev->be, HW_FLM_RCP_MASK, group_index,
				flm_mask);

	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_KID, group_index,
			   group_index + 2);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_OPN, group_index,
			   key_def->outer_proto);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_IPN, group_index,
			   key_def->inner_proto);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_BYT_DYN, group_index, 0);
	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_BYT_OFS, group_index,
			   -20);

	hw_mod_flm_rcp_flush(&dev->ndev->be, group_index, 1);

	return 0;
}

static int flm_flow_destroy_rcp(struct flow_eth_dev *dev, uint32_t group_index)
{
	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;
	struct flm_flow_group_s *flm_group;

	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	flm_group = &flm_handle->groups[group_index];

	hw_mod_flm_rcp_set(&dev->ndev->be, HW_FLM_RCP_PRESET_ALL, group_index,
			   0);
	hw_mod_flm_rcp_flush(&dev->ndev->be, group_index, 1);

	if (flm_group->miss_enabled) {
		uint32_t bm = 0;

		/* Change group 0 FLM RCP selection to point to 0 */
		hw_mod_cat_kcs_flm_set(&dev->ndev->be, HW_CAT_KCS_CATEGORY,
				       KM_FLM_IF_FIRST, flm_group->cfn_group0,
				       0);
		hw_mod_cat_kcs_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 flm_group->cfn_group0, 1);

		/* Change group 0 FT MISS to FT UNHANDLED */
		set_flow_type_flm(dev->ndev, flm_group->cfn_group0, 0, 2, 0);
		set_flow_type_flm(dev->ndev, flm_group->cfn_group0, 1, 2, 1);

		/* Finally, disable FLM for group 0 */
		hw_mod_cat_kce_flm_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST,
				       flm_group->cfn_group0 / 8, &bm);
		hw_mod_cat_kce_flm_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST, flm_group->cfn_group0 / 8,
				       bm & ~(1 << (flm_group->cfn_group0 % 8)));
		hw_mod_cat_kce_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 flm_group->cfn_group0 / 8, 1);

		memset(&flm_group->key_def, 0x0,
		       sizeof(struct flm_flow_key_def_s));
		flm_group->miss_enabled = 0;
	}

	return 0;
}

static int flm_flow_learn_prepare(struct flow_eth_dev *dev,
				  struct flow_handle *fh, uint32_t group_index,
				  struct flm_flow_key_def_s *key_def,
				  uint32_t *packet_mask,
				  /* Return values */
				  uint32_t *kid, uint32_t *ft, int *cfn_to_copy,
				  int *cfn_to_copy_km_ft,
				  struct flow_handle **fh_excisting)
{
	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;
	struct flm_flow_group_s *flm_group;
	struct flm_flow_ft_ident_s temp_ft_ident;
	struct nic_flow_def *fd = fh->fd;

	if (group_index >= FLM_FLOW_RCP_MAX) {
		NT_LOG(ERR, FILTER,
		       "FLM: Invalid index for FLM programming: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	flm_group = &flm_handle->groups[group_index];

	if (flm_group->cfn_group0 < 0) {
		NT_LOG(ERR, FILTER,
		       "FLM: Attempt to program to a unset CFN: Group=%d\n",
		       (int)group_index);
		return -1;
	}

	if (!flm_group->miss_enabled) {
		uint32_t bm = 0;

		if (flow_nic_allocate_fh_resource_index(dev->ndev, RES_FLM_RCP,
							(int)group_index, fh)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not get FLM RCP resource\n");
			return -1;
		}

		/* Change group 0 FLM RCP selection to point to "group_index" */
		hw_mod_cat_kcs_flm_set(&dev->ndev->be, HW_CAT_KCS_CATEGORY,
				       KM_FLM_IF_FIRST, flm_group->cfn_group0,
				       group_index);
		hw_mod_cat_kcs_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 flm_group->cfn_group0, 1);

		/* Setup FLM RCP "group_index" */
		flm_flow_setup_rcp(dev, key_def, packet_mask, group_index);

		/*
		 * Change group 0 FT UNHANDLED to FT MISS
		 * Note: Once this step is done, the filter is invalid until the KCE step is done
		 */
		set_flow_type_flm(dev->ndev, flm_group->cfn_group0, 1, 2, 0);
		set_flow_type_flm(dev->ndev, flm_group->cfn_group0, 0, 2, 1);

		/* Finally, enable FLM for group 0 */
		hw_mod_cat_kce_flm_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST,
				       flm_group->cfn_group0 / 8, &bm);
		hw_mod_cat_kce_flm_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST,
				       flm_group->cfn_group0 / 8,
				       bm | (1 << (flm_group->cfn_group0 % 8)));
		hw_mod_cat_kce_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 flm_group->cfn_group0 / 8, 1);

		flm_group->key_def.data = key_def->data;
		flm_group->miss_enabled = 1;
	}

	if (flm_group->key_def.data != key_def->data) {
		NT_LOG(ERR, FILTER,
		       "FLM: Attempt to program 2 different types of flows into group=%d\n",
		       (int)group_index);
		return -1;
	}

	/* Create action set */
	memset(&temp_ft_ident, 0x0, sizeof(struct flm_flow_ft_ident_s));
	temp_ft_ident.in_use = 1;

	if (fd->dst_num_avail == 0) {
		temp_ft_ident.drop = 1;
	} else {
		for (int i = 0; i < fd->dst_num_avail; ++i) {
			if (fd->dst_id[i].type == PORT_PHY) {
				temp_ft_ident.ltx_en = 1;
				temp_ft_ident.ltx_port = fd->dst_id[i].id;
			} else if (fd->dst_id[i].type == PORT_VIRT) {
				temp_ft_ident.queue_en = 1;
				temp_ft_ident.queue = fd->dst_id[i].id;
			}
		}
	}

	/* Set encap/decap data */
	if (fd->tun_hdr.len > 0) {
		temp_ft_ident.encap_len = fd->tun_hdr.len;
		temp_ft_ident.encap_vlans = fd->tun_hdr.nb_vlans & 0x3;
		temp_ft_ident.encap_ip = fd->tun_hdr.ip_version == 4 ? 0 : 1;
	}

	temp_ft_ident.decap_end = fd->header_strip_end_dyn & 0x1f;

	/* Find ft ident or create a new one */
	uint32_t ft_index = 0;

	if (flm_group->cashed_ft_index > 0 &&
			flm_group->ft[flm_group->cashed_ft_index].ident.data ==
			temp_ft_ident.data) {
		ft_index = flm_group->cashed_ft_index;
		*fh_excisting = flm_group->ft[ft_index].fh;
	} else {
		for (ft_index = 2; ft_index < FLM_FLOW_FT_MAX; ++ft_index) {
			struct flm_flow_ft_ident_s *ft_ident =
					&flm_group->ft[ft_index].ident;
			if (ft_ident->data == 0) {
				ft_ident->data = temp_ft_ident.data;
				*cfn_to_copy = flm_group->cfn_group0;
				*cfn_to_copy_km_ft = flm_group->km_ft_group0;
				flm_group->ft[ft_index].fh = fh;
				fh->flm_group_index = (uint8_t)group_index;
				fh->flm_ft_index = (uint8_t)ft_index;
				break;
			} else if (ft_ident->data == temp_ft_ident.data) {
				*fh_excisting = flm_group->ft[ft_index].fh;
				break;
			}
		}

		if (ft_index >= FLM_FLOW_FT_MAX) {
			NT_LOG(ERR, FILTER, "FLM: FT resource not available\n");
			return -1;
		}

		flm_group->cashed_ft_index = ft_index;
	}

	/* Set return values */
	 *kid = group_index + 2;
	 *ft = ft_index;

	return 0;
}

static int flow_flm_destroy_owner(struct flow_eth_dev *dev,
				  struct flow_handle *fh)
{
	int error = 0;

	struct flm_flow_handle_s *flm_handle =
		(struct flm_flow_handle_s *)dev->ndev->flm_res_handle;
	struct flm_flow_group_s *flm_group =
			&flm_handle->groups[fh->flm_group_index];

	memset(&flm_group->ft[fh->flm_ft_index], 0x0,
	       sizeof(struct flm_flow_group_ft_s));

	error |= set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index,
				   flm_group->km_ft_group0, 0, 0);
	error |= set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index,
				   (int)fh->flm_ft_index, 2, 0);

	return error;
}

#define FLM_MTR_PROFILE_SIZE 0x100000

struct flm_flow_mtr_handle_s {
	struct dual_buckets_s {
		uint16_t rate_a;
		uint16_t rate_b;
		uint16_t size_a;
		uint16_t size_b;
	} dual_buckets[FLM_MTR_PROFILE_SIZE];
};

int flow_mtr_supported(struct flow_eth_dev *dev)
{
	return hw_mod_flm_present(&dev->ndev->be) &&
	       dev->ndev->be.flm.nb_variant == 2;
}

uint64_t flow_mtr_meter_policy_n_max(void)
{
	return FLM_MTR_PROFILE_SIZE;
}

static inline uint64_t convert_to_bucket_size_units(uint64_t value)
{
	/* Assumes a 40-bit int as input */
	uint64_t lo_bits = (value & 0xfffff) * 1000000000;
	uint64_t hi_bits = ((value >> 20) & 0xfffff) * 1000000000;
	uint64_t round_up =
		(hi_bits & 0xfffff) || (lo_bits & 0xffffffffff) ? 1 : 0;
	return (hi_bits >> 20) + (lo_bits >> 40) + round_up;
}

int flow_mtr_set_profile(struct flow_eth_dev *dev, uint32_t profile_id,
			 uint64_t bucket_rate_a, uint64_t bucket_size_a,
			 uint64_t bucket_rate_b, uint64_t bucket_size_b)
{
	struct flow_nic_dev *ndev = dev->ndev;
	struct flm_flow_mtr_handle_s *handle =
		(struct flm_flow_mtr_handle_s *)ndev->flm_mtr_handle;
	struct dual_buckets_s *buckets = &handle->dual_buckets[profile_id];

	uint64_t bucket_rate_shift_a = 0;
	uint64_t bucket_rate_shift_b = 0;

	uint64_t bucket_size_shift_a = 0;
	uint64_t bucket_size_shift_b = 0;

	/* Round rates up to nearest 128 bytes/sec and shift to 128 bytes/sec units */
	bucket_rate_a = (bucket_rate_a & 0x7f) ? (bucket_rate_a >> 7) + 1 :
			(bucket_rate_a >> 7);
	bucket_rate_b = (bucket_rate_b & 0x7f) ? (bucket_rate_b >> 7) + 1 :
			(bucket_rate_b >> 7);

	/* Round rate down to max rate supported */
	if (bucket_rate_a > 0x7ff8000)
		bucket_rate_a = 0x7ff8000;
	if (bucket_rate_b > 0x7ff8000)
		bucket_rate_b = 0x7ff8000;

	/* Find shift to convert into 12-bit int */
	while ((bucket_rate_a >> bucket_rate_shift_a) > 0xfff)
		bucket_rate_shift_a += 1;
	while ((bucket_rate_b >> bucket_rate_shift_b) > 0xfff)
		bucket_rate_shift_b += 1;

	/* Store in format [11:0] shift-left [15:12] */
	buckets->rate_a = (bucket_rate_a >> bucket_rate_shift_a) |
			  (bucket_rate_shift_a << 12);
	buckets->rate_b = (bucket_rate_b >> bucket_rate_shift_b) |
			  (bucket_rate_shift_b << 12);

	/* Round size down to 38-bit int */
	if (bucket_size_a > 0x3fffffffff)
		bucket_size_a = 0x3fffffffff;
	if (bucket_size_b > 0x3fffffffff)
		bucket_size_b = 0x3fffffffff;

	/* Convert size to units of 2^40 / 10^9. Output is a 28-bit int. */
	bucket_size_a = convert_to_bucket_size_units(bucket_size_a);
	bucket_size_b = convert_to_bucket_size_units(bucket_size_b);

	/* Round rate down to max rate supported */
	if (bucket_size_a > 0x7ff8000)
		bucket_size_a = 0x7ff8000;
	if (bucket_size_b > 0x7ff8000)
		bucket_size_b = 0x7ff8000;

	/* Find shift to convert into 12-bit int */
	while ((bucket_size_a >> bucket_size_shift_a) > 0xfff)
		bucket_size_shift_a += 1;
	while ((bucket_size_b >> bucket_size_shift_b) > 0xfff)
		bucket_size_shift_b += 1;

	/* Store in format [11:0] shift-left [15:12] */
	buckets->size_a = (bucket_size_a >> bucket_size_shift_a) |
			  (bucket_size_shift_a << 12);
	buckets->size_b = (bucket_size_b >> bucket_size_shift_b) |
			  (bucket_size_shift_b << 12);

	return 0;
}

int flow_mtr_set_policy(UNUSED struct flow_eth_dev *dev,
			UNUSED uint32_t policy_id, UNUSED int drop)
{
	return 0;
}

#define FLM_MTR_STAT_SIZE 0x1000000
#define WORDS_PER_INF_DATA \
	(sizeof(struct flm_v17_inf_data_s) / sizeof(uint32_t))
#define MAX_INF_DATA_RECORDS_PER_READ 20
#define UINT64_MSB ((uint64_t)1 << 63)

/* 2^23 bytes ~ 8MB */
#define FLM_PERIODIC_STATS_BYTE_LIMIT 8
/* 2^16 pkt ~ 64K pkt */
#define FLM_PERIODIC_STATS_PKT_LIMIT 5
/* 2^38 ns ~ 275 sec */
#define FLM_PERIODIC_STATS_BYTE_TIMEOUT 23

uint32_t flow_mtr_meters_supported(void)
{
	return FLM_MTR_STAT_SIZE;
}

struct mtr_stat_s {
	struct dual_buckets_s *buckets;

	volatile atomic_uint_fast64_t n_pkt;
	volatile atomic_uint_fast64_t n_bytes;
	uint64_t n_pkt_base;
	uint64_t n_bytes_base;
	volatile atomic_uint_fast64_t stats_mask;
};

#define WORDS_PER_LEARN_DATA sizeof(struct flm_v17_lrn_data_s)
#define FLM_PROG_MAX_RETRY 100

static uint32_t flm_read_inf_rec_locked(struct flow_eth_dev *dev,
					uint32_t *data);

static int flow_flm_apply(struct flow_eth_dev *dev,
			  struct flm_v17_lrn_data_s *learn_record)
{
	uint32_t lrn_ready;
	uint32_t retry = 0;
	uint32_t data[WORDS_PER_INF_DATA * MAX_INF_DATA_RECORDS_PER_READ];

	hw_mod_flm_buf_ctrl_get(&dev->ndev->be, HW_FLM_BUF_CTRL_LRN_FREE,
				&lrn_ready);
	if (lrn_ready < WORDS_PER_LEARN_DATA) {
		hw_mod_flm_buf_ctrl_update(&dev->ndev->be);
		hw_mod_flm_buf_ctrl_get(&dev->ndev->be,
					HW_FLM_BUF_CTRL_LRN_FREE, &lrn_ready);
		while (lrn_ready < WORDS_PER_LEARN_DATA) {
			++retry;
			if (retry > FLM_PROG_MAX_RETRY)
				return 1;

			flm_read_inf_rec_locked(dev, data);

			hw_mod_flm_buf_ctrl_update(&dev->ndev->be);
			hw_mod_flm_buf_ctrl_get(&dev->ndev->be,
						HW_FLM_BUF_CTRL_LRN_FREE,
						&lrn_ready);
		}
	}

	int res = hw_mod_flm_lrn_data_set_flush(&dev->ndev->be,
						HW_FLM_FLOW_LRN_DATA_V17,
						(uint32_t *)learn_record);
	return res;
}

int flow_mtr_create_meter(struct flow_eth_dev *dev, uint32_t mtr_id,
			  uint32_t profile_id, UNUSED uint32_t policy_id,
			  uint64_t stats_mask)
{
	pthread_mutex_lock(&dev->ndev->mtx);

	struct flm_flow_mtr_handle_s *handle =
		(struct flm_flow_mtr_handle_s *)dev->ndev->flm_mtr_handle;
	struct dual_buckets_s *buckets = &handle->dual_buckets[profile_id];

	struct flm_v17_lrn_data_s learn_record;

	memset(&learn_record, 0x0, sizeof(struct flm_v17_lrn_data_s));

	learn_record.sw9 = mtr_id + 1;
	learn_record.kid = 1;

	learn_record.rate = buckets->rate_a;
	learn_record.size = buckets->size_a;
	learn_record.fill = buckets->size_a & 0x0fff;

	learn_record.ft_mbr = 15; /* FT to assign if MBR has been exceeded */

	learn_record.ent = 1;
	learn_record.op = 1;
	learn_record.eor = 1;

	learn_record.id[0] = mtr_id & 0xff;
	learn_record.id[1] = (mtr_id >> 8) & 0xff;
	learn_record.id[2] = (mtr_id >> 16) & 0xff;
	learn_record.id[3] = (mtr_id >> 24) & 0xff;
	learn_record.id[8] = 1U << 7;

	if (stats_mask)
		learn_record.vol_idx = 1;

	int res = flow_flm_apply(dev, &learn_record);

	if (res == 0) {
		struct mtr_stat_s *mtr_stat = dev->ndev->mtr_stat_handle;

		mtr_stat[mtr_id].buckets = buckets;
		atomic_store(&mtr_stat[mtr_id].stats_mask, stats_mask);
	}

	pthread_mutex_unlock(&dev->ndev->mtx);

	return res;
}

int flow_mtr_destroy_meter(struct flow_eth_dev *dev, uint32_t mtr_id)
{
	pthread_mutex_lock(&dev->ndev->mtx);

	struct flm_v17_lrn_data_s learn_record;

	memset(&learn_record, 0x0, sizeof(struct flm_v17_lrn_data_s));

	learn_record.sw9 = mtr_id + 1;
	learn_record.kid = 1;

	learn_record.ent = 1;
	learn_record.op = 0;
	learn_record.eor = 1;

	learn_record.id[0] = mtr_id & 0xff;
	learn_record.id[1] = (mtr_id >> 8) & 0xff;
	learn_record.id[2] = (mtr_id >> 16) & 0xff;
	learn_record.id[3] = (mtr_id >> 24) & 0xff;
	learn_record.id[8] = 1U << 7;

	/* Clear statistics so stats_mask prevents updates of counters on deleted meters */
	struct mtr_stat_s *mtr_stat = dev->ndev->mtr_stat_handle;

	atomic_store(&mtr_stat[mtr_id].stats_mask, 0);
	atomic_store(&mtr_stat[mtr_id].n_bytes, 0);
	atomic_store(&mtr_stat[mtr_id].n_pkt, 0);
	mtr_stat[mtr_id].n_bytes_base = 0;
	mtr_stat[mtr_id].n_pkt_base = 0;
	mtr_stat[mtr_id].buckets = NULL;

	int res = flow_flm_apply(dev, &learn_record);

	pthread_mutex_unlock(&dev->ndev->mtx);

	return res;
}

int flm_mtr_adjust_stats(struct flow_eth_dev *dev, uint32_t mtr_id,
			 uint32_t adjust_value)
{
	pthread_mutex_lock(&dev->ndev->mtx);

	struct mtr_stat_s *mtr_stat =
		&((struct mtr_stat_s *)dev->ndev->mtr_stat_handle)[mtr_id];

	struct flm_v17_lrn_data_s learn_record;

	memset(&learn_record, 0x0, sizeof(struct flm_v17_lrn_data_s));

	learn_record.sw9 = mtr_id + 1;
	learn_record.kid = 1;

	learn_record.rate = mtr_stat->buckets->rate_a;
	learn_record.size = mtr_stat->buckets->size_a;
	learn_record.adj = adjust_value;

	learn_record.ft_mbr = 15;

	learn_record.ent = 1;
	learn_record.op = 2;
	learn_record.eor = 1;

	if (atomic_load(&mtr_stat->stats_mask))
		learn_record.vol_idx = 1;

	int res = flow_flm_apply(dev, &learn_record);

	pthread_mutex_unlock(&dev->ndev->mtx);

	return res;
}

static uint32_t flm_read_inf_rec_locked(struct flow_eth_dev *dev,
					uint32_t *data)
{
	uint32_t inf_cnt = 0;

	hw_mod_flm_buf_ctrl_get(&dev->ndev->be, HW_FLM_BUF_CTRL_INF_AVAIL,
				&inf_cnt);
	if (inf_cnt < WORDS_PER_INF_DATA) {
		hw_mod_flm_buf_ctrl_update(&dev->ndev->be);
		hw_mod_flm_buf_ctrl_get(&dev->ndev->be,
					HW_FLM_BUF_CTRL_INF_AVAIL, &inf_cnt);
	}

	uint32_t records_to_read = inf_cnt / WORDS_PER_INF_DATA;

	if (records_to_read == 0)
		return 0;
	if (records_to_read > MAX_INF_DATA_RECORDS_PER_READ)
		records_to_read = MAX_INF_DATA_RECORDS_PER_READ;

	hw_mod_flm_inf_data_update_get(&dev->ndev->be, HW_FLM_FLOW_INF_DATA_V17,
				       data,
				       records_to_read * WORDS_PER_INF_DATA);

	return records_to_read;
}

uint32_t flm_mtr_update_stats(struct flow_eth_dev *dev)
{
	uint32_t data[WORDS_PER_INF_DATA * MAX_INF_DATA_RECORDS_PER_READ];

	pthread_mutex_lock(&dev->ndev->mtx);
	uint32_t records = flm_read_inf_rec_locked(dev, data);

	pthread_mutex_unlock(&dev->ndev->mtx);

	struct mtr_stat_s *mtr_stat = dev->ndev->mtr_stat_handle;

	for (uint32_t i = 0; i < records; ++i) {
		uint32_t *p_record = &data[i * WORDS_PER_INF_DATA];

		/* Check that received record hold valid meter statistics */
		if ((p_record[6] < flow_mtr_meters_supported() &&
				p_record[7] == 0 && (p_record[8] >> 31) == 1)) {
			uint32_t id = p_record[6];

			/* Don't update a deleted meter */
			uint64_t stats_mask =
				atomic_load(&mtr_stat[id].stats_mask);
			if (stats_mask) {
				uint64_t nb = ((uint64_t)p_record[1] << 32) |
					      p_record[0];
				uint64_t np = ((uint64_t)p_record[3] << 32) |
					      p_record[2];

				atomic_store(&mtr_stat[id].n_pkt,
					     np | UINT64_MSB);
				atomic_store(&mtr_stat[id].n_bytes, nb);
				atomic_store(&mtr_stat[id].n_pkt, np);
			}
		}
	}

	return records;
}

void flm_mtr_read_stats(struct flow_eth_dev *dev, uint32_t id,
			uint64_t *stats_mask, uint64_t *green_pkt,
			uint64_t *green_bytes, int clear)
{
	struct mtr_stat_s *mtr_stat = dev->ndev->mtr_stat_handle;
	*stats_mask = atomic_load(&mtr_stat[id].stats_mask);
	if (*stats_mask) {
		uint64_t pkt_1;
		uint64_t pkt_2;
		uint64_t nb;

		do {
			do {
				pkt_1 = atomic_load(&mtr_stat[id].n_pkt);
			} while (pkt_1 & UINT64_MSB);
			nb = atomic_load(&mtr_stat[id].n_bytes);
			pkt_2 = atomic_load(&mtr_stat[id].n_pkt);
		} while (pkt_1 != pkt_2);

		*green_pkt = pkt_1 - mtr_stat[id].n_pkt_base;
		*green_bytes = nb - mtr_stat[id].n_bytes_base;
		if (clear) {
			mtr_stat[id].n_pkt_base = pkt_1;
			mtr_stat[id].n_bytes_base = nb;
		}
	}
}

static inline uint8_t convert_port_to_ifr_mtu_recipe(uint32_t port)
{
	return port + 1;
}

static uint8_t get_port_from_port_id(struct flow_nic_dev *ndev,
				     uint32_t port_id)
{
	struct flow_eth_dev *dev = ndev->eth_base;

	while (dev) {
		if (dev->port_id == port_id)
			return dev->port;
		dev = dev->next;
	}

	return UINT8_MAX;
}

static void nic_insert_flow(struct flow_nic_dev *ndev, struct flow_handle *fh)
{
	if (ndev->flow_base)
		ndev->flow_base->prev = fh;
	fh->next = ndev->flow_base;
	fh->prev = NULL;
	ndev->flow_base = fh;
}

static void nic_remove_flow(struct flow_nic_dev *ndev, struct flow_handle *fh)
{
	struct flow_handle *next = fh->next;
	struct flow_handle *prev = fh->prev;

	if (next && prev) {
		prev->next = next;
		next->prev = prev;
	} else if (next) {
		ndev->flow_base = next;
		next->prev = NULL;
	} else if (prev) {
		prev->next = NULL;
	} else if (ndev->flow_base == fh) {
		ndev->flow_base = NULL;
	}
}

static void nic_insert_flow_flm(struct flow_nic_dev *ndev,
				struct flow_handle *fh)
{
	if (ndev->flow_base_flm)
		ndev->flow_base_flm->prev = fh;
	fh->next = ndev->flow_base_flm;
	fh->prev = NULL;
	ndev->flow_base_flm = fh;
}

static void nic_remove_flow_flm(struct flow_nic_dev *ndev,
				struct flow_handle *fh_flm)
{
	struct flow_handle *next = fh_flm->next;
	struct flow_handle *prev = fh_flm->prev;

	if (next && prev) {
		prev->next = next;
		next->prev = prev;
	} else if (next) {
		ndev->flow_base_flm = next;
		next->prev = NULL;
	} else if (prev) {
		prev->next = NULL;
	} else if (ndev->flow_base_flm == fh_flm) {
		ndev->flow_base_flm = NULL;
	}
}

static int flow_elem_type_vlan(const struct flow_elem elem[], int eidx, uint16_t implicit_vlan_vid,
	struct flow_error *error, struct nic_flow_def *fd, unsigned int sw_counter,
	uint32_t *packet_data, uint32_t *packet_mask, struct flm_flow_key_def_s *key_def)
{
	const struct flow_elem_vlan *vlan_spec = (const struct flow_elem_vlan *)elem[eidx].spec;
	const struct flow_elem_vlan *vlan_mask = (const struct flow_elem_vlan *)elem[eidx].mask;

	if (vlan_spec != NULL && vlan_mask != NULL) {
		if (vlan_mask->tci) {
			if (implicit_vlan_vid > 0) {
				NT_LOG(ERR, FILTER, "Multiple VLANs not supported "
					"for implicit VLAN patterns.\n");
				flow_nic_set_error(ERR_MATCH_INVALID_OR_UNSUPPORTED_ELEM, error);
				free(fd);
				return 1;
			}

			if (sw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *sw_data = &packet_data[1 - sw_counter];
			uint32_t *sw_mask = &packet_mask[1 - sw_counter];

			sw_mask[0] = ntohs(vlan_mask->tci);
			sw_data[0] = ntohs(vlan_spec->tci) & sw_mask[0];

			km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_FIRST_VLAN, 0);
			set_key_def_sw(key_def, sw_counter, DYN_FIRST_VLAN, 0);
			sw_counter += 1;
		}
	}

	fd->vlans += 1;
	return 0;
}

static int flow_elem_type_ipv4(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int qw_counter, unsigned int sw_counter,
	uint32_t *packet_data, uint32_t *packet_mask, struct flm_flow_key_def_s *key_def,
	uint32_t any_count)
{
	const struct flow_elem_ipv4 *ipv4_spec = (const struct flow_elem_ipv4 *)elem[eidx].spec;
	const struct flow_elem_ipv4 *ipv4_mask = (const struct flow_elem_ipv4 *)elem[eidx].mask;

	if (ipv4_spec != NULL && ipv4_mask != NULL) {
		if (ipv4_spec->hdr.frag_offset == 0xffff && ipv4_mask->hdr.frag_offset == 0xffff)
			fd->fragmentation = 0xfe;

		if (qw_counter < 2 && (ipv4_mask->hdr.src_ip || ipv4_mask->hdr.dst_ip)) {
			uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
			uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

			qw_mask[0] = ntohl(ipv4_mask->hdr.src_ip);
			qw_mask[1] = ntohl(ipv4_mask->hdr.dst_ip);

			qw_data[0] = ntohl(ipv4_spec->hdr.src_ip) & qw_mask[0];
			qw_data[1] = ntohl(ipv4_spec->hdr.dst_ip) & qw_mask[1];

			km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 2, DYN_L3, 12);
			set_key_def_qw(key_def, qw_counter, DYN_L3, 12);
			qw_counter += 1;
		} else {
			if (2 - sw_counter < ((ipv4_mask->hdr.src_ip ? 1U : 0U) +
				(ipv4_mask->hdr.dst_ip ? 1U : 0U))) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			if (ipv4_mask->hdr.src_ip) {
				uint32_t *sw_data = &packet_data[1 - sw_counter];
				uint32_t *sw_mask = &packet_mask[1 - sw_counter];

				sw_mask[0] = ntohl(ipv4_mask->hdr.src_ip);
				sw_data[0] = ntohl(ipv4_spec->hdr.src_ip) & sw_mask[0];

				km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L3, 12);
				set_key_def_sw(key_def, sw_counter, DYN_L3, 12);
				sw_counter += 1;
			}

			if (ipv4_mask->hdr.dst_ip) {
				uint32_t *sw_data = &packet_data[1 - sw_counter];
				uint32_t *sw_mask = &packet_mask[1 - sw_counter];

				sw_mask[0] = ntohl(ipv4_mask->hdr.dst_ip);
				sw_data[0] = ntohl(ipv4_spec->hdr.dst_ip) & sw_mask[0];

				km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L3, 16);
				set_key_def_sw(key_def, sw_counter, DYN_L3, 16);
				sw_counter += 1;
			}
		}
	}

	if (any_count > 0 || fd->l3_prot != -1)
		fd->tunnel_l3_prot = PROT_TUN_L3_IPV4;
	else
		fd->l3_prot = PROT_L3_IPV4;
	return 0;
}

static int flow_elem_type_ipv6(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int qw_counter, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def, uint32_t any_count)
{
	const struct flow_elem_ipv6 *ipv6_spec = (const struct flow_elem_ipv6 *)elem[eidx].spec;
	const struct flow_elem_ipv6 *ipv6_mask = (const struct flow_elem_ipv6 *)elem[eidx].mask;

	if (ipv6_spec != NULL && ipv6_mask != NULL) {
		if (is_non_zero(ipv6_spec->hdr.src_addr, 16)) {
			if (qw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of QW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
			uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

			memcpy(&qw_data[0], ipv6_spec->hdr.src_addr, 16);
			memcpy(&qw_mask[0], ipv6_mask->hdr.src_addr, 16);

			qw_data[0] = ntohl(qw_data[0]);
			qw_data[1] = ntohl(qw_data[1]);
			qw_data[2] = ntohl(qw_data[2]);
			qw_data[3] = ntohl(qw_data[3]);

			qw_mask[0] = ntohl(qw_mask[0]);
			qw_mask[1] = ntohl(qw_mask[1]);
			qw_mask[2] = ntohl(qw_mask[2]);
			qw_mask[3] = ntohl(qw_mask[3]);

			qw_data[0] &= qw_mask[0];
			qw_data[1] &= qw_mask[1];
			qw_data[2] &= qw_mask[2];
			qw_data[3] &= qw_mask[3];

			km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4, DYN_L3, 8);
			set_key_def_qw(key_def, qw_counter, DYN_L3, 8);
			qw_counter += 1;
		}

		if (is_non_zero(ipv6_spec->hdr.dst_addr, 16)) {
			if (qw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of QW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *qw_data = &packet_data[2 + 4 - qw_counter * 4];
			uint32_t *qw_mask = &packet_mask[2 + 4 - qw_counter * 4];

			memcpy(&qw_data[0], ipv6_spec->hdr.dst_addr, 16);
			memcpy(&qw_mask[0], ipv6_mask->hdr.dst_addr, 16);

			qw_data[0] = ntohl(qw_data[0]);
			qw_data[1] = ntohl(qw_data[1]);
			qw_data[2] = ntohl(qw_data[2]);
			qw_data[3] = ntohl(qw_data[3]);

			qw_mask[0] = ntohl(qw_mask[0]);
			qw_mask[1] = ntohl(qw_mask[1]);
			qw_mask[2] = ntohl(qw_mask[2]);
			qw_mask[3] = ntohl(qw_mask[3]);
			qw_data[0] &= qw_mask[0];
			qw_data[1] &= qw_mask[1];
			qw_data[2] &= qw_mask[2];
			qw_data[3] &= qw_mask[3];

			km_add_match_elem(&fd->km, &qw_data[0], &qw_mask[0], 4, DYN_L3, 24);
			set_key_def_qw(key_def, qw_counter, DYN_L3, 24);
			qw_counter += 1;
		}
	}

	if (any_count > 0 || fd->l3_prot != -1)
		fd->tunnel_l3_prot = PROT_TUN_L3_IPV6;
	else
		fd->l3_prot = PROT_L3_IPV6;
	return 0;
}

static int flow_elem_type_upd(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int sw_counter, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def, uint32_t any_count)
{
	const struct flow_elem_udp *udp_spec = (const struct flow_elem_udp *)elem[eidx].spec;
	const struct flow_elem_udp *udp_mask = (const struct flow_elem_udp *)elem[eidx].mask;

	if (udp_spec != NULL && udp_mask != NULL) {
		if (udp_mask->hdr.src_port || udp_mask->hdr.dst_port) {
			if (sw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *sw_data = &packet_data[1 - sw_counter];
			uint32_t *sw_mask = &packet_mask[1 - sw_counter];

			sw_mask[0] = (ntohs(udp_mask->hdr.src_port) << 16) |
				ntohs(udp_mask->hdr.dst_port);
			sw_data[0] = ((ntohs(udp_spec->hdr.src_port) << 16) |
				ntohs(udp_spec->hdr.dst_port)) & sw_mask[0];

			km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L4, 0);
			set_key_def_sw(key_def, sw_counter, DYN_L4, 0);
			sw_counter += 1;
		}
	}

	if (any_count > 0 || fd->l4_prot != -1) {
		fd->tunnel_l4_prot = PROT_TUN_L4_UDP;
		key_def->inner_proto = 1;
	} else {
		fd->l4_prot = PROT_L4_UDP;
		key_def->outer_proto = 1;
	}
	return 0;
}

static int flow_elem_type_sctp(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int sw_counter, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def, uint32_t any_count)
{
	const struct flow_elem_sctp *sctp_spec = (const struct flow_elem_sctp *)elem[eidx].spec;
	const struct flow_elem_sctp *sctp_mask = (const struct flow_elem_sctp *)elem[eidx].mask;

	if (sctp_spec != NULL && sctp_mask != NULL) {
		if (sctp_mask->hdr.src_port || sctp_mask->hdr.dst_port) {
			if (sw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *sw_data = &packet_data[1 - sw_counter];
			uint32_t *sw_mask = &packet_mask[1 - sw_counter];

			sw_mask[0] = (ntohs(sctp_mask->hdr.src_port) << 16) |
				ntohs(sctp_mask->hdr.dst_port);
			sw_data[0] = ((ntohs(sctp_spec->hdr.src_port) << 16) |
				ntohs(sctp_spec->hdr.dst_port)) & sw_mask[0];

			km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L4, 0);
			set_key_def_sw(key_def, sw_counter, DYN_L4, 0);
			sw_counter += 1;
		}
	}

	if (any_count > 0 || fd->l4_prot != -1) {
		fd->tunnel_l4_prot = PROT_TUN_L4_SCTP;
		key_def->inner_proto = 1;
	} else {
		fd->l4_prot = PROT_L4_SCTP;
		key_def->outer_proto = 1;
	}
	return 0;
}

static int flow_elem_type_tcp(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int sw_counter, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def, uint32_t any_count)
{
	const struct flow_elem_tcp *tcp_spec = (const struct flow_elem_tcp *)elem[eidx].spec;
	const struct flow_elem_tcp *tcp_mask = (const struct flow_elem_tcp *)elem[eidx].mask;

	if (tcp_spec != NULL && tcp_mask != NULL) {
		if (tcp_mask->hdr.src_port || tcp_mask->hdr.dst_port) {
			if (sw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *sw_data = &packet_data[1 - sw_counter];
			uint32_t *sw_mask = &packet_mask[1 - sw_counter];

			sw_mask[0] = (ntohs(tcp_mask->hdr.src_port) << 16) |
				ntohs(tcp_mask->hdr.dst_port);
			sw_data[0] = ((ntohs(tcp_spec->hdr.src_port) << 16) |
				ntohs(tcp_spec->hdr.dst_port)) & sw_mask[0];

			km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L4, 0);
			set_key_def_sw(key_def, sw_counter, DYN_L4, 0);
			sw_counter += 1;
		}
	}

	if (any_count > 0 || fd->l4_prot != -1) {
		fd->tunnel_l4_prot = PROT_TUN_L4_TCP;
		key_def->inner_proto = 1;
	} else {
		fd->l4_prot = PROT_L4_TCP;
		key_def->outer_proto = 1;
	}
	return 0;
}

static int flow_elem_type_gtp(const struct flow_elem elem[], int eidx, struct flow_error *error,
	struct nic_flow_def *fd, unsigned int sw_counter, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def)
{
	const struct flow_elem_gtp *gtp_spec = (const struct flow_elem_gtp *)elem[eidx].spec;
	const struct flow_elem_gtp *gtp_mask = (const struct flow_elem_gtp *)elem[eidx].mask;

	if (gtp_spec != NULL && gtp_mask != NULL) {
		if (gtp_mask->teid) {
			if (sw_counter >= 2) {
				NT_LOG(ERR, FILTER, "Key size too big. Out of SW resources.\n");
				flow_nic_set_error(ERR_FAILED, error);
				free(fd);
				return 1;
			}

			uint32_t *sw_data = &packet_data[1 - sw_counter];
			uint32_t *sw_mask = &packet_mask[1 - sw_counter];

			sw_mask[0] = ntohl(gtp_mask->teid);
			sw_data[0] = ntohl(gtp_spec->teid) & sw_mask[0];

			km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1, DYN_L4_PAYLOAD, 4);
			set_key_def_sw(key_def, sw_counter, DYN_L4_PAYLOAD, 4);
			sw_counter += 1;
		}
	}

	fd->tunnel_prot = PROT_TUN_GTPV1U;
	return 0;
}

static struct nic_flow_def *interpret_flow_elements(struct flow_eth_dev *dev,
	const struct flow_elem elem[], const struct flow_action action[],
	struct flow_error *error, uint16_t implicit_vlan_vid,
	uint32_t *in_port_id, uint32_t *num_dest_port,
	uint32_t *num_queues, uint32_t *packet_data,
	uint32_t *packet_mask, struct flm_flow_key_def_s *key_def)
{
	uint32_t any_count = 0;
	int mtr_count = 0;

	unsigned int encap_decap_order = 0;

	unsigned int qw_counter = 0;
	unsigned int sw_counter = 0;

	uint64_t modify_field_use_flags = 0x0;

	*in_port_id = UINT32_MAX;
	*num_dest_port = 0;
	*num_queues = 0;

	memset(packet_data, 0x0, sizeof(uint32_t) * 10);
	memset(packet_mask, 0x0, sizeof(uint32_t) * 10);
	key_def->data = 0;

	if (action == NULL || elem == NULL) {
		flow_nic_set_error(ERR_FAILED, error);
		NT_LOG(ERR, FILTER, "Flow items / actions missing\n");
		return NULL;
	}

	struct nic_flow_def *fd = calloc(1, sizeof(struct nic_flow_def));

	if (!fd) {
		flow_nic_set_error(ERR_MEMORY, error);
		NT_LOG(ERR, FILTER, "ERR Memory\n");
		return NULL;
	}

	/* Set default values for fd */
	fd->full_offload = -1;
	fd->in_port_override = -1;
	fd->mark = UINT32_MAX;
	fd->jump_to_group = UINT32_MAX;

	fd->l2_prot = -1;
	fd->l3_prot = -1;
	fd->l4_prot = -1;
	fd->vlans = 0;
	fd->tunnel_prot = -1;
	fd->tunnel_l3_prot = -1;
	fd->tunnel_l4_prot = -1;
	fd->fragmentation = -1;

	NT_LOG(DBG, FILTER,
	       ">>>>> [Dev %p] Nic %i, Port %i: fd %p - FLOW Interpretation <<<<<\n",
	       dev, dev->ndev->adapter_no, dev->port, fd);

	/*
	 * Gather flow match + actions and convert into internal flow definition structure
	 * (struct nic_flow_def_s)
	 * This is the 1st step in the flow creation - validate, convert and prepare
	 */
	for (int aidx = 0; action[aidx].type != FLOW_ACTION_TYPE_END; ++aidx) {
		switch (action[aidx].type) {
		case FLOW_ACTION_TYPE_PORT_ID:
			NT_LOG(DBG, FILTER,
			       "Dev:%p: FLOW_ACTION_TYPE_PORT_ID\n", dev);
			if (action[aidx].conf) {
				uint32_t port_id =
					((const struct flow_action_port_id *)
					 action[aidx]
					 .conf)
					->id;
				uint8_t port = get_port_from_port_id(dev->ndev,
								     port_id);

				if (fd->dst_num_avail == MAX_OUTPUT_DEST) {
					/* ERROR too many output destinations */
					NT_LOG(ERR, FILTER,
					       "Too many output destinations\n");
					flow_nic_set_error(ERR_OUTPUT_TOO_MANY,
							   error);
					free(fd);
					return NULL;
				}

				if (port >= dev->ndev->be.num_phy_ports) {
					/* ERROR phy port out of range */
					NT_LOG(ERR, FILTER,
					       "Phy port out of range\n");
					flow_nic_set_error(ERR_OUTPUT_INVALID,
							   error);
					free(fd);
					return NULL;
				}

				/* New destination port to add */
				fd->dst_id[fd->dst_num_avail].owning_port_id =
					port_id;
				fd->dst_id[fd->dst_num_avail].type = PORT_PHY;
				fd->dst_id[fd->dst_num_avail].id = (int)port;
				fd->dst_id[fd->dst_num_avail].active = 1;
				fd->dst_num_avail++;

				if (fd->flm_mtu_fragmentation_recipe == 0) {
					fd->flm_mtu_fragmentation_recipe =
						convert_port_to_ifr_mtu_recipe(port);
				}

				if (fd->full_offload < 0)
					fd->full_offload = 1;

				*num_dest_port += 1;

				NT_LOG(DBG, FILTER, "Phy port ID: %i\n",
				       (int)port);
			}
			break;

		case FLOW_ACTION_TYPE_QUEUE:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_QUEUE\n",
			       dev);
			if (action[aidx].conf) {
				const struct flow_action_queue *queue =
					(const struct flow_action_queue *)
					action[aidx]
					.conf;

				int hw_id = rx_queue_idx_to_hw_id(dev,
								  queue->index);

				fd->dst_id[fd->dst_num_avail].owning_port_id =
					dev->port;
				fd->dst_id[fd->dst_num_avail].id = hw_id;
				fd->dst_id[fd->dst_num_avail].type = PORT_VIRT;
				fd->dst_id[fd->dst_num_avail].active = 1;
				fd->dst_num_avail++;

				NT_LOG(DBG, FILTER,
				       "Dev:%p: FLOW_ACTION_TYPE_QUEUE port %u, queue index: %u, hw id %u\n",
				       dev, dev->port, queue->index, hw_id);

				fd->full_offload = 0;
				*num_queues += 1;
			}
			break;

		case FLOW_ACTION_TYPE_RSS:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_RSS\n",
			       dev);
			if (action[aidx].conf) {
				const struct flow_action_rss *rss =
					(const struct flow_action_rss *)
					action[aidx]
					.conf;

				for (uint32_t i = 0; i < rss->queue_num; ++i) {
					int hw_id = rx_queue_idx_to_hw_id(dev, rss->queue[i]);

					fd->dst_id[fd->dst_num_avail]
					.owning_port_id = dev->port;
					fd->dst_id[fd->dst_num_avail].id =
						hw_id;
					fd->dst_id[fd->dst_num_avail].type =
						PORT_VIRT;
					fd->dst_id[fd->dst_num_avail].active =
						1;
					fd->dst_num_avail++;
				}

				fd->full_offload = 0;
				*num_queues += rss->queue_num;
			}
			break;

		case FLOW_ACTION_TYPE_MARK:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_MARK\n",
			       dev);
			if (action[aidx].conf) {
				fd->mark = ((const struct flow_action_mark *)
					    action[aidx]
					    .conf)
					   ->id;
				NT_LOG(DBG, FILTER, "Mark: %i\n", fd->mark);
			}
			break;

		case FLOW_ACTION_TYPE_JUMP:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_JUMP\n",
			       dev);
			if (action[aidx].conf) {
				const struct flow_action_jump *jump =
					(const struct flow_action_jump *)
					action[aidx]
					.conf;
				fd->jump_to_group = jump->group;
				NT_LOG(DBG, FILTER,
				       "Dev:%p: FLOW_ACTION_TYPE_JUMP: group %u\n",
				       dev, jump->group);
			}
			break;

		case FLOW_ACTION_TYPE_DROP:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_DROP\n",
			       dev);
			if (action[aidx].conf) {
				fd->dst_id[fd->dst_num_avail].owning_port_id =
					0;
				fd->dst_id[fd->dst_num_avail].id = 0;
				fd->dst_id[fd->dst_num_avail].type = PORT_NONE;
				fd->dst_num_avail++;
			}
			break;

		case FLOW_ACTION_TYPE_METER:
			NT_LOG(DBG, FILTER, "Dev:%p: FLOW_ACTION_TYPE_METER\n",
			       dev);
			if (action[aidx].conf) {
				const struct flow_action_meter *meter =
					(const struct flow_action_meter *)
					action[aidx]
					.conf;
				if (mtr_count >= MAX_FLM_MTRS_SUPPORTED) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - Number of METER actions exceeds %d.\n",
					       MAX_FLM_MTRS_SUPPORTED);
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}
				fd->mtr_ids[mtr_count++] = meter->mtr_id + 1;
			}
			break;

		case FLOW_ACTION_TYPE_RAW_ENCAP:
			NT_LOG(DBG, FILTER,
			       "Dev:%p: FLOW_ACTION_TYPE_RAW_ENCAP\n", dev);
			if (action[aidx].conf) {
				const struct flow_action_raw_encap *encap =
					(const struct flow_action_raw_encap *)
					action[aidx]
					.conf;
				const struct flow_elem *items = encap->items;

				if (encap_decap_order != 1) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - RAW_ENCAP must follow RAW_DECAP.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				if (encap->size == 0 || encap->size > 255 ||
						encap->item_count < 2) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - RAW_ENCAP data/size invalid.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				encap_decap_order = 2;

				fd->tun_hdr.len = (uint8_t)encap->size;
				memcpy(fd->tun_hdr.d.hdr8, encap->data,
				       fd->tun_hdr.len);

				while (items->type != FLOW_ELEM_TYPE_END) {
					switch (items->type) {
					case FLOW_ELEM_TYPE_ETH:
						fd->tun_hdr.l2_len = 14;
						break;
					case FLOW_ELEM_TYPE_VLAN:
						fd->tun_hdr.nb_vlans += 1;
						fd->tun_hdr.l2_len += 4;
						break;
					case FLOW_ELEM_TYPE_IPV4:
						fd->tun_hdr.ip_version = 4;
						fd->tun_hdr.l3_len = sizeof(struct ipv4_hdr_s);
						fd->tun_hdr.new_outer = 1;
						break;
					case FLOW_ELEM_TYPE_IPV6:
						fd->tun_hdr.ip_version = 6;
						fd->tun_hdr.l3_len = sizeof(struct ipv6_hdr_s);
						fd->tun_hdr.new_outer = 1;
						break;
					case FLOW_ELEM_TYPE_SCTP:
						fd->tun_hdr.l4_len = sizeof(struct sctp_hdr_s);
						break;
					case FLOW_ELEM_TYPE_TCP:
						fd->tun_hdr.l4_len = sizeof(struct tcp_hdr_s);
						break;
					case FLOW_ELEM_TYPE_UDP:
						fd->tun_hdr.l4_len = sizeof(struct udp_hdr_s);
						break;
					case FLOW_ELEM_TYPE_ICMP:
						fd->tun_hdr.l4_len = sizeof(struct icmp_hdr_s);
						break;
					default:
						break;
					}
					items++;
				}

				if (fd->tun_hdr.nb_vlans > 3) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - Encapsulation with %d vlans not supported.\n",
					       (int)fd->tun_hdr.nb_vlans);
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				/* Convert encap data to 128-bit little endian */
				for (size_t i = 0; i < (encap->size + 15) / 16;
						++i) {
					uint8_t *data =
						fd->tun_hdr.d.hdr8 + i * 16;
					for (unsigned int j = 0; j < 8; ++j) {
						uint8_t t = data[j];

						data[j] = data[15 - j];
						data[15 - j] = t;
					}
				}
			}
			break;

		case FLOW_ACTION_TYPE_RAW_DECAP:
			NT_LOG(DBG, FILTER,
			       "Dev:%p: FLOW_ACTION_TYPE_RAW_DECAP\n", dev);
			if (action[aidx].conf) {
				const struct flow_action_raw_decap *decap =
					(const struct flow_action_raw_decap *)
					action[aidx]
					.conf;

				if (encap_decap_order != 0) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - RAW_ENCAP must follow RAW_DECAP.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				if (decap->item_count < 2) {
					NT_LOG(ERR, FILTER,
					       "ERROR: - RAW_DECAP must decap something.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				encap_decap_order = 1;

				fd->header_strip_start_dyn = 2;
				fd->header_strip_start_ofs = 2;

				switch (decap->items[decap->item_count - 2]
						.type) {
				case FLOW_ELEM_TYPE_ETH:
				case FLOW_ELEM_TYPE_VLAN:
					fd->header_strip_end_dyn = 4;
					fd->header_strip_end_ofs = 0;
					break;
				case FLOW_ELEM_TYPE_IPV4:
				case FLOW_ELEM_TYPE_IPV6:
					fd->header_strip_end_dyn = 7;
					fd->header_strip_end_ofs = 0;
					fd->header_strip_removed_outer_ip = 1;
					break;
				case FLOW_ELEM_TYPE_SCTP:
				case FLOW_ELEM_TYPE_TCP:
				case FLOW_ELEM_TYPE_UDP:
				case FLOW_ELEM_TYPE_ICMP:
					fd->header_strip_end_dyn = 8;
					fd->header_strip_end_ofs = 0;
					fd->header_strip_removed_outer_ip = 1;
					break;
				case FLOW_ELEM_TYPE_GTP:
					fd->header_strip_end_dyn = 13;
					fd->header_strip_end_ofs = 0;
					fd->header_strip_removed_outer_ip = 1;
					break;
				default:
					fd->header_strip_end_dyn = 1;
					fd->header_strip_end_ofs = 0;
					fd->header_strip_removed_outer_ip = 1;
					break;
				}
			}
			break;

		case FLOW_ACTION_TYPE_MODIFY_FIELD:
			NT_LOG(DBG, FILTER,
			       "Dev:%p: FLOW_ACTION_TYPE_MODIFY_FIELD\n", dev);
			{
				const struct flow_action_modify_field *modify_field =
					(const struct flow_action_modify_field *)
					action[aidx]
					.conf;
				uint64_t modify_field_use_flag = 0;

				if (modify_field->src.field !=
						FLOW_FIELD_VALUE) {
					NT_LOG(ERR, FILTER,
					       "MODIFY_FIELD only src type VALUE is supported.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				if (modify_field->dst.level > 2) {
					NT_LOG(ERR, FILTER,
					       "MODIFY_FIELD only dst level 0, 1, and 2 is supported.\n");
					flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
							   error);
					free(fd);
					return NULL;
				}

				if (modify_field->dst.field ==
						FLOW_FIELD_IPV4_TTL ||
						modify_field->dst.field ==
						FLOW_FIELD_IPV6_HOPLIMIT) {
					if (modify_field->operation !=
							FLOW_MODIFY_SUB) {
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD only operation SUB is supported for TTL/HOPLIMIT.\n");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					if (fd->ttl_sub_enable) {
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD TTL/HOPLIMIT resource already in use.\n");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					fd->ttl_sub_enable = 1;
					fd->ttl_sub_ipv4 =
						(modify_field->dst.field ==
						 FLOW_FIELD_IPV4_TTL) ?
						1 :
						0;
					fd->ttl_sub_outer =
						(modify_field->dst.level <= 1) ?
						1 :
						0;
				} else {
					if (modify_field->operation !=
							FLOW_MODIFY_SET) {
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD only operation SET "
						       "is supported in general.\n");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					if (fd->modify_field_count >=
							dev->ndev->be.tpe.nb_cpy_writers) {
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD exceeded maximum of %u"
						       " MODIFY_FIELD actions.\n",
						       dev->ndev->be.tpe
						       .nb_cpy_writers);
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					switch (modify_field->dst.field) {
					case FLOW_FIELD_IPV4_DSCP:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_DSCP_IPV4;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L3;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 1;
						fd->modify_field
						[fd->modify_field_count]
						.len = 1;
						break;
					case FLOW_FIELD_IPV6_DSCP:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_DSCP_IPV6;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L3;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 0;
						fd->modify_field
						/*
						 * len=2 is needed because IPv6 DSCP overlaps 2
						 * bytes.
						 */
						[fd->modify_field_count]
						.len = 2;
						break;
					case FLOW_FIELD_GTP_PSC_QFI:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_RQI_QFI;
						fd->modify_field
						[fd->modify_field_count]
						.dyn =
							DYN_L4_PAYLOAD;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 14;
						fd->modify_field
						[fd->modify_field_count]
						.len = 1;
						break;
					case FLOW_FIELD_IPV4_SRC:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_IPV4;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L3;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 12;
						fd->modify_field
						[fd->modify_field_count]
						.len = 4;
						break;
					case FLOW_FIELD_IPV4_DST:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_IPV4;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L3;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 16;
						fd->modify_field
						[fd->modify_field_count]
						.len = 4;
						break;
					case FLOW_FIELD_TCP_PORT_SRC:
					/* fallthrough */
					case FLOW_FIELD_UDP_PORT_SRC:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_PORT;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L4;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 0;
						fd->modify_field
						[fd->modify_field_count]
						.len = 2;
						break;
					case FLOW_FIELD_TCP_PORT_DST:
					/* fallthrough */
					case FLOW_FIELD_UDP_PORT_DST:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_PORT;
						fd->modify_field
						[fd->modify_field_count]
						.dyn = DYN_L4;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 2;
						fd->modify_field
						[fd->modify_field_count]
						.len = 2;
						break;
					case FLOW_FIELD_GTP_TEID:
						fd->modify_field
						[fd->modify_field_count]
						.select =
							CPY_SELECT_TEID;
						fd->modify_field
						[fd->modify_field_count]
						.dyn =
							DYN_L4_PAYLOAD;
						fd->modify_field
						[fd->modify_field_count]
						.ofs = 4;
						fd->modify_field
						[fd->modify_field_count]
						.len = 4;
						break;
					default:
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD dst type is not supported.\n");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					modify_field_use_flag =
						1
						<< fd->modify_field
						[fd->modify_field_count]
						.select;
					if (modify_field_use_flag &
							modify_field_use_flags) {
						NT_LOG(ERR, FILTER,
						       "MODIFY_FIELD dst type hardware "
						       "resource already used.\n");
						flow_nic_set_error(ERR_ACTION_UNSUPPORTED,
								   error);
						free(fd);
						return NULL;
					}

					memcpy(fd->modify_field
					       [fd->modify_field_count]
					       .value8,
					       modify_field->src.value, 16);

					fd->modify_field[fd->modify_field_count]
					.level =
						modify_field->dst.level;

					modify_field_use_flags |=
						modify_field_use_flag;
					fd->modify_field_count += 1;
				}
			}
			break;

		default:
			NT_LOG(ERR, FILTER,
			       "Invalid or unsupported flow action received - %i\n",
			       action[aidx].type);
			flow_nic_set_error(ERR_ACTION_UNSUPPORTED, error);
			free(fd);
			return NULL;
		}
	}

	if (!(encap_decap_order == 0 || encap_decap_order == 2)) {
		NT_LOG(ERR, FILTER, "Invalid encap/decap actions\n");
		free(fd);
		return NULL;
	}

	if (implicit_vlan_vid > 0) {
		uint32_t *sw_data = &packet_data[1 - sw_counter];
		uint32_t *sw_mask = &packet_mask[1 - sw_counter];

		sw_mask[0] = 0x0fff;
		sw_data[0] = implicit_vlan_vid & sw_mask[0];

		km_add_match_elem(&fd->km, &sw_data[0], &sw_mask[0], 1,
				  DYN_FIRST_VLAN, 0);
		set_key_def_sw(key_def, sw_counter, DYN_FIRST_VLAN, 0);
		sw_counter += 1;

		fd->vlans += 1;
	}

	/*
	 * All Actions interpreted
	 */
	for (int eidx = 0; elem[eidx].type != FLOW_ELEM_TYPE_END; ++eidx) {
		switch (elem[eidx].type) {
		case FLOW_ELEM_TYPE_ANY:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_ANY\n",
			       dev->ndev->adapter_no, dev->port);
			{
				const struct flow_elem_any *any_spec =
					(const struct flow_elem_any *)elem[eidx]
					.spec;
				const struct flow_elem_any *any_mask =
					(const struct flow_elem_any *)elem[eidx]
					.mask;

				if (any_spec && any_mask) {
					any_count += any_spec->num &
						     any_mask->num;
				}
			}
			break;

		case FLOW_ELEM_TYPE_ETH:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_ETH\n",
			       dev->ndev->adapter_no, dev->port);
			{
				const struct flow_elem_eth *eth_spec =
					(const struct flow_elem_eth *)elem[eidx]
					.spec;
				const struct flow_elem_eth *eth_mask =
					(const struct flow_elem_eth *)elem[eidx]
					.mask;

				if (any_count > 0) {
					NT_LOG(ERR, FILTER,
					       "Tunneled L2 ethernet not supported\n");
					flow_nic_set_error(ERR_FAILED, error);
					free(fd);
					return NULL;
				}

				if (qw_counter >= 2) {
					NT_LOG(ERR, FILTER,
					       "Key size too big. Out of QW resources.\n");
					flow_nic_set_error(ERR_FAILED, error);
					free(fd);
					return NULL;
				}

				if (eth_spec != NULL && eth_mask != NULL) {
					if (is_non_zero(eth_mask->d_addr.addr_b,
							6) ||
							is_non_zero(eth_mask->s_addr.addr_b,
								    6)) {
						uint32_t *qw_data =
							&packet_data[2 + 4 -
								       qw_counter *
								       4];
						uint32_t *qw_mask =
							&packet_mask[2 + 4 -
								       qw_counter *
								       4];

						qw_data[0] =
							((eth_spec->d_addr
							  .addr_b[0] &
							  eth_mask->d_addr
							  .addr_b[0])
							 << 24) +
							((eth_spec->d_addr
							  .addr_b[1] &
							  eth_mask->d_addr
							  .addr_b[1])
							 << 16) +
							((eth_spec->d_addr
							  .addr_b[2] &
							  eth_mask->d_addr
							  .addr_b[2])
							 << 8) +
							(eth_spec->d_addr
							 .addr_b[3] &
							 eth_mask->d_addr
							 .addr_b[3]);

						qw_data[1] =
							((eth_spec->d_addr
							  .addr_b[4] &
							  eth_mask->d_addr
							  .addr_b[4])
							 << 24) +
							((eth_spec->d_addr
							  .addr_b[5] &
							  eth_mask->d_addr
							  .addr_b[5])
							 << 16) +
							((eth_spec->s_addr
							  .addr_b[0] &
							  eth_mask->s_addr
							  .addr_b[0])
							 << 8) +
							(eth_spec->s_addr
							 .addr_b[1] &
							 eth_mask->s_addr
							 .addr_b[1]);

						qw_data[2] =
							((eth_spec->s_addr
							  .addr_b[2] &
							  eth_mask->s_addr
							  .addr_b[2])
							 << 24) +
							((eth_spec->s_addr
							  .addr_b[3] &
							  eth_mask->s_addr
							  .addr_b[3])
							 << 16) +
							((eth_spec->s_addr
							  .addr_b[4] &
							  eth_mask->s_addr
							  .addr_b[4])
							 << 8) +
							(eth_spec->s_addr
							 .addr_b[5] &
							 eth_mask->s_addr
							 .addr_b[5]);

						qw_mask[0] = (eth_mask->d_addr
							      .addr_b[0]
							      << 24) +
							     (eth_mask->d_addr
							      .addr_b[1]
							      << 16) +
							     (eth_mask->d_addr
							      .addr_b[2]
							      << 8) +
							     eth_mask->d_addr
							     .addr_b[3];

						qw_mask[1] = (eth_mask->d_addr
							      .addr_b[4]
							      << 24) +
							     (eth_mask->d_addr
							      .addr_b[5]
							      << 16) +
							     (eth_mask->s_addr
							      .addr_b[0]
							      << 8) +
							     eth_mask->s_addr
							     .addr_b[1];

						qw_mask[2] = (eth_mask->s_addr
							      .addr_b[2]
							      << 24) +
							     (eth_mask->s_addr
							      .addr_b[3]
							      << 16) +
							     (eth_mask->s_addr
							      .addr_b[4]
							      << 8) +
							     eth_mask->s_addr
							     .addr_b[5];

						km_add_match_elem(&fd->km,
								  &qw_data[(size_t)(qw_counter *
								  4)],
								  &qw_mask[(size_t)(qw_counter *
								  4)],
								  3, DYN_L2, 0);
						set_key_def_qw(key_def,
							       qw_counter,
							       DYN_L2, 0);
						qw_counter += 1;
					}
				}

				fd->l2_prot = PROT_L2_ETH2;
			}
			break;

		case FLOW_ELEM_TYPE_VLAN:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_VLAN\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_vlan(elem, eidx, implicit_vlan_vid, error, fd,
					sw_counter, packet_data, packet_mask, key_def))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_IPV4:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_IPV4\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_ipv4(elem, eidx, error, fd, qw_counter,
					sw_counter, packet_data, packet_mask, key_def, any_count))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_IPV6:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_IPV6\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_ipv6(elem, eidx, error, fd, qw_counter,
					packet_data, packet_mask, key_def, any_count))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_UDP:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_UDP\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_upd(elem, eidx, error, fd, sw_counter,
					packet_data, packet_mask, key_def, any_count))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_SCTP:
			NT_LOG(DBG, FILTER,
			       "Adap %i,Port %i:FLOW_ELEM_TYPE_SCTP\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_sctp(elem, eidx, error, fd, sw_counter,
					packet_data, packet_mask, key_def, any_count))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_TCP:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_TCP\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_tcp(elem, eidx, error, fd, sw_counter,
					packet_data, packet_mask, key_def, any_count))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_GTP:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_GTP\n",
			       dev->ndev->adapter_no, dev->port);
			{
				if (flow_elem_type_gtp(elem, eidx, error, fd, sw_counter,
					packet_data, packet_mask, key_def))
					return NULL;
			}
			break;

		case FLOW_ELEM_TYPE_PORT_ID:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_PORT_ID\n",
			       dev->ndev->adapter_no, dev->port);
			if (elem[eidx].spec) {
				*in_port_id =
					((const struct flow_elem_port_id *)
					 elem[eidx]
					 .spec)
					->id;
			}
			break;

		case FLOW_ELEM_TYPE_VOID:
			NT_LOG(DBG, FILTER,
			       "Adap %i, Port %i: FLOW_ELEM_TYPE_VOID\n",
			       dev->ndev->adapter_no, dev->port);
			break;

		default:
			NT_LOG(ERR, FILTER,
			       "Invalid or unsupported flow request: %d\n",
			       (int)elem[eidx].type);
			flow_nic_set_error(ERR_MATCH_INVALID_OR_UNSUPPORTED_ELEM,
					   error);
			free(fd);
			return NULL;
		}
	}

	return fd;
}

static int reset_cat_function_setup(struct flow_eth_dev *dev, int cfn)
{
	/* CFN */
	{
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PRESET_ALL, cfn,
				   0, 0);
		hw_mod_cat_cfn_flush(&dev->ndev->be, cfn, 1);
	}

	/* KM */
	{
		uint32_t bm = 0;

		hw_mod_cat_kce_km_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				      KM_FLM_IF_FIRST, cfn / 8, &bm);
		hw_mod_cat_kce_km_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				      KM_FLM_IF_FIRST, cfn / 8,
				      bm & ~(1 << (cfn % 8)));
		hw_mod_cat_kcs_km_set(&dev->ndev->be, HW_CAT_KCS_CATEGORY,
				      KM_FLM_IF_FIRST, cfn, 0);

		hw_mod_cat_kce_km_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					cfn / 8, 1);
		hw_mod_cat_kcs_km_flush(&dev->ndev->be, KM_FLM_IF_FIRST, cfn,
					1);

		for (unsigned int ft = 0; ft < dev->ndev->be.cat.nb_flow_types;
				ft++) {
			set_flow_type_km(dev->ndev, cfn, ft, 0, 0);
			set_flow_type_km(dev->ndev, cfn, ft, 1, 0);
			set_flow_type_km(dev->ndev, cfn, ft, 2, 0);
			set_flow_type_km(dev->ndev, cfn, ft, 3, 0);
		}
	}

	/* FLM */
	{
		uint32_t bm = 0;

		hw_mod_cat_kce_flm_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST, cfn / 8, &bm);
		hw_mod_cat_kce_flm_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST, cfn / 8,
				       bm & ~(1 << (cfn % 8)));
		hw_mod_cat_kcs_flm_set(&dev->ndev->be, HW_CAT_KCS_CATEGORY,
				       KM_FLM_IF_FIRST, cfn, 0);

		hw_mod_cat_kce_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 cfn / 8, 1);
		hw_mod_cat_kcs_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST, cfn,
					 1);

		for (unsigned int ft = 0; ft < dev->ndev->be.cat.nb_flow_types;
				ft++) {
			set_flow_type_flm(dev->ndev, cfn, ft, 0, 0);
			set_flow_type_flm(dev->ndev, cfn, ft, 1, 0);
			set_flow_type_flm(dev->ndev, cfn, ft, 2, 0);
			set_flow_type_flm(dev->ndev, cfn, ft, 3, 0);
		}
	}

	/* CTE / CTS */
	{
		uint32_t cte = 0;

		hw_mod_cat_cte_get(&dev->ndev->be, HW_CAT_CTE_ENABLE_BM, cfn,
				   &cte);

		if (cte) {
			const int cts_offset =
				((int)dev->ndev->be.cat.cts_num + 1) / 2;

			hw_mod_cat_cte_set(&dev->ndev->be, HW_CAT_CTE_ENABLE_BM,
					   cfn, 0);
			hw_mod_cat_cte_flush(&dev->ndev->be, cfn, 1);

			for (int cte_type = 0; cte_type < cts_offset;
					++cte_type) {
				hw_mod_cat_cts_set(&dev->ndev->be,
						   HW_CAT_CTS_CAT_A,
						   cts_offset * cfn + cte_type,
						   0);
				hw_mod_cat_cts_set(&dev->ndev->be,
						   HW_CAT_CTS_CAT_B,
						   cts_offset * cfn + cte_type,
						   0);
			}

			hw_mod_cat_cts_flush(&dev->ndev->be, cts_offset * cfn,
					     cts_offset);
		}
	}

	return 0;
}

static int convert_fd_to_flm(struct flow_handle *fh, struct nic_flow_def *fd,
			     const uint32_t *packet_data, uint32_t flm_key_id,
			     uint16_t rpl_ext_ptr, uint32_t priority)
{
	if (fh->type != FLOW_HANDLE_TYPE_FLM)
		return -1;

	switch (fd->l4_prot) {
	case PROT_L4_TCP:
		fh->flm_prot = 6;
		break;
	case PROT_L4_UDP:
		fh->flm_prot = 17;
		break;
	case PROT_L4_SCTP:
		fh->flm_prot = 132;
		break;
	case PROT_L4_ICMP:
		fh->flm_prot = 1;
		break;
	default:
		switch (fd->tunnel_l4_prot) {
		case PROT_TUN_L4_TCP:
			fh->flm_prot = 6;
			break;
		case PROT_TUN_L4_UDP:
			fh->flm_prot = 17;
			break;
		case PROT_TUN_L4_SCTP:
			fh->flm_prot = 132;
			break;
		case PROT_TUN_L4_ICMP:
			fh->flm_prot = 1;
			break;
		default:
			fh->flm_prot = 0;
			break;
		}
		break;
	}

	memcpy(fh->flm_data, packet_data, sizeof(uint32_t) * 10);

	fh->flm_kid = flm_key_id;
	fh->flm_rpl_ext_ptr = rpl_ext_ptr;
	fh->flm_prio = (uint8_t)priority;

	for (unsigned int i = 0; i < fd->modify_field_count; ++i) {
		switch (fd->modify_field[i].select) {
		case CPY_SELECT_DSCP_IPV4:
		/* fallthrough */
		case CPY_SELECT_DSCP_IPV6:
			fh->flm_dscp = fd->modify_field[i].value8[0];
			break;
		case CPY_SELECT_RQI_QFI:
			fh->flm_rqi = (fd->modify_field[i].value8[0] >> 6) &
				      0x1;
			fh->flm_qfi = fd->modify_field[i].value8[0] & 0x3f;
			break;
		case CPY_SELECT_IPV4:
			fh->flm_nat_ipv4 =
				ntohl(fd->modify_field[i].value32[0]);
			break;
		case CPY_SELECT_PORT:
			fh->flm_nat_port =
				ntohs(fd->modify_field[i].value16[0]);
			break;
		case CPY_SELECT_TEID:
			fh->flm_teid = ntohl(fd->modify_field[i].value32[0]);
			break;
		}
	}

	fh->flm_mtu_fragmentation_recipe = fd->flm_mtu_fragmentation_recipe;

	return 0;
}

static int flm_flow_programming(struct flow_eth_dev *dev,
				struct flow_handle *fh, uint32_t *mtr_ids,
				uint32_t flm_ft, uint32_t flm_op)
{
	struct flm_v17_lrn_data_s learn_record;

	if (fh->type != FLOW_HANDLE_TYPE_FLM)
		return -1;

	memset(&learn_record, 0x0, sizeof(struct flm_v17_lrn_data_s));

	learn_record.qw0[0] = fh->flm_data[9];
	learn_record.qw0[1] = fh->flm_data[8];
	learn_record.qw0[2] = fh->flm_data[7];
	learn_record.qw0[3] = fh->flm_data[6];
	learn_record.qw4[0] = fh->flm_data[5];
	learn_record.qw4[1] = fh->flm_data[4];
	learn_record.qw4[2] = fh->flm_data[3];
	learn_record.qw4[3] = fh->flm_data[2];
	learn_record.sw8 = fh->flm_data[1];
	learn_record.sw9 = fh->flm_data[0];
	learn_record.prot = fh->flm_prot;

	if (mtr_ids) {
		FLM_V17_MBR_ID1(learn_record.mbr_idx) = mtr_ids[0];
		FLM_V17_MBR_ID2(learn_record.mbr_idx) = mtr_ids[1];
		FLM_V17_MBR_ID3(learn_record.mbr_idx) = mtr_ids[2];
		FLM_V17_MBR_ID4(learn_record.mbr_idx) = mtr_ids[3];

		/* Last non-zero mtr is used for statistics */
		uint8_t mbrs = 0;

		while (mbrs < MAX_FLM_MTRS_SUPPORTED && mtr_ids[mbrs] != 0)
			++mbrs;
		learn_record.vol_idx = mbrs;
	}

	learn_record.nat_ip = fh->flm_nat_ipv4;
	learn_record.nat_port = fh->flm_nat_port;
	learn_record.nat_en = fh->flm_nat_ipv4 || fh->flm_nat_port ? 1 : 0;

	learn_record.dscp = fh->flm_dscp;
	learn_record.teid = fh->flm_teid;
	learn_record.qfi = fh->flm_qfi;
	learn_record.rqi = fh->flm_rqi;
	learn_record.color = fh->flm_rpl_ext_ptr &
			     0x3ff; /* Lower 10 bits used for RPL EXT PTR */
	learn_record.color |= (fh->flm_mtu_fragmentation_recipe & 0xf)
			      << 10; /* Bit [13:10] used for MTU recipe */

	learn_record.ent = 0;
	learn_record.op = flm_op & 0xf;
	learn_record.prio = fh->flm_prio & 0x3;
	learn_record.ft = flm_ft;
	learn_record.kid = fh->flm_kid;
	learn_record.eor = 1;

	int res = flow_flm_apply(dev, &learn_record);
	return res;
}

static int km_ft_handler(int *setup_km_ft, int *setup_km_rcp, int *setup_km,
	struct flow_handle *found_flow, int identical_flow_found, struct flow_eth_dev *dev,
	struct nic_flow_def *fd, struct flow_error *error, struct flow_handle *fh,
	struct flow_handle *flow)
{
	if (!identical_flow_found) {
				/* Find existing KM FT that can be reused */
		{
			int found_ft = 0, found_zero = 0;

			struct flm_flow_ft_ident_s *ft_idents =
				(struct flm_flow_ft_ident_s *)dev->ndev->ft_res_handle;
			struct flm_flow_ft_ident_s ft_ident = flow_def_to_ft_ident(fd);

			for (int i = 1; i < FLM_FLOW_FT_MAX; ++i) {
				if (ft_ident.data == ft_idents[i].data) {
					found_ft = i;
					break;
				} else if (found_zero == 0 && ft_idents[i].data == 0) {
					found_zero = i;
				}
			}

			if (found_ft) {
				if (flow_nic_ref_resource(dev->ndev, RES_KM_FLOW_TYPE, found_ft)) {
					NT_LOG(ERR, FILTER, "ERROR: Could not reference "
					       "KM FLOW TYPE resource\n");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
					return 1;
				}

				fh->resource[RES_KM_FLOW_TYPE].count = 1;
				fh->resource[RES_KM_FLOW_TYPE].index = found_ft;
				fh->resource[RES_KM_FLOW_TYPE].referenced = 1;
			} else if (found_zero) {
				if (flow_nic_allocate_fh_resource_index(dev->ndev, RES_KM_FLOW_TYPE,
				found_zero, fh)) {
					NT_LOG(ERR, FILTER, "ERROR: Could not get "
					       "KM FLOW TYPE resource\n");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
					return 1;
				}

				ft_idents[found_zero].data = ft_ident.data;
			} else {
				NT_LOG(ERR, FILTER, "ERROR: Could not get KM FLOW TYPE resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				return 1;
			}
		}
		/* Attach resources to KM entry */
		km_attach_ndev_resource_management(&fd->km, &dev->ndev->km_res_handle);
		fd->km.flow_type = fh->resource[RES_KM_FLOW_TYPE].index;

		/* _update existing KM RCP or allocate a new RCP */
		if (found_flow != NULL) {
			if (flow_nic_ref_resource(dev->ndev, RES_KM_CATEGORY, found_flow
				->resource[RES_KM_CATEGORY].index)) {
				NT_LOG(ERR, FILTER, "ERROR: Could not reference "
				       "KM CATEGORY resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				return 1;
			}

			fh->resource[RES_KM_CATEGORY].count = 1;
			fh->resource[RES_KM_CATEGORY].index =
				found_flow->resource[RES_KM_CATEGORY].index;
			fh->resource[RES_KM_CATEGORY].referenced = 1;

			if (fd->km.target == KM_CAM) {
				uint32_t ft_a_mask = 0;

				hw_mod_km_rcp_get(&dev->ndev->be, HW_KM_RCP_FTM_A,
					fh->resource[RES_KM_CATEGORY].index, 0, &ft_a_mask);
				hw_mod_km_rcp_set(&dev->ndev->be, HW_KM_RCP_FTM_A,
					fh->resource[RES_KM_CATEGORY].index, 0,
					ft_a_mask | (1 << fd->km.flow_type));
			}
		} else {
			if (flow_nic_allocate_fh_resource(dev->ndev, RES_KM_CATEGORY, fh, 1, 1)) {
				NT_LOG(ERR, FILTER, "ERROR: Could not get KM CATEGORY resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
				return 1;
			}

			/* Note: km_rcp_set clears existing RCPs */
			km_rcp_set(&fd->km, fh->resource[RES_KM_CATEGORY].index);
		}

		/* Set filter setup variables */
		*setup_km = 1;
		*setup_km_ft = fh->resource[RES_KM_FLOW_TYPE].index;
		*setup_km_rcp = fh->resource[RES_KM_CATEGORY].index;

		/* _flush KM RCP and entry */
		hw_mod_km_rcp_flush(&dev->ndev->be, fh->resource[RES_KM_CATEGORY].index, 1);

		km_write_data_match_entry(&fd->km, 0);
	} else {
		if (flow_nic_ref_resource(dev->ndev, RES_KM_FLOW_TYPE,
			found_flow->resource[RES_KM_FLOW_TYPE].index)) {
			NT_LOG(ERR, FILTER, "ERROR: Could not reference KM FLOW TYPE resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			return 1;
		}

		fh->resource[RES_KM_FLOW_TYPE].count = 1;
		fh->resource[RES_KM_FLOW_TYPE].index = found_flow->resource[RES_KM_FLOW_TYPE].index;
		fh->resource[RES_KM_FLOW_TYPE].referenced = 1;

		if (flow_nic_ref_resource(dev->ndev, RES_KM_CATEGORY,
			found_flow->resource[RES_KM_CATEGORY].index)) {
			NT_LOG(ERR, FILTER, "ERROR: Could not reference KM CATEGORY resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
			return 1;
		}

		fh->resource[RES_KM_CATEGORY].count = 1;
		fh->resource[RES_KM_CATEGORY].index = found_flow->resource[RES_KM_CATEGORY].index;
		fh->resource[RES_KM_CATEGORY].referenced = 1;

		km_attach_ndev_resource_management(&fd->km, &dev->ndev->km_res_handle);
		fd->km.flow_type = fh->resource[RES_KM_FLOW_TYPE].index;

		km_refer_data_match_entry(&fd->km, &found_flow->fd->km);

		*setup_km = 1;
		*setup_km_ft = flow->resource[RES_KM_FLOW_TYPE].index;
		*setup_km_rcp = flow->resource[RES_KM_CATEGORY].index;
	}
	return 0;
}

/*
 * Tunneling invalidates dynamic offsets, so change them to static
 * offsets starting at beginning of L2.
 */
static void align_tun_offset(struct nic_flow_def *fd, const uint32_t eth_length, int i,
	uint32_t *ofs, uint32_t select, const uint32_t l2_length, const uint32_t l3_length,
	const uint32_t l4_length, uint32_t *dyn)
{
	if (fd->tun_hdr.len > eth_length) {
		if (!fd->tun_hdr.new_outer || fd->modify_field[i].level > 1) {
			ofs += fd->tun_hdr.len - eth_length;
		} else {
			switch (select) {
			case CPY_SELECT_IPV4:
			case CPY_SELECT_DSCP_IPV4:
			case CPY_SELECT_DSCP_IPV6:
				*ofs += l2_length;
				break;
			case CPY_SELECT_PORT:
				*ofs += l2_length + l3_length;
				break;
			case CPY_SELECT_TEID:
			case CPY_SELECT_RQI_QFI:
				*ofs += l2_length + l3_length + l4_length;
				break;
			}
			*dyn = 1;
		}
	}
}

static struct flow_handle *
create_flow_filter(struct flow_eth_dev *dev, struct nic_flow_def *fd,
		   const struct flow_attr *attr, struct flow_error *error,
		   uint32_t port_id, uint32_t num_dest_port,
		   uint32_t num_queues, uint32_t *packet_data,
		   uint32_t *packet_mask, struct flm_flow_key_def_s *key_def)
{
	uint32_t qsl_size = num_dest_port > num_queues ? num_dest_port :
			    num_queues;
	uint32_t flm_key_id = 0;
	uint32_t flm_ft = 0;
	uint16_t flm_rpl_ext_ptr = 0;

	struct flow_handle *fh_flm = NULL;
	struct flow_handle *fh = calloc(1, sizeof(struct flow_handle));

	if (!fh) {
		NT_LOG(ERR, FILTER, "ERR memory\n");
		flow_nic_set_error(ERR_MEMORY, error);
		return NULL;
	}

	fh->type = FLOW_HANDLE_TYPE_FLOW;
	fh->port_id = port_id;
	fh->dev = dev;
	fh->fd = fd;

	int setup_cat_cfn = 0;
	int setup_cat_cot = 0;
	int setup_cat_cts = 0;
	int setup_qsl_rcp = 0;

	int setup_flm = 0;
	int setup_flm_ft = 0;

	int setup_km = 0;
	int setup_km_ft = 0;
	int setup_km_rcp = 0;

	int setup_default_ft = 0;

	int setup_hst = 0;
	int setup_tpe = 0;
	int setup_tpe_encap_data = 0;

	int free_fd = 0;

	const int empty_pattern =
		fd->l2_prot < 0 && fd->l3_prot < 0 && fd->l4_prot < 0 &&
		fd->vlans == 0 && fd->tunnel_prot < 0 &&
		fd->tunnel_l3_prot < 0 && fd->tunnel_l4_prot < 0;

	if (attr->group > 0 && empty_pattern) {
		/*
		 * Group 0 default filter actions
		 */
		struct flow_handle *fh_miss = NULL;

		if (flm_flow_get_group_miss_fh(dev, attr->group, &fh_miss)) {
			/* Error was printed to log by flm_flow_get_group_miss_fh */
			flow_nic_set_error(ERR_FAILED, error);
			free(fh);
			return NULL;
		}

		if (fh_miss == NULL) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not setup default action for uninitialized group\n");
			flow_nic_set_error(ERR_FAILED, error);
			free(fh);
			return NULL;
		}

		if (qsl_size > 0 &&
				flow_nic_allocate_fh_resource(dev->ndev, RES_QSL_QST, fh,
						qsl_size, 1)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not get QSL QST resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			free(fh);
			return NULL;
		}

		if (flow_nic_ref_resource(dev->ndev, RES_QSL_RCP,
					  fh_miss->resource[RES_QSL_RCP].index)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not reference QSL RCP resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			free(fh);
			return NULL;
		}

		fh->resource[RES_QSL_RCP].count = 1;
		fh->resource[RES_QSL_RCP].index =
			fh_miss->resource[RES_QSL_RCP].index;
		fh->resource[RES_QSL_RCP].referenced = 1;

		nic_insert_flow(dev->ndev, fh);

		setup_qsl_rcp = 1;
	} else if (attr->group > 0) {
		/*
		 * FLM programming
		 */
		struct flow_handle *fh_excisting = NULL;
		int cfn_to_copy = -1;

		if (attr->priority >= dev->ndev->be.flm.nb_prios) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Priority value of FLM flow exceeds %u"
			       "\n",
			       dev->ndev->be.flm.nb_prios);
			flow_nic_set_error(ERR_FLOW_PRIORITY_VALUE_INVALID,
					   error);
			free(fh);
			return NULL;
		}

		if (flm_flow_learn_prepare(dev, fh, attr->group, key_def,
					   packet_mask, &flm_key_id, &flm_ft,
					   &cfn_to_copy, &setup_km_ft,
					   &fh_excisting)) {
			/* Error was printed to log by flm_flow_learn_prepare */
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			free(fh);
			return NULL;
		}

		setup_tpe_encap_data = (fd->tun_hdr.len > 0);
		setup_tpe =
			(fd->modify_field_count > 0 || fd->ttl_sub_enable > 0);

		/* Create HIT filter for new FLM FT */
		if (cfn_to_copy >= 0) {
			uint32_t value = 0;

			nic_insert_flow(dev->ndev, fh);

			setup_qsl_rcp = 1;
			setup_cat_cot = 1;
			setup_cat_cts = 1;

			setup_default_ft = 1;

			setup_flm = 1;
			setup_flm_ft = (int)flm_ft;

			setup_tpe |= setup_tpe_encap_data;

			if (fd->header_strip_start_dyn != fd->header_strip_end_dyn ||
					fd->header_strip_start_ofs != fd->header_strip_end_ofs)
				setup_hst = 1;

			if (flow_nic_allocate_fh_resource(dev->ndev,
							  RES_CAT_CFN,
							  fh, 1, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get CAT CFN resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			if (flow_nic_allocate_fh_resource(dev->ndev,
							  RES_CAT_COT,
							  fh, 1, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get CAT COT resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			if (flow_nic_allocate_fh_resource(dev->ndev,
							  RES_QSL_RCP,
							  fh, 1, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get QSL RCP resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			if (qsl_size > 0 &&
					flow_nic_allocate_fh_resource(dev->ndev,
								      RES_QSL_QST,
								      fh, qsl_size, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get QSL QST resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			NT_LOG(DBG, FILTER,
			       "FLM: Creating new CFN %d as a copy of CFN %d with FT %d\n",
			       fh->resource[RES_CAT_CFN].index, cfn_to_copy,
			       setup_flm_ft);

			/* Copy parts from base MISS filter */
			hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_COPY_FROM,
					   fh->resource[RES_CAT_CFN].index, 0,
					   cfn_to_copy);
			hw_mod_cat_cfn_flush(&dev->ndev->be,
					     fh->resource[RES_CAT_CFN].index,
					     1);

			hw_mod_cat_kcs_km_get(&dev->ndev->be,
					      HW_CAT_KCS_CATEGORY,
					      KM_FLM_IF_FIRST, cfn_to_copy,
					      &value);
			if (value > 0) {
				setup_km = 1;
				setup_km_rcp = (int)value;
			}

			hw_mod_cat_kcs_flm_get(&dev->ndev->be,
					       HW_CAT_KCS_CATEGORY,
					       KM_FLM_IF_FIRST, cfn_to_copy,
					       &value);
			hw_mod_cat_kcs_flm_set(&dev->ndev->be,
					       HW_CAT_KCS_CATEGORY,
					       KM_FLM_IF_FIRST,
					       fh->resource[RES_CAT_CFN].index,
					       value);
			hw_mod_cat_kcs_flm_flush(&dev->ndev->be,
						 KM_FLM_IF_FIRST,
						 fh->resource[RES_CAT_CFN].index,
						 1);

			fh_flm = calloc(1, sizeof(struct flow_handle));
			if (!fh_flm) {
				flow_nic_set_error(ERR_MEMORY, error);
				return NULL;
			}

			nic_insert_flow_flm(dev->ndev, fh_flm);

			fh_flm->type = FLOW_HANDLE_TYPE_FLM;
			fh_flm->dev = dev;
			fh_flm->flm_owner = fh;
		} else {
			/* Reuse allocated memory */
			fh_flm = fh;
			fh = fh_excisting;

			nic_insert_flow_flm(dev->ndev, fh_flm);

			fh_flm->type = FLOW_HANDLE_TYPE_FLM;
			fh_flm->dev = dev;
			fh_flm->flm_owner = fh_excisting;

			free_fd = 1;
		}

		fh_flm->flm_owner->flm_ref_count += 1;
	} else {
		/*
		 * Filter creation
		 */
		nic_insert_flow(dev->ndev, fh);

		setup_cat_cfn = 1;
		setup_cat_cts = 1;
		setup_qsl_rcp = 1;

		if (fd->km.num_ftype_elem) {
			struct flow_handle *flow = dev->ndev->flow_base,
						    *found_flow = NULL;
			int identical_flow_found = 0;

			/* Compute new KM key */
			if (km_key_create(&fd->km, fh->port_id)) {
				NT_LOG(ERR, FILTER, "KM creation failed\n");
				flow_nic_set_error(ERR_MATCH_FAILED_BY_HW_LIMITS,
						   error);
				return NULL;
			}

			fd->km.be = &dev->ndev->be;

			/* Find existing KM key that can be reused */
			while (flow) {
				if (flow->type == FLOW_HANDLE_TYPE_FLOW &&
						flow->fd->km
						.flow_type && /* This check also skips self */
						flow->resource[RES_KM_CATEGORY].count) {
					int res = km_key_compare(&fd->km,
								 &flow->fd->km);
					if (res < 0) {
						identical_flow_found = 1;
						found_flow = flow;
						break;
					} else if (res > 0 &&
							!flow->resource[RES_KM_CATEGORY]
							.referenced &&
							found_flow == NULL)
						found_flow = flow;
				}
				flow = flow->next;
			}
				if (km_ft_handler(&setup_km_ft, &setup_km_rcp, &setup_km,
					found_flow, identical_flow_found, dev, fd, error, fh, flow))
					return NULL;
		}

		setup_default_ft = 1;

		if (flow_nic_allocate_fh_resource(dev->ndev, RES_CAT_CFN,
						  fh, 1, 1)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not get CAT CFN resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			return NULL;
		}

		if (flow_nic_allocate_fh_resource(dev->ndev, RES_QSL_RCP, fh, 1,
						  1)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not get QSL RCP resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			return NULL;
		}

		if (qsl_size > 0 &&
				flow_nic_allocate_fh_resource(dev->ndev, RES_QSL_QST,
							      fh, qsl_size, 1)) {
			NT_LOG(ERR, FILTER,
			       "ERROR: Could not get QSL QST resource\n");
			flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
					   error);
			return NULL;
		}

		/* Check if filter is set up for FLM */
		if (fd->jump_to_group != UINT32_MAX) {
			flm_flow_setup_group(dev, fd->jump_to_group,
					     fh->resource[RES_CAT_CFN].index,
					     fh->resource[RES_KM_FLOW_TYPE].index,
					     fh);
		}
	}

	/*
	 * Setup QSL
	 */
	if (setup_qsl_rcp) {
		if (qsl_size == 0) {
			/* Create drop filter */
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_DISCARD,
					   fh->resource[RES_QSL_RCP].index,
					   0x0);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_DROP,
					   fh->resource[RES_QSL_RCP].index,
					   0x3);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_LR,
					   fh->resource[RES_QSL_RCP].index,
					   0x0);

			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_TBL_LO,
					   fh->resource[RES_QSL_RCP].index, 0);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_TBL_HI,
					   fh->resource[RES_QSL_RCP].index, 0);

			hw_mod_qsl_rcp_flush(&dev->ndev->be,
					     fh->resource[RES_QSL_RCP].index,
					     1);
		} else {
			const int table_start = fh->resource[RES_QSL_QST].index;
			const int table_end = table_start +
					      fh->resource[RES_QSL_QST].count -
					      1;

			/* Use 0x0 for pure retransmit */
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_DISCARD,
					   fh->resource[RES_QSL_RCP].index,
					   0x0);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_DROP,
					   fh->resource[RES_QSL_RCP].index,
					   0x0);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_LR,
					   fh->resource[RES_QSL_RCP].index,
					   num_dest_port > 0 ? 0x3 : 0x0);

			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_TBL_LO,
					   fh->resource[RES_QSL_RCP].index,
					   table_start);
			hw_mod_qsl_rcp_set(&dev->ndev->be, HW_QSL_RCP_TBL_HI,
					   fh->resource[RES_QSL_RCP].index,
					   table_end);

			hw_mod_qsl_rcp_flush(&dev->ndev->be,
					     fh->resource[RES_QSL_RCP].index,
					     1);

			/* Setup QSL QST/QEN */
			if (num_dest_port > 0 && num_queues > 0) {
				int ports[num_dest_port];
				int queues[num_queues];

				int port_index = 0;
				int queue_index = 0;

				for (int i = 0; i < fd->dst_num_avail; ++i) {
					if (fd->dst_id[i].type == PORT_PHY) {
						ports[port_index++] =
							fd->dst_id[i].id;
					} else if (fd->dst_id[i].type ==
							PORT_VIRT) {
						queues[queue_index++] =
							fd->dst_id[i].id;
					}
				}

				for (int i = 0; i < fd->dst_num_avail; ++i) {
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_TX_PORT,
							   table_start + i,
							   ports[i % num_dest_port]);
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_LRE,
							   table_start + i, 1);

					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_QUEUE,
							   table_start + i,
							   queues[i % num_queues]);
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_EN,
							   table_start + i, 1);
				}
			} else if (num_dest_port > 0) {
				for (int i = 0; i < fd->dst_num_avail; ++i) {
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_TX_PORT,
							   table_start + i,
							   fd->dst_id[i].id);
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_LRE,
							   table_start + i, 1);
				}
			} else if (num_queues > 0) {
				for (int i = 0; i < fd->dst_num_avail; ++i) {
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_QUEUE,
							   table_start + i,
							   fd->dst_id[i].id);
					hw_mod_qsl_qst_set(&dev->ndev->be,
							   HW_QSL_QST_EN,
							   table_start + i, 1);
				}
			}

			hw_mod_qsl_qst_flush(&dev->ndev->be, table_start,
					     fd->dst_num_avail);
		}
	}

	/*
	 * Setup CAT KM functionality
	 */
	if (setup_km) {
		uint32_t bm = 0;

		/* Enable KM match FS for key A */
		set_flow_type_km(dev->ndev, fh->resource[RES_CAT_CFN].index,
				 setup_km_ft, 0, 1);

		/* KM function select */
		hw_mod_cat_kcs_km_set(&dev->ndev->be, HW_CAT_KCS_CATEGORY,
				      KM_FLM_IF_FIRST,
				      fh->resource[RES_CAT_CFN].index,
				      setup_km_rcp);
		hw_mod_cat_kcs_km_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					fh->resource[RES_CAT_CFN].index, 1);

		/* KM function enable */
		hw_mod_cat_kce_km_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				      KM_FLM_IF_FIRST,
				      fh->resource[RES_CAT_CFN].index / 8, &bm);
		hw_mod_cat_kce_km_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				      KM_FLM_IF_FIRST, fh->resource[RES_CAT_CFN].index / 8,
				      bm | (1 << (fh->resource[RES_CAT_CFN].index % 8)));
		hw_mod_cat_kce_km_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					fh->resource[RES_CAT_CFN].index / 8, 1);
	} else if (setup_default_ft) {
		/* Enable "no KM match" FT for key A */
		set_flow_type_km(dev->ndev, fh->resource[RES_CAT_CFN].index,
				 0, 0, 1);
	}

	/*
	 * Setup CAT FLM functionality
	 */
	if (setup_flm) {
		uint32_t bm = 0;

		/* Enable KM match FT for key A, and FLM match FT for key C */
		set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index,
				  setup_km_ft, 0, 1); /* KM FT A */
		set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index,
				  setup_flm_ft, 2, 1); /* FLM FT C */

		/* FLM function enable */
		hw_mod_cat_kce_flm_get(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST,
				       fh->resource[RES_CAT_CFN].index / 8,
				       &bm);
		hw_mod_cat_kce_flm_set(&dev->ndev->be, HW_CAT_KCE_ENABLE_BM,
				       KM_FLM_IF_FIRST, fh->resource[RES_CAT_CFN].index / 8,
				       bm | (1 << (fh->resource[RES_CAT_CFN].index % 8)));
		hw_mod_cat_kce_flm_flush(&dev->ndev->be, KM_FLM_IF_FIRST,
					 fh->resource[RES_CAT_CFN].index / 8,
					 1);
	} else if (setup_default_ft) {
		/* Enable KM for key A and UNHANDLED for key C */
		set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index,
				  setup_km_ft, 0, 1);
		set_flow_type_flm(dev->ndev, fh->resource[RES_CAT_CFN].index, 1,
				  2, 1);
	}

	/*
	 * Setup HST
	 */
	if (setup_hst) {
		int hst_index = -1;

		for (int i = 1;
				i < (int)dev->ndev->res[RES_HST_RCP].resource_count; ++i) {
			uint32_t values[] = { 0, 0, 0, 0, 0 };

			if (!flow_nic_is_resource_used(dev->ndev, RES_HST_RCP,
						       i))
				continue;

			hw_mod_hst_rcp_get(&dev->ndev->be,
					   HW_HST_RCP_STRIP_MODE, i,
					   &values[0]);
			hw_mod_hst_rcp_get(&dev->ndev->be, HW_HST_RCP_START_DYN,
					   i, &values[1]);
			hw_mod_hst_rcp_get(&dev->ndev->be, HW_HST_RCP_START_OFS,
					   i, &values[2]);
			hw_mod_hst_rcp_get(&dev->ndev->be, HW_HST_RCP_END_DYN,
					   i, &values[3]);
			hw_mod_hst_rcp_get(&dev->ndev->be, HW_HST_RCP_END_OFS,
					   i, &values[4]);

			if ((int)values[0] == 1 &&
					(int)values[1] == fd->header_strip_start_dyn &&
					(int)values[2] == fd->header_strip_start_ofs &&
					(int)values[3] == fd->header_strip_end_dyn &&
					(int)values[4] == fd->header_strip_end_ofs) {
				hst_index = i;
				break;
			}
		}

		if (hst_index >= 0) {
			if (flow_nic_ref_resource(dev->ndev, RES_HST_RCP,
						  hst_index)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not reference HST RCP resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			fh->resource[RES_HST_RCP].count = 1;
			fh->resource[RES_HST_RCP].index = hst_index;
			fh->resource[RES_HST_RCP].referenced = 1;
		} else {
			if (flow_nic_allocate_fh_resource(dev->ndev,
							  RES_HST_RCP,
							  fh, 1, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get HST RCP resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			hw_mod_hst_rcp_set(&dev->ndev->be,
					   HW_HST_RCP_STRIP_MODE,
					   fh->resource[RES_HST_RCP].index, 1);
			hw_mod_hst_rcp_set(&dev->ndev->be, HW_HST_RCP_START_DYN,
					   fh->resource[RES_HST_RCP].index,
					   fd->header_strip_start_dyn);
			hw_mod_hst_rcp_set(&dev->ndev->be, HW_HST_RCP_START_OFS,
					   fh->resource[RES_HST_RCP].index,
					   fd->header_strip_start_ofs);
			hw_mod_hst_rcp_set(&dev->ndev->be, HW_HST_RCP_END_DYN,
					   fh->resource[RES_HST_RCP].index,
					   fd->header_strip_end_dyn);
			hw_mod_hst_rcp_set(&dev->ndev->be, HW_HST_RCP_END_OFS,
					   fh->resource[RES_HST_RCP].index,
					   fd->header_strip_end_ofs);

			hw_mod_hst_rcp_set(&dev->ndev->be,
					   HW_HST_RCP_MODIF0_CMD,
					   fh->resource[RES_HST_RCP].index,
					   fd->header_strip_removed_outer_ip ? 7 : 6);
			hw_mod_hst_rcp_set(&dev->ndev->be,
					   HW_HST_RCP_MODIF0_DYN,
					   fh->resource[RES_HST_RCP].index, 2);
			hw_mod_hst_rcp_set(&dev->ndev->be,
					   HW_HST_RCP_MODIF0_OFS,
					   fh->resource[RES_HST_RCP].index, 0);

			hw_mod_hst_rcp_flush(&dev->ndev->be,
					     fh->resource[RES_HST_RCP].index, 1);
		}
	}

	/*
	 * Setup TPE
	 */
	if (setup_tpe_encap_data) {
		int ext_rpl_index = -1;
		int rpl_rpl_index = -1;
		int rpl_rpl_length = -1;

		/* Find existing RPL */
		for (int i = 1;
				i < (int)dev->ndev->res[RES_TPE_EXT].resource_count; ++i) {
			int found = 1;
			uint32_t len;
			uint32_t ptr;

			if (!flow_nic_is_resource_used(dev->ndev, RES_TPE_EXT,
						       i))
				continue;

			hw_mod_tpe_rpl_ext_get(&dev->ndev->be,
					       HW_TPE_RPL_EXT_META_RPL_LEN, i,
					       &len);
			if (len != fd->tun_hdr.len)
				continue;

			hw_mod_tpe_rpl_ext_get(&dev->ndev->be,
					       HW_TPE_RPL_EXT_RPL_PTR, i, &ptr);

			for (uint32_t ptr_it = 0; ptr_it < (len + 15) / 16;
					++ptr_it) {
				uint32_t data[4];

				hw_mod_tpe_rpl_rpl_get(&dev->ndev->be,
						       HW_TPE_RPL_RPL_VALUE,
						       ptr + ptr_it, data);

				if (fd->tun_hdr.d.hdr32[ptr_it * 4 + 0] !=
						data[0] ||
						fd->tun_hdr.d.hdr32[ptr_it * 4 + 1] !=
						data[1] ||
						fd->tun_hdr.d.hdr32[ptr_it * 4 + 2] !=
						data[2] ||
						fd->tun_hdr.d.hdr32[ptr_it * 4 + 3] !=
						data[3]) {
					found = 0;
					break;
				}
			}

			if (found) {
				ext_rpl_index = i;
				rpl_rpl_index = (int)ptr;
				rpl_rpl_length = (int)len;
				break;
			}
		}

		/* Set RPL data */
		if (ext_rpl_index >= 0) {
			if (flow_nic_ref_resource(dev->ndev, RES_TPE_EXT,
						  ext_rpl_index)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not reference TPE EXT resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			for (int i = 0; i < (rpl_rpl_length + 15) / 16; ++i) {
				if (flow_nic_ref_resource(dev->ndev,
							  RES_TPE_RPL,
							  rpl_rpl_index + i)) {
					NT_LOG(ERR, FILTER,
					       "ERROR: Could not reference TPE RPL resource\n");
					flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
							   error);
					return NULL;
				}
			}
		} else {
			ext_rpl_index = flow_nic_alloc_resource(dev->ndev,
								RES_TPE_EXT, 1);
			if (ext_rpl_index < 0) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get TPE EXT resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			rpl_rpl_length = ((int)fd->tun_hdr.len + 15) / 16;
			rpl_rpl_index = flow_nic_alloc_resource_contig(dev->ndev,
								       RES_TPE_RPL,
								       rpl_rpl_length,
								       1);
			if (rpl_rpl_index < 0) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get TPE RPL resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			/* Program new encap header data */
			hw_mod_tpe_rpl_ext_set(&dev->ndev->be,
					       HW_TPE_RPL_EXT_RPL_PTR,
					       ext_rpl_index, rpl_rpl_index);
			hw_mod_tpe_rpl_ext_set(&dev->ndev->be,
					       HW_TPE_RPL_EXT_META_RPL_LEN,
					       ext_rpl_index, fd->tun_hdr.len);
			hw_mod_tpe_rpl_ext_flush(&dev->ndev->be, ext_rpl_index,
						 1);

			for (int i = 0; i < rpl_rpl_length; ++i) {
				hw_mod_tpe_rpl_rpl_set(&dev->ndev->be,
						       HW_TPE_RPL_RPL_VALUE,
						       rpl_rpl_index + i,
						       fd->tun_hdr.d.hdr32 + i * 4);
			}
			hw_mod_tpe_rpl_rpl_flush(&dev->ndev->be, rpl_rpl_index,
						 rpl_rpl_length);
		}

		flm_rpl_ext_ptr = ext_rpl_index;
	}

	if (setup_tpe) {
		const uint32_t eth_length = 14;
		const uint32_t l2_length = fd->tun_hdr.l2_len;
		const uint32_t l3_length = fd->tun_hdr.l3_len;
		const uint32_t l4_length = fd->tun_hdr.l4_len;
		const uint32_t fcs_length = 4;

		int tpe_index = -1;

		/* Find existing RCP */
		for (int i = 1;
				i < (int)dev->ndev->res[RES_TPE_RCP].resource_count; ++i) {
			uint32_t value;

			if (!flow_nic_is_resource_used(dev->ndev, RES_TPE_RCP,
						       i))
				continue;

			hw_mod_tpe_rpl_rcp_get(&dev->ndev->be,
					       HW_TPE_RPL_RCP_LEN, i, &value);
			if (value != fd->tun_hdr.len)
				continue;
			hw_mod_tpe_rpl_rcp_get(&dev->ndev->be,
					       HW_TPE_RPL_RCP_DYN, i, &value);
			if (value != 1)
				continue;
			hw_mod_tpe_rpl_rcp_get(&dev->ndev->be,
					       HW_TPE_RPL_RCP_OFS, i, &value);
			if (value != 0)
				continue;
			hw_mod_tpe_hfu_rcp_get(&dev->ndev->be,
					       HW_TPE_HFU_RCP_L3_PRT, i,
					       &value);
			if (value != (fd->tun_hdr.ip_version == 4 ? 1 : 2))
				continue;
			hw_mod_tpe_hfu_rcp_get(&dev->ndev->be,
					       HW_TPE_HFU_RCP_OUTER_L3_OFS, i,
					       &value);
			if (value != l2_length)
				continue;

			tpe_index = i;
			break;
		}

		/* Set RCP data */
		if (tpe_index >= 0) {
			if (flow_nic_ref_resource(dev->ndev, RES_TPE_RCP,
						  tpe_index)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not reference TPE RCP resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			fh->resource[RES_TPE_RCP].count = 1;
			fh->resource[RES_TPE_RCP].index = tpe_index;
			fh->resource[RES_TPE_RCP].referenced = 1;
		} else {
			if (flow_nic_allocate_fh_resource(dev->ndev,
							  RES_TPE_RCP,
							  fh, 1, 1)) {
				NT_LOG(ERR, FILTER,
				       "ERROR: Could not get TPE RCP resource\n");
				flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION,
						   error);
				return NULL;
			}

			/* Extend packet if needed. */
			if (fd->tun_hdr.len > eth_length) {
				/* Extend FPGA packet buffer */
				hw_mod_tpe_rpp_rcp_set(&dev->ndev->be,
						       HW_TPE_RPP_RCP_EXP,
						       fh->resource[RES_TPE_RCP].index,
						       fd->tun_hdr.len - eth_length);
				hw_mod_tpe_rpp_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index,
							 1);

				/*
				 * Insert 0's into packet
				 * After this step DYN offsets are shifted by encap length,
				 * so only DYN offset 1 and 18 should be used
				 */
				hw_mod_tpe_ins_rcp_set(&dev->ndev->be,
						       HW_TPE_INS_RCP_DYN,
						       fh->resource[RES_TPE_RCP].index, 1);
				hw_mod_tpe_ins_rcp_set(&dev->ndev->be,
						       HW_TPE_INS_RCP_OFS,
						       fh->resource[RES_TPE_RCP].index, 0);
				hw_mod_tpe_ins_rcp_set(&dev->ndev->be,
						       HW_TPE_INS_RCP_LEN,
						       fh->resource[RES_TPE_RCP].index,
						       fd->tun_hdr.len - eth_length);
				hw_mod_tpe_ins_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index,
							 1);
			}

			if (fd->tun_hdr.len > 0) {
				/* Write header data to beginning of packet */
				hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
						       HW_TPE_RPL_RCP_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
						       HW_TPE_RPL_RCP_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
						       HW_TPE_RPL_RCP_LEN,
						       fh->resource[RES_TPE_RCP].index,
						       fd->tun_hdr.len);
				hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
						       HW_TPE_RPL_RCP_RPL_PTR,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
						       HW_TPE_RPL_RCP_EXT_PRIO,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_rpl_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index,
							 1);
			}

			for (unsigned int i = 0; i < fd->modify_field_count;
					++i) {
				uint32_t select = fd->modify_field[i].select;
				uint32_t dyn = fd->modify_field[i].dyn;
				uint32_t ofs = fd->modify_field[i].ofs;
				uint32_t len = fd->modify_field[i].len;

				align_tun_offset(fd, eth_length, i, &ofs, select, l2_length,
					l3_length, l4_length, &dyn);

				hw_mod_tpe_cpy_rcp_set(&dev->ndev->be,
						       HW_TPE_CPY_RCP_READER_SELECT,
						       fh->resource[RES_TPE_RCP].index +
						       16 * i,
						       select);
				hw_mod_tpe_cpy_rcp_set(&dev->ndev->be,
						       HW_TPE_CPY_RCP_DYN,
						       fh->resource[RES_TPE_RCP].index +
						       16 * i,
						       dyn);
				hw_mod_tpe_cpy_rcp_set(&dev->ndev->be,
						       HW_TPE_CPY_RCP_OFS,
						       fh->resource[RES_TPE_RCP].index +
						       16 * i,
						       ofs);
				hw_mod_tpe_cpy_rcp_set(&dev->ndev->be,
						       HW_TPE_CPY_RCP_LEN,
						       fh->resource[RES_TPE_RCP].index +
						       16 * i,
						       len);
				hw_mod_tpe_cpy_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index +
							 16 * i,
							 1);
			}

			if (fd->tun_hdr.new_outer) {
				/*
				 * UDP length
				 * dyn_ofs[ADD_DYN] - dyn_ofs[SUB_DYN] + ADD_OFS
				 */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_WR,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_OUTER_L4_LEN,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_POS_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_POS_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       l2_length + l3_length + 4);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_ADD_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       18);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_ADD_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       -(l2_length + l3_length + fcs_length));
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_A_SUB_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);

				/* IPv4/IPv6 length */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_WR,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_POS_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_POS_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       l2_length +
						       (fd->tun_hdr.ip_version == 4 ? 2 : 4));
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_ADD_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       18);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_ADD_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       -(l2_length +
						       (fd->tun_hdr.ip_version == 4 ?
						       0 : l3_length) + fcs_length));
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_B_SUB_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);

				/* GTP length */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_WR,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_POS_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_POS_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       l2_length + l3_length + l4_length + 2);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_ADD_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       18);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_ADD_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       -(l2_length + l3_length + l4_length +
						       8 + fcs_length));
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_LEN_C_SUB_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       1);

				/* _update TTL */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_TTL_WR,
						       fh->resource[RES_TPE_RCP].index,
						       fd->ttl_sub_enable);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_TTL_POS_DYN,
						       fh->resource[RES_TPE_RCP].index,
						       fd->ttl_sub_outer ? 1 : DYN_L3);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_TTL_POS_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       (fd->ttl_sub_outer ?
						       l2_length :
						       fd->tun_hdr.len - eth_length) +
						       (fd->ttl_sub_ipv4 ? 8 : 7));

				/* _update FPGA DYN offsets */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_CS_INF,
						       fh->resource[RES_TPE_RCP].index,
						       1);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L3_PRT,
						       fh->resource[RES_TPE_RCP].index,
						       (fd->tun_hdr.ip_version == 4 ? 1 : 2));
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L3_FRAG,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_TUNNEL,
						       fh->resource[RES_TPE_RCP].index,
						       6);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L4_PRT,
						       fh->resource[RES_TPE_RCP].index,
						       2);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_OUTER_L3_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       l2_length);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_OUTER_L4_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       l2_length + l3_length);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_INNER_L3_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       fd->tun_hdr.len - eth_length);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_INNER_L4_OFS,
						       fh->resource[RES_TPE_RCP].index,
						       fd->tun_hdr.len - eth_length);

				hw_mod_tpe_hfu_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index,
							 1);
			} else {
				/* _update TTL */
				if (fd->ttl_sub_enable) {
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_TTL_WR,
							       fh->resource[RES_TPE_RCP].index,
							       fd->ttl_sub_enable);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_TTL_POS_DYN,
							       fh->resource[RES_TPE_RCP].index,
							       fd->ttl_sub_outer ? DYN_L3 :
							       DYN_TUN_L3);
					if (fd->tun_hdr.len == 0) {
						hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
								       HW_TPE_HFU_RCP_TTL_POS_OFS,
								       fh->resource[RES_TPE_RCP]
								       .index,
								       fd->ttl_sub_ipv4 ? 8 : 7);
					} else {
						hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
								       HW_TPE_HFU_RCP_TTL_POS_OFS,
								       fh->resource[RES_TPE_RCP]
								       .index,
								       (fd->tun_hdr.len -
								       eth_length) +
								       (fd->ttl_sub_ipv4 ?
								       8 : 7));
					}
				} else {
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_TTL_WR,
							       fh->resource[RES_TPE_RCP].index,
							       0);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_TTL_POS_DYN,
							       fh->resource[RES_TPE_RCP].index,
							       0);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_TTL_POS_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       0);
				}

				/* _update FPGA DYN offsets */
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_CS_INF,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L3_PRT,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L3_FRAG,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_TUNNEL,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
						       HW_TPE_HFU_RCP_L4_PRT,
						       fh->resource[RES_TPE_RCP].index,
						       0);
				if (fd->tun_hdr.len == 0) {
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_OUTER_L3_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       0);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_OUTER_L4_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       0);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_INNER_L3_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       0);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_INNER_L4_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       0);
				} else {
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_OUTER_L3_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       fd->tun_hdr.len - eth_length);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_OUTER_L4_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       fd->tun_hdr.len - eth_length);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_INNER_L3_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       fd->tun_hdr.len - eth_length);
					hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
							       HW_TPE_HFU_RCP_INNER_L4_OFS,
							       fh->resource[RES_TPE_RCP].index,
							       fd->tun_hdr.len - eth_length);
				}

				hw_mod_tpe_hfu_rcp_flush(&dev->ndev->be,
							 fh->resource[RES_TPE_RCP].index,
							 1);
			}

			/* Calculate valid outer and inner checksums */
			hw_mod_tpe_csu_rcp_set(&dev->ndev->be,
					       HW_TPE_CSU_RCP_OUTER_L3_CMD,
					       fh->resource[RES_TPE_RCP].index,
					       3);
			hw_mod_tpe_csu_rcp_set(&dev->ndev->be,
					       HW_TPE_CSU_RCP_OUTER_L4_CMD,
					       fh->resource[RES_TPE_RCP].index,
					       3);
			hw_mod_tpe_csu_rcp_set(&dev->ndev->be,
					       HW_TPE_CSU_RCP_INNER_L3_CMD,
					       fh->resource[RES_TPE_RCP].index,
					       3);
			hw_mod_tpe_csu_rcp_set(&dev->ndev->be,
					       HW_TPE_CSU_RCP_INNER_L4_CMD,
					       fh->resource[RES_TPE_RCP].index,
					       3);
			hw_mod_tpe_csu_rcp_flush(&dev->ndev->be,
						 fh->resource[RES_TPE_RCP].index,
						 1);
		}
	}

	/*
	 * Setup CAT Color Table functionality
	 */
	if (setup_cat_cot) {
		hw_mod_cat_cot_set(&dev->ndev->be, HW_CAT_COT_COLOR,
				   fh->resource[RES_CAT_COT].index, 0);
		hw_mod_cat_cot_set(&dev->ndev->be, HW_CAT_COT_KM,
				   fh->resource[RES_CAT_COT].index, 0x4);
		hw_mod_cat_cot_flush(&dev->ndev->be,
				     fh->resource[RES_CAT_COT].index, 1);
	}

	/*
	 * Setup CAT action functionality
	 */
	if (setup_cat_cts) {
		/* Setup CAT CTS */
		const int offset = ((int)dev->ndev->be.cat.cts_num + 1) / 2;

		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 0,
				   fh->resource[RES_CAT_COT].index);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 0,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 1,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 1,
				   fh->resource[RES_QSL_RCP].index);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 2,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 2,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 3,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 3,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 4,
				   fh->resource[RES_HST_RCP].index);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 4,
				   0);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_A,
				   offset * fh->resource[RES_CAT_CFN].index + 5,
				   fh->resource[RES_TPE_RCP].index);
		hw_mod_cat_cts_set(&dev->ndev->be, HW_CAT_CTS_CAT_B,
				   offset * fh->resource[RES_CAT_CFN].index + 5,
				   0);

		hw_mod_cat_cts_flush(&dev->ndev->be,
				     offset * fh->resource[RES_CAT_CFN].index,
				     6);
		hw_mod_cat_cts_flush(&dev->ndev->be,
				     offset * fh->resource[RES_CAT_CFN].index,
				     6);

		/* Setup CAT CTE */
		hw_mod_cat_cte_set(&dev->ndev->be,
				   HW_CAT_CTE_ENABLE_BM,
				   fh->resource[RES_CAT_CFN].index,
				   (fh->resource[RES_CAT_COT].index ? 0x001 : 0) | 0x004 |
				   (fh->resource[RES_QSL_RCP].index ? 0x008 : 0) |
				   0x040 |
				   (fh->resource[RES_HST_RCP].index ? 0x100 : 0) |
				   (fh->resource[RES_TPE_RCP].index ? 0x400 : 0));
		hw_mod_cat_cte_flush(&dev->ndev->be,
				     fh->resource[RES_CAT_CFN].index, 1);
	}

	/*
	 * Setup CAT CFN
	 *
	 * Once CAT CFN has been programmed traffic will start match the filter,
	 * so CAT CFN must be the last thing to be programmed.
	 */
	if (setup_cat_cfn) {
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_SET_ALL_DEFAULTS,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ENABLE,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_INV,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);

		/* Protocol checks */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_INV,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_ISL,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_CFP,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_MAC,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_L2,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->l2_prot != -1 ? (1 << fd->l2_prot) : -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_VNTAG,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_VLAN,
				   fh->resource[RES_CAT_CFN].index, 0,
				   (0xf << fd->vlans) & 0xf);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_MPLS,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_L3,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->l3_prot != -1 ? (1 << fd->l3_prot) : -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_FRAG,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->fragmentation);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_IP_PROT,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_L4,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->l4_prot != -1 ? (1 << fd->l4_prot) : -1);
		hw_mod_cat_cfn_set(&dev->ndev->be,
				   HW_CAT_CFN_PTC_TUNNEL,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->tunnel_prot != -1 ? (1 << fd->tunnel_prot) : -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_L2,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_VLAN,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_MPLS,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_L3,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->tunnel_l3_prot != -1 ?
				   (1 << fd->tunnel_l3_prot) : -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_FRAG,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_IP_PROT,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PTC_TNL_L4,
				   fh->resource[RES_CAT_CFN].index, 0,
				   fd->tunnel_l4_prot != -1 ?
				   (1 << fd->tunnel_l4_prot) : -1);

		/* Error checks */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_INV,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_CV,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_FCS,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_TRUNC,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_L3_CS,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_L4_CS,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_TNL_L3_CS,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_ERR_TNL_L4_CS,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be,
				   HW_CAT_CFN_ERR_TTL_EXP,
				   fh->resource[RES_CAT_CFN].index, 0,
				   (fd->ttl_sub_enable && fd->ttl_sub_outer) ? -1 : 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be,
				   HW_CAT_CFN_ERR_TNL_TTL_EXP,
				   fh->resource[RES_CAT_CFN].index, 0,
				   (fd->ttl_sub_enable && !fd->ttl_sub_outer) ? -1 : 0x1);

		/* MAC port check */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_MAC_PORT,
				   fh->resource[RES_CAT_CFN].index, 0,
				   1 << fh->port_id);

		/* Pattern match checks */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_CMP,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_DCT,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_EXT_INV,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_CMB,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_AND_INV,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_OR_INV,
				   fh->resource[RES_CAT_CFN].index, 0, -1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_PM_INV,
				   fh->resource[RES_CAT_CFN].index, 0, -1);

		/* Length checks */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_LC,
				   fh->resource[RES_CAT_CFN].index, 0, 0x0);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_LC_INV,
				   fh->resource[RES_CAT_CFN].index, 0, -1);

		/* KM and FLM */
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_KM0_OR,
				   fh->resource[RES_CAT_CFN].index, 0, 0x1);
		hw_mod_cat_cfn_set(&dev->ndev->be, HW_CAT_CFN_KM1_OR,
				   fh->resource[RES_CAT_CFN].index, 0, 0x3);

		hw_mod_cat_cfn_flush(&dev->ndev->be,
				     fh->resource[RES_CAT_CFN].index, 1);
	}

	/* Program FLM flow */
	if (fh_flm) {
		convert_fd_to_flm(fh_flm, fd, packet_data, flm_key_id,
				  flm_rpl_ext_ptr, attr->priority);
		flm_flow_programming(dev, fh_flm, fd->mtr_ids, flm_ft, 1);
	}

	if (free_fd)
		free(fd);

	return (fh_flm) ? fh_flm : fh;
}

/*
 * Public functions
 */

int initialize_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev)
{
	if (!ndev->flow_mgnt_prepared) {
		/* Check static arrays are big enough */
		assert(ndev->be.tpe.nb_cpy_writers <=
		       MAX_CPY_WRITERS_SUPPORTED);

		/* KM Flow Type 0 is reserved */
		flow_nic_mark_resource_used(ndev, RES_KM_FLOW_TYPE, 0);
		flow_nic_mark_resource_used(ndev, RES_KM_CATEGORY, 0);

		/* FLM Flow Type 0 and 1 is reserved */
		flow_nic_mark_resource_used(ndev, RES_FLM_FLOW_TYPE, 0);
		flow_nic_mark_resource_used(ndev, RES_FLM_FLOW_TYPE, 1);
		flow_nic_mark_resource_used(ndev, RES_FLM_RCP, 0);

		/* CAT CFN 0 is reserved as a low priority catch all filter */
		hw_mod_cat_cfn_set(&ndev->be, HW_CAT_CFN_SET_ALL_DEFAULTS,
				   0, 0, 0);
		hw_mod_cat_cfn_flush(&ndev->be, 0, 1);
		flow_nic_mark_resource_used(ndev, RES_CAT_CFN, 0);

		/* Initialize QSL with unmatched recipe index 0 - discard */
		if (hw_mod_qsl_rcp_set(&ndev->be, HW_QSL_RCP_DISCARD, 0, 0x1) < 0)
			goto err_exit0;
		if (hw_mod_qsl_rcp_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_QSL_RCP, 0);

		/* Initialize QST with default index 0 */
		if (hw_mod_qsl_qst_set(&ndev->be, HW_QSL_QST_PRESET_ALL, 0,
				       0x0) < 0)
			goto err_exit0;
		if (hw_mod_qsl_qst_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_QSL_QST, 0);

		/* HST & TPE index 0 is reserved */
		flow_nic_mark_resource_used(ndev, RES_HST_RCP, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_RCP, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_EXT, 0);
		flow_nic_mark_resource_used(ndev, RES_TPE_RPL, 0);

		/* PDB setup Direct Virtio Scatter-Gather descriptor of 12 bytes for its recipe 0 */
		if (hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_DESCRIPTOR, 0, 7) <
				0)
			goto err_exit0;
		if (hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_DESC_LEN, 0, 6) <
				0)
			goto err_exit0;

		if (hw_mod_pdb_rcp_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_PDB_RCP, 0);

		/* Set default hasher recipe to 5-tuple */
		flow_nic_set_hasher(ndev, 0, HASH_ALGO_5TUPLE);
		hw_mod_hsh_rcp_flush(&ndev->be, 0, 1);

		flow_nic_mark_resource_used(ndev, RES_HSH_RCP, 0);

		/*
		 * COT - set color to 0 for unmatched - color encoding must not have CAO enabled for
		 * this entry
		 */
		hw_mod_cat_cot_set(&ndev->be, HW_CAT_COT_PRESET_ALL, 0, 0);
		if (hw_mod_cat_cot_flush(&ndev->be, 0, 1) < 0)
			goto err_exit0;

		flow_nic_mark_resource_used(ndev, RES_CAT_COT, 0);

		/* Unblock MAC and MAC statistics on this NIC */
		if (hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_BLOCK_STATT, 0) < 0)
			goto err_exit0;
		/* block keep alive - not needed */
		if (hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_BLOCK_KEEPA, 1) < 0)
			goto err_exit0;
		/*
		 * Unblock all MAC ports
		 */
		if (hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_BLOCK_MAC_PORT, 0) < 0)
			goto err_exit0;

		/*
		 *  unblock RPP slices
		 */
		hw_mod_rmc_ctrl_set(&ndev->be, HW_RMC_BLOCK_RPP_SLICE, 0);

		if (hw_mod_rmc_ctrl_flush(&ndev->be) < 0)
			goto err_exit0;

		/* FLM */
		if (flm_sdram_calibrate(ndev) < 0)
			goto err_exit0;
		if (flm_sdram_reset(ndev, 1) < 0)
			goto err_exit0;
		flm_flow_handle_create(&ndev->flm_res_handle);

		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_LDS,
				       0); /* Learn done status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_LFS,
				       0); /* Learn fail status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_LIS,
				       0); /* Learn ignore status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_UDS,
				       0); /* Unlearn done status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_UIS,
				       0); /* Unlearn ignore status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_RDS,
				       0); /* Relearn done status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_RIS,
				       0); /* Relearn ignore status */
		hw_mod_flm_control_set(&ndev->be, HW_FLM_CONTROL_RBL, 4);
		hw_mod_flm_control_flush(&ndev->be);

		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_LIMIT0,
				    0); /* Drop at 100% FIFO fill level */
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_FT0, 1);
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_LIMIT1,
				    6); /* Drop at 37,5% FIFO fill level */
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_FT1, 1);
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_LIMIT2,
				    4); /* Drop at 25% FIFO fill level */
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_FT2, 1);
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_LIMIT3,
				    2); /* Drop at 12,5% FIFO fill level */
		hw_mod_flm_prio_set(&ndev->be, HW_FLM_PRIO_FT3, 1);
		hw_mod_flm_prio_flush(&ndev->be);

		for (uint32_t i = 0; i < ndev->be.flm.nb_pst_profiles; ++i) {
			hw_mod_flm_pst_set(&ndev->be, HW_FLM_PST_BP, i,
					   FLM_PERIODIC_STATS_BYTE_LIMIT);
			hw_mod_flm_pst_set(&ndev->be, HW_FLM_PST_PP, i,
					   FLM_PERIODIC_STATS_PKT_LIMIT);
			hw_mod_flm_pst_set(&ndev->be, HW_FLM_PST_TP, i,
					   FLM_PERIODIC_STATS_BYTE_TIMEOUT);
		}
		hw_mod_flm_pst_flush(&ndev->be, 0, ALL_ENTRIES);

		hw_mod_flm_stat_update(&ndev->be);

		ndev->flm_mtr_handle =
			calloc(1, sizeof(struct flm_flow_mtr_handle_s));
		ndev->ft_res_handle =
			calloc(FLM_FLOW_FT_MAX, sizeof(struct flm_flow_ft_ident_s));
		ndev->mtr_stat_handle =
			calloc(FLM_MTR_STAT_SIZE, sizeof(struct mtr_stat_s));

		if (ndev->flm_mtr_handle == NULL ||
				ndev->ft_res_handle == NULL ||
				ndev->mtr_stat_handle == NULL)
			goto err_exit0;

		struct mtr_stat_s *mtr_stat = ndev->mtr_stat_handle;

		for (uint32_t i = 0; i < FLM_MTR_STAT_SIZE; ++i) {
			atomic_init(&mtr_stat[i].n_pkt, 0);
			atomic_init(&mtr_stat[i].n_bytes, 0);
			atomic_init(&mtr_stat[i].stats_mask, 0);
		}

		if (flow_group_handle_create(&ndev->group_handle,
					     FLM_FLOW_RCP_MAX))
			goto err_exit0;

		ndev->flow_mgnt_prepared = 1;
	}
	return 0;

err_exit0:
	done_flow_management_of_ndev_profile_inline(ndev);
	return -1;
}

int done_flow_management_of_ndev_profile_inline(struct flow_nic_dev *ndev)
{
#ifdef FLOW_DEBUG
	ndev->be.iface->set_debug_mode(ndev->be.be_dev,
				       FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	if (ndev->flow_mgnt_prepared) {
		flm_sdram_reset(ndev, 0);
		flm_flow_handle_remove(&ndev->flm_res_handle);

		flow_nic_free_resource(ndev, RES_KM_FLOW_TYPE, 0);
		flow_nic_free_resource(ndev, RES_KM_CATEGORY, 0);

		hw_mod_flm_rcp_set(&ndev->be, HW_FLM_RCP_PRESET_ALL, 0, 0);
		hw_mod_flm_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_FLM_FLOW_TYPE, 0);
		flow_nic_free_resource(ndev, RES_FLM_FLOW_TYPE, 1);
		flow_nic_free_resource(ndev, RES_FLM_RCP, 0);

		free(ndev->flm_mtr_handle);
		free(ndev->ft_res_handle);
		free(ndev->mtr_stat_handle);
		flow_group_handle_destroy(&ndev->group_handle);

		hw_mod_cat_cfn_set(&ndev->be, HW_CAT_CFN_PRESET_ALL, 0, 0, 0);
		hw_mod_cat_cfn_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_CAT_CFN, 0);

		hw_mod_qsl_rcp_set(&ndev->be, HW_QSL_RCP_PRESET_ALL, 0, 0);
		hw_mod_qsl_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_QSL_RCP, 0);

		hw_mod_hst_rcp_set(&ndev->be, HW_HST_RCP_PRESET_ALL, 0, 0);
		hw_mod_hst_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_HST_RCP, 0);

		hw_mod_tpe_reset(&ndev->be);
		flow_nic_free_resource(ndev, RES_TPE_RCP, 0);
		flow_nic_free_resource(ndev, RES_TPE_EXT, 0);
		flow_nic_free_resource(ndev, RES_TPE_RPL, 0);

		hw_mod_pdb_rcp_set(&ndev->be, HW_PDB_RCP_PRESET_ALL, 0, 0);
		hw_mod_pdb_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_PDB_RCP, 0);

		hw_mod_hsh_rcp_set(&ndev->be, HW_HSH_RCP_PRESET_ALL, 0, 0, 0);
		hw_mod_hsh_rcp_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_HSH_RCP, 0);

		hw_mod_cat_cot_set(&ndev->be, HW_CAT_COT_PRESET_ALL, 0, 0);
		hw_mod_cat_cot_flush(&ndev->be, 0, 1);
		flow_nic_free_resource(ndev, RES_CAT_COT, 0);

#ifdef FLOW_DEBUG
		ndev->be.iface->set_debug_mode(ndev->be.be_dev,
					       FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

		ndev->flow_mgnt_prepared = 0;
	}

	return 0;
}

int flow_validate_profile_inline(struct flow_eth_dev *dev,
				 const struct flow_elem elem[],
				 const struct flow_action action[],
				 struct flow_error *error)
{
	uint32_t port_id = 0;
	uint32_t num_dest_port = 0;
	uint32_t num_queues = 0;

	uint32_t packet_data[10];
	uint32_t packet_mask[10];
	struct flm_flow_key_def_s key_def;

	flow_nic_set_error(ERR_SUCCESS, error);

	pthread_mutex_lock(&dev->ndev->mtx);
	struct nic_flow_def *fd = interpret_flow_elements(dev, elem, action,
							  error, 0, &port_id,
							  &num_dest_port, &num_queues,
							  packet_data, packet_mask,
							  &key_def);
	pthread_mutex_unlock(&dev->ndev->mtx);

	if (!fd)
		return -1;

	free(fd);
	return 0;
}

struct flow_handle *flow_create_profile_inline(struct flow_eth_dev *dev,
	const struct flow_attr *attr, const struct flow_elem elem[],
	const struct flow_action action[], struct flow_error *error)
{
	struct flow_handle *fh = NULL;

	uint32_t port_id = UINT32_MAX;
	uint32_t num_dest_port;
	uint32_t num_queues;

	uint32_t packet_data[10];
	uint32_t packet_mask[10];
	struct flm_flow_key_def_s key_def;

	struct flow_attr attr_local;

	memcpy(&attr_local, attr, sizeof(struct flow_attr));
	if (attr_local.group > 0)
		attr_local.forced_vlan_vid = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	pthread_mutex_lock(&dev->ndev->mtx);

	struct nic_flow_def *fd = interpret_flow_elements(dev, elem, action, error,
							  attr_local.forced_vlan_vid,
							  &port_id, &num_dest_port,
							  &num_queues, packet_data,
							  packet_mask, &key_def);
	if (!fd)
		goto err_exit;

	/* Translate group IDs */
	if (fd->jump_to_group != UINT32_MAX &&
			flow_group_translate_get(dev->ndev->group_handle,
					attr_local.caller_id, fd->jump_to_group,
					&fd->jump_to_group)) {
		NT_LOG(ERR, FILTER, "ERROR: Could not get group resource\n");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		goto err_exit;
	}
	if (attr_local.group > 0 &&
			flow_group_translate_get(dev->ndev->group_handle,
					attr_local.caller_id, attr_local.group,
					&attr_local.group)) {
		NT_LOG(ERR, FILTER, "ERROR: Could not get group resource\n");
		flow_nic_set_error(ERR_MATCH_RESOURCE_EXHAUSTION, error);
		goto err_exit;
	}

	if (port_id == UINT32_MAX)
		port_id = dev->port_id;

	/* Create and flush filter to NIC */
	fh = create_flow_filter(dev, fd, &attr_local, error, port_id,
				num_dest_port, num_queues, packet_data,
				packet_mask, &key_def);
	if (!fh)
		goto err_exit;

	NT_LOG(DBG, FILTER,
	       "New FlOW: fh (flow handle) %p, fd (flow definition) %p\n", fh,
	       fd);
	NT_LOG(DBG, FILTER,
	       ">>>>> [Dev %p] Nic %i, Port %i: fh %p fd %p - implementation <<<<<\n",
	       dev, dev->ndev->adapter_no, dev->port, fh, fd);

	pthread_mutex_unlock(&dev->ndev->mtx);

	return fh;

err_exit:
	if (fh)
		flow_destroy_locked_profile_inline(dev, fh, NULL);

	pthread_mutex_unlock(&dev->ndev->mtx);

	NT_LOG(ERR, FILTER, "ERR: %s\n", __func__);
	return NULL;
}

int flow_destroy_locked_profile_inline(struct flow_eth_dev *dev,
				       struct flow_handle *fh,
				       struct flow_error *error)
{
	assert(dev);
	assert(fh);

	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	/* take flow out of ndev list - may not have been put there yet */
	if (fh->type == FLOW_HANDLE_TYPE_FLM)
		nic_remove_flow_flm(dev->ndev, fh);

	else
		nic_remove_flow(dev->ndev, fh);

#ifdef FLOW_DEBUG
	dev->ndev->be.iface->set_debug_mode(dev->ndev->be.be_dev,
					    FLOW_BACKEND_DEBUG_MODE_WRITE);
#endif

	if (fh->type == FLOW_HANDLE_TYPE_FLM) {
		err |= flm_flow_programming(dev, fh, NULL, 0, 0);

		if (fh->flm_rpl_ext_ptr > 0 &&
				flow_nic_deref_resource(dev->ndev, RES_TPE_EXT,
							(int)fh->flm_rpl_ext_ptr) == 0) {
			uint32_t ptr = 0;
			uint32_t len = 0;

			hw_mod_tpe_rpl_ext_get(&dev->ndev->be,
					       HW_TPE_RPL_EXT_RPL_PTR,
					       (int)fh->flm_rpl_ext_ptr, &ptr);
			hw_mod_tpe_rpl_ext_get(&dev->ndev->be,
					       HW_TPE_RPL_EXT_META_RPL_LEN,
					       (int)fh->flm_rpl_ext_ptr, &len);

			hw_mod_tpe_rpl_ext_set(&dev->ndev->be,
					       HW_TPE_PRESET_ALL,
					       (int)fh->flm_rpl_ext_ptr, 0);
			hw_mod_tpe_rpl_ext_flush(&dev->ndev->be,
						 (int)fh->flm_rpl_ext_ptr, 1);

			for (uint32_t ii = 0; ii < (len + 15) / 16; ii++) {
				if (flow_nic_deref_resource(dev->ndev,
							    RES_TPE_RPL,
							    (int)(ptr + ii)) == 0) {
					uint32_t rpl_zero[] = { 0, 0, 0, 0 };

					hw_mod_tpe_rpl_rpl_set(&dev->ndev->be,
							       HW_TPE_PRESET_ALL,
							       (int)(ptr + ii),
							       rpl_zero);
					hw_mod_tpe_rpl_rpl_flush(&dev->ndev->be,
								 (int)(ptr + ii),
								 1);
				}
			}
		}

		flow_group_translate_release(dev->ndev->group_handle,
					     fh->flm_owner->flm_group_index);

		fh->flm_owner->flm_ref_count -= 1;
		if (fh->flm_owner->flm_ref_count == 0) {
			err |= flow_flm_destroy_owner(dev, fh->flm_owner);
			err |= flow_destroy_locked_profile_inline(dev,
								  fh->flm_owner,
								  error);
		}
	} else {
		NT_LOG(DBG, FILTER, "removing flow :%p\n", fh);

		if (fh->fd) {
			if (fh->fd->km.num_ftype_elem)
				km_clear_data_match_entry(&fh->fd->km);

			if (fh->fd->jump_to_group != UINT32_MAX) {
				err |= flm_flow_destroy_group(dev,
							      fh->fd->jump_to_group);
				flow_group_translate_release(dev->ndev->group_handle,
							     fh->fd->jump_to_group);
			}
		}

		for (int res_type = 0; res_type < RES_COUNT; res_type++) {
			if (fh->resource[res_type].count < 1)
				continue;

			for (int ii = 0; ii < fh->resource[res_type].count;
					ii++) {
				/* If last ref count of this resource, free it */
				if (flow_nic_deref_resource(dev->ndev,
							    res_type,
							    fh->resource[res_type].index +
							    ii) == 0) {
					/* Free resource up in NIC */
					switch (res_type) {
					case RES_CAT_CFN:
						assert(ii == 0);
						err |= reset_cat_function_setup(dev,
							fh->resource[RES_CAT_CFN]
							.index + ii);
						break;

					case RES_QSL_QST:
						hw_mod_qsl_qst_set(&dev->ndev->be,
								   HW_QSL_QST_PRESET_ALL,
								   fh->resource[RES_QSL_QST]
								   .index + ii,
								   0);
						hw_mod_qsl_qst_flush(&dev->ndev->be,
								     fh->resource[RES_QSL_QST]
								     .index + ii,
								     1);
						break;

					case RES_QSL_RCP:
						hw_mod_qsl_rcp_set(&dev->ndev->be,
								   HW_QSL_RCP_PRESET_ALL,
								   fh->resource[RES_QSL_RCP]
								   .index + ii,
								   0);
						hw_mod_qsl_rcp_flush(&dev->ndev->be,
								     fh->resource[RES_QSL_RCP]
								     .index + ii,
								     1);
						break;

					case RES_CAT_COT:
						hw_mod_cat_cot_set(&dev->ndev->be,
								   HW_CAT_COT_PRESET_ALL,
								   fh->resource[res_type]
								   .index + ii,
								   0);
						hw_mod_cat_cot_flush(&dev->ndev->be,
								     fh->resource[res_type]
								     .index + ii,
								     1);
						break;

					case RES_KM_CATEGORY:
						assert(ii == 0);
						hw_mod_km_rcp_set(&dev->ndev->be,
								  HW_KM_RCP_PRESET_ALL,
								  fh->resource[res_type]
								  .index + ii,
								  0, 0);
						hw_mod_km_rcp_flush(&dev->ndev->be,
								    fh->resource[res_type]
								    .index + ii,
								    1);
						break;

					case RES_KM_FLOW_TYPE: {
						struct flm_flow_ft_ident_s *ft_idents =
							(struct flm_flow_ft_ident_s
							 *)dev->ndev
							->ft_res_handle;
						ft_idents[fh->resource[res_type]
							  .index +
							  ii]
						.data = 0;
					}
					break;

					case RES_FLM_RCP:
						assert(ii == 0);
						err |= flm_flow_destroy_rcp(dev,
									    fh->resource[res_type]
									    .index + ii);
						break;

					case RES_FLM_FLOW_TYPE:
						/* Nothing needed */
						break;

					case RES_HSH_RCP:
						hw_mod_hsh_rcp_set(&dev->ndev->be,
								   HW_HSH_RCP_PRESET_ALL,
								   fh->resource[res_type]
								   .index + ii,
								   0, 0);
						hw_mod_hsh_rcp_flush(&dev->ndev->be,
								     fh->resource[res_type]
								     .index +
								     ii,
								     1);
						break;

					case RES_PDB_RCP:
						hw_mod_pdb_rcp_set(&dev->ndev->be,
								   HW_PDB_RCP_PRESET_ALL,
								   fh->resource[res_type]
								   .index + ii,
								   0);
						hw_mod_pdb_rcp_flush(&dev->ndev->be,
								     fh->resource[res_type]
								     .index + ii,
								     1);
						break;

					case RES_HST_RCP:
						hw_mod_hst_rcp_set(&dev->ndev->be,
								   HW_HST_RCP_PRESET_ALL,
								   fh->resource[res_type]
								   .index + ii,
								   0);
						hw_mod_hst_rcp_flush(&dev->ndev->be,
								     fh->resource[res_type]
								     .index + ii,
								     1);
						break;

					case RES_TPE_RCP:
						hw_mod_tpe_rpp_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_rpp_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_ins_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_ins_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_rpl_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_rpl_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_rpl_ext_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_rpl_ext_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_cpy_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_cpy_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_hfu_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_hfu_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						hw_mod_tpe_csu_rcp_set(&dev->ndev->be,
								       HW_TPE_PRESET_ALL,
								       fh->resource[res_type]
								       .index + ii,
								       0);
						hw_mod_tpe_csu_rcp_flush(&dev->ndev->be,
									 fh->resource[res_type]
									 .index + ii,
									 1);
						break;

					case RES_TPE_EXT:
						/* Nothing needed */
						break;

					case RES_TPE_RPL:
						/* Nothing needed */
						break;

					default:
						err |= -1;
						break;
					}
				}
			}
		}
		free(fh->fd);
	}

	if (err) {
		NT_LOG(ERR, FILTER, "FAILED removing flow: %p\n", fh);
		flow_nic_set_error(ERR_REMOVE_FLOW_FAILED, error);
	}

	free(fh);

#ifdef FLOW_DEBUG
	dev->ndev->be.iface->set_debug_mode(dev->ndev->be.be_dev,
					    FLOW_BACKEND_DEBUG_MODE_NONE);
#endif

	return err;
}

int flow_destroy_profile_inline(struct flow_eth_dev *dev,
				struct flow_handle *flow,
				struct flow_error *error)
{
	int err = 0;

	flow_nic_set_error(ERR_SUCCESS, error);

	pthread_mutex_lock(&dev->ndev->mtx);
	if (flow) {
		/* Delete this flow */
		err = flow_destroy_locked_profile_inline(dev, flow, error);
	} else {
		/* Delete all created flows from this eth device */
		flow = dev->ndev->flow_base;

		while (flow && !err) {
			if (flow->dev == dev) {
				struct flow_handle *flow_next = flow->next;

				err = flow_destroy_locked_profile_inline(dev,
									 flow,
									 NULL);
				flow = flow_next;
			} else {
				flow = flow->next;
			}
		}

		/* Delete all created FLM flows from this eth device */
		flow = dev->ndev->flow_base_flm;

		while (flow && !err) {
			if (flow->dev == dev) {
				struct flow_handle *flow_next = flow->next;

				err = flow_destroy_locked_profile_inline(dev,
									 flow,
									 NULL);
				flow = flow_next;
			} else {
				flow = flow->next;
			}
		}
	}

	pthread_mutex_unlock(&dev->ndev->mtx);

	return err;
}

int flow_flush_profile_inline(UNUSED struct flow_eth_dev *dev,
			      struct flow_error *error)
{
	NT_LOG(ERR, FILTER, "ERROR: Not implemented yet\n");
	error->type = FLOW_ERROR_GENERAL;
	error->message = "rte_flow_flush is not supported";
	return -1;
}

int flow_query_profile_inline(UNUSED struct flow_eth_dev *dev,
			      UNUSED struct flow_handle *flow,
			      UNUSED const struct flow_action *action,
			      void **data, uint32_t *length,
			      struct flow_error *error)
{
	NT_LOG(ERR, FILTER, "ERROR: Not implemented yet\n");

	*length = 0;
	*data = NULL;
	error->type = FLOW_ERROR_GENERAL;
	error->message = "rte_flow_query is not supported";
	return -1;
}

int flow_get_flm_stats_profile_inline(struct flow_nic_dev *ndev, uint64_t *data,
				      uint64_t size)
{
	const enum hw_flm_e fields[] = {
		HW_FLM_STAT_FLOWS,	HW_FLM_STAT_LRN_DONE,
		HW_FLM_STAT_LRN_IGNORE, HW_FLM_STAT_LRN_FAIL,
		HW_FLM_STAT_UNL_DONE,	HW_FLM_STAT_UNL_IGNORE,
		HW_FLM_STAT_AUL_DONE,	HW_FLM_STAT_AUL_IGNORE,
		HW_FLM_STAT_AUL_FAIL,	HW_FLM_STAT_TUL_DONE,
		HW_FLM_STAT_REL_DONE,	HW_FLM_STAT_REL_IGNORE,
		HW_FLM_STAT_PRB_DONE,	HW_FLM_STAT_PRB_IGNORE,

		HW_FLM_STAT_STA_DONE,	HW_FLM_STAT_INF_DONE,
		HW_FLM_STAT_INF_SKIP,	HW_FLM_STAT_PCK_HIT,
		HW_FLM_STAT_PCK_MISS,	HW_FLM_STAT_PCK_UNH,
		HW_FLM_STAT_PCK_DIS,	HW_FLM_STAT_CSH_HIT,
		HW_FLM_STAT_CSH_MISS,	HW_FLM_STAT_CSH_UNH,
		HW_FLM_STAT_CUC_START,	HW_FLM_STAT_CUC_MOVE,
	};

	const uint64_t fields_cnt = sizeof(fields) / sizeof(enum hw_flm_e);

	if (size < fields_cnt)
		return -1;

	hw_mod_flm_stat_update(&ndev->be);

	for (uint64_t i = 0; i < fields_cnt; ++i) {
		uint32_t value = 0;

		hw_mod_flm_stat_get(&ndev->be, fields[i], &value);
		data[i] = (fields[i] == HW_FLM_STAT_FLOWS) ? value :
			  data[i] + value;
		if (ndev->be.flm.ver < 18 &&
				fields[i] == HW_FLM_STAT_PRB_IGNORE)
			break;
	}

	return 0;
}

int flow_set_mtu_inline(struct flow_eth_dev *dev, uint32_t port, uint16_t mtu)
{
	if (port >= 255)
		return -1;

	int err = 0;
	uint8_t ifr_mtu_recipe = convert_port_to_ifr_mtu_recipe(port);
	struct flow_nic_dev *ndev = dev->ndev;

	err |= hw_mod_tpe_rpp_ifr_rcp_set(&ndev->be, HW_TPE_IFR_RCP_EN,
					  ifr_mtu_recipe, 1);
	err |= hw_mod_tpe_rpp_ifr_rcp_set(&ndev->be, HW_TPE_IFR_RCP_MTU,
					  ifr_mtu_recipe, mtu);
	err |= hw_mod_tpe_ifr_rcp_set(&ndev->be, HW_TPE_IFR_RCP_EN,
				      ifr_mtu_recipe, 1);
	err |= hw_mod_tpe_ifr_rcp_set(&ndev->be, HW_TPE_IFR_RCP_MTU,
				      ifr_mtu_recipe, mtu);

	if (err == 0) {
		err |= hw_mod_tpe_rpp_ifr_rcp_flush(&ndev->be, ifr_mtu_recipe,
						    1);
		err |= hw_mod_tpe_ifr_rcp_flush(&ndev->be, ifr_mtu_recipe, 1);
	}

	return err;
}
