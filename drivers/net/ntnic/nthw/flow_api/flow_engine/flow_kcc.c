/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Napatech A/S
 */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "flow_api_backend.h"
#include "flow_api_engine.h"
#include "flow_hasher.h"

/*
 * KCC-CAM structures and defines
 */
struct kcc_cam_distrib_s {
	struct kcc_flow_def_s *kcc_owner;
	int ref_cnt;
};

#define BE_CAM_KCC_DIST_IDX(bnk) \
	({ \
		int _temp_bnk = (bnk); \
		(_temp_bnk * kcc->be->cat.kcc_records + kcc->record_indexes[_temp_bnk]); \
	})


#define BE_CAM_ENTRIES \
	(kcc->be->cat.kcc_size * sizeof(struct kcc_cam_distrib_s))
#define BE_UNIQUE_IDS_SIZE ((1U << kcc->be->cat.kcc_id_bit_size) / 8)

#define KCC_CUCKOO_MOVE_MAX_DEPTH 8
static int kcc_cam_addr_reserved_stack[KCC_CUCKOO_MOVE_MAX_DEPTH];

void kcc_attach_ndev_resource_management(struct kcc_flow_def_s *kcc,
		void **handle)
{
	/*
	 *  KCC entries occupied in CAM - to manage the cuckoo shuffling
	 *  and manage CAM population and usage
	 */
	if (!*handle) {
		*handle = calloc(1, BE_CAM_ENTRIES + sizeof(uint32_t) +
				 BE_UNIQUE_IDS_SIZE +
				 sizeof(struct hasher_s));
		NT_LOG(DBG, FILTER,
		       "Allocate NIC DEV KCC-CAM record manager\n");
	}
	kcc->cam_dist = (struct kcc_cam_distrib_s *)*handle;
	kcc->cuckoo_moves =
		(uint32_t *)((char *)kcc->cam_dist + BE_CAM_ENTRIES);
	kcc->kcc_unique_ids = (uint8_t *)((char *)kcc->cam_dist +
					  BE_CAM_ENTRIES + sizeof(uint32_t));

	kcc->hsh = (struct hasher_s *)((char *)kcc->kcc_unique_ids +
				       BE_UNIQUE_IDS_SIZE);
	init_hasher(kcc->hsh, kcc->be->cat.kcc_banks, kcc->be->cat.kcc_records);
}

void kcc_free_ndev_resource_management(void **handle)
{
	if (*handle) {
		free(*handle);
		NT_LOG(DBG, FILTER, "Free NIC DEV KCC-CAM record manager\n");
	}
	*handle = NULL;
}

/*
 * Key for KCC CAM
 */
int kcc_key_add_no_sideband(struct kcc_flow_def_s *kcc)
{
	kcc->key.sb_data = 0xffffffff;
	kcc->key.sb_type = 0;
	return 0;
}

int kcc_key_add_vlan(struct kcc_flow_def_s *kcc, uint16_t tpid, uint16_t vid)
{
	kcc->key.sb_data = ((uint32_t)tpid << 16) | (vid & 0x0fff);
	kcc->key.sb_type = 1;
	return 0;
}

int kcc_key_add_vxlan(struct kcc_flow_def_s *kcc, uint32_t vni)
{
	kcc->key.sb_data = (vni & 0x00ffffff) | 0x02000000;
	kcc->key.sb_type = 2;
	return 0;
}

int kcc_key_add_port(struct kcc_flow_def_s *kcc, uint16_t port)
{
	kcc->key.port = port;
	return 0;
}

int kcc_key_add_cat_cfn(struct kcc_flow_def_s *kcc, uint8_t cat_cfn)
{
	kcc->key.cat_cfn = cat_cfn;
	return 0;
}

uint8_t kcc_key_get_cat_cfn(struct kcc_flow_def_s *kcc)
{
	return kcc->key.cat_cfn;
}

/*
 * other settings for KCC CAM
 */
int kcc_add_km_category(struct kcc_flow_def_s *kcc, uint32_t category)
{
	kcc->km_category = category;
	return 0;
}

int kcc_alloc_unique_id(struct kcc_flow_def_s *kcc)
{
	uint32_t i, ii;
	/* search a free unique ID in allocation bitmap */
	for (i = 0; i < BE_UNIQUE_IDS_SIZE; i++)
		if (kcc->kcc_unique_ids[i] != 0xff)
			break;

	if (i == BE_UNIQUE_IDS_SIZE)
		return -1;

	for (ii = 0; ii < 8; ii++) {
		if ((kcc->kcc_unique_ids[i] & (uint8_t)(1U << ii)) == 0) {
			kcc->kcc_unique_ids[i] =
				(uint8_t)(kcc->kcc_unique_ids[i] |
					  (uint8_t)(1U << ii));
			kcc->id = (uint16_t)(i * 8 + ii);
			NT_LOG(DBG, FILTER, "Allocate new KCC ID : %i\n",
			       kcc->id);
			return (int)kcc->id;
		}
	}
	return -1;
}

void kcc_free_unique_id(struct kcc_flow_def_s *kcc)
{
	if (kcc->id == KCC_ID_INVALID)
		return;

	uint32_t idx = kcc->id >> 3;
	uint8_t shft = (uint8_t)(kcc->id & 7);

	assert(idx < BE_UNIQUE_IDS_SIZE);
	if (idx < BE_UNIQUE_IDS_SIZE) {
		assert(kcc->kcc_unique_ids[idx] & (uint8_t)(1 << shft));
		kcc->kcc_unique_ids[idx] &= (uint8_t)~(1 << shft);
		NT_LOG(DBG, FILTER, "Free KCC ID : %i\n", kcc->id);
		kcc->id = KCC_ID_INVALID;
	}
}

int kcc_key_compare(struct kcc_flow_def_s *kcc, struct kcc_flow_def_s *kcc1)
{
	if (kcc->key64 == kcc1->key64)
		return 1;
	return 0;
}

static int kcc_cam_populate(struct kcc_flow_def_s *kcc, int bank)
{
	int res;
	int idx = bank * kcc->be->cat.kcc_records + kcc->record_indexes[bank];

	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_KEY, idx, 0,
				 kcc->key32[0]);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_KEY, idx, 1,
				 kcc->key32[1]);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_CATEGORY, idx, 0,
				 kcc->km_category);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_ID, idx, 0, kcc->id);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_flush(kcc->be, idx, 1);

	kcc->cam_dist[BE_CAM_KCC_DIST_IDX(bank)].kcc_owner = kcc;
	kcc->cam_dist[BE_CAM_KCC_DIST_IDX(bank)].ref_cnt = 1;
	return res;
}

static int kcc_cam_reset_entry(struct kcc_flow_def_s *kcc, int bank)
{
	int res = 0;
	int idx = bank * kcc->be->cat.kcc_records + kcc->record_indexes[bank];

	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_KEY, idx, 0, 0);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_KEY, idx, 1, 0);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_CATEGORY, idx, 0, 0);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_set(kcc->be, HW_CAT_KCC_ID, idx, 0, 0);
	if (res)
		return -1;
	res = hw_mod_cat_kcc_flush(kcc->be, idx, 1);

	kcc->cam_dist[BE_CAM_KCC_DIST_IDX(bank)].kcc_owner = NULL;
	kcc->cam_dist[BE_CAM_KCC_DIST_IDX(bank)].ref_cnt = 0;

	kcc->key64 = 0UL;
	kcc->km_category = 0;
	/* "kcc->id" holds an allocated unique id, so cleared/freed later */
	return res;
}

static int kcc_move_cuckoo_index(struct kcc_flow_def_s *kcc)
{
	assert(kcc->cam_dist[BE_CAM_KCC_DIST_IDX(kcc->bank_used)].kcc_owner);

	for (uint32_t bank = 0; bank < kcc->be->cat.kcc_banks; bank++) {
		/* It will not select itself */
		if (kcc->cam_dist[BE_CAM_KCC_DIST_IDX(bank)].kcc_owner ==
				NULL) {
			/*
			 * Populate in new position
			 */
			int res = kcc_cam_populate(kcc, bank);

			if (res) {
				NT_LOG(DBG, FILTER,
				       "Error: failed to write to KM CAM in cuckoo move\n");
				return 0;
			}

			/*
			 * Reset/free entry in old bank
			 * HW flushes are really not needed, the old addresses are always taken over
			 * by the caller If you change this code in future updates, this may no
			 * longer be true then!
			 */
			kcc->cam_dist[BE_CAM_KCC_DIST_IDX(kcc->bank_used)]
			.kcc_owner = NULL;
			NT_LOG(DBG, FILTER,
			       "KCC Cuckoo hash moved from bank %i to bank %i (%04X => %04X)\n",
			       kcc->bank_used, bank,
			       BE_CAM_KCC_DIST_IDX(kcc->bank_used),
			       BE_CAM_KCC_DIST_IDX(bank));

			kcc->bank_used = bank;
			(*kcc->cuckoo_moves)++;
			return 1;
		}
	}
	return 0;
}

static int kcc_move_cuckoo_index_level(struct kcc_flow_def_s *kcc_parent,
				       int bank_idx, int levels,
				       int cam_adr_list_len)
{
	struct kcc_flow_def_s *kcc = kcc_parent->cam_dist[bank_idx].kcc_owner;

	assert(levels <= KCC_CUCKOO_MOVE_MAX_DEPTH);

	if (kcc_move_cuckoo_index(kcc))
		return 1;
	if (levels <= 1)
		return 0;

	assert(cam_adr_list_len < KCC_CUCKOO_MOVE_MAX_DEPTH);

	kcc_cam_addr_reserved_stack[cam_adr_list_len++] = bank_idx;

	for (uint32_t i = 0; i < kcc->be->cat.kcc_banks; i++) {
		int reserved = 0;
		int new_idx = BE_CAM_KCC_DIST_IDX(i);

		for (int i_reserved = 0; i_reserved < cam_adr_list_len;
				i_reserved++) {
			if (kcc_cam_addr_reserved_stack[i_reserved] ==
					new_idx) {
				reserved = 1;
				break;
			}
		}
		if (reserved)
			continue;

		int res = kcc_move_cuckoo_index_level(kcc, new_idx, levels - 1,
						      cam_adr_list_len);
		if (res) {
			if (kcc_move_cuckoo_index(kcc))
				return 1;

			else
				assert(0);
		}
	}

	return 0;
}

static uint32_t kcc_hsh_key[16];

static int kcc_write_data_to_cam(struct kcc_flow_def_s *kcc)
{
	int res = 0;
	int val[MAX_BANKS];

	kcc_hsh_key[0] = kcc->key32[1];
	kcc_hsh_key[1] = kcc->key32[0];
	NT_LOG(DBG, FILTER, "TEMP TEMP TEMP");
	NT_LOG(DBG, FILTER, "Hash key[0] %08x", kcc_hsh_key[0]);
	NT_LOG(DBG, FILTER, "Hash key[1] %08x", kcc_hsh_key[1]);
	NT_LOG(DBG, FILTER, "TEMP TEMP TEMP - swapped");

	/* 2-15 never changed - remains zero */

	gethash(kcc->hsh, kcc_hsh_key, val);

	for (uint32_t i = 0; i < kcc->be->cat.kcc_banks; i++)
		kcc->record_indexes[i] = val[i];
	NT_LOG(DBG, FILTER, "KCC HASH [%03X, %03X, %03X]\n",
	       kcc->record_indexes[0], kcc->record_indexes[1],
	       kcc->record_indexes[2]);

	int bank = -1;
	/*
	 * first step, see if any of the banks are free
	 */
	for (uint32_t i_bank = 0; i_bank < kcc->be->cat.kcc_banks; i_bank++) {
		if (kcc->cam_dist[BE_CAM_KCC_DIST_IDX(i_bank)].kcc_owner ==
				NULL) {
			bank = i_bank;
			break;
		}
	}

	if (bank < 0) {
		/*
		 * Second step - cuckoo move existing flows if possible
		 */
		for (uint32_t i_bank = 0; i_bank < kcc->be->cat.kcc_banks;
				i_bank++) {
			if (kcc_move_cuckoo_index_level(kcc,
							BE_CAM_KCC_DIST_IDX(i_bank),
							4, 0)) {
				bank = i_bank;
				break;
			}
		}

		if (bank < 0)
			return -1;
	}

	/* populate CAM */
	NT_LOG(DBG, FILTER, "KCC Bank = %i (addr %04X)\n", bank,
	       BE_CAM_KCC_DIST_IDX(bank));
	res = kcc_cam_populate(kcc, bank);
	if (res == 0) {
		kcc->flushed_to_target = 1;
		kcc->bank_used = bank;
	} else {
		NT_LOG(DBG, FILTER, "KCC CAM populate failed\n");
	}
	return res;
}

int kcc_write_data_match_entry(struct kcc_flow_def_s *kcc)
{
	int res = -1;

	NT_LOG(DBG, FILTER,
	       "KCC Write Data entry. Create New Key: %016lx, KM category %i, id %i\n",
	       kcc->key64, kcc->km_category, kcc->id);
	res = kcc_write_data_to_cam(kcc);
	return res;
}

static int kcc_clear_data_match_entry(struct kcc_flow_def_s *kcc)
{
	int res = 0;

	if (kcc->flushed_to_target) {
		res = kcc_cam_reset_entry(kcc, kcc->bank_used);
		kcc->flushed_to_target = 0;
		kcc->bank_used = 0;
	}
	return res;
}

int kcc_key_ref_count_add(struct kcc_flow_def_s *kcc)
{
	assert(kcc->bank_used >= 0 &&
	       kcc->bank_used < (int)kcc->be->cat.kcc_banks);

	struct kcc_cam_distrib_s *cam_entry =
		&kcc->cam_dist[BE_CAM_KCC_DIST_IDX(kcc->bank_used)];

	NT_LOG(DBG, FILTER,
	       "KCC ADD Ref existing Key: %016lx, KM category %i, id %i (new ref count %i)\n",
	       kcc->key64, kcc->km_category, kcc->id, cam_entry->ref_cnt + 1);
	return ++cam_entry->ref_cnt;
}

int kcc_key_ref_count_dec(struct kcc_flow_def_s *kcc)
{
	if (kcc->bank_used < 0 || kcc->bank_used >= (int)kcc->be->cat.kcc_banks)
		return -1;

	struct kcc_cam_distrib_s *cam_entry =
		&kcc->cam_dist[BE_CAM_KCC_DIST_IDX(kcc->bank_used)];

	if (cam_entry->ref_cnt) {
		if (--cam_entry->ref_cnt == 0) {
			kcc_clear_data_match_entry(kcc);
			NT_LOG(DBG, FILTER,
			       "KCC DEC Ref on Key became zero - Delete\n");
		}
	}

	NT_LOG(DBG, FILTER,
	       "KCC DEC Ref on Key: %016lx, KM category %i, id %i (new ref count %i)\n",
	       kcc->key64, kcc->km_category, kcc->id, cam_entry->ref_cnt);
	return cam_entry->ref_cnt;
}
