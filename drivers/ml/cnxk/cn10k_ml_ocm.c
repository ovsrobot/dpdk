/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2022 Marvell.
 */

#include <rte_mldev_pmd.h>

#include "cn10k_ml_dev.h"
#include "cn10k_ml_model.h"
#include "cn10k_ml_ocm.h"

#include "roc_api.h"

/* OCM macros */
#define BYTE_LEN	   8
#define OCM_MAP_WORD_SIZE  (sizeof(uint8_t) * BYTE_LEN)
#define IS_BIT_SET(num, n) ((num) & (1 << (n)))
#define SET_BIT(num, n)	   ((num) | (1 << (n)))
#define CLEAR_BIT(num, n)  ((num) &= ~((1) << (n)))

/* Left shift multi-word mask by 1 bit.
 *
 * For example, given a mask of two uint8_t words
 * Input:  [00110101] [00110111]
 * Output: [01101010] [01101110]
 */
static void
lshift_mask(uint8_t *mask, int nwords)
{
	int i;
	int word_sz;

	word_sz = sizeof(uint8_t) * BYTE_LEN;
	for (i = nwords - 1; i >= 0; i--) {
		mask[i] = mask[i] << 1;
		if (i != 0)
			mask[i] = mask[i] | (mask[i - 1] >> (word_sz - 1));
	}
}

/* Get the index of the first unused slot in a multi-word mask (base_mask). Unused slots only after
 * the start_pos are considered. An unused slot is a sequence of slot_sz continuous unset bits in
 * the multi-word mask. For example given a multi-word mask,
 *
 * The program creates a search_mask with slot_sz bits set. Uses a sliding windows approach to scan
 * the mask to identify the available first slot. search_mask slides left from start_pos to end.
 *
 * [10111000] [01001001]
 * - WORD 1 --- WORD 0 -
 *
 * When start = 0,
 * Index of the first unused slot of size 4 is 7.
 * Index of the first unused slot of size 3 is 7.
 * Index of the first unused slot of size 2 is 1.
 * Index of the first unused slot of size 1 is 1.
 *
 * When start = 2,
 * Index of the first unused slot of size 4 is 7.
 * Index of the first unused slot of size 2 is 4.
 * Index of the first unused slot of size 1 is 2.
 *
 * When unable to find a valid slot, return 0
 * When slot_sz is zero, return max_idx + 1
 */
static int
slot_index_lowest(uint8_t *base_mask, int nwords, int slot_sz, int start_pos)
{
	uint8_t *search_mask;
	int word_sz;
	int end_pos;
	int min_idx;
	int max_idx;
	bool match;
	int i, j;
	int idx;

	word_sz = sizeof(uint8_t) * BYTE_LEN;
	min_idx = 0;
	max_idx = word_sz * nwords;
	idx = min_idx - 1;

	if (slot_sz == 0)
		return max_idx;

	/* Create a mask with slot_sz bits set */
	search_mask = plt_zmalloc(nwords * sizeof(uint8_t), 0);
	if (search_mask == NULL)
		goto error;

	for (i = 0; i < nwords; i++) {
		if (i < slot_sz / word_sz)
			search_mask[i] = 0xFF;
		else if (i > slot_sz / word_sz)
			search_mask[i] = 0x00;
		else
			search_mask[i] = (1 << (slot_sz % word_sz)) - 1;
	}

	/* Shift search mask by start_pos bits */
	for (i = 0; i < start_pos; i++)
		lshift_mask(search_mask, nwords);

	/* Scan for a slot, left shift search mask after every iteration */
	end_pos = nwords * word_sz - slot_sz + 1;
	for (j = start_pos; j < end_pos; j++) {
		match = true;
		for (i = 0; i < nwords; i++)
			match = match && (((~base_mask[i]) & search_mask[i]) == search_mask[i]);

		if (match) {
			idx = j;
			goto found;
		}

		lshift_mask(search_mask, nwords);
	}

found:
	plt_free(search_mask);

error:
	return idx;
}

/* Find the largest possible unused slot, with a minimum size of search_sz in a multi-work mask. The
 * function returns the start index of the slot and the size of the identified slot (slot_sz).
 *
 * For example, in multi-word mask
 *
 * [10111000] [01001001]
 * - WORD 1 --- WORD 0 -
 *
 * When search_sz > 4, return value = -1, slot_sz = 0
 * When search_sz <=4, return value = 7, slot_sz = 4
 */
static int
slot_index_largest(uint8_t *base_mask, int nwords, int search_sz, int *slot_sz)
{
	uint8_t *search_mask;
	int mask_sz;
	int word_sz;
	int end_pos;
	bool match;
	int i, j;
	int idx;

	word_sz = sizeof(uint8_t) * BYTE_LEN;
	mask_sz = nwords * word_sz;
	idx = -1;

	/* Create a mask with mask_sz bits set */
	search_mask = plt_zmalloc(mask_sz, 0);
	if (search_mask == NULL)
		goto error;

start:
	for (i = 0; i < nwords; i++) {
		if (i < mask_sz / word_sz)
			search_mask[i] = 0xFF;
		else if (i > mask_sz / word_sz)
			search_mask[i] = 0x00;
		else
			search_mask[i] = (1 << (mask_sz % word_sz)) - 1;
	}

	/* Scan for a slot, left shift search mask after every iteration */
	end_pos = nwords * word_sz - mask_sz + 1;
	for (j = 0; j < end_pos; j++) {
		match = true;
		for (i = 0; i < nwords; i++)
			match = match && (((~base_mask[i]) & search_mask[i]) == search_mask[i]);

		if (match) {
			idx = j;
			goto found;
		}
		lshift_mask(search_mask, nwords);
	}

	mask_sz--;
	if (mask_sz >= search_sz)
		goto start;
	else
		mask_sz = 0;

found:
	plt_free(search_mask);
	if (search_sz == 0)
		idx = word_sz * nwords;

error:
	if (slot_sz)
		*slot_sz = mask_sz;

	return idx;
}

/* Count number of bits in a tilemask. Assumes that all set bits are contiguous. */
int
cn10k_ml_ocm_tilecount(uint64_t tilemask, int *start, int *end)
{
	uint8_t count;

	PLT_ASSERT(tilemask != 0);

	*start = __builtin_ctzl(tilemask);
	*end = 64 - __builtin_clzl(tilemask) - 1;
	count = *end - *start + 1;

	PLT_ASSERT(count == __builtin_popcountl(tilemask));
	return count;
}

/* Find the tiles and wb_page_start to load the model on given 'num_tiles' tiles with the specified
 * scratch & WB pages and OCM allocation mode.
 */
int
cn10k_ml_ocm_tilemask_find(struct rte_ml_dev *dev, uint8_t num_tiles, uint16_t wb_pages,
			   uint16_t scratch_pages, uint64_t *tilemask)
{
	struct cn10k_ml_dev *mldev;
	struct cn10k_ml_ocm *ocm;

	uint8_t local_ocm_mask[ML_CN10K_OCM_MASKWORDS] = {0};
	uint16_t used_scratch_pages_max;
	uint16_t scratch_page_start;
	int used_last_wb_page_max;
	uint16_t scratch_page_end;
	uint8_t search_start_tile;
	uint8_t search_end_tile;
	int wb_page_start_curr;
	int max_slot_sz_curr;
	uint8_t tile_start;
	int ocm_alloc_mode;
	int wb_page_start;
	uint16_t tile_id;
	uint16_t word_id;
	uint8_t tile_idx;
	int max_slot_sz;
	int start_tile;
	int page_id;

	mldev = dev->data->dev_private;
	ocm = &mldev->ocm;

	if (num_tiles > ML_CN10K_OCM_NUMTILES) {
		plt_err("Invalid num_tiles = %u (> ML_CN10K_OCM_NUMTILES)", num_tiles);
		return -1;
	}

	memset(tilemask, 0, sizeof(uint64_t));
	wb_page_start = -1;
	used_scratch_pages_max = 0;
	used_last_wb_page_max = -1;
	start_tile = -1;
	max_slot_sz_curr = 0;
	max_slot_sz = 0;
	tile_idx = 0;
	ocm_alloc_mode = 2;

	if ((start_tile != -1) && (start_tile % num_tiles != 0)) {
		plt_err("Invalid start_tile, %d", start_tile);
		return -1;
	}

	if (start_tile < 0) {
		search_start_tile = 0;
		search_end_tile = ocm->num_tiles - num_tiles;
	} else {
		search_start_tile = start_tile;
		search_end_tile = start_tile;
	}

	tile_start = search_start_tile;
start_search:
	used_scratch_pages_max = 0;
	used_last_wb_page_max = -1;
	for (tile_id = tile_start; tile_id < tile_start + num_tiles; tile_id++) {
		used_scratch_pages_max =
			PLT_MAX(ocm->tile_ocm_info[tile_id].scratch_pages, used_scratch_pages_max);
		used_last_wb_page_max =
			PLT_MAX(ocm->tile_ocm_info[tile_id].last_wb_page, used_last_wb_page_max);
	}

	memset(local_ocm_mask, 0, sizeof(local_ocm_mask));
	for (tile_id = tile_start; tile_id < tile_start + num_tiles; tile_id++) {
		for (word_id = 0; word_id < ocm->mask_words; word_id++)
			local_ocm_mask[word_id] |= ocm->tile_ocm_info[tile_id].ocm_mask[word_id];
	}

	if (used_scratch_pages_max < scratch_pages) { /* Check for extra scratch pages */
		if (ocm->num_pages - used_last_wb_page_max - 1 >=
		    scratch_pages) { /* Pages available */
			scratch_page_start = ocm->num_pages - scratch_pages;
			scratch_page_end = ocm->num_pages - 1;
			for (page_id = scratch_page_start; page_id <= scratch_page_end;
			     page_id++) { /* Mark the extra scratch pages as used */
				local_ocm_mask[page_id / OCM_MAP_WORD_SIZE] =
					SET_BIT(local_ocm_mask[page_id / OCM_MAP_WORD_SIZE],
						page_id % OCM_MAP_WORD_SIZE);
			}
		} else { /* Pages not available, check for next set of tiles */
			goto next_search;
		}
	}

	if (ocm_alloc_mode == 1) {
		wb_page_start = slot_index_lowest(local_ocm_mask, ocm->mask_words, wb_pages, 0);
		if (wb_page_start != -1) { /* Have a valid slot for WB, else next set of tiles */
			tile_idx = tile_start;
			goto found;
		}
	} else if (ocm_alloc_mode == 2) {
		wb_page_start_curr = slot_index_largest(local_ocm_mask, ocm->mask_words, wb_pages,
							&max_slot_sz_curr);
		if (max_slot_sz_curr > max_slot_sz) {
			wb_page_start = wb_page_start_curr;
			max_slot_sz = max_slot_sz_curr;
			tile_idx = tile_start;
		} else if (max_slot_sz_curr == max_slot_sz) {
			wb_page_start = wb_page_start_curr;
			if (wb_page_start == ocm->num_pages) {
				tile_idx = tile_start;
				goto found;
			}
		}
	}

next_search:
	tile_start = tile_start + num_tiles;
	if (tile_start <= search_end_tile)
		goto start_search;

found:
	if (wb_page_start != -1)
		*tilemask = GENMASK_ULL(tile_idx + num_tiles - 1, tile_idx);

	return wb_page_start;
}

void
cn10k_ml_ocm_reserve_pages(struct rte_ml_dev *dev, uint16_t model_id, uint64_t tilemask,
			   int wb_page_start, uint16_t wb_pages, uint16_t scratch_pages)
{
	struct cn10k_ml_model *model;
	struct cn10k_ml_dev *mldev;
	struct cn10k_ml_ocm *ocm;

	int scratch_page_start;
	int scratch_page_end;
	int wb_page_end;
	int tile_start;
	int tile_end;
	int tile_id;
	int page_id;

	mldev = dev->data->dev_private;
	ocm = &mldev->ocm;
	model = dev->data->models[model_id];

	/* Get first set bit, tile_start */
	tile_start = 0;
	tile_end = 0;
	cn10k_ml_ocm_tilecount(tilemask, &tile_start, &tile_end);
	wb_page_end = wb_page_start + wb_pages - 1;
	scratch_page_start = ocm->num_pages - scratch_pages;
	scratch_page_end = ocm->num_pages - 1;

	/* Update tile_ocm_info */
	for (tile_id = tile_start; tile_id <= tile_end; tile_id++) {
		/* Scratch pages */
		for (page_id = scratch_page_start; page_id <= scratch_page_end; page_id++)
			ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE] = SET_BIT(
				ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE],
				page_id % OCM_MAP_WORD_SIZE);
		ocm->tile_ocm_info[tile_id].scratch_pages =
			PLT_MAX(ocm->tile_ocm_info[tile_id].scratch_pages, scratch_pages);

		/* WB pages */
		for (page_id = wb_page_start; page_id <= wb_page_end; page_id++)
			ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE] = SET_BIT(
				ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE],
				page_id % OCM_MAP_WORD_SIZE);
		if (wb_pages != 0)
			ocm->tile_ocm_info[tile_id].last_wb_page =
				PLT_MAX(ocm->tile_ocm_info[tile_id].last_wb_page, wb_page_end);
	}

	model->addr.tile_start = tile_start;
	model->addr.tile_end = tile_end;

	plt_ml_dbg("model_id = %u, tilemask = 0x%016lx", model_id, tilemask);
	plt_ml_dbg("model_id = %u, wb_page_start = %d, wb_page_end = %d", model_id, wb_page_start,
		   wb_page_end);
	plt_ml_dbg("model_id = %u, scratch_page_start = %d, scratch_page_end = %d", model_id,
		   scratch_page_start, scratch_page_end);
}

void
cn10k_ml_ocm_free_pages(struct rte_ml_dev *dev, uint16_t model_id)
{
	struct cn10k_ml_model *model;
	struct cn10k_ml_dev *mldev;
	struct cn10k_ml_ocm *ocm;

	int scratch_resize_pages;
	int wb_page_start;
	int wb_page_end;
	int prev_start;
	int curr_start;
	int tile_id;
	int page_id;
	uint16_t i;

	mldev = dev->data->dev_private;
	ocm = &mldev->ocm;
	model = dev->data->models[model_id];

	/* Update OCM info for WB memory */
	wb_page_start = model->model_mem_map.wb_page_start;
	wb_page_end = wb_page_start + model->model_mem_map.wb_pages - 1;
	for (tile_id = model->addr.tile_start; tile_id <= model->addr.tile_end; tile_id++) {
		for (page_id = wb_page_start; page_id <= wb_page_end; page_id++) {
			ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE] =
				CLEAR_BIT(ocm->tile_ocm_info[tile_id]
						  .ocm_mask[page_id / OCM_MAP_WORD_SIZE],
					  page_id % OCM_MAP_WORD_SIZE);
		}

		/* Update last_wb_page size */
		if (wb_page_end == ocm->tile_ocm_info[tile_id].last_wb_page)
			ocm->tile_ocm_info[tile_id].last_wb_page = wb_page_start - 1;

		/* Update scratch page size and clear extra bits */
		scratch_resize_pages = 0;
		/* Get max scratch pages required, excluding the current model */
		for (i = 0; i < dev->data->nb_models; i++) {
			struct cn10k_ml_model *model = dev->data->models[i];

			if ((i != model_id) && (model != NULL)) {
				if (IS_BIT_SET(model->model_mem_map.tilemask, tile_id))
					scratch_resize_pages =
						PLT_MAX((int)model->model_mem_map.scratch_pages,
							scratch_resize_pages);
			}
		}

		/* Clear extra scratch pages */
		if (scratch_resize_pages < ocm->tile_ocm_info[tile_id].scratch_pages) {
			prev_start = ocm->num_pages - ocm->tile_ocm_info[tile_id].scratch_pages;
			curr_start = ocm->num_pages - scratch_resize_pages;
			for (page_id = prev_start; page_id < curr_start; page_id++) {
				ocm->tile_ocm_info[tile_id].ocm_mask[page_id / OCM_MAP_WORD_SIZE] =
					CLEAR_BIT(ocm->tile_ocm_info[tile_id]
							  .ocm_mask[page_id / OCM_MAP_WORD_SIZE],
						  page_id % OCM_MAP_WORD_SIZE);
			}
			ocm->tile_ocm_info[tile_id].scratch_pages = scratch_resize_pages;
		}
	}
}
