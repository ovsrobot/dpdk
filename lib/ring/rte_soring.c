/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Huawei Technologies Co., Ltd
 */

#include "soring.h"
#include <rte_string_fns.h>

RTE_LOG_REGISTER_DEFAULT(soring_logtype, INFO);
#define RTE_LOGTYPE_SORING soring_logtype
#define SORING_LOG(level, ...) \
	RTE_LOG_LINE(level, SORING, "" __VA_ARGS__)

static uint32_t
soring_calc_elem_num(uint32_t count)
{
	return rte_align32pow2(count + 1);
}

static int
soring_check_param(uint32_t esize, uint32_t stsize, uint32_t count,
	uint32_t stages)
{
	if (stages == 0) {
		SORING_LOG(ERR, "invalid number of stages: %u", stages);
		return -EINVAL;
	}

	/* Check if element size is a multiple of 4B */
	if (esize == 0 || esize % 4 != 0) {
		SORING_LOG(ERR, "invalid element size: %u", esize);
		return -EINVAL;
	}

	/* Check if ret-code size is a multiple of 4B */
	if (stsize % 4 != 0) {
		SORING_LOG(ERR, "invalid retcode size: %u", stsize);
		return -EINVAL;
	}

	 /* count must be a power of 2 */
	if (rte_is_power_of_2(count) == 0 ||
			(count > RTE_SORING_ELEM_MAX + 1)) {
		SORING_LOG(ERR, "invalid number of elements: %u", count);
		return -EINVAL;
	}

	return 0;
}

/*
 * Calculate size offsets for SORING internal data layout.
 */
static size_t
soring_get_szofs(uint32_t esize, uint32_t stsize, uint32_t count,
	uint32_t stages, size_t *elst_ofs, size_t *state_ofs,
	size_t *stage_ofs)
{
	size_t sz;
	const struct rte_soring * const r = NULL;

	sz = sizeof(r[0]) + (size_t)count * esize;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);

	if (elst_ofs != NULL)
		*elst_ofs = sz;

	sz = sz + (size_t)count * stsize;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);

	if (state_ofs != NULL)
		*state_ofs = sz;

	sz += sizeof(r->state[0]) * count;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);

	if (stage_ofs != NULL)
		*stage_ofs = sz;

	sz += sizeof(r->stage[0]) * stages;
	sz = RTE_ALIGN(sz, RTE_CACHE_LINE_SIZE);

	return sz;
}


ssize_t
rte_soring_get_memsize(const struct rte_soring_param *prm)
{
	int32_t rc;
	uint32_t count;

	count = soring_calc_elem_num(prm->elems);
	rc = soring_check_param(prm->esize, prm->stsize, count, prm->stages);
	if (rc != 0)
		return rc;

	return soring_get_szofs(prm->esize, prm->stsize, count, prm->stages,
			NULL, NULL, NULL);
}

int
rte_soring_init(struct rte_soring *r, const struct rte_soring_param *prm)
{
	int32_t rc;
	uint32_t n;
	size_t elst_ofs, stage_ofs, state_ofs;

	if (r == NULL || prm == NULL)
		return -EINVAL;

	n = soring_calc_elem_num(prm->elems);
	rc = soring_check_param(prm->esize, prm->stsize, n, prm->stages);
	if (rc != 0)
		return rc;

	soring_get_szofs(prm->esize, prm->stsize, n, prm->stages, &elst_ofs,
			&state_ofs, &stage_ofs);

	memset(r, 0, sizeof(*r));
	rc = strlcpy(r->name, prm->name, sizeof(r->name));
	if (rc < 0 || rc >= (int)sizeof(r->name))
		return -ENAMETOOLONG;

	r->size = n;
	r->mask = r->size - 1;
	r->capacity = prm->elems;
	r->esize = prm->esize;
	r->stsize = prm->stsize;

	r->prod.ht.sync_type = prm->prod_synt;
	r->cons.ht.sync_type = prm->cons_synt;

	r->state = (union soring_state *)((uintptr_t)r + state_ofs);
	memset(r->state, 0, sizeof(r->state[0]) * r->size);

	r->stage = (struct soring_stage *)((uintptr_t)r + stage_ofs);
	r->nb_stage = prm->stages;
	memset(r->stage, 0, r->nb_stage * sizeof(r->stage[0]));

	if (r->stsize != 0)
		r->elemst = (void *)((uintptr_t)r + elst_ofs);

	return 0;
}
