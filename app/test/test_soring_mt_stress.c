/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Huawei Technologies Co., Ltd
 */

#include "test_soring_stress_impl.h"

static inline uint32_t
_st_ring_dequeue_bulk(struct rte_soring *r, void **obj, uint32_t n,
	enum rte_ring_queue_behavior bhv, uint32_t *avail)
{
	return rte_soring_dequeue(r, obj, NULL, n, bhv, avail);
}

static inline uint32_t
_st_ring_enqueue_bulk(struct rte_soring *r, void * const *obj, uint32_t n,
	enum rte_ring_queue_behavior bhv, uint32_t *free)
{
	return rte_soring_enqueue(r, obj, NULL, n, bhv, free);
}

static inline uint32_t
_st_ring_stage_acquire(struct rte_soring *r, uint32_t stage, void **obj,
	uint32_t num, enum rte_ring_queue_behavior bhv, uint32_t *token,
	uint32_t *avail)
{
	return rte_soring_acquire(r, obj, NULL, stage, num, bhv,
			token, avail);
}

static inline void
_st_ring_stage_release(struct rte_soring *r, uint32_t stage, uint32_t token,
	void * const *obj, uint32_t num)
{
	RTE_SET_USED(obj);
	rte_soring_release(r, NULL, NULL, stage, num, token);
}

static const enum rte_ring_queue_behavior ring_behavior =
	RTE_RING_QUEUE_VARIABLE;

const struct test test_soring_mt_stress = {
	.name = "MT",
	.nb_case = RTE_DIM(tests),
	.cases = tests,
};
