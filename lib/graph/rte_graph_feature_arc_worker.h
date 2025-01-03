/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_FEATURE_ARC_WORKER_H_
#define _RTE_GRAPH_FEATURE_ARC_WORKER_H_

#include <stddef.h>
#include <rte_graph_feature_arc.h>
#include <rte_bitops.h>
#include <rte_mbuf.h>
#include <rte_mbuf_dyn.h>

/**
 * @file
 *
 * rte_graph_feature_arc_worker.h
 *
 * Defines fast path structure for feature arc
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 *
 * Slow path feature node info list
 */
struct rte_graph_feature_node_list {
	/** Next feature */
	STAILQ_ENTRY(rte_graph_feature_node_list) next_feature;

	char feature_name[RTE_GRAPH_FEATURE_ARC_NAMELEN];

	/** node id representing feature */
	rte_node_t feature_node_id;

	/** How many indexes/interfaces using this feature */
	int32_t ref_count;

	/**
	 * feature arc process function overrides to feature node's original
	 * process function
	 */
	rte_node_process_t feature_node_process_fn;

	/** Callback for freeing application resources when */
	rte_graph_feature_change_notifier_cb_t notifier_cb;

	/* finfo_index in list. same as rte_graph_feature_t */
	uint32_t finfo_index;

	/** Back pointer to feature arc */
	void *feature_arc;

	/** rte_edge_t to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;

	/* rte_edge_t from this feature node to last feature node */
	rte_edge_t edge_to_last_feature;
};

/**
 * rte_graph Feature arc object
 *
 * Feature arc object holds control plane and fast path information for all
 * features and all interface index information for steering packets across
 * feature nodes
 *
 * Within a feature arc, only RTE_GRAPH_FEATURE_MAX_PER_ARC features can be
 * added. If more features needs to be added, another feature arc can be
 * created
 *
 * In fast path, rte_graph_feature_arc_t can be translated to (struct
 * rte_graph_feature_arc *) via rte_graph_feature_arc_get(). Later is needed to
 * add as an input argument to all fast path feature arc APIs
 */
struct __rte_cache_aligned rte_graph_feature_arc {
	/** Slow path variables follows*/
	RTE_MARKER slow_path_variables;

	/** All feature lists */
	STAILQ_HEAD(, rte_graph_feature_node_list) all_features;

	/** feature arc name */
	char feature_arc_name[RTE_GRAPH_FEATURE_ARC_NAMELEN];

	/** control plane counter to track enabled features */
	uint32_t runtime_enabled_features;

	/** index in feature_arc_main */
	uint16_t feature_arc_index;

	/* process ref count to track feature_arc_destroy() */
	uint8_t process_ref_count;

	/** Back pointer to feature_arc_main */
	void *feature_arc_main;

	/** Arc's start/end node */
	struct rte_node_register *start_node;
	struct rte_graph_feature_register end_feature;

	/* arc start process function */
	rte_node_process_t arc_start_process;

	/* total arc_size allocated */
	size_t arc_size;

	/** Slow path bit mask per feature per index */
	uint64_t *feature_bit_mask_by_index;

	/** Cache aligned fast path variables */
	alignas(RTE_CACHE_LINE_SIZE) RTE_MARKER fast_path_variables;

	/**
	 * Quick fast path bitmask indicating if any feature enabled. Each bit
	 * corresponds to single feature Helps in optimally process packets for
	 * the case when features are added but not enabled
	 */
	RTE_ATOMIC(uint64_t) fp_feature_enable_bitmask;

	/** maximum number of features supported by this arc
	 *  Immutable during fast path
	 */
	uint16_t max_features;

	/** maximum number of index supported by this arc
	 *  Immutable during fast path
	 */
	uint16_t max_indexes;

	/** arc + fp_first_feature_arr_offset
	 * Immutable during fast path
	 */
	uint16_t fp_first_feature_offset;

	/** arc + fp_feature_data_arr_offset
	 * Immutable during fast path
	 */
	uint16_t fp_feature_data_offset;

	/**
	 * Size of each feature in fastpath.
	 * ALIGN(sizeof(struct rte_graph_feature_data) * arc->max_indexes)
	 * Immutable during fast path
	 */
	uint32_t fp_feature_size;

	/**
	 * Arc specific fast path data
	 * It accommodates:
	 *
	 * 1. first enabled feature for every index
	 * rte_graph_feature_t (fdata as shown below)
	 *
	 * +-------------------------+ <- cache_aligned
	 * |  0th Index | 1st Index  |
	 * +-------------------------+
	 * |  feature0  | feature1   |
	 * +-------------------------+
	 *
	 * 2. struct rte_graph_feature_data per index per feature
	 *
	 * feature0-> +----------------------------------------+ ^ <- cache_aligned
	 *            |  struct rte_graph_feature_data[Index0] | |
	 *            +----------------------------------------+ | fp_feature_size
	 *            |  struct rte_graph_feature_data[Index1] | |
	 * feature1-> +----------------------------------------+ v <- cache aligned
	 *            |  struct rte_graph_feature_data[Index0] | ^
	 *            +----------------------------------------+ | fp_feature_size
	 *            |  struct rte_graph_feature_data[Index1] | |
	 *            +----------------------------------------+ v
	 *                    ...            ....
	 *                    ...            ....
	 */
	RTE_MARKER8 fp_arc_data;
};

/**
 * Feature arc main object
 *
 * Holds all feature arcs created by application
 */
typedef struct rte_feature_arc_main {
	/** number of feature arcs created by application */
	uint32_t num_feature_arcs;

	/** max features arcs allowed */
	uint32_t max_feature_arcs;

	/** Pointer to all feature arcs */
	uintptr_t feature_arcs[];
} rte_graph_feature_arc_main_t;

/**
 *  Fast path feature data object
 *
 *  Used by fast path inline feature arc APIs
 *  Corresponding to rte_graph_feature_data_t
 *  It holds
 *  - edge to reach to next feature node
 *  - next_feature_data corresponding to next enabled feature
 *  - app_cookie set by application in rte_graph_feature_enable()
 */
struct rte_graph_feature_data {
	/** edge from previous enabled feature to this enabled feature */
	RTE_ATOMIC(rte_edge_t) next_edge;

	/** Next feature data from this feature data */
	RTE_ATOMIC(rte_graph_feature_data_t) next_feature_data;

	/**
	 * app_cookie set by application in rte_graph_feature_enable() for
	 * - current feature
	 * - interface index
	 */
	RTE_ATOMIC(uint32_t) app_cookie;
};

/** feature arc specific mbuf dynfield structure. */
struct rte_graph_feature_arc_mbuf_dynfields {
	/** each mbuf carries feature data */
	rte_graph_feature_data_t feature_data;
};

/** Name of dynamic mbuf field offset registered in rte_graph_feature_arc_init() */
#define RTE_GRAPH_FEATURE_ARC_DYNFIELD_NAME    "__rte_graph_feature_arc_mbuf_dynfield"

/** log2(sizeof (struct rte_graph_feature_data)) */
#define RTE_GRAPH_FEATURE_DATA_SIZE_LOG2	3

/** Number of struct rte_graph_feature_data per feature*/
#define RTE_GRAPH_FEATURE_DATA_NUM_PER_FEATURE(arc)				\
	(arc->fp_feature_size >> RTE_GRAPH_FEATURE_DATA_SIZE_LOG2)

/** Get rte_graph_feature_data_t from rte_graph_feature_t */
#define RTE_GRAPH_FEATURE_TO_FEATURE_DATA(arc, feature, index)			\
		((rte_graph_feature_data_t)					\
		 ((RTE_GRAPH_FEATURE_DATA_NUM_PER_FEATURE(arc) * feature) + index))

/** extern variables */
extern rte_graph_feature_arc_main_t *__rte_graph_feature_arc_main;
extern int __rte_graph_feature_arc_mbuf_dyn_offset;

/** get feature arc dynamic offset
 *
 * @return
 *  offset to feature arc specific fields in mbuf
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_arc_mbuf_dynfield_offset_get(void)
{
	return __rte_graph_feature_arc_mbuf_dyn_offset;
}

/**
 * Get dynfield offset to feature arc specific fields in mbuf
 *
 * @param mbuf
 *  Pointer to packet
 * @param dyn_off
 *  offset to feature arc specific fields in mbuf
 *
 * @return
 *  NULL: On Failure
 *  Non-NULL pointer on Success
 */
__rte_experimental
static __rte_always_inline struct rte_graph_feature_arc_mbuf_dynfields *
rte_graph_feature_arc_mbuf_dynfields_get(struct rte_mbuf *mbuf, const int dyn_off)
{
	return RTE_MBUF_DYNFIELD(mbuf, dyn_off,
				 struct rte_graph_feature_arc_mbuf_dynfields *);
}

/**
 * API to know if feature is valid or not
 *
 * @param feature
 *  rte_graph_feature_t
 *
 * @return
 *  1: If feature is valid
 *  0: If feature is invalid
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_is_valid(rte_graph_feature_t feature)
{
	return (feature != RTE_GRAPH_FEATURE_INVALID);
}

/**
 * API to know if feature data is valid or not
 *
 * @param feature_data
 *  rte_graph_feature_data_t
 *
 * @return
 *  1: If feature data is valid
 *  0: If feature data is invalid
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_data_is_valid(rte_graph_feature_data_t feature_data)
{
	return (feature_data != RTE_GRAPH_FEATURE_DATA_INVALID);
}

/**
 * Get pointer to feature arc object from rte_graph_feature_arc_t
 *
 * @param arc
 *  feature arc
 *
 * @return
 *  NULL: On Failure
 *  Non-NULL pointer on Success
 */
__rte_experimental
static __rte_always_inline struct rte_graph_feature_arc *
rte_graph_feature_arc_get(rte_graph_feature_arc_t arc)
{
	rte_graph_feature_arc_main_t *fm = NULL;

	fm = __rte_graph_feature_arc_main;

	if (likely(fm != NULL && arc < fm->max_feature_arcs))
		return (struct rte_graph_feature_arc *)fm->feature_arcs[arc];

	return NULL;
}

/**
 * Get rte_graph_feature_t from feature arc object without any checks
 *
 * @param arc
 *  feature arc
 * @param fdata
 *  feature data object
 *
 * @return
 *   Pointer to feature data object
 */
__rte_experimental
static __rte_always_inline struct rte_graph_feature_data*
__rte_graph_feature_data_get(struct rte_graph_feature_arc *arc,
			     rte_graph_feature_data_t fdata)
{
	return ((struct rte_graph_feature_data *) ((uint8_t *)arc + arc->fp_feature_data_offset +
						   (fdata << RTE_GRAPH_FEATURE_DATA_SIZE_LOG2)));
}

/**
 * Get next edge from feature data pointer, without any check
 *
 * @param fdata
 *  feature data object
 *
 * @return
 *  next edge
 */
__rte_experimental
static __rte_always_inline rte_edge_t
__rte_graph_feature_data_edge_get(struct rte_graph_feature_data *fdata)
{
	return rte_atomic_load_explicit(&fdata->next_edge, rte_memory_order_relaxed);
}

/**
 * Get app_cookie from feature data pointer, without any check
 *
 * @param fdata
 *  feature data object
 *
 * @return
 *  app_cookie set by caller in rte_graph_feature_enable() API
 */
__rte_experimental
static __rte_always_inline uint32_t
__rte_graph_feature_data_app_cookie_get(struct rte_graph_feature_data *fdata)
{
	return rte_atomic_load_explicit(&fdata->app_cookie, rte_memory_order_relaxed);
}

/**
 * Get next_enabled_feature_data from pointer to feature data, without any check
 *
 * @param fdata
 *  feature data object
 *
 * @return
 *  next enabled feature data from this feature data
 */
__rte_experimental
static __rte_always_inline rte_graph_feature_data_t
__rte_graph_feature_data_next_feature_get(struct rte_graph_feature_data *fdata)
{
	return rte_atomic_load_explicit(&fdata->next_feature_data, rte_memory_order_relaxed);
}

/**
 * Get next edge from feature data object with checks
 *
 * @param arc
 *  feature arc
 * @param fdata
 *  feature data object
 *
 * @return
 *  next edge
 */
__rte_experimental
static __rte_always_inline rte_edge_t
rte_graph_feature_data_edge_get(struct rte_graph_feature_arc *arc,
				rte_graph_feature_data_t fdata)
{
	struct rte_graph_feature_data *fdata_obj = __rte_graph_feature_data_get(arc, fdata);

	return __rte_graph_feature_data_edge_get(fdata_obj);
}

/**
 * Get app_cookie from feature data object with checks
 *
 * @param arc
 *  feature arc
 * @param fdata
 *  feature data object
 *
 * @return
 *  app_cookie set by caller in rte_graph_feature_enable() API
 */
__rte_experimental
static __rte_always_inline uint32_t
rte_graph_feature_data_app_cookie_get(struct rte_graph_feature_arc *arc,
				      rte_graph_feature_data_t fdata)
{
	struct rte_graph_feature_data *fdata_obj = __rte_graph_feature_data_get(arc, fdata);

	return __rte_graph_feature_data_app_cookie_get(fdata_obj);
}

/**
 * Get next_enabled_feature_data from current feature data object with checks
 *
 * @param arc
 *  feature arc
 * @param fdata
 *  feature data object
 *
 * @return
 *  next enabled feature data from this feature data
 */
__rte_experimental
static __rte_always_inline rte_graph_feature_data_t
rte_graph_feature_data_next_feature_get(struct rte_graph_feature_arc *arc,
					rte_graph_feature_data_t fdata)
{
	struct rte_graph_feature_data *fdata_obj = __rte_graph_feature_data_get(arc, fdata);

	return __rte_graph_feature_data_next_feature_get(fdata_obj);
}

/**
 * Get struct rte_graph_feature_data from rte_graph_feature_dat_t
 *
 * @param arc
 *   feature arc
 * @param fdata
 *  feature data object
 *
 * @return
 *   NULL: On Failure
 *   Non-NULL pointer on Success
 */
__rte_experimental
static __rte_always_inline struct rte_graph_feature_data*
rte_graph_feature_data_get(struct rte_graph_feature_arc *arc,
			   rte_graph_feature_data_t fdata)
{
	if (unlikely(fdata > (RTE_GRAPH_FEATURE_TO_FEATURE_DATA(arc,
								arc->max_features - 1,
								arc->max_indexes - 1))))
		return NULL;

	return __rte_graph_feature_data_get(arc, fdata);
}

/**
 * Get feature data corresponding to first enabled feature on index
 * @param arc
 *   feature arc
 * @param index
 *   Interface index
 * @param[out] fdata
 *  feature data object
 *
 * @return
 *  1: if any feature enabled on index, return corresponding valid feature data
 *  0: if no feature is enabled on index
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_data_first_feature_get(struct rte_graph_feature_arc *arc,
					 uint32_t index,
					 rte_graph_feature_data_t *fdata)
{
	rte_graph_feature_t *feature = NULL;

	*fdata = RTE_GRAPH_FEATURE_DATA_INVALID;

	feature = (rte_graph_feature_t *)((uint8_t *)arc + arc->fp_first_feature_offset +
					  (sizeof(rte_graph_feature_t) * index));

	if ((index < arc->max_indexes) && rte_graph_feature_is_valid(*feature)) {
		*fdata = RTE_GRAPH_FEATURE_TO_FEATURE_DATA(arc, *feature, index);
		return 1;
	}

	return 0;
}

/**
 * Fast path API to check if any feature enabled on a feature arc
 * Typically from arc->start_node process function
 *
 * @param arc
 *   Feature arc object
 *
 * @return
 *  0: If no feature enabled
 *  Non-Zero: Bitmask of features enabled.
 *
 */
__rte_experimental
static __rte_always_inline uint64_t
rte_graph_feature_arc_is_any_feature_enabled(struct rte_graph_feature_arc *arc)
{
	return (rte_atomic_load_explicit(&arc->fp_feature_enable_bitmask,
					 rte_memory_order_relaxed));
}

/**
 * Fast path API to check if provided feature is enabled on any interface/index
 * or not
 *
 * @param arc
 *   Feature arc object
 * @param feature
 *   Input rte_graph_feature_t that needs to be checked. Can be retrieved in
 *   control path via rte_graph_feature_lookup()
 *
 * @return
 * 1: If input [feature] is enabled in arc
 * 0: If input [feature] is not enabled in arc
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_arc_is_feature_enabled(struct rte_graph_feature_arc *arc,
					 rte_graph_feature_t feature)
{
	uint64_t bitmask = RTE_BIT64(feature);

	return (bitmask & rte_atomic_load_explicit(&arc->fp_feature_enable_bitmask,
						   rte_memory_order_relaxed));
}

/**
 * Prefetch feature arc fast path cache line
 *
 * @param arc
 *   RTE_GRAPH feature arc object
 */
__rte_experimental
static __rte_always_inline void
rte_graph_feature_arc_prefetch(struct rte_graph_feature_arc *arc)
{
	rte_prefetch0((void *)arc->fast_path_variables);
}

/**
 * Prefetch feature data related fast path cache line
 *
 * @param arc
 *   RTE_GRAPH feature arc object
 * @param fdata
 *   Pointer to feature data object
 */
__rte_experimental
static __rte_always_inline void
rte_graph_feature_arc_feature_data_prefetch(struct rte_graph_feature_arc *arc,
					    rte_graph_feature_data_t fdata)
{
	if (unlikely(fdata == RTE_GRAPH_FEATURE_DATA_INVALID))
		return;

	rte_prefetch0((void *)__rte_graph_feature_data_get(arc, fdata));
}

#ifdef __cplusplus
}
#endif
#endif
