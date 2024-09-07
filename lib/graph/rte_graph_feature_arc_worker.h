/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_FEATURE_ARC_WORKER_H_
#define _RTE_GRAPH_FEATURE_ARC_WORKER_H_

#include <stddef.h>
#include <rte_graph_feature_arc.h>
#include <rte_bitops.h>

/**
 * @file
 *
 * rte_graph_feature_arc_worker.h
 *
 * Defines fast path structure
 */

#ifdef __cplusplus
extern "C" {
#endif

/** @internal
 *
 * Slow path feature node info list
 */
struct rte_graph_feature_node_list {
	/** Next feature */
	STAILQ_ENTRY(rte_graph_feature_node_list) next_feature;

	/** node representing feature */
	struct rte_node_register *feature_node;

	/** How many indexes/interfaces using this feature */
	int32_t ref_count;

	/* node_index in list (after feature_enable())*/
	uint32_t node_index;

	/** Back pointer to feature arc */
	void *feature_arc;

	/** rte_edge_t to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;
};

/**
 * Fast path holding rte_edge_t and next enabled feature for an feature
 */
typedef struct __rte_packed rte_graph_feature_data {
	/* next node to which current mbuf should go*/
	rte_edge_t next_edge;

	/* next enabled feature on this arc for current index */
	union {
		uint16_t reserved;
		struct {
			rte_graph_feature_t next_enabled_feature;
		};
	};

	/* user_data */
	int32_t user_data;
} rte_graph_feature_data_t;

/**
 * Fast path feature structure. Holds re_graph_feature_data_t per index
 */
struct __rte_cache_aligned rte_graph_feature {
	uint16_t this_feature_index;

	/* Array of size arc->feature_data_size
	 * [data-index-0][data-index-1]...
	 * Each index of size: sizeof(rte_graph_feature_data_t)
	 */
	uint8_t feature_data_by_index[];
};

/**
 * fast path cache aligned feature list holding all features
 * There are two feature lists: active, passive
 *
 * Fast APIs works on active list while control plane updates passive list
 * A atomic update to arc->active_feature_list is done to switch between active
 * and passive
 */
typedef struct __rte_cache_aligned rte_graph_feature_list {
	/**
	 * fast path array holding per_feature data.
	 * Duplicate entry as feature-arc also hold this pointer
	 * arc->features[]
	 *
	 *<-------------feature-0 ---------><CEIL><---------feature-1 -------------->...
	 *[index-0][index-1]...[max_index-1]      [index-0][index-1] ...[max_index-1]...
	 */
	struct rte_graph_feature *indexed_by_features;
	/*
	 * fast path array holding first enabled feature per index
	 * (Required in start_node. In non start_node, mbuf can hold next enabled
	 * feature)
	 */
	rte_graph_feature_t first_enabled_feature_by_index[];
} rte_graph_feature_list_t;

/**
 * rte_graph feature arc object
 *
 * A feature-arc can only hold RTE_GRAPH_FEATURE_MAX_PER_ARC features but no
 * limit to interface index
 *
 * Representing a feature arc holding all features which are enabled/disabled
 * on any interfaces
 */
struct __rte_cache_aligned rte_graph_feature_arc {
	/* First 64B is fast path variables */
	RTE_MARKER fast_path_variables;

	/** runtime active feature list */
	rte_graph_feature_rt_list_t active_feature_list;

	/* Actual Size of feature_list0 */
	uint16_t feature_list_size;

	/**
	 * Size each feature in fastpath.
	 * sizeof(arc->active_list->indexed_by_feature[0])
	 */
	uint16_t feature_size;

	/* Size of arc->max_index * sizeof(rte_graph_feature_data_t) */
	uint16_t feature_data_size;

	/**
	 * Fast path bitmask indicating if a feature is enabled or not Number
	 * of bits: RTE_GRAPH_FEATURE_MAX_PER_ARC
	 */
	uint64_t feature_enable_bitmask[2];
	rte_graph_feature_list_t *feature_list[2];
	struct rte_graph_feature *features[2];

	/** index in feature_arc_main */
	uint16_t feature_arc_index;

	uint16_t reserved[3];

	/** Slow path variables follows*/
	RTE_MARKER slow_path_variables;

	/** feature arc name */
	char feature_arc_name[RTE_GRAPH_FEATURE_ARC_NAMELEN];

	/** All feature lists */
	STAILQ_HEAD(, rte_graph_feature_node_list) all_features;

	uint32_t runtime_enabled_features;

	/** Back pointer to feature_arc_main */
	void *feature_arc_main;

	/* start_node */
	struct rte_node_register *start_node;

	/* maximum number of features supported by this arc */
	uint32_t max_features;

	/* maximum number of index supported by this arc */
	uint32_t max_indexes;

	/* Slow path bit mask per feature per index */
	uint64_t feature_bit_mask_by_index[];
};

/** Feature arc main */
typedef struct feature_arc_main {
	/** number of feature arcs created by application */
	uint32_t num_feature_arcs;

	/** max features arcs allowed */
	uint32_t max_feature_arcs;

	/** feature arcs */
	rte_graph_feature_arc_t feature_arcs[];
} rte_graph_feature_arc_main_t;

/** @internal Get feature arc pointer from object */
#define rte_graph_feature_arc_get(arc) ((struct rte_graph_feature_arc *)arc)

extern rte_graph_feature_arc_main_t *__feature_arc_main;

/**
 * API to know if feature is valid or not
 */

static __rte_always_inline int
rte_graph_feature_is_valid(rte_graph_feature_t feature)
{
	return (feature != RTE_GRAPH_FEATURE_INVALID);
}

/**
 * Get rte_graph_feature object with no checks
 *
 * @param arc
 *   Feature arc pointer
 * @param feature
 *   Feature index
 * @param feature_list
 *   active feature list retrieved from rte_graph_feature_arc_has_any_feature()
 *   or rte_graph_feature_arc_has_feature()
 *
 *   @return
 *     Internal feature object.
 */
static __rte_always_inline struct rte_graph_feature *
__rte_graph_feature_get(struct rte_graph_feature_arc *arc, rte_graph_feature_t feature,
			const rte_graph_feature_rt_list_t feature_list)
{
	return ((struct rte_graph_feature *)((uint8_t *)(arc->features[feature_list] +
					     (feature * arc->feature_size))));
}

/**
 * Get rte_graph_feature object for a given interface/index from feature arc
 *
 * @param arc
 *   Feature arc pointer
 * @param feature
 *   Feature index
 *
 *   @return
 *     Internal feature object.
 */
static __rte_always_inline struct rte_graph_feature *
rte_graph_feature_get(struct rte_graph_feature_arc *arc, rte_graph_feature_t feature)
{
	RTE_VERIFY(feature < arc->max_features);

	if (likely(rte_graph_feature_is_valid(feature)))
		return __rte_graph_feature_get(arc, feature, arc->active_feature_list);

	return NULL;
}

static __rte_always_inline rte_graph_feature_data_t *
__rte_graph_feature_data_get(struct rte_graph_feature_arc *arc, struct rte_graph_feature *feature,
			     uint8_t index)
{
	RTE_SET_USED(arc);
	return ((rte_graph_feature_data_t *)(feature->feature_data_by_index +
					   (index * sizeof(rte_graph_feature_data_t))));
}

/**
 * Get rte_graph feature data object for a index in feature
 *
 * @param arc
 *   feature arc
 * @param feature
 *  Pointer to feature object
 * @param index
 *  Index of feature maintained in slow path linked list
 *
 * @return
 *   Valid feature data
 */
static __rte_always_inline rte_graph_feature_data_t *
rte_graph_feature_data_get(struct rte_graph_feature_arc *arc, struct rte_graph_feature *feature,
			   uint8_t index)
{
	if (likely(index < arc->max_indexes))
		return __rte_graph_feature_data_get(arc, feature, index);

	RTE_VERIFY(0);
}

/**
 * Fast path API to check if any feature enabled on a feature arc
 * Typically from arc->start_node process function
 *
 * @param arc
 *   Feature arc object
 * @param[out] plist
 *   Pointer to runtime active feature list which needs to be provided to other
 *   fast path APIs
 *
 * @return
 * 0: If no feature enabled
 * Non-Zero: Bitmask of features enabled. plist is valid
 *
 */
static __rte_always_inline uint64_t
rte_graph_feature_arc_has_any_feature(struct rte_graph_feature_arc *arc,
				      rte_graph_feature_rt_list_t *plist)
{
	*plist = __atomic_load_n(&arc->active_feature_list, __ATOMIC_RELAXED);

	return (__atomic_load_n(arc->feature_enable_bitmask + (uint8_t)*plist,
				__ATOMIC_RELAXED));
}

/**
 * Fast path API to check if provided feature is enabled on any interface/index
 * or not
 *
 * @param arc
 *   Feature arc object
 * @param feature
 *   Input rte_graph_feature_t that needs to be checked
 * @param[out] plist
 *  Returns active list to caller which needs to be provided to other fast path
 *  APIs
 *
 * @return
 * 1: If feature is enabled in arc
 * 0: If feature is not enabled in arc
 */
static __rte_always_inline int
rte_graph_feature_arc_has_feature(struct rte_graph_feature_arc *arc,
				  rte_graph_feature_t feature,
				  rte_graph_feature_rt_list_t *plist)
{
	uint64_t bitmask = RTE_BIT64(feature);

	*plist = __atomic_load_n(&arc->active_feature_list, __ATOMIC_RELAXED);

	return (bitmask & __atomic_load_n(arc->feature_enable_bitmask + (uint8_t)*plist,
					  __ATOMIC_RELAXED));
}

/**
 * Prefetch feature arc fast path cache line
 *
 * @param arc
 *   RTE_GRAPH feature arc object
 */
static __rte_always_inline void
rte_graph_feature_arc_prefetch(struct rte_graph_feature_arc *arc)
{
	rte_prefetch0((void *)&arc->fast_path_variables);
}

/**
 * Prefetch feature related fast path cache line
 *
 * @param arc
 *   RTE_GRAPH feature arc object
 * @param list
 *  Pointer to runtime active feature list from rte_graph_feature_arc_has_any_feature();
 * @param feature
 *   Pointer to feature object
 */
static __rte_always_inline void
rte_graph_feature_arc_feature_prefetch(struct rte_graph_feature_arc *arc,
				       const rte_graph_feature_rt_list_t list,
				       rte_graph_feature_t feature)
{
	/* feature cache line */
	if (likely(rte_graph_feature_is_valid(feature)))
		rte_prefetch0((void *)__rte_graph_feature_get(arc, feature, list));
}

/**
 * Prefetch feature data upfront. Perform sanity
 *
 * @param _arc
 *   RTE_GRAPH feature arc object
 * @param list
 *  Pointer to runtime active feature list from rte_graph_feature_arc_has_any_feature();
 * @param feature
 *   Pointer to feature object returned from @ref
 *   rte_graph_feature_arc_first_feature_get()
 * @param index
 *   Interface/index
 */
static __rte_always_inline void
rte_graph_feature_arc_data_prefetch(struct rte_graph_feature_arc *arc,
				    const rte_graph_feature_rt_list_t list,
				    rte_graph_feature_t feature, uint32_t index)
{
	if (likely(rte_graph_feature_is_valid(feature)))
		rte_prefetch0((void *)((uint8_t *)arc->features[list] +
			      offsetof(struct rte_graph_feature, feature_data_by_index) +
			      (index * sizeof(rte_graph_feature_data_t))));
}

/**
 * Fast path API to get first enabled feature on interface index
 * Typically required in arc->start_node so that from returned feature,
 * feature-data can be retrieved to steer packets
 *
 * @param arc
 *   Feature arc object
 * @param list
 *   Pointer to runtime active feature list from
 *   rte_graph_feature_arc_has_any_feature() or
 *   rte_graph_feature_arc_has_feature()
 * @param index
 *  Interface Index
 * @param[out] feature
 *  Pointer to rte_graph_feature_t.
 *
 * @return
 * 0. Success. feature field is valid
 * 1. Failure. feature field is invalid
 *
 */
static __rte_always_inline int
rte_graph_feature_arc_first_feature_get(struct rte_graph_feature_arc *arc,
					const rte_graph_feature_rt_list_t list,
					uint32_t index,
					rte_graph_feature_t *feature)
{
	struct rte_graph_feature_list *feature_list = arc->feature_list[list];

	*feature = feature_list->first_enabled_feature_by_index[index];

	return rte_graph_feature_is_valid(*feature);
}

/**
 * Fast path API to get next enabled feature on interface index with provided
 * input feature
 *
 * @param arc
 *   Feature arc object
 * @param list
 *   Pointer to runtime active feature list from
 *   rte_graph_feature_arc_has_any_feature() or
 * @param index
 *   Interface Index
 * @param[in][out] feature
 *   Pointer to rte_graph_feature_t. Input feature set to next enabled feature
 *   after success return
 * @param[out] next_edge
 *    Edge from current feature to next feature. Valid only if next feature is valid
 *
 * @return
 * 0. Success. next enabled feature is valid.
 * 1. Failure. next enabled feature is invalid
 */
static __rte_always_inline int
rte_graph_feature_arc_next_feature_get(struct rte_graph_feature_arc *arc,
				       const rte_graph_feature_rt_list_t list,
				       uint32_t index,
				       rte_graph_feature_t *feature,
				       rte_edge_t *next_edge)
{
	rte_graph_feature_data_t *feature_data = NULL;
	struct rte_graph_feature *f = NULL;

	if (likely(rte_graph_feature_is_valid(*feature))) {
		f = __rte_graph_feature_get(arc, *feature, list);
		feature_data = rte_graph_feature_data_get(arc, f, index);
		*feature = feature_data->next_enabled_feature;
		*next_edge = feature_data->next_edge;
		return (*feature == RTE_GRAPH_FEATURE_INVALID);
	}

	return 1;
}

/**
 * Set fields with respect to first enabled feature in an arc and return edge
 * Typically returned feature and interface index must be saved in rte_mbuf
 * structure to pass this information to next feature node
 *
 * @param arc
 *   Feature arc object
 * @param list
 *   Pointer to runtime active feature list from rte_graph_feature_arc_has_any_feature();
 * @param index
 *  Index (of interface)
 * @param[out] gf
 *  Pointer to rte_graph_feature_t. Valid if API returns Success
 * @param[out] edge
 *  Edge to steer packet from arc->start_node to first enabled feature. Valid
 *  only if API returns Success
 *
 * @return
 * 0: If valid feature is set by API
 * 1: If valid feature is NOT set by API
 */
static __rte_always_inline rte_graph_feature_t
rte_graph_feature_arc_feature_set(struct rte_graph_feature_arc *arc,
				  const rte_graph_feature_rt_list_t list,
				  uint32_t index,
				  rte_graph_feature_t *gf,
				  rte_edge_t *edge)
{
	struct rte_graph_feature_list *feature_list = arc->feature_list[list];
	struct rte_graph_feature_data *feature_data = NULL;
	struct rte_graph_feature *feature = NULL;
	rte_graph_feature_t f;

	/* reset */
	*gf = RTE_GRAPH_FEATURE_INVALID;
	f = feature_list->first_enabled_feature_by_index[index];

	if (unlikely(rte_graph_feature_is_valid(f))) {
		feature = __rte_graph_feature_get(arc, f, list);
		feature_data = rte_graph_feature_data_get(arc, feature, index);
		*gf = f;
		*edge = feature_data->next_edge;
		return 0;
	}

	return 1;
}

/**
 * Get user data corresponding to current feature set by application in
 * rte_graph_feature_enable()
 *
 * @param arc
 *  Feature arc object
 * @param list
 *  Pointer to runtime active feature list from rte_graph_feature_arc_has_any_feature();
 * @param feature
 *  Feature index
 * @param index
 *  Interface index
 *
 *  @return
 *  UINT32_MAX: Failure
 *  Valid user data: Success
 */
static __rte_always_inline uint32_t
rte_graph_feature_user_data_get(struct rte_graph_feature_arc *arc,
				const rte_graph_feature_rt_list_t list,
				rte_graph_feature_t feature,
				uint32_t index)
{
	rte_graph_feature_data_t *fdata = NULL;
	struct rte_graph_feature *f = NULL;

	if (likely(rte_graph_feature_is_valid(feature))) {
		f = __rte_graph_feature_get(arc, feature, list);
		fdata = rte_graph_feature_data_get(arc, f, index);
		return fdata->user_data;
	}

	return UINT32_MAX;
}
#ifdef __cplusplus
}
#endif
#endif
