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
 *  Feature data object:
 *
 *  Feature data stores information to steer packets for:
 *  - a feature with in feature arc
 *  - Index i.e. Port/Interface index
 *
 *  Each feature data object holds
 *  - User data of current feature retrieved via rte_graph_feature_user_data_get()
 *  - next_edge is used in two conditions when packet to be steered from
 *    -- start_node to first enabled feature on an interface index
 *    -- current feature node to next enabled feature on an interface index
 *  - next_enabled_feature on interface index, if current feature is not
 *  consuming packet
 *
 *  While user_data corresponds to current enabled feature node however
 *  next_edge and next_enabled_feature corresponds to next enabled feature
 *  node on an interface index
 *
 *  First enabled feature on interface index can be retrieved via:
 * - rte_graph_feature_first_feature_get() if arc's start_node is trying to
 *   steer packet from start_node to first enabled feature on interface index
 *
 *  Next enabled feature on interface index can be retrieved via:
 * - rte_graph_feature_next_feature_get() if current node is not arc's
 *   start_node. Input to rte_graph_feature_next_feature_get() is current
 *   enabled feature and interface index
 */
typedef struct __rte_packed rte_graph_feature_data {
	/** edge from current node to next enabled feature */
	rte_edge_t next_edge;

	union {
		uint16_t reserved;
		struct {
			/** next enabled feature on index from current feature */
			rte_graph_feature_t next_enabled_feature;
		};
	};

	/** user_data set by application in rte_graph_feature_enable() for
	 * - current feature
	 * - interface index
	 */
	int32_t user_data;
} rte_graph_feature_data_t;

/**
 * Feature object
 *
 * Feature object holds feature data object for every index/interface within
 * feature
 *
 * Within a given arc and interface index, first feature object can be
 * retrieved in arc's start_node via:
 * - rte_graph_feature_arc_first_feature_get()
 *
 * Feature data information can be retrieved for first feature in start node via
 * - rte_graph_feature_arc_feature_set()
 *
 * Next enabled feature on interface index can be retrieved via:
 * - rte_graph_feature_arc_next_feature_get()
 *
 * Typically application stores rte_graph_feature_t object in rte_mbuf.
 * rte_graph_feature_t can be translated to (struct rte_graph_feature *) via
 * rte_graph_feature_get() in fast path. Further if needed, feature data for an
 * index within a feature can be retrieved via rte_graph_feature_data_get()
 */
struct __rte_cache_aligned rte_graph_feature {
	/** feature index or rte_graph_feature_t */
	uint16_t this_feature_index;

	/*
	 * Array of size arc->feature_data_size
	 *
	 * <-----------------  Feature -------------------------->
	 * [data-index-0][data-index-1]...[data-index-max_index-1]
	 *
	 * sizeof(feature_data_by_index[0] == sizeof(rte_graph_feature_data_t)
	 *
	 */
	uint8_t feature_data_by_index[];
};

/**
 * Feature list object
 *
 * Feature list is required to decouple fast path APIs with control path APIs.
 *
 * There are two feature lists: active, passive
 * Passive list is duplicate of active list in terms of memory.
 *
 * While fast path APIs always work on active list but control plane work on
 * passive list. When control plane needs to enable/disable any feature, it
 * populates passive list afresh and atomically switch passive list to active
 * list to make it available for fast path APIs
 *
 * Each feature node in start of its fast path function, must grab active list from
 * arc via
 * - rte_graph_feature_arc_has_any_feature() or
 *   rte_graph_feature_arc_has_feature()
 *
 * Retrieved list must be provided to other feature arc fast path APIs so that
 * any control plane changes of active list should not impact current node
 * execution iteration. Active list change would be reflected to current node
 * in next iteration
 *
 * With active/passive lists and RCU mechanism in graph worker
 * loop, application can update features at runtime without stopping fast path
 * cores.  A RCU synchronization is required when a feature needs to be
 * disabled via rte_graph_feature_disable(). On enabling a feature, RCU
 * synchronization may not be required
 *
 */
typedef struct __rte_cache_aligned rte_graph_feature_list {
	/**
	 * fast path array holding per_feature data.
	 * Duplicate entry as feature-arc also hold this pointer
	 * arc->features[]
	 *
	 *<-------------feature-0 ---------><---------feature-1 -------------->...
	 *[index-0][index-1]...[max_index-1]<-ALIGN->[index-0][index-1] ...[max_index-1]...
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
 * Application gets rte_graph_feature_arc_t object via
 * - rte_graph_feature_arc_create() OR
 * - rte_graph_feature_arc_lookup_by_name()
 *
 * In fast path, rte_graph_feature_arc_t can be translated to (struct
 * rte_graph_feature_arc *) via rte_graph_feature_arc_get(). Later is needed to
 * add as an input argument to all fast path feature arc APIs
 */
struct __rte_cache_aligned rte_graph_feature_arc {
	/* First 64B is fast path variables */
	RTE_MARKER fast_path_variables;

	/** runtime active feature list */
	RTE_ATOMIC(rte_graph_feature_rt_list_t) active_feature_list;

	/** Actual Size of feature_list object */
	uint16_t feature_list_size;

	/**
	 * Size each feature in fastpath.
	 * Required to navigate from feature to another feature in fast path
	 */
	uint16_t feature_size;

	/**
	 * Size of all feature data for an index
	 * Required to navigate through various feature data within a feature
	 * in fast path
	 */
	uint16_t feature_data_size;

	/**
	 * Quick fast path bitmask indicating if any feature enabled or not on
	 * any of the indexes. Helps in optimally process packets for the case
	 * when features are added but not enabled
	 *
	 * Separate for active and passive list
	 */
	RTE_ATOMIC(uint64_t) feature_enable_bitmask[2];

	/**
	 * Pointer to both active and passive feature list object
	 */
	rte_graph_feature_list_t *feature_list[2];

	/**
	 * Feature objects for each list
	 */
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

	/** control plane counter to track enabled features */
	uint32_t runtime_enabled_features;

	/** Back pointer to feature_arc_main */
	void *feature_arc_main;

	/** Arc's start/base node */
	struct rte_node_register *start_node;

	/** maximum number of features supported by this arc */
	uint32_t max_features;

	/** maximum number of index supported by this arc */
	uint32_t max_indexes;

	/** Slow path bit mask per feature per index */
	uint64_t feature_bit_mask_by_index[];
};

/**
 * Feature arc main object
 *
 * Holds all feature arcs created by application
 *
 * RTE_GRAPH_FEATURE_ARC_MAX number of feature arcs can be created by
 * application via rte_graph_feature_arc_create()
 */
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
__rte_experimental
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
 * @return
 *   Internal feature object.
 */
__rte_experimental
static __rte_always_inline struct rte_graph_feature *
__rte_graph_feature_get(struct rte_graph_feature_arc *arc, rte_graph_feature_t feature,
			const rte_graph_feature_rt_list_t feature_list)
{
	return ((struct rte_graph_feature *)(((uint8_t *)arc->features[feature_list]) +
					     (feature * arc->feature_size)));
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
__rte_experimental
static __rte_always_inline struct rte_graph_feature *
rte_graph_feature_get(struct rte_graph_feature_arc *arc, rte_graph_feature_t feature)
{
	rte_graph_feature_rt_list_t list;

	if (unlikely(feature >= arc->max_features))
		RTE_VERIFY(0);

	if (likely(rte_graph_feature_is_valid(feature))) {
		list = rte_atomic_load_explicit(&arc->active_feature_list,
						rte_memory_order_relaxed);
		return __rte_graph_feature_get(arc, feature, list);
	}

	return NULL;
}

__rte_experimental
static __rte_always_inline rte_graph_feature_data_t *
__rte_graph_feature_data_get(struct rte_graph_feature_arc *arc, struct rte_graph_feature *feature,
			     uint8_t index)
{
	RTE_SET_USED(arc);
	return ((rte_graph_feature_data_t *)(((uint8_t *)feature->feature_data_by_index) +
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
__rte_experimental
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
__rte_experimental
static __rte_always_inline uint64_t
rte_graph_feature_arc_has_any_feature(struct rte_graph_feature_arc *arc,
				      rte_graph_feature_rt_list_t *plist)
{
	*plist = rte_atomic_load_explicit(&arc->active_feature_list, rte_memory_order_relaxed);

	return (rte_atomic_load_explicit(arc->feature_enable_bitmask + (uint8_t)*plist,
					 rte_memory_order_relaxed));
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
 * 1: If input [feature] is enabled in arc
 * 0: If input [feature] is not enabled in arc
 */
__rte_experimental
static __rte_always_inline int
rte_graph_feature_arc_has_feature(struct rte_graph_feature_arc *arc,
				  rte_graph_feature_t feature,
				  rte_graph_feature_rt_list_t *plist)
{
	uint64_t bitmask = RTE_BIT64(feature);

	*plist = rte_atomic_load_explicit(&arc->active_feature_list, rte_memory_order_relaxed);

	return (bitmask & rte_atomic_load_explicit(arc->feature_enable_bitmask + (uint8_t)*plist,
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
__rte_experimental
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
 * @param arc
 *   RTE_GRAPH feature arc object
 * @param list
 *  Pointer to runtime active feature list from rte_graph_feature_arc_has_any_feature();
 * @param feature
 *   Pointer to feature object returned from @ref
 *   rte_graph_feature_arc_first_feature_get()
 * @param index
 *   Interface/index
 */
__rte_experimental
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
 * 1. Success. If first feature field is enabled and returned [feature] is valid
 * 0. Failure. If first feature field is disabled in arc
 *
 */
__rte_experimental
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
 * @param[out] feature
 *   Pointer to rte_graph_feature_t. API sets next enabled feature on [index]
 *   from provided input feature. Valid only if API returns Success
 * @param[out] next_edge
 *    Edge from current feature to next feature. Valid only if next feature is valid
 *
 * @return
 * 1. Success. first feature field is enabled/valid
 * 0. Failure. first feature field is disabled/invalid
 */
__rte_experimental
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
		return rte_graph_feature_is_valid(*feature);
	}

	return 0;
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
 * 0: If valid feature is enabled and set by API in *gf
 * 1: If valid feature is NOT enabled
 */
__rte_experimental
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

__rte_experimental
static __rte_always_inline int32_t
__rte_graph_feature_user_data_get(rte_graph_feature_data_t *fdata)
{
	return fdata->user_data;
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
 *  -1: Failure
 *  Valid user data: Success
 */
__rte_experimental
static __rte_always_inline int32_t
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
		return __rte_graph_feature_user_data_get(fdata);
	}

	return -1;
}
#ifdef __cplusplus
}
#endif
#endif
