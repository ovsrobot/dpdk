/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_FEATURE_ARC_WORKER_H_
#define _RTE_GRAPH_FEATURE_ARC_WORKER_H_

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
struct __rte_cache_aligned rte_graph_feature_node_list {
	/** Next feature */
	STAILQ_ENTRY(rte_graph_feature_node_list) next_feature;

	/** node representing feature */
	struct rte_node_register *feature_node;

	/** How many indexes/interfaces using this feature */
	int32_t ref_count;

	/** Back pointer to feature arc */
	void *feature_arc;

	/** rte_edge_t to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;
};

/**
 * RTE_GRAPH feature data representing a fast path feature object on an interface/index
 */
typedef struct rte_graph_feature_data {
	/** Data provided by application during @ref rte_graph_feature_enable on interface */
	int64_t data;

	/** this feature data index */
	uint32_t feature_data_index;

	/** Edge to this feature node from feature_arc->start_node */
	rte_edge_t edge_to_this_feature;

	/**
	 * Edge to next enabled feature on a given interface/index. This field
	 * keeps on changing as @ref rte_graph_feature_enable()/@ref
	 * rte_graph_feature_disable() are called on a given interface/index
	 */
	rte_edge_t edge_to_next_feature;

	/** Slow path node_info object */
	struct rte_graph_feature_node_list *node_info;
} rte_graph_feature_data_t;

/**
 * RTE_GRAPH Feature object
 *
 * Holds all feature related data of a given feature on *all* interfaces
 */
struct __rte_cache_aligned rte_graph_feature {
	/**
	 * Slow path node_info
	 * 1st DWORD
	 */
	struct rte_graph_feature_node_list *node_info;

	/** Feature arc back pointer
	 *  2nd DWORD
	 */
	void *feature_arc;

	/**
	 * Number of enabled features in this feature_arc
	 * 3rd WORD
	 */
	uint32_t num_enabled_features;

	/* uint32_t reserved; */

	/**
	 * Array of feature_data by index/interface
	 *
	 */
	struct rte_graph_feature_data feature_data[RTE_GRAPH_FEATURE_MAX_PER_ARC];
};

/**
 * RTE_GRAPH Feature arc object
 *
 * Representing a feature arc holding all features which are enabled/disabled on any interfaces
 */
struct __rte_cache_aligned rte_graph_feature_arc {
	/** All feature lists */
	STAILQ_HEAD(, rte_graph_feature_node_list) all_features;

	/** feature arc name */
	char feature_arc_name[RTE_GRAPH_FEATURE_ARC_NAMELEN];

	/** this feature group index in feature_arc_main */
	uint32_t feature_arc_index;

	/** Back pointer to feature_arc_main */
	void *feature_arc_main;

	/**
	 * Start_node or Base node where this feature arc is checked for any feature
	 */
	struct rte_node_register *start_node;

	/** Max features supported in this arc */
	uint32_t max_features;

	/** Boolean indicating @ref rte_graph_feature_enable has started and not
	 * further addition is allowed
	 */
	int feature_enable_started;

	/* Fast path stuff*/
	alignas(RTE_CACHE_LINE_SIZE) RTE_MARKER c0;

	/** RTE_GRAPH feature by interface */
	struct rte_graph_feature *features_by_index;

	/** Max interfaces supported */
	uint32_t max_indexes;

	/** Bitmask by interface. Set bit indicates feature is enabled on interface */
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
#define rte_graph_feature_arc_get(dfl) ((struct rte_graph_feature_arc *)dfl)

extern rte_graph_feature_arc_main_t *__feature_arc_main;

/**
 * Get rte_graph feature data object for a index in feature
 *
 * @param df
 *   Feature pointer
 * @param feature_index
 *  Index of feature maintained in slow path linked list
 *
 * @return
 *   Valid feature data
 */
static inline struct rte_graph_feature_data *
rte_graph_feature_data_get(struct rte_graph_feature *df, uint32_t feature_index)
{
	return (df->feature_data + feature_index);
}

/**
 * Get rte_graph_feature object for a given interface/index from feature arc
 *
 * @param dfl
 *   Feature arc pointer
 * @param index
 *   Interface index
 *
 * @return
 *   Valid feature pointer
 */
static inline struct rte_graph_feature *
rte_graph_feature_get(struct rte_graph_feature_arc *dfl, uint32_t index)
{
	return (dfl->features_by_index + index);
}

/**
 * Fast path API to check if first feature enabled on a feature arc
 *
 * Must be called in feature_arc->start_node processing
 *
 * @param dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to rte_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If feature is enabled
 * 0: If feature is not enabled
 *
 */
static inline int
rte_graph_feature_arc_has_first_feature(struct rte_graph_feature_arc *dfl,
					uint32_t index, rte_graph_feature_t *feature)
{
	return rte_bsf64_safe(dfl->feature_bit_mask_by_index[index], feature);
}

/**
 * Fast path API to get next feature when current node is already on an feature
 * arc and not consuming packet. This feature must forward the packet to next
 * enabled feature by passing returned rte_graph_feature_t to
 * rte_graph_feature_arc_next_feature_data_get()
 *
 * @param dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to rte_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If next feature is enabled
 * 0: If next feature is not enabled
 */
static inline int
rte_graph_feature_arc_has_next_feature(struct rte_graph_feature_arc *dfl,
				       uint32_t index, rte_graph_feature_t *feature)
{
	uint32_t next_feature;
	uint64_t bitmask;

#ifdef RTE_GRAPH_FEATURE_ARC_DEBUG
	struct rte_graph_feature *df = rte_graph_feature_get(dfl, index);
	struct rte_graph_feature_data *dfd = NULL;

	dfd = rte_graph_feature_data_get(df, *feature);
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != *feature))
		return 0;
#endif

	/* Create bitmask where current feature is cleared to get next feature
	 * bit set
	 */
	next_feature = (uint32_t)*feature;
	bitmask = UINT64_MAX << (next_feature + 1);
	bitmask = dfl->feature_bit_mask_by_index[index] & bitmask;

	return rte_bsf64_safe(bitmask, feature);
}

/**
 * Fast path API to check if any feature enabled on a feature arc
 *
 * @param _dfl
 *   Feature arc object
 * @param index
 *   Interface/Index
 * @param[out] feature
 *   Pointer to rte_graph_feature_t. Valid if API returns 1
 *
 * @return
 * 1: If feature is enabled
 * 0: If feature is not enabled
 *
 */
static inline int
rte_graph_feature_arc_has_feature(rte_graph_feature_arc_t _dfl, uint32_t index,
				  rte_graph_feature_t *feature)
{
	struct rte_graph_feature_arc *dfl = rte_graph_feature_arc_get(_dfl);

#ifdef RTE_GRAPH_FEATURE_ARC_DEBUG
	if (unlikely(dfl->max_indexes < index))
		return 0;

	if (unlikely(!feature))
		return 0;
#endif
	/* Look for first feature */
	if (*feature == RTE_GRAPH_FEATURE_INVALID_VALUE)
		return rte_graph_feature_arc_has_first_feature(dfl, index, feature);
	else
		return rte_graph_feature_arc_has_next_feature(dfl, index, feature);
}


/**
 * Prefetch feature data upfront
 *
 * @param _dfl
 *   RTE_GRAPH feature arc object
 * @param index
 *   Interface/index
 * @param feature
 *   Pointer to feature object returned from @ref
 *   rte_graph_feature_arc_has_feature() or @ref
 *   rte_graph_feature_arc_first_feature_data_get()
 */
static inline void
__rte_graph_prefetch_data_prefetch(rte_graph_feature_arc_t _dfl, int index,
				   rte_graph_feature_t feature)
{
	struct rte_graph_feature_arc *dfl = rte_graph_feature_arc_get(_dfl);
	struct rte_graph_feature *df = rte_graph_feature_get(dfl, index);

	rte_prefetch0((void *)rte_graph_feature_data_get(df, feature));
}

/**
 * Prefetch feature data upfront. Perform sanity
 *
 * @param _dfl
 *   RTE_GRAPH feature arc object
 * @param index
 *   Interface/index
 * @param feature
 *   Pointer to feature object returned from @ref
 *   rte_graph_feature_arc_has_feature() or @ref
 *   rte_graph_feature_arc_first_feature_data_get()
 */
static inline void
rte_graph_feature_data_prefetch(rte_graph_feature_arc_t _dfl, uint32_t index,
				rte_graph_feature_t feature)
{
#ifdef RTE_GRAPH_FEATURE_ARC_DEBUG
	struct rte_graph_feature_arc *dfl = rte_graph_feature_arc_get(_dfl);

	if (unlikely(index >= dfl->max_indexes))
		return;

	if (unlikely(feature >= rte_graph_feature_cast(dfl->max_features)))
		return;
#endif

	if (feature != RTE_GRAPH_FEATURE_INVALID_VALUE)
		__rte_graph_prefetch_data_prefetch(_dfl, index, feature);
}

/**
 * Fast path API to get first feature data aka {edge, int32_t data}
 *
 * Must be called in feature_arc->start_node processing
 *
 * @param _dfl
 *   Feature arc object
 * @param feature
 *  returned from rte_graph_feature_arc_has_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via rte_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */
static inline int
rte_graph_feature_arc_first_feature_data_get(struct rte_graph_feature_arc *dfl,
					     rte_graph_feature_t feature,
					     uint32_t index, rte_edge_t *edge,
					     int64_t *data)
{
	struct rte_graph_feature *df = rte_graph_feature_get(dfl, index);
	struct rte_graph_feature_data *dfd = NULL;

	dfd = rte_graph_feature_data_get(df, feature);

#ifdef RTE_GRAPH_FEATURE_ARC_DEBUG
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != feature))
		return -1;

	if (unlikely(!edge && !data))
		return -1;
#endif

	*edge = dfd->edge_to_this_feature;
	*data = dfd->data;

	return 0;
}

/**
 * Fast path API to get next feature data aka {edge, int32_t data}
 *
 * Must NOT be called in feature_arc->start_node processing instead must be
 * called in intermediate feature nodes on a featur-arc.
 *
 * @param _dfl
 *   Feature arc object
 * @param feature
 *  returned from rte_graph_feature_arc_has_next_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via rte_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */
static inline int
rte_graph_feature_arc_next_feature_data_get(struct rte_graph_feature_arc *dfl,
					    rte_graph_feature_t feature,
					    uint32_t index, rte_edge_t *edge,
					    int64_t *data)
{
	struct rte_graph_feature *df = rte_graph_feature_get(dfl, index);
	struct rte_graph_feature_data *dfd = NULL;

	dfd = rte_graph_feature_data_get(df, feature);

#ifdef RTE_GRAPH_FEATURE_ARC_DEBUG
	/** Check feature sanity */
	if (unlikely(dfd->feature_data_index != feature))
		return -1;

	if (unlikely(!edge && !data))
		return -1;
#endif

	*edge = dfd->edge_to_next_feature;
	*data = dfd->data;

	return 0;
}

/**
 * Fast path API to get next feature data aka {edge, int32_t data}
 *
 * @param _dfl
 *   Feature arc object
 * @param feature
 *  returned from rte_graph_feature_arc_has_feature()
 * @param index
 *   Interface/Index
 * @param[out] edge
 *   Pointer to rte_node edge. Valid if API returns Success
 * @param[out] data
 *   Pointer to int64_t data set via rte_graph_feature_enable(). Valid if API returns
 *   Success
 *
 * @return
 *  0: Success
 * <0: Failure
 */

static inline int
rte_graph_feature_arc_feature_data_get(rte_graph_feature_arc_t _dfl,
				       rte_graph_feature_t feature, uint32_t
				       index, rte_edge_t *edge, int64_t *data)
{
	struct rte_graph_feature_arc *dfl = rte_graph_feature_arc_get(_dfl);

	if (feature == RTE_GRAPH_FEATURE_INVALID_VALUE)
		return rte_graph_feature_arc_first_feature_data_get(dfl, feature, index, edge,
								    data);
	else
		return rte_graph_feature_arc_next_feature_data_get(dfl, feature, index, edge, data);
}

#ifdef __cplusplus
}
#endif
#endif
