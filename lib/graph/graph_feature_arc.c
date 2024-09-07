/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#include "graph_private.h"
#include <rte_graph_feature_arc_worker.h>
#include <rte_malloc.h>

#define __RTE_GRAPH_FEATURE_ARC_MAX 32

#define ARC_PASSIVE_LIST(arc) (arc->active_feature_list ^ 0x1)

#define rte_graph_uint_cast(x) ((unsigned int)x)
#define feat_dbg graph_err

rte_graph_feature_arc_main_t *__feature_arc_main;

/* Make sure fast path cache line is compact */
_Static_assert((offsetof(struct rte_graph_feature_arc, slow_path_variables)
		- offsetof(struct rte_graph_feature_arc, fast_path_variables))
	       <= RTE_CACHE_LINE_SIZE);


static int
feature_lookup(struct rte_graph_feature_arc *arc, const char *feat_name,
	       struct rte_graph_feature_node_list **ffinfo, uint32_t *slot)
{
	struct rte_graph_feature_node_list *finfo = NULL;
	const char *name;

	if (!feat_name)
		return -1;

	if (slot)
		*slot = 0;

	STAILQ_FOREACH(finfo, &arc->all_features, next_feature) {
		RTE_VERIFY(finfo->feature_arc == arc);
		name = rte_node_id_to_name(finfo->feature_node->id);
		if (!strncmp(name, feat_name, RTE_GRAPH_NAMESIZE)) {
			if (ffinfo)
				*ffinfo = finfo;
			return 0;
		}
		if (slot)
			(*slot)++;
	}
	return -1;
}

static int
feature_arc_node_info_lookup(struct rte_graph_feature_arc *arc, uint32_t feature_index,
			     struct rte_graph_feature_node_list **ppfinfo)
{
	struct rte_graph_feature_node_list *finfo = NULL;
	uint32_t index = 0;

	if (!ppfinfo)
		return -1;

	*ppfinfo = NULL;
	STAILQ_FOREACH(finfo, &arc->all_features, next_feature) {
		if (index == feature_index) {
			if (finfo->node_index == feature_index)
				return -1;
			*ppfinfo = finfo;
		}
		index++;
	}
	if (feature_index && (index >= feature_index))
		return -1;

	return 0;
}

static void
prepare_feature_arc(struct rte_graph_feature_arc *arc)
{
	struct rte_graph_feature_node_list *finfo = NULL;
	uint32_t index = 0;

	STAILQ_FOREACH(finfo, &arc->all_features, next_feature) {
		finfo->node_index = index;
		index++;
	}
}

static int
feature_arc_lookup(rte_graph_feature_arc_t _arc)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	rte_graph_feature_arc_main_t *dm = __feature_arc_main;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == RTE_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		if (arc == (rte_graph_feature_arc_get(dm->feature_arcs[iter])))
			return 0;
	}
	return -1;
}

static int
get_existing_edge(const char *arc_name, struct rte_node_register *parent_node,
		  struct rte_node_register *child_node, rte_edge_t *_edge)
{
	char **next_edges = NULL;
	uint32_t count, i;

	RTE_SET_USED(arc_name);

	count = rte_node_edge_get(parent_node->id, NULL);
	next_edges = malloc(count);

	if (!next_edges)
		return -1;

	count = rte_node_edge_get(parent_node->id, next_edges);
	for (i = 0; i < count; i++) {
		if (strstr(child_node->name, next_edges[i])) {
			feat_dbg("%s: Edge exists [%s[%u]: \"%s\"]", arc_name,
				  parent_node->name, i, child_node->name);
			if (_edge)
				*_edge = (rte_edge_t)i;

			free(next_edges);
			return 0;
		}
	}
	free(next_edges);

	return -1;
}

static int
connect_graph_nodes(struct rte_node_register *parent_node, struct rte_node_register *child_node,
		    rte_edge_t *_edge, char *arc_name)
{
	const char *next_node = NULL;
	rte_edge_t edge;

	if (!get_existing_edge(arc_name, parent_node, child_node, &edge)) {
		feat_dbg("%s: add_feature: Edge reused [%s[%u]: \"%s\"]", arc_name,
			parent_node->name, edge, child_node->name);

		if (_edge)
			*_edge = edge;

		return 0;
	}

	/* Node to be added */
	next_node = child_node->name;

	edge = rte_node_edge_update(parent_node->id, RTE_EDGE_ID_INVALID, &next_node, 1);

	if (edge == RTE_EDGE_ID_INVALID) {
		graph_err("edge invalid");
		return -1;
	}
	edge = rte_node_edge_count(parent_node->id) - 1;

	feat_dbg("%s: add_feature: edge added [%s[%u]: \"%s\"]", arc_name, parent_node->name, edge,
		child_node->name);

	if (_edge)
		*_edge = edge;

	return 0;
}

static int
feature_arc_init(rte_graph_feature_arc_main_t **pfl, uint32_t max_feature_arcs)
{
	rte_graph_feature_arc_main_t *pm = NULL;
	uint32_t i;
	size_t sz;

	if (!pfl)
		return -1;

	sz = sizeof(rte_graph_feature_arc_main_t) +
		(sizeof(pm->feature_arcs[0]) * max_feature_arcs);

	pm = malloc(sz);
	if (!pm)
		return -1;

	memset(pm, 0, sz);

	for (i = 0; i < max_feature_arcs; i++)
		pm->feature_arcs[i] = RTE_GRAPH_FEATURE_ARC_INITIALIZER;

	pm->max_feature_arcs = max_feature_arcs;

	*pfl = pm;

	return 0;
}

int
rte_graph_feature_arc_init(int max_feature_arcs)
{
	if (!max_feature_arcs)
		return -1;

	if (__feature_arc_main)
		return -1;

	return feature_arc_init(&__feature_arc_main, max_feature_arcs);
}

static void
feature_arc_list_reset(struct rte_graph_feature_arc *arc, uint32_t list_index)
{
	rte_graph_feature_data_t *fdata = NULL;
	rte_graph_feature_list_t *list = NULL;
	struct rte_graph_feature *feat = NULL;
	uint32_t i, j;

	list = arc->feature_list[list_index];
	feat = arc->features[list_index];

	/*Initialize variables*/
	memset(feat, 0, arc->feature_size);
	memset(list, 0, arc->feature_list_size);

	/* Initialize feature and feature_data */
	for (i = 0; i < arc->max_features; i++) {
		feat = __rte_graph_feature_get(arc, i, list_index);
		feat->this_feature_index = i;

		for (j = 0; j < arc->max_indexes; j++) {
			fdata = rte_graph_feature_data_get(arc, feat, j);
			fdata->next_enabled_feature = RTE_GRAPH_FEATURE_INVALID;
			fdata->next_edge = UINT16_MAX;
			fdata->user_data = UINT32_MAX;
		}
	}

	for (i = 0; i < arc->max_indexes; i++)
		list->first_enabled_feature_by_index[i] = RTE_GRAPH_FEATURE_INVALID;
}

static int
feature_arc_list_init(struct rte_graph_feature_arc *arc, const char *flist_name,
			  rte_graph_feature_list_t **pplist,
			  struct rte_graph_feature **ppfeature, uint32_t list_index)
{
	char fname[2 * RTE_GRAPH_FEATURE_ARC_NAMELEN];
	size_t list_size, feat_size, fdata_size;
	rte_graph_feature_list_t *list = NULL;
	struct rte_graph_feature *feat = NULL;

	list_size = sizeof(list->first_enabled_feature_by_index[0]) * arc->max_indexes;

	list = rte_malloc(flist_name, list_size, RTE_CACHE_LINE_SIZE);
	if (!list)
		return -ENOMEM;

	fdata_size = arc->max_indexes * sizeof(rte_graph_feature_data_t);

	/* Let one feature capture complete cache lines */
	feat_size = RTE_ALIGN_CEIL(sizeof(struct rte_graph_feature) + fdata_size,
				   RTE_CACHE_LINE_SIZE);

	snprintf(fname, sizeof(fname), "%s-%s", arc->feature_arc_name, "feat");

	feat = rte_malloc(fname, feat_size * arc->max_features, RTE_CACHE_LINE_SIZE);
	if (!feat) {
		rte_free(list);
		return -ENOMEM;
	}
	arc->feature_size = feat_size;
	arc->feature_data_size = fdata_size;
	arc->feature_list_size = list_size;

	/* Initialize list */
	list->indexed_by_features = feat;
	*pplist = list;
	*ppfeature = feat;

	feature_arc_list_reset(arc, list_index);

	return 0;
}

static void
feature_arc_list_destroy(rte_graph_feature_list_t *list)
{
	rte_free(list->indexed_by_features);
	rte_free(list);
}

int
rte_graph_feature_arc_create(const char *feature_arc_name, int max_features, int max_indexes,
		       struct rte_node_register *start_node, rte_graph_feature_arc_t *_arc)
{
	char name[2 * RTE_GRAPH_FEATURE_ARC_NAMELEN];
	rte_graph_feature_arc_main_t *dfm = NULL;
	struct rte_graph_feature_arc *arc = NULL;
	struct rte_graph_feature_data *gfd = NULL;
	struct rte_graph_feature *df = NULL;
	uint32_t iter, j, arc_index;
	size_t sz;

	if (!_arc)
		return -1;

	if (max_features < 2)
		return -1;

	if (!start_node)
		return -1;

	if (!feature_arc_name)
		return -1;

	if (max_features > RTE_GRAPH_FEATURE_MAX_PER_ARC) {
		graph_err("Invalid max features: %u", max_features);
		return -1;
	}

	/*
	 * Application hasn't called rte_graph_feature_arc_init(). Initialize with
	 * default values
	 */
	if (!__feature_arc_main) {
		if (rte_graph_feature_arc_init((int)__RTE_GRAPH_FEATURE_ARC_MAX) < 0) {
			graph_err("rte_graph_feature_arc_init() failed");
			return -1;
		}
	}

	dfm = __feature_arc_main;

	/* threshold check */
	if (dfm->num_feature_arcs > (dfm->max_feature_arcs - 1)) {
		graph_err("max threshold for num_feature_arcs: %d reached",
			  dfm->max_feature_arcs - 1);
		return -1;
	}
	/* Find the free slot for feature arc */
	for (iter = 0; iter < dfm->max_feature_arcs; iter++) {
		if (dfm->feature_arcs[iter] == RTE_GRAPH_FEATURE_ARC_INITIALIZER)
			break;
	}
	arc_index = iter;

	if (arc_index >= dfm->max_feature_arcs) {
		graph_err("No free slot found for num_feature_arc");
		return -1;
	}

	/* This should not happen */
	RTE_VERIFY(dfm->feature_arcs[arc_index] == RTE_GRAPH_FEATURE_ARC_INITIALIZER);

	/* size of feature arc + feature_bit_mask_by_index */
	sz = sizeof(*arc) + (sizeof(uint64_t) * max_indexes);

	arc = rte_malloc(feature_arc_name, sz, RTE_CACHE_LINE_SIZE);

	if (!arc) {
		graph_err("malloc failed for feature_arc_create()");
		return -1;
	}

	memset(arc, 0, sz);

	/* Initialize rte_graph port group fixed variables */
	STAILQ_INIT(&arc->all_features);
	strncpy(arc->feature_arc_name, feature_arc_name, RTE_GRAPH_FEATURE_ARC_NAMELEN - 1);
	arc->feature_arc_main = (void *)dfm;
	arc->start_node = start_node;
	arc->max_features = max_features;
	arc->max_indexes = max_indexes;

	snprintf(name, sizeof(name), "%s-%s", feature_arc_name, "flist0");

	if (feature_arc_list_init(arc, name, &arc->feature_list[0], &arc->features[0], 0) < 0) {
		rte_free(arc);
		graph_err("feature_arc_list_init(0) failed");
		return -1;
	}
	snprintf(name, sizeof(name), "%s-%s", feature_arc_name, "flist1");

	if (feature_arc_list_init(arc, name, &arc->feature_list[1], &arc->features[1], 1) < 0) {
		feature_arc_list_destroy(arc->feature_list[0]);
		graph_err("feature_arc_list_init(1) failed");
		return -1;
	}

	for (iter = 0; iter < arc->max_features; iter++) {
		df = rte_graph_feature_get(arc, iter);
		for (j = 0; j < arc->max_indexes; j++) {
			gfd = rte_graph_feature_data_get(arc, df, j);
			gfd->next_enabled_feature = RTE_GRAPH_FEATURE_INVALID;
		}
	}
	arc->feature_arc_index = arc_index;
	dfm->feature_arcs[arc->feature_arc_index] = (rte_graph_feature_arc_t)arc;
	dfm->num_feature_arcs++;

	if (_arc)
		*_arc = (rte_graph_feature_arc_t)arc;

	return 0;
}

int
rte_graph_feature_add(rte_graph_feature_arc_t _arc, struct rte_node_register *feature_node,
		const char *after_feature, const char *before_feature)
{
	struct rte_graph_feature_node_list *after_finfo = NULL, *before_finfo = NULL;
	struct rte_graph_feature_node_list *temp = NULL, *finfo = NULL;
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	uint32_t slot, add_flag;
	rte_edge_t edge = -1;

	RTE_VERIFY(arc->feature_arc_main == __feature_arc_main);

	if (feature_arc_lookup(_arc)) {
		graph_err("invalid feature arc: 0x%016" PRIx64, (uint64_t)_arc);
		return -1;
	}

	if (arc->runtime_enabled_features) {
		graph_err("adding features after enabling any one of them is not supported");
		return -1;
	}

	if ((after_feature != NULL) && (before_feature != NULL) &&
	    (after_feature == before_feature)) {
		graph_err("after_feature and before_feature are same '%s:%s]", after_feature,
			before_feature);
		return -1;
	}

	if (!feature_node) {
		graph_err("feature_node: %p invalid", feature_node);
		return -1;
	}

	arc = rte_graph_feature_arc_get(_arc);

	if (feature_node->id == RTE_NODE_ID_INVALID) {
		graph_err("Invalid node: %s", feature_node->name);
		return -1;
	}

	if (!feature_lookup(arc, feature_node->name, &finfo, &slot)) {
		graph_err("%s feature already added", feature_node->name);
		return -1;
	}

	if (slot >= RTE_GRAPH_FEATURE_MAX_PER_ARC) {
		graph_err("Max slot %u reached for feature addition", slot);
		return -1;
	}

	if (strstr(feature_node->name, arc->start_node->name)) {
		graph_err("Feature %s cannot point to itself: %s", feature_node->name,
			arc->start_node->name);
		return -1;
	}

	if (connect_graph_nodes(arc->start_node, feature_node, &edge, arc->feature_arc_name)) {
		graph_err("unable to connect %s -> %s", arc->start_node->name, feature_node->name);
		return -1;
	}

	finfo = malloc(sizeof(*finfo));
	if (!finfo)
		return -1;

	memset(finfo, 0, sizeof(*finfo));

	finfo->feature_arc = (void *)arc;
	finfo->feature_node = feature_node;
	finfo->edge_to_this_feature = edge;

	/* Check for before and after constraints */
	if (before_feature) {
		/* before_feature sanity */
		if (feature_lookup(arc, before_feature, &before_finfo, NULL))
			SET_ERR_JMP(EINVAL, finfo_free,
				     "Invalid before feature name: %s", before_feature);

		if (!before_finfo)
			SET_ERR_JMP(EINVAL, finfo_free,
				     "before_feature %s does not exist", before_feature);

		/*
		 * Starting from 0 to before_feature, continue connecting edges
		 */
		add_flag = 1;
		STAILQ_FOREACH(temp, &arc->all_features, next_feature) {
			/*
			 * As soon as we see before_feature. stop adding edges
			 */
			if (!strncmp(temp->feature_node->name, before_feature,
				     RTE_GRAPH_NAMESIZE))
				if (!connect_graph_nodes(finfo->feature_node, temp->feature_node,
							 &edge, arc->feature_arc_name))
					add_flag = 0;

			if (add_flag)
				connect_graph_nodes(temp->feature_node, finfo->feature_node, NULL,
						    arc->feature_arc_name);
		}
	}

	if (after_feature) {
		if (feature_lookup(arc, after_feature, &after_finfo, NULL))
			SET_ERR_JMP(EINVAL, finfo_free,
				     "Invalid after feature_name %s", after_feature);

		if (!after_finfo)
			SET_ERR_JMP(EINVAL, finfo_free,
				     "after_feature %s does not exist", after_feature);

		/* Starting from after_feature to end continue connecting edges */
		add_flag = 0;
		STAILQ_FOREACH(temp, &arc->all_features, next_feature) {
			/* We have already seen after_feature now */
			if (add_flag)
				/* Add all features as next node to current feature*/
				connect_graph_nodes(finfo->feature_node, temp->feature_node, NULL,
						    arc->feature_arc_name);

			/* as soon as we see after_feature. start adding edges
			 * from next iteration
			 */
			if (!strncmp(temp->feature_node->name, after_feature, RTE_GRAPH_NAMESIZE))
				/* connect after_feature to this feature */
				if (!connect_graph_nodes(temp->feature_node, finfo->feature_node,
							 &edge, arc->feature_arc_name))
					add_flag = 1;
		}

		/* add feature next to after_feature */
		STAILQ_INSERT_AFTER(&arc->all_features, after_finfo, finfo, next_feature);
	} else {
		if (before_finfo) {
			after_finfo = NULL;
			STAILQ_FOREACH(temp, &arc->all_features, next_feature) {
				if (before_finfo == temp) {
					if (after_finfo)
						STAILQ_INSERT_AFTER(&arc->all_features, after_finfo,
								    finfo, next_feature);
					else
						STAILQ_INSERT_HEAD(&arc->all_features, finfo,
								   next_feature);

					return 0;
				}
				after_finfo = temp;
			}
		} else {
			STAILQ_INSERT_TAIL(&arc->all_features, finfo, next_feature);
		}
	}

	return 0;

finfo_free:
	free(finfo);

	return -1;
}

int
rte_graph_feature_lookup(rte_graph_feature_arc_t _arc, const char *feature_name,
			 rte_graph_feature_t *feat)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	struct rte_graph_feature_node_list *finfo = NULL;
	uint32_t slot;

	if (!feature_lookup(arc, feature_name, &finfo, &slot)) {
		*feat = (rte_graph_feature_t) slot;
		return 0;
	}

	return -1;
}

int
rte_graph_feature_validate(rte_graph_feature_arc_t _arc, uint32_t index, const char *feature_name,
			   int is_enable_disable)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	struct rte_graph_feature_node_list *finfo = NULL;
	struct rte_graph_feature *gf = NULL;
	uint32_t slot;

	/* validate _arc */
	if (arc->feature_arc_main != __feature_arc_main) {
		graph_err("invalid feature arc: 0x%016" PRIx64, (uint64_t)_arc);
		return -EINVAL;
	}

	/* validate index */
	if (index >= arc->max_indexes) {
		graph_err("%s: Invalid provided index: %u >= %u configured", arc->feature_arc_name,
			index, arc->max_indexes);
		return -1;
	}

	/* validate feature_name is already added or not  */
	if (feature_lookup(arc, feature_name, &finfo, &slot)) {
		graph_err("%s: No feature %s added", arc->feature_arc_name, feature_name);
		return -EINVAL;
	}

	if (!finfo) {
		graph_err("%s: No feature: %s found", arc->feature_arc_name, feature_name);
		return -EINVAL;
	}

	/* slot should be in valid range */
	if (slot >= arc->max_features) {
		graph_err("%s/%s: Invalid free slot %u(max=%u) for feature", arc->feature_arc_name,
			feature_name, slot, arc->max_features);
		return -EINVAL;
	}

	/* slot should be in range of 0 - 63 */
	if (slot > (RTE_GRAPH_FEATURE_MAX_PER_ARC - 1)) {
		graph_err("%s/%s: Invalid slot: %u", arc->feature_arc_name,
			  feature_name, slot);
		return -EINVAL;
	}

	if (finfo->node_index != slot) {
		graph_err("%s/%s: feature lookup slot mismatch with finfo index: %u and lookup slot: %u",
			  arc->feature_arc_name, feature_name, finfo->node_index, slot);
		return -1;
	}

	/* Get feature from active list */
	gf = __rte_graph_feature_get(arc, slot, ARC_PASSIVE_LIST(arc));
	if (gf->this_feature_index != slot) {
		graph_err("%s: %s received feature_index: %u does not match with saved feature_index: %u",
			  arc->feature_arc_name, feature_name, slot, gf->this_feature_index);
		return -1;
	}

	if (is_enable_disable && (arc->feature_bit_mask_by_index[index] &
				  RTE_BIT64(slot))) {
		graph_err("%s: %s already enabled on index: %u",
			  arc->feature_arc_name, feature_name, index);
		return -1;
	}

	if (!is_enable_disable && !arc->runtime_enabled_features) {
		graph_err("%s: No feature enabled to disable", arc->feature_arc_name);
		return -1;
	}

	if (!is_enable_disable && !(arc->feature_bit_mask_by_index[index] & RTE_BIT64(slot))) {
		graph_err("%s: %s not enabled in bitmask for index: %u",
			  arc->feature_arc_name, feature_name, index);
		return -1;
	}

	return 0;
}

static void
copy_fastpath_user_data(struct rte_graph_feature_arc *arc, uint16_t dest_list_index,
			uint16_t src_list_index)
{
	rte_graph_feature_data_t *sgfd = NULL, *dgfd = NULL;
	struct rte_graph_feature *sgf = NULL, *dgf = NULL;
	uint32_t i, j;

	for (i = 0; i < arc->max_features; i++) {
		sgf = __rte_graph_feature_get(arc, i, src_list_index);
		dgf = __rte_graph_feature_get(arc, i, dest_list_index);
		for (j = 0; j < arc->max_indexes; j++) {
			sgfd = rte_graph_feature_data_get(arc, sgf, j);
			dgfd = rte_graph_feature_data_get(arc, dgf, j);
			dgfd->user_data = sgfd->user_data;
		}
	}
}

static void
refill_feature_fastpath_data(struct rte_graph_feature_arc *arc, uint16_t list_index)
{
	struct rte_graph_feature_node_list *finfo = NULL, *prev_finfo = NULL;
	struct rte_graph_feature_data *gfd = NULL, *prev_gfd = NULL;
	struct rte_graph_feature *gf = NULL, *prev_gf = NULL;
	rte_graph_feature_list_t *flist = NULL;
	uint32_t fi, di, prev_fi;
	uint64_t bitmask;
	rte_edge_t edge;

	flist = arc->feature_list[list_index];

	for (di = 0; di < arc->max_indexes; di++) {
		bitmask = arc->feature_bit_mask_by_index[di];
		prev_fi = RTE_GRAPH_FEATURE_INVALID;
		/* for each feature set for index, set fast path data */
		while (rte_bsf64_safe(bitmask, &fi)) {
			gf = __rte_graph_feature_get(arc, fi, list_index);
			gfd = rte_graph_feature_data_get(arc, gf, di);
			feature_arc_node_info_lookup(arc, fi, &finfo);

			/* If previous feature_index was valid in last loop */
			if (prev_fi != RTE_GRAPH_FEATURE_INVALID) {
				prev_gf = __rte_graph_feature_get(arc, prev_fi, list_index);
				prev_gfd = rte_graph_feature_data_get(arc, prev_gf, di);
				/*
				 * Get edge of previous feature node connecting to this feature node
				 */
				feature_arc_node_info_lookup(arc, prev_fi, &prev_finfo);
				if (!get_existing_edge(arc->feature_arc_name,
						      prev_finfo->feature_node,
						      finfo->feature_node, &edge)) {
					feat_dbg("[%s/%s(%2u)/idx:%2u]: %s[%u] = %s",
						 arc->feature_arc_name,
						 prev_finfo->feature_node->name, prev_fi, di,
						 prev_finfo->feature_node->name,
						 edge, finfo->feature_node->name);
					/* Copy feature index for next iteration*/
					gfd->next_edge = edge;
					prev_fi = fi;
					/*
					 * Fill current feature as next enabled
					 * feature to previous one
					 */
					prev_gfd->next_enabled_feature = fi;
				} else {
					/* Should not fail */
					RTE_VERIFY(0);
				}
			}
			/* On first feature edge of the node to be added */
			if (fi == rte_bsf64(arc->feature_bit_mask_by_index[di])) {
				if (!get_existing_edge(arc->feature_arc_name, arc->start_node,
						      finfo->feature_node,
						      &edge)) {
					feat_dbg("[%s/%s/%2u/idx:%2u]: 1st feat %s[%u] = %s",
						 arc->feature_arc_name,
						 arc->start_node->name, fi, di,
						 arc->start_node->name, edge,
						 finfo->feature_node->name);
					/* Copy feature index for next iteration*/
					gfd->next_edge = edge;
					prev_fi = fi;
					/* Set first feature set array for index*/
					flist->first_enabled_feature_by_index[di] = fi;
				} else {
					/* Should not fail */
					RTE_VERIFY(0);
				}
			}
			/* Clear current feature index */
			bitmask &= ~RTE_BIT64(fi);
		}
	}
}

int
rte_graph_feature_enable(rte_graph_feature_arc_t _arc, uint32_t index, const
			 char *feature_name, int32_t user_data)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	struct rte_graph_feature_node_list *finfo = NULL;
	struct rte_graph_feature_data *gfd = NULL;
	rte_graph_feature_rt_list_t passive_list;
	struct rte_graph_feature *gf = NULL;
	uint64_t fp_bitmask;
	uint32_t slot;

	if (rte_graph_feature_validate(_arc, index, feature_name, 1))
		return -1;

	/** This should not fail as validate() has passed */
	if (feature_lookup(arc, feature_name, &finfo, &slot))
		RTE_VERIFY(0);

	if (!arc->runtime_enabled_features)
		prepare_feature_arc(arc);

	passive_list = ARC_PASSIVE_LIST(arc);

	gf = __rte_graph_feature_get(arc, slot, passive_list);
	gfd = rte_graph_feature_data_get(arc, gf, index);

	feat_dbg("%s/%s: Enabling feature on list: %u for index: %u at feature slot %u",
		 arc->feature_arc_name, feature_name, passive_list, index, slot);

	/* Reset feature list */
	feature_arc_list_reset(arc, passive_list);

	/* Copy user-data */
	copy_fastpath_user_data(arc, passive_list, arc->active_feature_list);

	/* Set current user-data */
	gfd->user_data = user_data;

	/* Set bitmask in control path bitmask */
	rte_bit_relaxed_set64(rte_graph_uint_cast(slot), &arc->feature_bit_mask_by_index[index]);
	refill_feature_fastpath_data(arc, passive_list);

	/* Set fast path enable bitmask */
	fp_bitmask = __atomic_load_n(&arc->feature_enable_bitmask[passive_list], __ATOMIC_RELAXED);
	fp_bitmask |= RTE_BIT64(slot);
	__atomic_store(&arc->feature_enable_bitmask[passive_list], &fp_bitmask, __ATOMIC_RELAXED);

	/* Slow path updates */
	arc->runtime_enabled_features++;

	/* Increase feature node info reference count */
	finfo->ref_count++;

	/* Store release semantics for active_list update */
	__atomic_store(&arc->active_feature_list, &passive_list, __ATOMIC_RELEASE);

	return 0;
}

int
rte_graph_feature_disable(rte_graph_feature_arc_t _arc, uint32_t index, const char *feature_name)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	struct rte_graph_feature_data *gfd = NULL;
	struct rte_graph_feature_node_list *finfo = NULL;
	rte_graph_feature_rt_list_t passive_list;
	struct rte_graph_feature *gf = NULL;
	uint32_t slot;

	if (rte_graph_feature_validate(_arc, index, feature_name, 0))
		return -1;

	if (feature_lookup(arc, feature_name, &finfo, &slot))
		return -1;

	passive_list = ARC_PASSIVE_LIST(arc);

	gf = __rte_graph_feature_get(arc, slot, passive_list);
	gfd = rte_graph_feature_data_get(arc, gf, index);

	feat_dbg("%s/%s: Disabling feature for index: %u at feature slot %u", arc->feature_arc_name,
		feature_name, index, slot);

	rte_bit_relaxed_clear64(rte_graph_uint_cast(slot), &arc->feature_bit_mask_by_index[index]);

	/* Set fast path enable bitmask */
	arc->feature_enable_bitmask[passive_list] &= ~(RTE_BIT64(slot));

	/* Reset feature list */
	feature_arc_list_reset(arc, passive_list);

	/* Copy user-data */
	copy_fastpath_user_data(arc, passive_list, arc->active_feature_list);

	/* Reset current user-data */
	gfd->user_data = ~0;

	refill_feature_fastpath_data(arc, passive_list);

	finfo->ref_count--;
	arc->runtime_enabled_features--;

	/* Store release semantics for active_list update */
	__atomic_store(&arc->active_feature_list, &passive_list, __ATOMIC_RELEASE);

	return 0;
}

int
rte_graph_feature_arc_destroy(rte_graph_feature_arc_t _arc)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);
	rte_graph_feature_arc_main_t *dm = __feature_arc_main;
	struct rte_graph_feature_node_list *node_info = NULL;

	while (!STAILQ_EMPTY(&arc->all_features)) {
		node_info = STAILQ_FIRST(&arc->all_features);
		STAILQ_REMOVE_HEAD(&arc->all_features, next_feature);
		free(node_info);
	}
	feature_arc_list_destroy(arc->feature_list[0]);
	feature_arc_list_destroy(arc->feature_list[1]);
	rte_free(arc->features[0]);
	rte_free(arc->features[1]);

	dm->feature_arcs[arc->feature_arc_index] = RTE_GRAPH_FEATURE_ARC_INITIALIZER;

	rte_free(arc);
	return 0;
}

int
rte_graph_feature_arc_cleanup(void)
{
	rte_graph_feature_arc_main_t *dm = __feature_arc_main;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == RTE_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		rte_graph_feature_arc_destroy((rte_graph_feature_arc_t)dm->feature_arcs[iter]);
	}
	free(dm);

	__feature_arc_main = NULL;

	return 0;
}

int
rte_graph_feature_arc_lookup_by_name(const char *arc_name, rte_graph_feature_arc_t *_arc)
{
	rte_graph_feature_arc_main_t *dm = __feature_arc_main;
	struct rte_graph_feature_arc *arc = NULL;
	uint32_t iter;

	if (!__feature_arc_main)
		return -1;

	for (iter = 0; iter < dm->max_feature_arcs; iter++) {
		if (dm->feature_arcs[iter] == RTE_GRAPH_FEATURE_ARC_INITIALIZER)
			continue;

		arc = rte_graph_feature_arc_get(dm->feature_arcs[iter]);

		if (strstr(arc_name, arc->feature_arc_name)) {
			if (_arc)
				*_arc = (rte_graph_feature_arc_t)arc;
			return 0;
		}
	}

	return -1;
}

int
rte_graph_feature_arc_num_enabled_features(rte_graph_feature_arc_t _arc)
{
	struct rte_graph_feature_arc *arc = rte_graph_feature_arc_get(_arc);

	return arc->runtime_enabled_features;
}


