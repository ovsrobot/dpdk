/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Intel Corporation
 */

#ifndef _RTE_FLOW_GRAPH_H_
#define _RTE_FLOW_GRAPH_H_

/**
 * @file
 * RTE Flow Graph Parser (Internal Driver API)
 *
 * This file provides a graph-based flow pattern parser for PMD drivers.
 * It defines structures and functions to validate and process rte_flow
 * patterns using a directed graph representation.
 *
 * @warning
 * This is an internal API for PMD drivers only. Applications must not use it.
 */

#include <rte_flow.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Logging for flow graph parse errors. This is an internal driver API;
 * RTE_FLOW_GRAPH_LOG requires RTE_COMPONENT_NAME (set by meson for drivers)
 * and the corresponding driver logtype variable to be registered.
 */
#ifdef RTE_COMPONENT_NAME
extern int RTE_CONCAT(RTE_COMPONENT_NAME, _logtype_driver);
#define RTE_FLOW_GRAPH_LOG(level, fmt, ...) \
	rte_log(RTE_LOG_##level, RTE_CONCAT(RTE_COMPONENT_NAME, _logtype_driver), \
		"ETHDEV FLOW GRAPH: %s(): " fmt "\n", __func__, ##__VA_ARGS__)
#else
/* Use ETHDEV log level when included outside driver context */
#define RTE_FLOW_GRAPH_LOG(level, fmt, ...) \
	rte_log(RTE_LOG_##level, \
			rte_eth_dev_logtype, \
			"ETHDEV FLOW GRAPH: %s(): " fmt "\n", __func__, ##__VA_ARGS__)
#endif

#define RTE_FLOW_NODE_FIRST (0)
/* Edge array termination sentinel (not a valid node index). */
#define RTE_FLOW_NODE_EDGE_END ((size_t)~0U)

static inline const char *
rte_flow_graph_item_type_to_str(enum rte_flow_item_type type)
{
	const char *name = NULL;
	int ret;

	/*
	 * this is a hack of monumental proportions.
	 *
	 * currently, chkincs will build each driver SDK header file using three
	 * build flag combinations: with INTERNAL+EXPERIMENTAL allowed, with
	 * EXPERIMENTAL allowed, and with neither allowed. That last one will
	 * fail for this header, because `rte_flow_conv` is defined as an
	 * experimental API.
	 *
	 * Arguably, this is a bug in chkincs because this header is installed
	 * as driver_sdk only (see lib/ethdev Meson file), meaning that this
	 * file is driver-internal only and is never exported to the user.
	 * Drivers themselves are already always built with experimental API
	 * enabled (see drivers Meson file, specifically default_cflags), so
	 * in practice chkincs tests a configuration that never exists in real
	 * life for driver SDK.
	 *
	 * So, again, arguably, this should be fixed in chkincs, but I have no
	 * idea what would be the correct way to do that, so for now I'll just
	 * avoid calling `rte_flow_conv` whenever experimental API's aren't
	 * allowed, and hopefully we'll come up with a proper solution in one
	 * of the next versions of this patchset.
	 */
#ifdef ALLOW_EXPERIMENTAL_API
	ret = rte_flow_conv(RTE_FLOW_CONV_OP_ITEM_NAME_PTR,
			&name, sizeof(name), (const void *)(uintptr_t)type, NULL);
#else
	ret = -1;
	RTE_SET_USED(type);
#endif
	if (ret < 0 || name == NULL)
		return "UNKNOWN";

	return name;
}

/**
 * For a lot of nodes, there are multiple common patterns of validation behavior. This enum allows
 * marking nodes as implementing one of these common behaviors without need for expressing that in
 * validation code. Can be ORed together to express support for multiple node types. These checks
 * are not combined (any one of them being satisfied is sufficient).
 */
enum rte_flow_graph_node_expect {
	RTE_FLOW_NODE_EXPECT_NONE = 0,             /**< No special constraints. */
	RTE_FLOW_NODE_EXPECT_EMPTY = (1 << 0),     /**< spec, mask, last must be NULL. */
	RTE_FLOW_NODE_EXPECT_SPEC = (1 << 1),      /**< spec is required, mask and last must be NULL. */
	RTE_FLOW_NODE_EXPECT_MASK = (1 << 2),      /**< mask is required, spec and last must be NULL. */
	RTE_FLOW_NODE_EXPECT_SPEC_MASK = (1 << 3), /**< spec and mask required, last must be NULL. */
	RTE_FLOW_NODE_EXPECT_RANGE = (1 << 4),     /**< spec, mask, and last are required. */
	RTE_FLOW_NODE_EXPECT_NOT_RANGE = (1 << 5), /**< last must be NULL. */
};

/**
 * Node validation callback.
 *
 * Called when the graph traversal reaches this node. Validates the
 * rte_flow_item (spec, mask, last) against driver-specific constraints.
 *
 * Drivers are suggested to perform all checks in this callback.
 *
 * @param ctx
 *   Opaque driver context for accumulating parsed state.
 * @param item
 *   Pointer to the rte_flow_item being validated.
 * @param error
 *   Pointer to rte_flow_error structure for reporting failures.
 * @return
 *   0 on success, or the value returned by rte_flow_error_set() on failure.
 *   On failure the callback must report the error with rte_flow_error_set().
 */
typedef int (*rte_flow_node_validate_fn)(
	const void *ctx,
	const struct rte_flow_item *item,
	struct rte_flow_error *error);

/**
 * Node processing callback.
 *
 * Called after validation succeeds. Extracts fields from the rte_flow_item
 * and stores them in driver-specific state for later hardware programming.
 *
 * Drivers are suggested to implement "happy path" in this callback.
 *
 * @param ctx
 *   Opaque driver context for accumulating parsed state.
 * @param item
 *   Pointer to the rte_flow_item to process.
 * @param error
 *   Pointer to rte_flow_error structure for reporting failures.
 * @return
 *   0 on success, or the value returned by rte_flow_error_set() on failure.
 *   On failure the callback must report the error with rte_flow_error_set().
 */
typedef int (*rte_flow_node_process_fn)(
	void *ctx,
	const struct rte_flow_item *item,
	struct rte_flow_error *error);

/**
 * Graph node definition.
 *
 * Node validity rules:
 * - all nodes must define a name,
 * - all non-END nodes must define an edge list,
 * - start node must not define validation/processing callbacks.
 */
struct rte_flow_graph_node {
	const char *name;                    /**< Node name. */
	const enum rte_flow_item_type type;  /**< Corresponding rte_flow_item_type. */
	const enum rte_flow_graph_node_expect constraints; /**< Common validation constraints (ORed). */
	rte_flow_node_validate_fn validate;  /**< Validation callback (NULL if unsupported). */
	rte_flow_node_process_fn process;    /**< Processing callback (NULL if no extraction needed). */
};

/**
 * Graph edge definition.
 *
 * Describes allowed transitions from one node to others. The 'next' array
 * lists all valid successor node types and is terminated by RTE_FLOW_NODE_EDGE_END.
 * Drivers define edges to express their supported protocol sequences. Edges
 * must be unique, as split path following is not supported.
 */
struct rte_flow_graph_edge {
	const size_t *next;  /**< Array of valid successor nodes, terminated by RTE_FLOW_NODE_EDGE_END. */
};

/**
 * Flow graph to be implemented by drivers.
 *
 * Graph contents are expected to be well-formed. This library validates
 * traversal semantics for pattern items, but does not attempt to harden
 * against arbitrary malformed node/edge table definitions.
 */
struct rte_flow_graph {
	struct rte_flow_graph_node *nodes;
	struct rte_flow_graph_edge *edges;
	const enum rte_flow_item_type *ignore_nodes; /**< Additional node types to ignore, terminated by RTE_FLOW_ITEM_TYPE_END. */
};

static inline bool
__flow_graph_node_check_constraint(enum rte_flow_graph_node_expect c,
		bool has_spec, bool has_mask, bool has_last)
{
	bool empty = !has_spec && !has_mask && !has_last;

	if ((c & RTE_FLOW_NODE_EXPECT_EMPTY) && empty)
		return true;
	if ((c & RTE_FLOW_NODE_EXPECT_NOT_RANGE) && !has_last)
		return true;
	if ((c & RTE_FLOW_NODE_EXPECT_SPEC) && has_spec && !has_mask && !has_last)
		return true;
	if ((c & RTE_FLOW_NODE_EXPECT_MASK) && has_mask && !has_spec && !has_last)
		return true;
	if ((c & RTE_FLOW_NODE_EXPECT_SPEC_MASK) && has_spec && has_mask && !has_last)
		return true;
	if ((c & RTE_FLOW_NODE_EXPECT_RANGE) && has_mask && has_spec && has_last)
		return true;

	return false;
}

static inline bool
__flow_graph_node_is_expected(const struct rte_flow_graph_node *node,
		const struct rte_flow_item *item, struct rte_flow_error *error)
{
	enum rte_flow_graph_node_expect c = node->constraints;

	if (c == RTE_FLOW_NODE_EXPECT_NONE)
		return true;

	bool has_spec = (item->spec != NULL);
	bool has_mask = (item->mask != NULL);
	bool has_last = (item->last != NULL);

	if (__flow_graph_node_check_constraint(c, has_spec, has_mask, has_last))
		return true;

	/*
	 * In the interest of everyone debugging flow parsing code, we should provide the user with
	 * meaningful messages about exactly what failed, as no one likes non-descript "node
	 * constraints not met" errors with no clear indication of where this is even coming from.
	 * What follows is us building said meaningful error messages. It's a bit ugly, but it is
	 * for the greater good.
	 */
	const char *msg;

	/* for empty items, we know exactly what went wrong */
	if (c == RTE_FLOW_NODE_EXPECT_EMPTY) {
		if (has_spec)
			msg = "Unexpected spec in flow item";
		else if (has_mask)
			msg = "Unexpected mask in flow item";
		else /* has_last */
			msg = "Unexpected last in flow item";
	} else {
		/*
		 * for non-empty constraints, we need to figure out the one thing user is missing
		 * (or has extra) that would've satisfied the constraints.
		 * We do that by flipping each presence bit in turn and seeing whether that single
		 * change would have satisfied the node constraints.
		 */

		/* check spec first */
		if (!has_spec && __flow_graph_node_check_constraint(c, true, has_mask, has_last)) {
			msg = "Missing spec in flow item";
		} else if (has_spec && __flow_graph_node_check_constraint(c, false, has_mask, has_last)) {
			msg = "Unexpected spec in flow item";
		}
		/* check mask next */
		else if (!has_mask && __flow_graph_node_check_constraint(c, has_spec, true, has_last)) {
			msg = "Missing mask in flow item";
		} else if (has_mask && __flow_graph_node_check_constraint(c, has_spec, false, has_last)) {
			msg = "Unexpected mask in flow item";
		}
		/* finally, check range */
		else if (!has_last && __flow_graph_node_check_constraint(c, has_spec, has_mask, true)) {
			msg = "Missing last in flow item";
		} else if (has_last && __flow_graph_node_check_constraint(c, has_spec, has_mask, false)) {
			msg = "Unexpected last in flow item";
		/* multiple things are wrong with the constraint, so just output a generic error */
		} else {
			msg = "Flow item does not meet node constraints";
		}
	}

	rte_flow_error_set(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, item, msg);

	return false;
}

/**
 * Check if a flow item type should be ignored by the graph.
 *
 * Checks if the item type is in the graph's ignore list.
 */
static inline bool
__flow_graph_node_is_ignored(const struct rte_flow_graph *graph,
			  enum rte_flow_item_type fi_type)
{
	const enum rte_flow_item_type *ignored;

	/* Always skip VOID items */
	if (fi_type == RTE_FLOW_ITEM_TYPE_VOID)
		return true;

	if (graph->ignore_nodes == NULL)
		return false;

	for (ignored = graph->ignore_nodes; *ignored != RTE_FLOW_ITEM_TYPE_END; ignored++) {
		if (*ignored == fi_type)
			return true;
	}

	return false;
}

/**
 * Get the index of a node within a graph.
 */
static inline size_t
__flow_graph_get_node_index(const struct rte_flow_graph *graph, const struct rte_flow_graph_node *node)
{
	return (size_t)(node - graph->nodes);
}

/**
 * Check if a graph node is valid.
 */
static inline bool
__flow_graph_node_is_valid(const struct rte_flow_graph *graph,
			   const struct rte_flow_graph_node *node,
			   struct rte_flow_error *error)
{
	size_t node_idx;

	if (node == NULL) {
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Flow graph node pointer is NULL");
		return false;
	}

	if (node->name == NULL) {
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, node,
				"Flow graph node name is not defined");
		return false;
	}

	node_idx = __flow_graph_get_node_index(graph, node);

	/* first node can't have callbacks because there's no item */
	if (node_idx == RTE_FLOW_NODE_FIRST &&
			(node->validate != NULL || node->process != NULL)) {
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, node,
				"Flow graph start node callbacks are not allowed");
		return false;
	}

	/* all non-END nodes must have edges */
	if (node->type != RTE_FLOW_ITEM_TYPE_END &&
			graph->edges[node_idx].next == NULL) {
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, node,
				"Flow graph edge list is not defined for non-END node");
		return false;
	}

	return true;
}

/**
 * Find the next node in the graph matching the given item type.
 */
static inline const struct rte_flow_graph_node *
__flow_graph_find_next_node(const struct rte_flow_graph *graph,
		      const struct rte_flow_graph_node *cur_node,
		      enum rte_flow_item_type next_type,
		      struct rte_flow_error *error)
{
	const size_t *next_nodes;
	size_t cur_idx, edge_idx;

	if (!__flow_graph_node_is_valid(graph, cur_node, error))
		return NULL;

	cur_idx = __flow_graph_get_node_index(graph, cur_node);
	next_nodes = graph->edges[cur_idx].next;

	for (edge_idx = 0; next_nodes[edge_idx] != RTE_FLOW_NODE_EDGE_END; edge_idx++) {
		const struct rte_flow_graph_node *tmp =
				&graph->nodes[next_nodes[edge_idx]];
		/* if node is invalid, graph is broken */
		if (!__flow_graph_node_is_valid(graph, tmp, error))
			return NULL;
		if (tmp->type == next_type)
			return tmp;
	}

	return NULL;
}

/**
 * Visit (validate and extract) a node's item.
 */
static inline int
__flow_graph_visit_node(const struct rte_flow_graph_node *node, void *ctx,
		const struct rte_flow_item *item, struct rte_flow_error *error)
{
	int ret;

	/* if we expect a certain type of node, check for it */
	if (item != NULL && !__flow_graph_node_is_expected(node, item, error))
		return -EINVAL;

	/* Does this node fit driver's criteria? */
	if (node->validate != NULL) {
		ret = node->validate(ctx, item, error);
		if (ret != 0)
			return ret;
	}

	/* Extract data from this item */
	if (node->process != NULL) {
		ret = node->process(ctx, item, error);
		if (ret != 0)
			return ret;
	}

	return 0;
}

/**
 * Parse and validate a flow pattern using the flow graph.
 *
 * Traverses the pattern items and validates them against the driver's graph
 * structure. For each item, checks that the transition from the current node
 * is allowed, then invokes validation and processing callbacks.
 *
 * @param graph
 *   Pointer to the driver's flow graph definition with nodes and edges.
 * @param pattern
 *   Array of rte_flow_item structures to parse, terminated by RTE_FLOW_ITEM_TYPE_END.
 * @param error
 *   Pointer to rte_flow_error structure for reporting failures.
 * @param ctx
 *   Opaque driver context for accumulating parsed state.
 * @return
 *   0 on success, negative errno on failure (error is set).
 */
static inline int
rte_flow_graph_parse(const struct rte_flow_graph *graph, const struct rte_flow_item *pattern,
		struct rte_flow_error *error, void *ctx)
{
	const struct rte_flow_graph_node *cur_node;
	const struct rte_flow_item *item;
	int ret;

	if (graph == NULL || graph->nodes == NULL || graph->edges == NULL) {
		RTE_FLOW_GRAPH_LOG(DEBUG, "flow graph is not defined");
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
				"Flow graph is not defined");
	}
	if (pattern == NULL) {
		RTE_FLOW_GRAPH_LOG(DEBUG, "flow pattern is NULL");
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				"Flow pattern is NULL");
	}

	/* use start node as traversal anchor */
	cur_node = &graph->nodes[RTE_FLOW_NODE_FIRST];

	/* is the node valid? */
	if (!__flow_graph_node_is_valid(graph, cur_node, error)) {
		/* error may be NULL */
		if (error != NULL)
			RTE_FLOW_GRAPH_LOG(DEBUG, "%s", error->message);
		return -EINVAL;
	}

	/* Traverse pattern items */
	for (item = pattern; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {

		/* Skip items in the graph's ignore list */
		if (__flow_graph_node_is_ignored(graph, item->type)) {
			RTE_FLOW_GRAPH_LOG(DEBUG, "ignored item %s",
					rte_flow_graph_item_type_to_str(item->type));
			continue;
		}

		/* Find the next graph node for this item type */
		cur_node = __flow_graph_find_next_node(graph, cur_node,
				item->type, error);
		if (cur_node == NULL) {
			RTE_FLOW_GRAPH_LOG(DEBUG, "cannot traverse to item %s",
					rte_flow_graph_item_type_to_str(item->type));
			return rte_flow_error_set(error, ENOTSUP,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item, "Pattern item not supported");
		}
		RTE_FLOW_GRAPH_LOG(DEBUG, "processing %s", cur_node->name);
		/* Validate and process the current item at this node */
		ret = __flow_graph_visit_node(cur_node, ctx, item, error);
		if (ret != 0) {
			/* error may be NULL */
			if (error != NULL)
				RTE_FLOW_GRAPH_LOG(DEBUG, "%s", error->message);
			return ret;
		}
	}

	/* Pattern items have ended but we still need to process the end */
	cur_node = __flow_graph_find_next_node(graph, cur_node, item->type, error);
	if (cur_node == NULL) {
		RTE_FLOW_GRAPH_LOG(DEBUG, "cannot traverse to item %s",
				rte_flow_graph_item_type_to_str(item->type));
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item, "Pattern item not supported");
	}
	ret = __flow_graph_visit_node(cur_node, ctx, item, error);
	if (ret != 0) {
		/* error may be NULL */
		if (error != NULL)
			RTE_FLOW_GRAPH_LOG(DEBUG, "%s", error->message);
		return ret;
	}

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_FLOW_GRAPH_H_ */
