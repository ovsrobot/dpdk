/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2024 Marvell International Ltd.
 */

#ifndef _RTE_GRAPH_FEATURE_ARC_H_
#define _RTE_GRAPH_FEATURE_ARC_H_

#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_debug.h>
#include <rte_graph.h>
#include <rte_graph_worker.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file
 *
 * rte_graph_feature_arc.h
 *
 * Define APIs and structures/variables with respect to feature arc
 *
 * - Feature arc(s)
 * - Feature(s)
 *
 * A feature arc represents an ordered list of features/protocol-nodes at a
 * given networking layer. Feature arc provides a high level abstraction to
 * connect various *rte_graph* nodes, designated as *feature nodes*, and
 * allowing steering of packets across these feature nodes fast path processing
 * in a generic manner. In a typical network stack, often a protocol or feature
 * must be first enabled on a given interface, before any packet is steered
 * towards it for feature processing. For eg: incoming IPv4 packets are sent to
 * routing sub-system only after a valid IPv4 address is assigned to the
 * received interface. In other words, often packets needs to be steered across
 * features not based on the packet content but based on whether a feature is
 * enable or disable on a given incoming/outgoing interface. Feature arc
 * provides mechanism to enable/disable feature(s) on each interface at runtime
 * and allow seamless packet steering across runtime enabled feature nodes in
 * fast path.
 *
 * Feature arc also provides a way to steer packets from standard nodes to
 * custom/user-defined *feature nodes* without any change in standard node's
 * fast path functions
 *
 * On a given interface multiple feature(s) might be enabled in a particular
 * feature arc. For instance, both "ipv4-output" and "IPsec policy output"
 * features may be enabled on "eth0" interface in "L3-output" feature arc.
 * Similarly, "ipv6-output" and "ipsec-output" may be enabled on "eth1"
 * interface in same "L3-output" feature arc.
 *
 * When multiple features are present in a given feature arc, its imperative
 * to allow each feature processing in a particular sequential order. For
 * instance, in "L3-input" feature arc it may be required to run "IPsec
 * input" feature first, for packet decryption, before "ip-lookup".  So a
 * sequential order must be maintained among features present in a feature arc.
 *
 * Features are enabled/disabled multiple times at runtime to some or all
 * available interfaces present in the system. Features can be enabled/disabled
 * even after @b rte_graph_create() is called. Enable/disabling features on one
 * interface is independent of other interface.
 *
 * A given feature might consume packet (if it's configured to consume) or may
 * forward it to next enabled feature. For instance, "IPsec input" feature may
 * consume/drop all packets with "Protect" policy action while all packets with
 * policy action as "Bypass" may be forwarded to next enabled feature (with in
 * same feature arc)
 *
 * This library facilitates rte graph based applications to steer packets in
 * fast path to different feature nodes with-in a feature arc and support all
 * functionalities described above
 *
 * In order to use feature-arc APIs, applications needs to do following in
 * control path:
 * - Initialize feature arc library via rte_graph_feature_arc_init()
 * - Create feature arc via rte_graph_feature_arc_create()
 * - *Before calling rte_graph_create()*, features must be added to feature-arc
 *   via rte_graph_feature_add(). rte_graph_feature_add() allows adding
 *   features in a sequential order with "runs_after" and "runs_before"
 *   constraints.
 * - Post rte_graph_create(), features can be enabled/disabled at runtime on
 *   any interface via rte_graph_feature_enable()/rte_graph_feature_disable()
 * - Feature arc can be destroyed via rte_graph_feature_arc_destroy()
 *
 * In fast path, APIs are provided to steer packets towards feature path from
 * - start_node (provided as an argument to rte_graph_feature_arc_create())
 * - feature nodes (which are added via rte_graph_feature_add())
 *
 * For typical steering of packets across feature nodes, application required
 * to know "rte_edges" which are saved in feature data object. Feature data
 * object is unique for every interface per feature with in a feature arc.
 *
 * When steering packets from start_node to feature node:
 * - rte_graph_feature_arc_first_feature_get() provides first enabled feature.
 * - Next rte_edge from start_node to first enabled feature can be obtained via
 *   rte_graph_feature_arc_feature_set()
 *
 * rte_mbuf can carry [current feature, index] from start_node of an arc to other
 * feature nodes
 *
 * In feature node, application can get 32-bit user_data
 * via_rte_graph_feature_user_data_get() which is provided in
 * rte_graph_feature_enable(). User data can hold feature specific cookie like
 * IPsec policy database index (if more than one are supported)
 *
 * If feature node is not consuming packet, next enabled feature and next
 * rte_edge can be obtained via rte_graph_feature_arc_next_feature_get()
 *
 * It is application responsibility to ensure that at-least *last feature*(or sink
 * feature) must be enabled from where packet can exit feature-arc path, if
 * *NO* intermediate feature is consuming the packet and it has reached till
 * the end of feature arc path
 *
 * Synchronization among cores
 * ---------------------------
 * Subsequent calls to rte_graph_feature_enable() is allowed while worker cores
 * are processing in rte_graph_walk() loop. However, for
 * rte_graph_feature_disable() application must use RCU based synchronization
 */

/**< Initializer value for rte_graph_feature_arc_t */
#define RTE_GRAPH_FEATURE_ARC_INITIALIZER ((rte_graph_feature_arc_t)UINT64_MAX)

/** Max number of features supported in a given feature arc */
#define RTE_GRAPH_FEATURE_MAX_PER_ARC 64

/** Length of feature arc name */
#define RTE_GRAPH_FEATURE_ARC_NAMELEN RTE_NODE_NAMESIZE

/** @internal */
#define rte_graph_feature_cast(x) ((rte_graph_feature_t)x)

/**< Initializer value for rte_graph_feature_arc_t */
#define RTE_GRAPH_FEATURE_INVALID rte_graph_feature_cast(UINT8_MAX)

/** rte_graph feature arc object */
typedef uint64_t rte_graph_feature_arc_t;

/** rte_graph feature object */
typedef uint8_t rte_graph_feature_t;

/** runtime active feature list index with in feature arc*/
typedef uint8_t rte_graph_feature_rt_list_t;

/** per feature arc monotonically increasing counter to synchronize fast path APIs */
typedef uint16_t rte_graph_feature_counter_t;

/**
 * Initialize feature arc subsystem
 *
 * @param max_feature_arcs
 *   Maximum number of feature arcs required to be supported
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_init(int max_feature_arcs);

/**
 * Create a feature arc
 *
 * @param feature_arc_name
 *   Feature arc name with max length of @ref RTE_GRAPH_FEATURE_ARC_NAMELEN
 * @param max_features
 *   Maximum number of features to be supported in this feature arc
 * @param max_indexes
 *   Maximum number of interfaces/ports/indexes to be supported
 * @param start_node
 *   Base node where this feature arc's features are checked in fast path
 * @param[out] _arc
 *  Feature arc object
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_create(const char *feature_arc_name, int max_features, int max_indexes,
				 struct rte_node_register *start_node,
				 rte_graph_feature_arc_t *_arc);

/**
 * Get feature arc object with name
 *
 * @param arc_name
 *   Feature arc name provided to successful @ref rte_graph_feature_arc_create
 * @param[out] _arc
 *   Feature arc object returned
 *
 * @return
 *  0: Success
 * <0: Failure.
 */
__rte_experimental
int rte_graph_feature_arc_lookup_by_name(const char *arc_name, rte_graph_feature_arc_t *_arc);

/**
 * Add a feature to already created feature arc. For instance
 *
 * 1. Add first feature node: "ipv4-input" to input arc
 *    rte_graph_feature_add(ipv4_input_arc, "ipv4-input", NULL, NULL);
 *
 * 2. Add "ipsec-input" feature node after "ipv4-input" node
 *    rte_graph_feature_add(ipv4_input_arc, "ipsec-input", "ipv4-input", NULL);
 *
 * 3. Add "ipv4-pre-classify-input" node before "ipv4-input" node
 *    rte_graph_feature_add(ipv4_input_arc, "ipv4-pre-classify-input"", NULL, "ipv4-input");
 *
 * 4. Add "acl-classify-input" node after ipv4-input but before ipsec-input
 *    rte_graph_feature_add(ipv4_input_arc, "acl-classify-input", "ipv4-input", "ipsec-input");
 *
 * @param _arc
 *   Feature arc handle returned from @ref rte_graph_feature_arc_create()
 * @param feature_node
 *   Graph node representing feature. On success, feature_node is next_node of
 *   feature_arc->start_node
 * @param runs_after
 *   Add this feature_node after already added "runs_after". Creates
 *   start_node -> runs_after -> this_feature sequence
 * @param runs_before
 *  Add this feature_node before already added "runs_before". Creates
 *  start_node -> this_feature -> runs_before sequence
 *
 * <I> Must be called before rte_graph_create() </I>
 * <I> rte_graph_feature_add() is not allowed after call to
 * rte_graph_feature_enable() so all features must be added before they can be
 * enabled </I>
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_add(rte_graph_feature_arc_t _arc, struct rte_node_register *feature_node,
		    const char *runs_after, const char *runs_before);

/**
 * Enable feature within a feature arc
 *
 * Must be called after @b rte_graph_create().
 *
 * @param _arc
 *   Feature arc object returned by @ref rte_graph_feature_arc_create or @ref
 *   rte_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref rte_graph_feature_add
 * @param user_data
 *   Application specific data which is retrieved in fast path
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_enable(rte_graph_feature_arc_t _arc, uint32_t index, const char *feature_name,
			     int32_t user_data);

/**
 * Validate whether subsequent enable/disable feature would succeed or not.
 * API is thread-safe
 *
 * @param _arc
 *   Feature arc object returned by @ref rte_graph_feature_arc_create or @ref
 *   rte_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref rte_graph_feature_add
 * @param is_enable_disable
 *   If 1, validate whether subsequent @ref rte_graph_feature_enable would pass or not
 *   If 0, validate whether subsequent @ref rte_graph_feature_disable would pass or not
 *
 * @return
 *  0: Subsequent enable/disable API would pass
 * <0: Subsequent enable/disable API would not pass
 */
__rte_experimental
int rte_graph_feature_validate(rte_graph_feature_arc_t _arc, uint32_t index,
			       const char *feature_name, int is_enable_disable);

/**
 * Disable already enabled feature within a feature arc
 *
 * Must be called after @b rte_graph_create(). API is *NOT* Thread-safe
 *
 * @param _arc
 *   Feature arc object returned by @ref rte_graph_feature_arc_create or @ref
 *   rte_graph_feature_arc_lookup_by_name
 * @param index
 *   Application specific index. Can be corresponding to interface_id/port_id etc
 * @param feature_name
 *   Name of the node which is already added via @ref rte_graph_feature_add
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_disable(rte_graph_feature_arc_t _arc, uint32_t index,
			      const char *feature_name);

/**
 * Get rte_graph_feature_t object from feature name
 *
 * @param arc
 *   Feature arc object returned by @ref rte_graph_feature_arc_create or @ref
 *   rte_graph_feature_arc_lookup_by_name
 * @param feature_name
 *   Feature name provided to @ref rte_graph_feature_add
 * @param[out] feature
 *   Feature object
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_lookup(rte_graph_feature_arc_t _arc, const char *feature_name,
			     rte_graph_feature_t *feature);

/**
 * Delete feature_arc object
 *
 * @param _arc
 *   Feature arc object returned by @ref rte_graph_feature_arc_create or @ref
 *   rte_graph_feature_arc_lookup_by_name
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_destroy(rte_graph_feature_arc_t _arc);

/**
 * Cleanup all feature arcs
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_cleanup(void);

/**
 * Slow path API to know how many features are currently enabled within a featur-arc
 *
 * @param _arc
 *  Feature arc object
 *
 * @return: Number of enabled features
 */
__rte_experimental
int rte_graph_feature_arc_num_enabled_features(rte_graph_feature_arc_t _arc);
#ifdef __cplusplus
}
#endif

#endif
