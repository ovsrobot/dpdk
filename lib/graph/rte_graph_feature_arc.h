/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2025 Marvell International Ltd.
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
#include <rte_rcu_qsbr.h>

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
 * A feature arc represents an ordered list of features/protocols nodes at a
 * given networking layer. It provides a high level abstraction to
 * enable/disable feature nodes on a given interface at runtime and steer packets
 * across these feature nodes in a generic manner.
 *
 * A feature arc in a graph is represented via *start_node* and *end_node*.
 * Feature nodes are added between start_node and end_node. Packets steering
 * from start_node to feature nodes are controlled via
 * rte_graph_feature_enable()/rte_graph_feature_disable().
 *
 * In a typical network stack, often a protocol or feature must be first
 * enabled on a given interface, before any packet is steered towards it for
 * feature processing. For eg: incoming IPv4 packets are sent to
 * routing sub-system only after a valid IPv4 address is assigned to the
 * received interface. In other words, often packets needs to be steered across
 * features not based on the packet content but based on whether a feature is
 * enable or disable on a given incoming/outgoing interface. Feature arc
 * provides mechanism to enable/disable feature(s) on each interface at runtime
 * and allow seamless packet steering across runtime enabled feature nodes in
 * fast path.
 *
 * Feature arc also provides a way to steer packets from in-built nodes to
 * out-of-tree *feature nodes* without any change in in-built node's
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
 * available interfaces present in the system. Enable/disabling features on one
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
 * - Create feature arc's using RTE_GRAPH_FEATURE_ARC_REGISTER()
 * - New features can be added to an arc via RTE_GRAPH_FEATURE_REGISTER()
 * - Before calling rte_graph_create(), rte_graph_feature_arc_init() API must
 *   be called. If rte_graph_feature_arc_init() is not called by application,
 *   feature arc library is NOP
 * - Features can be enabled/disabled on any interface via
 *   rte_graph_feature_enable()/rte_graph_feature_disable()
 * - Feature arc can be destroyed via rte_graph_feature_arc_destroy()
 *
 * In fast path, APIs are provided to steer packets towards feature path from
 * - start_node (@ref RTE_GRAPH_FEATURE_ARC_REGISTER())
 * - feature nodes added via RTE_GRAPH_FEATURE_REGISTER()
 *
 * For typical steering of packets across feature nodes, application required
 * to know "rte_edges" which are saved in feature data object. Feature data
 * object is unique for every interface per feature with in a feature arc.
 *
 * APIs used to steer packets from start_node to first enabled feature node are:
 *  - rte_graph_feature_data_first_feature_get(). Once valid feature data is
 *  returned, application can use
 *    - rte_graph_feature_data_edge_get() to get edge from start_node to first
 *    feature
 *
 * rte_mbuf can carry [feature_data] into feature arc specific mbuf dynamic
 * field rte_graph_feature_arc_mbuf_dynfield_offset_get()
 *
 * APIs used to steer packets from one feature node to next enabled feature
 * node
 *  - rte_graph_feature_data_app_cookie_get() to get application specific data
 *  set by application in rte_graph_feature_enable()
 *  - rte_graph_feature_data_edge_get() to get edge from current node to next
 *  feature node
 *  - mbuf->dynfield[feature_data] needs to be updated with new feature data
 *  via rte_graph_feature_data_next_feature_get()
 *
 *  Fast path synchronization
 *  -------------------------
 *  Any feature enable/disable in control plane does not require stopping of
 *  worker cores.
 *
 *  rte_graph_feature_enable()/rte_graph_feature_disable() APIs accepts
 *  (rte_rcu_qsbr *) as an argument to allow application releasing
 *  resources associated with features it may have allocated for per feature
 *  per interface.
 *
 *  After every successful enable/disable, API internally calls
 *   - rte_rcu_qsbr_synchronize(rte_rcu_qsbr *) to synchronize all worker cores
 *   - Calls RTE_GRAPH_FEATURE_REGISTER()->notifier_cb() with app_cookie,
 *   provided per feature per interface in rte_graph_feature_enable()
 */

/** Length of feature arc name */
#define RTE_GRAPH_FEATURE_ARC_NAMELEN RTE_NODE_NAMESIZE

/** Initializer values for ARC, Feature, Feature data */
#define RTE_GRAPH_FEATURE_ARC_INITIALIZER ((rte_graph_feature_arc_t)UINT16_MAX)
#define RTE_GRAPH_FEATURE_DATA_INVALID ((rte_graph_feature_data_t)UINT16_MAX)
#define RTE_GRAPH_FEATURE_INVALID  ((rte_graph_feature_t)UINT8_MAX)

/** rte_graph feature arc object */
typedef uint16_t rte_graph_feature_arc_t;

/** rte_graph feature object */
typedef uint8_t rte_graph_feature_t;

/** rte_graph feature data object */
typedef uint16_t rte_graph_feature_data_t;

/** feature notifier callback called when feature is enabled/disabled */
typedef void (*rte_graph_feature_change_notifier_cb_t)(const char *arc_name,
						       const char *feature_name,
						       uint16_t index,
						       bool enable_disable,
						       uint32_t app_cookie);

/**
 *  Feature registration structure provided to
 *  RTE_GRAPH_FEATURE_REGISTER()
 */
struct rte_graph_feature_register {
	STAILQ_ENTRY(rte_graph_feature_register) next_feature;

	/** Name of the arc which is registered either via
	 * RTE_GRAPH_FEATURE_ARC_REGISTER() or via
	 * rte_graph_feature_arc_create()
	 */
	const char *arc_name;

	/* Name of the feature */
	const char *feature_name;

	/**
	 * Node id of feature_node.
	 *
	 * Setting this field can be skipped if registering feature via
	 * RTE_GRAPH_FEATURE_REGISTER()
	 */
	rte_node_t feature_node_id;

	/**
	 * Feature node process() function calling feature fast path APIs.
	 *
	 * If application calls rte_graph_feature_arc_init(), node->process()
	 * provided in RTE_NODE_REGISTER() is overwritten by this
	 * function.
	 */
	rte_node_process_t feature_process_fn;

	/*
	 * Pointer to Feature node registration
	 *
	 * Used when features are registered via
	 * RTE_GRAPH_FEATURE_REGISTER().
	 */
	struct rte_node_register *feature_node;

	/** Feature ordering constraints
	 * runs_after: Name of the feature which must run before "this feature"
	 * runs_before: Name of the feature which must run after "this feature"
	 */
	const char *runs_after;
	const char *runs_before;

	/**
	 * Callback for notifying any change in feature enable/disable state
	 */
	rte_graph_feature_change_notifier_cb_t notifier_cb;
};

/** Feature arc registration structure */
struct rte_graph_feature_arc_register {
	STAILQ_ENTRY(rte_graph_feature_arc_register) next_arc;

	/** Name of the feature arc */
	const char *arc_name;

	/**
	 * Maximum number of features supported in this feature arc.
	 *
	 * This field can be skipped for feature arc registration via
	 * RTE_GRAPH_FEATURE_ARC_REGISTER().
	 *
	 * API internally sets this field by calculating number of
	 * RTE_GRAPH_FEATURE_REGISTER() for every arc registration via
	 * RTE_GRAPH_FEATURE_ARC_REGISTER()
	 */
	uint32_t max_features;

	/**
	 * Maximum number of indexes supported in this feature arc
	 *
	 * Typically number of interfaces or ethdevs (For eg: RTE_MAX_ETHPORTS)
	 */
	uint32_t max_indexes;

	/** Start node of this arc */
	struct rte_node_register *start_node;

	/**
	 * Feature arc specific process() function for Start node.
	 * If application calls rte_graph_feature_arc_init(),
	 * start_node->process() is replaced by this function
	 */
	rte_node_process_t start_node_feature_process_fn;

	/** End feature node registration */
	struct rte_graph_feature_register *end_feature;
};

/** constructor to register feature to an arc */
#define RTE_GRAPH_FEATURE_REGISTER(reg)                                                 \
	RTE_INIT(__rte_graph_feature_register_##reg)                                    \
	{                                                                               \
		__rte_graph_feature_register(&reg, __func__, __LINE__);                 \
	}

/** constructor to register a feature arc */
#define RTE_GRAPH_FEATURE_ARC_REGISTER(reg)                                             \
		RTE_INIT(__rte_graph_feature_arc_register_##reg)                        \
		{                                                                       \
			__rte_graph_feature_arc_register(&reg, __func__, __LINE__);     \
		}
/**
 * Initialize feature arc subsystem
 *
 * This API
 * - Initializes feature arc module and alloc associated memory
 * - creates feature arc for every RTE_GRAPH_FEATURE_ARC_REGISTER()
 * - Add feature node to a feature arc for every RTE_GRAPH_FEATURE_REGISTER()
 * - Replaces all RTE_NODE_REGISTER()->process() functions for
 *   - Every start_node/end_node provided in arc registration
 *   - Every feature node provided in feature registration
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_init(void);

/**
 * Create a feature arc.
 *
 * This API can be skipped if RTE_GRAPH_FEATURE_ARC_REGISTER() is used
 *
 * @param reg
 *   Pointer to struct rte_graph_feature_arc_register
 * @param[out] _arc
 *  Feature arc object
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_arc_create(struct rte_graph_feature_arc_register *reg,
				 rte_graph_feature_arc_t *_arc);

/**
 * Get feature arc object with name
 *
 * @param arc_name
 *   Feature arc name provided to successful @ref rte_graph_feature_arc_create
 * @param[out] _arc
 *   Feature arc object returned. Valid only when API returns SUCCESS
 *
 * @return
 *  0: Success
 * <0: Failure.
 */
__rte_experimental
int rte_graph_feature_arc_lookup_by_name(const char *arc_name, rte_graph_feature_arc_t *_arc);

/**
 * Add a feature to already created feature arc.
 *
 * This API is not required in case RTE_GRAPH_FEATURE_REGISTER() is used
 *
 * @param feat_reg
 * Pointer to struct rte_graph_feature_register
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
int rte_graph_feature_add(struct rte_graph_feature_register *feat_reg);

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
 * @param app_cookie
 *   Application specific data which is retrieved in fast path
 * @param qsbr
 *   RCU QSBR object.  After enabling feature, API calls
 *   rte_rcu_qsbr_synchronize() followed by call to struct
 *   rte_graph_feature_register::notifier_cb(), if it is set, to notify feature
 *   caller This object can be passed NULL as well if no RCU synchronization is
 *   required
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_enable(rte_graph_feature_arc_t _arc, uint32_t index, const
			     char *feature_name, uint32_t app_cookie,
			     struct rte_rcu_qsbr *qsbr);

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
 * @param qsbr
 *   RCU QSBR object.  After disabling feature, API calls
 *   rte_rcu_qsbr_synchronize() followed by call to struct
 *   rte_graph_feature_register::notifier_cb(), if it is set, to notify feature
 *   caller This object can be passed NULL as well if no RCU synchronization is
 *   required
 *
 * @return
 *  0: Success
 * <0: Failure
 */
__rte_experimental
int rte_graph_feature_disable(rte_graph_feature_arc_t _arc, uint32_t index,
			      const char *feature_name, struct rte_rcu_qsbr *qsbr);

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
int rte_graph_feature_lookup(rte_graph_feature_arc_t arc, const char *feature_name,
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
 * Slow path API to know how many features are added (NOT enabled) within a
 * feature arc
 *
 * @param _arc
 *  Feature arc object
 *
 * @return: Number of added features to arc
 */
__rte_experimental
uint32_t rte_graph_feature_arc_num_features(rte_graph_feature_arc_t _arc);

/**
 * Slow path API to know how many features are currently enabled within a
 * feature arc across all indexes. If a single feature is enabled on all interfaces,
 * this API would return "number_of_interfaces" as count (but not "1")
 *
 * @param _arc
 *  Feature arc object
 *
 * @return: Number of enabled features across all indexes
 */
__rte_experimental
uint32_t rte_graph_feature_arc_num_enabled_features(rte_graph_feature_arc_t _arc);

/**
 * Slow path API to get feature node name from rte_graph_feature_t object
 *
 * @param _arc
 *   Feature arc object
 * @param feature
 *   Feature object
 *
 * @return: Name of the feature node
 */
__rte_experimental
char *rte_graph_feature_arc_feature_to_name(rte_graph_feature_arc_t _arc,
					    rte_graph_feature_t feature);

/**
 * Slow path API to get corresponding rte_node_t from
 * rte_graph_feature_t
 *
 * @param _arc
 *   Feature arc object
 * @param feature
 *   Feature object
 * @param[out] node
 *   rte_node_t of feature node, Valid only when API returns SUCCESS
 *
 * @return: 0 on success, < 0 on failure
 */
__rte_experimental
int
rte_graph_feature_arc_feature_to_node(rte_graph_feature_arc_t _arc,
				      rte_graph_feature_t feature,
				      rte_node_t *node);

/**
 * Slow path API to dump valid feature arc names
 *
 *  @param[out] arc_names
 *   Buffer to copy the arc names. The NULL value is allowed in that case,
 * the function returns the size of the array that needs to be allocated.
 *
 * @return
 *   When next_nodes == NULL, it returns the size of the array else
 *  number of item copied.
 */
__rte_experimental
uint32_t
rte_graph_feature_arc_names_get(char *arc_names[]);

/**
 * @internal
 *
 * function declaration for registering arc
 *
 * @param reg
 *      Pointer to struct rte_graph_feature_arc_register
 *  @param caller_name
 *      Name of the function which is calling this API
 *  @param lineno
 *      Line number of the function which is calling this API
 */
__rte_experimental
void __rte_graph_feature_arc_register(struct rte_graph_feature_arc_register *reg,
				      const char *caller_name, int lineno);

/**
 * @internal
 *
 * function declaration for registering feature
 *
 * @param reg
 *      Pointer to struct rte_graph_feature_register
 * @param caller_name
 *      Name of the function which is calling this API
 * @param lineno
 *      Line number of the function which is calling this API
 */
__rte_experimental
void __rte_graph_feature_register(struct rte_graph_feature_register *reg,
				  const char *caller_name, int lineno);

#ifdef __cplusplus
}
#endif

#endif
