/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Intel Corporation
 */

#ifndef _COMMON_INTEL_FLOW_ENGINE_H_
#define _COMMON_INTEL_FLOW_ENGINE_H_

#include <stddef.h>
#include <stdio.h>
#include <sys/queue.h>

#include <rte_malloc.h>

#include <ethdev_driver.h>
#include <rte_flow.h>
#include <rte_flow_graph.h>
#include <rte_tailq.h>
#include <rte_rwlock.h>
#include <rte_hexdump.h>

#include "log.h"

/*
 * This is a common header for Intel Ethernet drivers' flow engine
 * implementations. It defines the interfaces and data structures required to
 * implement flow rule engines that can be plugged into the drivers' flow
 * handling logic.
 *
 * Design considerations:
 *
 * 1. Ease of implementation
 *
 * The flow engine interface is designed to be as simple as possible with
 * obvious defaults (i.e. not specifying something leads to behavior that
 * would've been the most expected in context). The point is not to produce a
 * monstrous driver-within-a-driver framework, but rather to make engine
 * definitions follow semantic expectations of what the engine actually does.
 *
 * All the boilerplate (flow management, engine enablement tracking, etc.) is
 * handled by the common flow infrastructure, so the engine implementation only
 * needs to focus on the actual logic of parsing and installing/uninstalling
 * flow rules, and defining each step of the process as it pertains to each flow
 * engine.
 *
 * It is expected that drivers will use other utility functions from the common
 * flow-related code where applicable (e.g. flow_util.h, flow_check.h, etc.),
 * however this is obviously up to each individual driver to handle.
 *
 * 2. Full secondary process compatibility
 *
 * In order to support rte_flow operations in secondary processes, we need to
 * store which engines are enabled for particular driver instance, and resolve
 * them at runtime. The engine index (its position in the engine list) is used as a
 * bitshift-mask into a driver-specific 64-bit field of enabled engines. This
 * way, the engine definitions can be stored in read-only memory, and referenced
 * by both primary and secondary processes without issues.
 *
 * For this to remain safe, flow engine lists and engine definitions must be
 * immutable for process lifetime (declare them as const).
 *
 * Note that this does not imply that all drivers are therefore able to support
 * rte_flow-related operations in secondary processes - that is still up to each
 * driver to implement. This just ensures that the flow engine framework does
 * not prevent it.
 *
 * The per-instance engine configuration (enablement bitmask and per-engine
 * private data) is set up and torn down exclusively by
 * ci_flow_engine_conf_init() and ci_flow_engine_conf_reset(). These run the
 * engine_init/engine_uninit callbacks and mutate state shared with secondary
 * processes, so they are primary-process operations: a secondary process must
 * never call them. Doing so is a driver bug that clobbers shared state.
 *
 * 3. Flow object lifecycle is framework-owned
 *
 * Engines are expected to treat framework-provided context and flow objects as
 * storage they fill in, not storage they own. In other words, engine logic
 * should focus on contents of flow data, while object lifetime is managed by
 * the framework.
 *
 * Engines may still allocate auxiliary data (for per-engine private state or
 * pointers stored inside flows), but all such allocations must be from shared
 * memory and should follow engine_init/engine_uninit or flow lifetime as
 * appropriate.
 *
 * 4. Pattern parsing: rte_flow_graph and pattern_parse callback
 *
 * The flow engine framework is designed to work hand-in-hand with the
 * rte_flow_graph parsing infrastructure. Each engine may provide a pattern
 * graph that is used to match the flow pattern, and extract relevant data
 * into the engine context. This allows for cleaner separation of concerns,
 * where the engine focuses on handling actions and attributes, while the
 * graph parser deals with the pattern matching.
 *
 * Engines may also provide a `pattern_parse` callback that is invoked before
 * the graph parser runs. This allows engines to handle pattern items that
 * don't fit neatly into the graph model (e.g. FUZZY items that can appear at
 * any position), as well as ignoring the graph parser entirely and implementing
 * custom pattern parsing.
 *
 * If neither the graph nor the callback is provided, a default empty pattern
 * graph is used that matches either [END], or [ANY] -> [END] patterns. A NULL
 * pattern is also allowed in such case.
 *
 * NULL pattern handling therefore follows directly from mode selection:
 *
 * - empty fallback accepts NULL pattern
 * - all other modes require non-NULL pattern
 *
 * Pattern matching mode summary:
 *
 * - graph only: graph != NULL, pattern_parse == NULL
 * - callback only: graph == NULL, pattern_parse != NULL
 * - callback + graph: graph != NULL, pattern_parse != NULL
 * - empty fallback: graph == NULL, pattern_parse == NULL
 *
 * In callback + graph mode, the callback does not remove items from the
 * original pattern stream. The graph parser still sees the same pattern, so the
 * graph should define its `ignore_nodes` list appropriately.
 *
 * There is no way to completely ignore pattern contents for the engine except
 * for defining a noop `pattern_parse` callback. This is by design, as such case
 * is considered rte_flow API misuse. By default, even for empty fallback case,
 * a meaningful pattern (one that is not empty or ANY) will be treated as error.
 */

/* forward declarations for flow engine data types */
struct ci_flow_engine_ops;
struct ci_flow_engine_ctx;
struct ci_flow_engine;
struct ci_flow_engine_ref;
struct ci_flow_engine_list;
struct ci_flow_engine_conf;
struct ci_flow;

/*
 * Flow engine ops.
 *
 * Each flow engine must provide a set of operations to handle common
 * operations, such as:
 *
 * - Initialize and clean up engine resources (engine_init/engine_uninit)
 * - Allocate memory for flow rules (flow_alloc)
 * - Parse flow attributes and actions into engine-specific context (ctx_parse)
 * - Parse pattern into engine-specific context (pattern_parse)
 * - Pattern graph to use when parsing flow patterns (see `ci_flow_engine`)
 * - Validate the parsed attributes and actions against the data parsed from
 *   pattern (ctx_validate)
 * - Build the actual flow rule structure from the parsed context (ctx_to_flow)
 * - Add/remove the flow rule to/from hardware or driver's internal state
 *   (flow_install/flow_uninstall)
 * - Query data for the flow rule (flow_query)
 *
 * The intended flow and semantics is as follows:
 *
 * - at init time:
 *   [engine_init]
 *
 * - at reset/uninit time:
 *   [engine_uninit]
 *
 * - at rte_flow_validate time:
 *   ctx_parse -> [pattern_parse] -> [graph parser] -> [ctx_validate] -> [ctx_to_flow]
 *
 * - at rte_flow_create time:
 *   [flow_alloc] -> ctx_parse -> [pattern_parse] -> [graph parser] -> [ctx_validate] -> [ctx_to_flow] -> [flow_install]
 *
 * - at rte_flow_destroy/rte_flow_flush time:
 *   [flow_uninstall] -> [flow_free]
 *
 * - at rte_flow_query time:
 *   [flow_query]
 *
 * 1) Engine availability and lifecycle
 *
 * The engine availability can be checked by the driver at init time. The exact
 * mechanics of this is left up to each individual driver - it may be hardware
 * capability bits, PHY type check, devargs, or any other criteria that makes
 * sense in the context of driver/adapter. If the engine_init callback is not
 * implemented, the engine is assumed to be always available.
 *
 * If `priv_size` is non-zero, the framework allocates a zeroed private block
 * and passes it to engine_init/engine_uninit. Each allocated flow will also
 * carry a pointer to this per-device private data in `flow->engine_priv`.
 *
 * 2) Input parsing
 *
 * `ctx_parse` is mandatory and acts as the main gateway for parsing actions and
 * attributes into engine context.
 *
 * Patterns are matched either against the pattern graph provided by the
 * `ci_flow_engine`, or by the `pattern_parse` callback, or both.
 *
 * Pattern handling mode is selected from graph/callback presence:
 *
 * - graph only: graph parser runs
 * - callback only: pattern_parse runs
 * - callback + graph: pattern_parse runs, then graph parser runs
 * - neither graph nor callback: empty fallback matcher is used
 *
 * Empty fallback matcher accepts:
 *
 * - NULL pattern
 * - empty pattern (start -> end)
 * - ANY-only pattern (start -> any -> end)
 *
 * Any other patterns will be rejected by the empty path.
 *
 * 3) Consistency check
 *
 * `ctx_validate` is an optional final check for consistency between parsed
 * action/attribute data and pattern-derived data.
 *
 * 4) Rule materialization
 *
 * `ctx_to_flow` translates parsed context into the concrete engine-specific
 * flow rule representation. As a general guideline, flow rule should not
 * contain anything that isn't useful for rule installation or querying. All
 * of the temporary data should be stored in the engine context, while the
 * rule should only contain data that is pertinent to flow programming.
 *
 * 5) Rule lifecycle hooks:
 *
 * `flow_alloc`/`flow_free` are optional custom object lifecycle callbacks.
 * If `flow_alloc` is not provided (or returns NULL), the framework falls back
 * to rte_zmalloc-based allocation. If allocation callback exists, `flow_free`
 * must exist as well.
 *
 * Contract: flow_alloc/flow_free are allocation-policy callbacks only. They
 * may allocate memory and update allocator-associated state, but must not
 * produce parse-time semantics that engine callbacks depend on.
 *
 * In particular, ctx_parse/pattern_parse/ctx_validate/ctx_to_flow must remain
 * correct without any flow_alloc-specific side effects (e.g. on validate path).
 *
 * The engines only own engine-specific fields. The common `ci_flow` fields
 * (engine_idx, engine_priv, fallback_alloc, dev_data, node) are owned and
 * managed by the framework.
 *
 * `flow_install`/`flow_uninstall` are optional hooks that synchronize accepted
 * rules with hardware and/or driver internal state. If the engine requires
 * per-flow allocations, this is the place to make them.
 *
 * IMPORTANT: by the time flow_install is called, the engine has already
 * accepted the flow through ctx_parse/ctx_validate/ctx_to_flow. A failure in
 * flow_install (e.g. hardware resource exhaustion) is treated as a hard
 * failure: no other engines will be tried. It is therefore implied that if the
 * flow parser has accepted the flow, it should in principle be installable -
 * any checks that would prevent that from happening that are intrinsic to the
 * pattern itself should have been done at parse/validate stage.
 *
 * 6) Flow query
 *
 * For querying data, the flow_query function is provided to query data for the
 * flow rule. The engine may not provide this function, in which case any
 * attempt to query the rule will result in failure.
 *
 * 7) Concurrency model
 *
 * The framework serializes access to each driver instance's flow state with a
 * single rwlock. Create, destroy and flush take it exclusively (write);
 * validate and query take it shared (read). Consequently the parse-phase
 * callbacks (ctx_parse, pattern_parse, ctx_validate, ctx_to_flow) can run
 * concurrently with each other on the validate path, and flow_query can run
 * concurrently with other queries. These callbacks must treat shared engine
 * state - including engine_priv - as read-only and must not mutate it. State
 * mutation belongs in the write-locked callbacks (engine_init/engine_uninit,
 * flow_alloc/flow_free, flow_install/flow_uninstall).
 */
struct ci_flow_engine_ops {
	/* engine init callback - can be NULL */
	int (*engine_init)(const struct ci_flow_engine *engine,
			struct rte_eth_dev_data *dev_data,
			void *priv);
	/* engine uninit callback - can be NULL */
	void (*engine_uninit)(const struct ci_flow_engine *engine,
			void *priv);
	/* allocation callback for flow rules - can be NULL */
	struct ci_flow *(*flow_alloc)(const struct ci_flow_engine *engine,
			struct rte_eth_dev_data *dev_data,
			void *priv);
	/* deallocation callback for flow rules - can be NULL */
	void (*flow_free)(struct ci_flow *flow,
			struct rte_eth_dev_data *dev_data,
			void *priv);
	/* initialize engine context from flow attr/actions - mandatory */
	int (*ctx_parse)(const struct rte_flow_action actions[],
			const struct rte_flow_attr *attr,
			struct ci_flow_engine_ctx *ctx,
			struct rte_flow_error *error);
	/* pattern parsing callback - can be NULL */
	int (*pattern_parse)(struct ci_flow_engine_ctx *ctx,
			const struct rte_flow_item pattern[],
			struct rte_flow_error *error);
	/* final pass before converting context to flow - can be NULL */
	int (*ctx_validate)(struct ci_flow_engine_ctx *ctx,
			struct rte_flow_error *error);
	/* initialize flow rule from parsed context - can be NULL */
	int (*ctx_to_flow)(const struct ci_flow_engine_ctx *ctx,
			struct ci_flow *flow,
			struct rte_flow_error *error);
	/* install a flow rule - can be NULL */
	int (*flow_install)(struct ci_flow *flow,
			struct rte_flow_error *error);
	/* uninstall a flow rule - can be NULL */
	int (*flow_uninstall)(struct ci_flow *flow,
			struct rte_flow_error *error);
	/* query flow - can be NULL */
	int (*flow_query)(struct ci_flow *flow,
			const struct rte_flow_action *action,
			void *data,
			struct rte_flow_error *error);
};

/*
 * common definition for flow engine context.
 * each engine will define its own context structure that
 * *must* start with this base structure.
 */
struct ci_flow_engine_ctx {
	/* ethernet device this context belongs to */
	struct rte_eth_dev_data *dev_data;
};

/*
 * Common definition for flow rule.
 *
 * For flow rules, there are three parts to consider:
 *
 * 1) Common data
 * 2) Driver-specific data
 * 3) Engine-specific data
 *
 * The common data is defined here as the `ci_flow` structure. It contains
 * fields that are common to all flow rules, regardless of driver or engine.
 * This includes a linked list node for managing flow rules in a list, a pointer
 * to the device (driver instance) the flow belongs to, and the engine index
 * that created the flow.
 *
 * With rte_flow API, each driver is meant to define its own rte_flow structure
 * that contains driver-specific data. This structure must start with the
 * `ci_flow` structure defined here, followed by driver-specific fields.
 *
 * Additionally, each *engine* may want to define its own flow rule structure
 * that contains actual engine-specific data. This structure must start with the
 * driver-wide `rte_flow` structure such that it contains everything before it,
 * followed by engine-specific fields.
 *
 * IMPORTANT:
 *
 * All of these structures will be referred to by the same pointer and can be
 * freely (and safely) cast between each other *as long as* each structure
 * definition has the parent structure as its first member. E.g. the common flow
 * struct is `ci_flow`, and the driver-specific `rte_flow` must be defined as
 * follows:
 *
 * struct rte_flow {
 *     struct ci_flow base;
 *     ...any driver-specific fields...
 * }
 *
 * If the engine needs to define its own flow structure, in turn it should be
 * defined as follows:
 *
 * struct ixgbe_fdir_flow {
 *     struct rte_flow base;
 *     ...any engine-specific fields...
 * }
 *
 * This ensures pointer conversion safety between all three types:
 *
 *     struct ci_flow *flow = ...;
 *     struct rte_flow *rte_flow = (struct rte_flow *)flow;
 *     struct ixgbe_fdir_flow *fdir_flow = (struct ixgbe_fdir_flow *)flow;
 *
 * The engine structure provides a `flow_size` field that indicates how much
 * memory is required for a particular engine's flow structure. The driver must
 * provide that value for each engine, as it will be used to size flow structure
 * allocations. If the engine does not require any memory beyond the `rte_flow`
 * structure, this value should be set to `sizeof(rte_flow)` for those engines.
 *
 * Engine references and engine_idx:
 *
 * The engine index is treated as the engine type discriminator and is stored in
 * every flow. Runtime code then reconstructs a `ci_flow_engine_ref`
 * (engine pointer + index) from the immutable engine list and this stored
 * index. This gives two important guarantees:
 *
 * - The framework works only with immutable engine definitions/lists.
 * - We avoid repeated pointer-to-index lookups after flow creation; rebuilding
 *   a ref from index is direct and keeps call sites explicit about both values.
 *
 * This is particularly important for secondary-process compatibility where the
 * index is the stable identity and pointer values are only meaningful in the
 * context of the shared immutable engine list.
 *
 * Code that works with engine pointers and engine indices should be careful,
 * and should treat engine references as the basic building block.
 *
 * Per-engine private data (engine_priv):
 *
 * Each flow will also carry a pointer to engine-private data, to allow for
 * reaching engine-specific data, such as custom allocation structures to
 * be used with flow_alloc/flow_free at allocation time.
 */
struct ci_flow {
	TAILQ_ENTRY(ci_flow) node;
	/* device this flow belongs to */
	struct rte_eth_dev_data *dev_data;
	/* index of engine this flow was created by */
	size_t engine_idx;
	/* per-engine private data pointer, set by the framework at alloc time */
	void *engine_priv;
	/* set if engine allocator callback existed but fallback allocator was used */
	bool fallback_alloc;
};

/* flow engine definition */
struct ci_flow_engine {
	/* engine name */
	const char *name;
	/* size of scratch space structure, can be 0 */
	size_t ctx_size;
	/* size of flow rule structure, must not be 0 */
	size_t flow_size;
	/* size of per-device engine private data, can be 0 */
	size_t priv_size;
	/* ops for this flow engine */
	const struct ci_flow_engine_ops *ops;
	/* pattern graph this engine supports - can be NULL */
	const struct rte_flow_graph *graph;
};

/* engine reference: immutable engine pointer paired with its list index */
struct ci_flow_engine_ref {
	const struct ci_flow_engine *engine;
	size_t engine_idx;
};

#define CI_FLOW_ENGINE_MAX	64

/* flow engine list definition */
struct ci_flow_engine_list {
	/* NULL-terminated immutable array of flow engine pointers */
	const struct ci_flow_engine * const engines[CI_FLOW_ENGINE_MAX];
};

/* flow engine configuration - each device must have its own instance */
struct ci_flow_engine_conf {
	/* lock to protect config */
	rte_rwlock_t config_lock;
	/* list of flows created on this device */
	TAILQ_HEAD(ci_flow_list, ci_flow) flows;
	/* bitmask of enabled engines */
	uint64_t enabled_engines;
	/* back-reference to device structure */
	struct rte_eth_dev_data *dev_data;
	/* reference to the driver's engine list */
	const struct ci_flow_engine_list *engines;
	/* per-engine private data pointers, indexed by engine index */
	void *engine_priv[CI_FLOW_ENGINE_MAX];
};

/* build engine ref from engine config and engine index - thread-unsafe */
static inline struct ci_flow_engine_ref
ci_flow_engine_ref_from_idx(const struct ci_flow_engine_conf *engine_conf,
		const size_t engine_idx)
{
	/* check if valid reference can be constructed at all */
	if (engine_conf == NULL || engine_conf->engines == NULL ||
			engine_idx >= CI_FLOW_ENGINE_MAX) {
		return (struct ci_flow_engine_ref) {
			.engine = NULL,
			.engine_idx = CI_FLOW_ENGINE_MAX
		};
	}

	return (struct ci_flow_engine_ref) {
		.engine = engine_conf->engines->engines[engine_idx],
		.engine_idx = engine_idx,
	};
}

/* helper macro to iterate over list of engines as engine refs */
#define CI_FLOW_ENGINE_LIST_FOREACH(engine_ref, engine_conf)                         \
	for (size_t __ci_flow_engine_idx = 0;                                        \
		__ci_flow_engine_idx < CI_FLOW_ENGINE_MAX &&                         \
			(((engine_ref) = ci_flow_engine_ref_from_idx((engine_conf),  \
		__ci_flow_engine_idx)).engine != NULL);                              \
		__ci_flow_engine_idx++)

/* basic checks for flow engine validity */
static inline bool
ci_flow_engine_is_valid(const struct ci_flow_engine *engine)
{
	/* is the pointer valid? */
	if (engine == NULL)
		return false;
	/* does the engine have a name? */
	if (engine->name == NULL)
		return false;
	/* does the engine have ops? */
	if (engine->ops == NULL)
		return false;
	/* does the engine have mandatory ctx_parse op? */
	if (engine->ops->ctx_parse == NULL)
		return false;
	/* flow size cannot be less than ci_flow */
	if (engine->flow_size < sizeof(struct ci_flow))
		return false;
	/* alloc and free must both be defined or NULL */
	if ((engine->ops->flow_alloc == NULL) != (engine->ops->flow_free == NULL))
		return false;
	/* engine looks valid */
	return true;
}

/* helper to check whether an engine is enabled in the bitmask - thread-unsafe */
static inline bool
ci_flow_engine_is_enabled(const struct ci_flow_engine_conf *conf,
		const size_t engine_idx)
{
	return (conf->enabled_engines & (1ULL << engine_idx)) != 0;
}

/* helper to enable an engine in the bitmask - thread-unsafe */
static inline void
ci_flow_engine_set_enabled(struct ci_flow_engine_conf *conf, const size_t engine_idx,
		bool enabled)
{
	if (enabled)
		conf->enabled_engines |= (1ULL << engine_idx);
	else
		conf->enabled_engines &= ~(1ULL << engine_idx);
}

static inline struct ci_flow *
ci_flow_alloc(const struct ci_flow_engine_conf *engine_conf,
		struct ci_flow_engine_ref engine_ref)
{
	const struct ci_flow_engine *engine = engine_ref.engine;
	void *priv = engine_conf->engine_priv[engine_ref.engine_idx];
	struct ci_flow *flow = NULL;
	bool fallback = false;

	/* if engine has an allocator callback, try it first */
	if (engine->ops->flow_alloc != NULL)
		flow = engine->ops->flow_alloc(engine, engine_conf->dev_data, priv);
	/* if allocator callback is not defined or failed, use default allocator */
	if (flow == NULL) {
		flow = (struct ci_flow *)rte_zmalloc(NULL, engine->flow_size, 0);

		/* if callback exists and we're here, allocation has fallen back */
		if (flow != NULL && engine->ops->flow_alloc != NULL)
			fallback = true;
	}
	/* set the engine data to enable correct deallocation in case of failure */
	if (flow != NULL) {
		/* erase the common parts - the rest is left up to the engine */
		memset(flow, 0, sizeof(struct ci_flow));
		flow->fallback_alloc = fallback;
		flow->engine_idx = engine_ref.engine_idx;
		flow->dev_data = engine_conf->dev_data;
		flow->engine_priv = priv;
	}
	return flow;
}

static inline void
ci_flow_free(struct ci_flow_engine_ref engine_ref, struct ci_flow *flow)
{
	const struct ci_flow_engine *engine = engine_ref.engine;

	if (engine->ops->flow_free != NULL && !flow->fallback_alloc)
		engine->ops->flow_free(flow, flow->dev_data, flow->engine_priv);
	else
		rte_free(flow);
}

/* allocate per-device engine private data and call init - thread-unsafe */
static inline int
ci_flow_engine_init(struct ci_flow_engine_conf *engine_conf,
		struct ci_flow_engine_ref engine_ref)
{
	const struct ci_flow_engine *engine = engine_ref.engine;
	void *priv = NULL;
	int ret;

	if (engine->priv_size > 0) {
		priv = rte_zmalloc(engine->name, engine->priv_size, 0);
		if (priv == NULL) {
			ret = -ENOMEM;
			goto err;
		}
	}

	if (engine->ops->engine_init != NULL) {
		ret = engine->ops->engine_init(engine, engine_conf->dev_data, priv);
		if (ret != 0)
			goto err;
	}
	engine_conf->engine_priv[engine_ref.engine_idx] = priv;
	return 0;
err:
	rte_free(priv);
	return ret;
}

/* call uninit and free per-device engine private data - thread-unsafe */
static inline void
ci_flow_engine_uninit(struct ci_flow_engine_conf *engine_conf,
		struct ci_flow_engine_ref engine_ref)
{
	const struct ci_flow_engine *engine = engine_ref.engine;
	void *priv;

	priv = engine_conf->engine_priv[engine_ref.engine_idx];

	CI_DRV_LOG(DEBUG, "engine '%s': uninit", engine->name);
	/* ignore uninit errors */
	if (engine->ops->engine_uninit != NULL)
		engine->ops->engine_uninit(engine, priv);

	if (priv != NULL) {
		rte_free(priv);
		engine_conf->engine_priv[engine_ref.engine_idx] = NULL;
	}
}

/* disable all engines for a specific driver instance - thread-safe */
static inline void
ci_flow_engine_conf_reset(struct ci_flow_engine_conf *engine_conf)
{
	struct ci_flow_engine_ref engine_ref;
	struct ci_flow *flow, *tmp;

	/* lock the config */
	rte_rwlock_write_lock(&engine_conf->config_lock);

	/* free all flows - shouldn't have any at this point */
	RTE_TAILQ_FOREACH_SAFE(flow, &engine_conf->flows, node, tmp) {
		TAILQ_REMOVE(&engine_conf->flows, flow, node);
		/* can't make it into the list if this was invalid, so no checks */
		engine_ref = ci_flow_engine_ref_from_idx(engine_conf, flow->engine_idx);
		ci_flow_free(engine_ref, flow);
	}

	CI_FLOW_ENGINE_LIST_FOREACH(engine_ref, engine_conf) {
		if (!ci_flow_engine_is_enabled(engine_conf, engine_ref.engine_idx))
			continue;
		/* ignore errors */
		ci_flow_engine_uninit(engine_conf, engine_ref);
		ci_flow_engine_set_enabled(engine_conf,
				engine_ref.engine_idx, false);
	}

	/* erase device pointer */
	engine_conf->dev_data = NULL;
	engine_conf->engines = NULL;

	/* unlock the config */
	rte_rwlock_write_unlock(&engine_conf->config_lock);
}

/* enable all engines for a specific driver instance - thread-unsafe */
static inline int
ci_flow_engine_conf_init(struct ci_flow_engine_conf *engine_conf,
		const struct ci_flow_engine_list *engine_list,
		struct rte_eth_dev_data *dev_data)
{
	struct ci_flow_engine_ref engine_ref;

	/* reject invalid configuration */
	if (engine_conf == NULL || engine_list == NULL || dev_data == NULL)
		return -1;

	/* init the lock */
	rte_rwlock_init(&engine_conf->config_lock);

	/* store data in conf */
	engine_conf->dev_data = dev_data;
	engine_conf->engines = engine_list;

	/* init the flow list */
	TAILQ_INIT(&engine_conf->flows);

	/* enable all engines */
	CI_FLOW_ENGINE_LIST_FOREACH(engine_ref, engine_conf) {
		/* skip invalid engines */
		if (!ci_flow_engine_is_valid(engine_ref.engine)) {
			CI_DRV_LOG(DEBUG, "engine[%zu]: invalid, skipping",
					engine_ref.engine_idx);
			continue;
		}
		if (ci_flow_engine_init(engine_conf, engine_ref) != 0) {
			CI_DRV_LOG(DEBUG, "engine '%s': init failed, skipping",
					engine_ref.engine->name);
			continue;
		}

		ci_flow_engine_set_enabled(engine_conf,
				engine_ref.engine_idx, true);
		CI_DRV_LOG(DEBUG, "engine '%s': enabled", engine_ref.engine->name);
	}
	return 0;
}

/* validate whether a flow is valid for a specific engine configuration - thread-unsafe */
static inline bool
ci_flow_is_valid(const struct ci_flow *flow,
		const struct ci_flow_engine_conf *engine_conf)
{
	/* is the pointer valid? */
	if (flow == NULL)
		return false;
	/* is the conf initialized? */
	if (engine_conf == NULL || engine_conf->dev_data == NULL ||
			engine_conf->engines == NULL)
		return false;
	/* does the flow belong to this device? */
	if (flow->dev_data != engine_conf->dev_data)
		return false;
	/* can we find the engine that created this flow? */
	if (flow->engine_idx >= CI_FLOW_ENGINE_MAX)
		return false;
	/* engine must be enabled */
	if (!ci_flow_engine_is_enabled(engine_conf, flow->engine_idx))
		return false;
	/* flow looks valid */
	return true;
}

/* default empty pattern graph definitions */
enum ci_flow_empty_graph_node_id {
	CI_FLOW_EMPTY_GRAPH_NODE_START = RTE_FLOW_NODE_FIRST,
	CI_FLOW_EMPTY_GRAPH_NODE_ANY,
	CI_FLOW_EMPTY_GRAPH_NODE_END,
};

static const struct rte_flow_graph ci_flow_empty_graph = {
	.nodes = (struct rte_flow_graph_node []) {
		[CI_FLOW_EMPTY_GRAPH_NODE_START] = {
			.name = "START",
		},
		[CI_FLOW_EMPTY_GRAPH_NODE_ANY] = {
			.name = "ANY",
			.type = RTE_FLOW_ITEM_TYPE_ANY,
			.constraints = RTE_FLOW_NODE_EXPECT_EMPTY,
		},
		[CI_FLOW_EMPTY_GRAPH_NODE_END] = {
			.name = "END",
			.type = RTE_FLOW_ITEM_TYPE_END,
		},
	},
	.edges = (struct rte_flow_graph_edge []) {
		[CI_FLOW_EMPTY_GRAPH_NODE_START] = {
			.next = (const size_t []) {
				CI_FLOW_EMPTY_GRAPH_NODE_ANY,
				CI_FLOW_EMPTY_GRAPH_NODE_END,
				RTE_FLOW_NODE_EDGE_END,
			},
		},
		[CI_FLOW_EMPTY_GRAPH_NODE_ANY] = {
			.next = (const size_t []) {
				CI_FLOW_EMPTY_GRAPH_NODE_END,
				RTE_FLOW_NODE_EDGE_END,
			},
		},
	}
};

/* concrete pattern-matching mode selected from graph/callback presence */
enum ci_match_type {
	CI_MATCH_EMPTY,    /* no graph, no callback */
	CI_MATCH_CALLBACK, /* callback only */
	CI_MATCH_GRAPH,    /* graph only */
	CI_MATCH_ALL,      /* callback + graph */
};

/*
 * helper to match a pattern against an engine's pattern graph and/or callback,
 * depending on the match type. Thread-unsafe.
 */
static inline int
ci_flow_match(const struct ci_flow_engine *engine,
		const struct rte_flow_item pattern[],
		struct ci_flow_engine_ctx *ctx,
		enum ci_match_type match_type,
		struct rte_flow_error *error)
{
	switch (match_type) {
	case CI_MATCH_EMPTY:
		/* for empty matching, NULL pattern is not an error */
		if (pattern != NULL) {
			return rte_flow_graph_parse(&ci_flow_empty_graph,
					pattern, error, ctx);
		}
		return 0;

	case CI_MATCH_CALLBACK:
		/* for callback matching, pattern cannot be NULL */
		if (pattern == NULL) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					"Pattern cannot be NULL");
		}
		return engine->ops->pattern_parse(ctx, pattern, error);

	case CI_MATCH_GRAPH:
		/* for graph matching, pattern cannot be NULL */
		if (pattern == NULL) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					"Pattern cannot be NULL");
		}
		return rte_flow_graph_parse(engine->graph, pattern, error, ctx);

	case CI_MATCH_ALL:
	{
		int ret;

		/* for callback + graph matching, pattern cannot be NULL */
		if (pattern == NULL) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM, NULL,
					"Pattern cannot be NULL");
		}
		ret = engine->ops->pattern_parse(ctx, pattern, error);
		if (ret != 0)
			return ret;
		return rte_flow_graph_parse(engine->graph, pattern, error, ctx);
	}

	default:
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				"Invalid match type");
	}
}

/* parse a flow using a specific engine - thread-unsafe */
static inline int
ci_flow_parse(const struct ci_flow_engine_conf *engine_conf,
		const struct ci_flow_engine *engine,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct ci_flow *flow,
		struct rte_flow_error *error)
{
	enum ci_match_type match_type;
	struct ci_flow_engine_ctx *ctx;
	int ret = 0;

	/*
	 * Determine the type of matching we are going to perform based on the
	 * presence of pattern graph and pattern_parse callback. The logic is as
	 * follows:
	 *
	 * - if graph but no callback, match against graph
	 *
	 * Expected default case: pattern matching is graph based, no special
	 * handling for any pattern items.
	 *
	 * - if both graph and callback, match against callback + graph
	 *
	 * Preprocessor case, i.e. preprocess the pattern with the callback
	 * before handling the matching to the graph engine. The assumption is
	 * that the graph will be set up with a proper ignore list to skip over
	 * nodes that weren't meant for the graph processing.
	 *
	 * - if no graph but callback, match against callback
	 *
	 * Fully custom pattern parsing case.
	 *
	 * - if no graph and no callback, match against empty graph
	 *
	 * "Pattern is not meaningful" case, for engines that do not care about
	 * the pattern at all. A default matching behavior against empty
	 * patterns is provided (i.e. allow NULL pattern, and allow END or ANY
	 * -> END patterns). Note that this is not the same as ignoring pattern
	 * entirely: the engine will still reject patterns that are not empty.
	 */
	match_type = engine->graph == NULL ?
		(engine->ops->pattern_parse == NULL ? CI_MATCH_EMPTY : CI_MATCH_CALLBACK) :
		(engine->ops->pattern_parse == NULL ? CI_MATCH_GRAPH : CI_MATCH_ALL);

	CI_DRV_LOG(DEBUG, "engine '%s': parsing flow", engine->name);

	/* allocate context */
	ctx = (struct ci_flow_engine_ctx *)calloc(1,
			RTE_MAX(engine->ctx_size, sizeof(struct ci_flow_engine_ctx)));
	if (ctx == NULL) {
		return rte_flow_error_set(error, ENOMEM,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Failed to allocate memory for rule engine context");
	}
	ctx->dev_data = engine_conf->dev_data;
	flow->dev_data = engine_conf->dev_data;

	/* parse flow parameters */
	ret = engine->ops->ctx_parse(actions, attr, ctx, error);

	/* context init failed - that means engine can't be used for this flow */
	if (ret != 0)
		goto free_ctx;

	/* match the pattern */
	ret = ci_flow_match(engine, pattern, ctx, match_type, error);

	/* check if pattern didn't match */
	if (ret != 0)
		goto free_ctx;

	/* final verification, if the operation is defined */
	if (engine->ops->ctx_validate != NULL)
		ret = engine->ops->ctx_validate(ctx, error);

	/* finalization failed - mismatch between parsed data and context data */
	if (ret != 0)
		goto free_ctx;

	/* if we need to build rules from context, do it */
	if (engine->ops->ctx_to_flow != NULL) {
		ret = engine->ops->ctx_to_flow(ctx, flow, error);

		/* flow building failed - something wrong with context data */
		if (ret != 0)
			goto free_ctx;
	}
	/* success */
	ret = 0;

free_ctx:
	free(ctx);
	return ret;
}

/* install a flow using its appropriate engine - thread-unsafe */
static inline int
ci_flow_install(struct ci_flow_engine_ref engine_ref,
		struct ci_flow *flow,
		struct rte_flow_error *error)
{
	const struct ci_flow_engine *engine = engine_ref.engine;

	if (engine->ops->flow_install != NULL)
		return engine->ops->flow_install(flow, error);

	return 0;
}

/* uninstall a flow using its appropriate engine - thread-unsafe */
static inline int
ci_flow_uninstall(struct ci_flow_engine_ref engine_ref,
		struct ci_flow *flow,
		struct rte_flow_error *error)
{
	const struct ci_flow_engine *engine = engine_ref.engine;

	/* uninstall the flow if required */
	if (engine->ops->flow_uninstall != NULL)
		return engine->ops->flow_uninstall(flow, error);

	return 0;
}

/*
 * The following functions are designed to be called from the context of
 * rte_flow API implementations and are provided as default implementations.
 *
 * Thread-safe.
 */

/* default implementation of rte_flow_create using flow engines */
static inline struct rte_flow *
ci_flow_create(struct ci_flow_engine_conf *engine_conf,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct ci_flow_engine_ref engine_ref;
	struct ci_flow *flow = NULL;
	int ret;

	if (attr == NULL || actions == NULL) {
		CI_DRV_LOG(DEBUG, "attr or actions is NULL");
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ATTR, NULL,
				"Attributes and actions cannot be NULL");
		return NULL;
	}

	/* lock the config for writing */
	rte_rwlock_write_lock(&engine_conf->config_lock);

	/* find an engine that can handle this flow */
	CI_FLOW_ENGINE_LIST_FOREACH(engine_ref, engine_conf) {
		if (!ci_flow_engine_is_enabled(engine_conf, engine_ref.engine_idx))
			continue;

		flow = ci_flow_alloc(engine_conf, engine_ref);
		if (flow == NULL) {
			CI_DRV_LOG(DEBUG, "engine '%s': failed to allocate flow",
					engine_ref.engine->name);
			rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to allocate memory for flow rule");
			/* this is a serious error so don't continue */
			goto unlock;
		}

		ret = ci_flow_parse(engine_conf, engine_ref.engine, attr, pattern,
				actions, flow, error);

		/* parsing failed - free the flow and try next engine */
		if (ret != 0) {
			ci_flow_free(engine_ref, flow);
			if (error != NULL)
				CI_DRV_LOG(DEBUG, "engine '%s' rejected flow: %s",
						engine_ref.engine->name, error->message);
			else
				CI_DRV_LOG(DEBUG, "engine '%s' rejected flow",
						engine_ref.engine->name);
			continue;
		}

		CI_DRV_LOG(DEBUG, "engine '%s' accepted flow, installing",
				engine_ref.engine->name);

		/* engine accepted the flow - install is now a hard commitment */
		ret = ci_flow_install(engine_ref, flow, error);
		if (ret != 0) {
			/* install failed after parse accepted - this is an
			 * engine bug, do not try other engines
			 */
			if (error != NULL)
				CI_DRV_LOG(DEBUG, "engine '%s' install failed: %s",
						engine_ref.engine->name, error->message);
			else
				CI_DRV_LOG(DEBUG, "engine '%s' install failed",
						engine_ref.engine->name);
			ci_flow_free(engine_ref, flow);
			flow = NULL;
			goto unlock;
		}

		CI_DRV_LOG(DEBUG, "flow installed by engine '%s'",
				engine_ref.engine->name);
		/* success */
		TAILQ_INSERT_TAIL(&engine_conf->flows, flow, node);
		goto unlock;
	}

	/* no engine could handle this flow */
	CI_DRV_LOG(DEBUG, "no engine accepted the flow");
	flow = NULL;
	rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"No flow engine could handle the requested flow");
unlock:
	rte_rwlock_write_unlock(&engine_conf->config_lock);

	return (struct rte_flow *)flow;
}

/* default implementation of rte_flow_validate using flow engines */
static inline int
ci_flow_validate(struct ci_flow_engine_conf *engine_conf,
		const struct rte_flow_attr *attr,
		const struct rte_flow_item pattern[],
		const struct rte_flow_action actions[],
		struct rte_flow_error *error)
{
	struct ci_flow_engine_ref engine_ref;
	int ret;

	if (attr == NULL || actions == NULL) {
		CI_DRV_LOG(DEBUG, "attr or actions is NULL");
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ATTR, NULL,
				"Attributes and actions cannot be NULL");
	}

	/* lock the config for reading */
	rte_rwlock_read_lock(&engine_conf->config_lock);

	/* find an engine that can handle this flow */
	CI_FLOW_ENGINE_LIST_FOREACH(engine_ref, engine_conf) {
		struct ci_flow *flow;

		if (!ci_flow_engine_is_enabled(engine_conf, engine_ref.engine_idx))
			continue;

		/* use OS allocator as we're not keeping the flow */
		flow = (struct ci_flow *)calloc(1, engine_ref.engine->flow_size);
		if (flow == NULL) {
			/* this is a serious error so don't continue */
			CI_DRV_LOG(DEBUG, "engine '%s': failed to allocate flow",
					engine_ref.engine->name);
			ret = rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to allocate memory for flow rule");
			goto unlock;
		}
		/* set up the flow fields */
		flow->fallback_alloc = false;
		flow->engine_idx = engine_ref.engine_idx;
		flow->dev_data = engine_conf->dev_data;
		flow->engine_priv = engine_conf->engine_priv[engine_ref.engine_idx];

		/* try to parse the flow with this engine */
		ret = ci_flow_parse(engine_conf, engine_ref.engine, attr, pattern,
				actions, flow, error);
		free(flow);

		if (ret == 0) {
			CI_DRV_LOG(DEBUG, "engine '%s' accepted flow",
					engine_ref.engine->name);
			goto unlock;
		} else if (error != NULL) {
			CI_DRV_LOG(DEBUG, "engine '%s' rejected flow: %s",
					engine_ref.engine->name, error->message);
		} else {
			CI_DRV_LOG(DEBUG, "engine '%s' rejected flow",
					engine_ref.engine->name);
		}
	}
	/* no engine could handle this flow */
	CI_DRV_LOG(DEBUG, "no engine accepted the flow");
	ret = rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"No flow engine could handle the requested flow");
unlock:
	rte_rwlock_read_unlock(&engine_conf->config_lock);
	return ret;
}

/* default implementation of rte_flow_destroy using flow engines. */
static inline int
ci_flow_destroy(struct ci_flow_engine_conf *engine_conf,
		struct rte_flow *rte_flow,
		struct rte_flow_error *error)
{
	struct ci_flow *flow = (struct ci_flow *)rte_flow;
	struct ci_flow_engine_ref engine_ref;
	int ret = 0;

	if (rte_flow == NULL) {
		CI_DRV_LOG(DEBUG, "flow handle is NULL");
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Flow handle cannot be NULL");
	}

	/* lock the config for writing */
	rte_rwlock_write_lock(&engine_conf->config_lock);

	/* validate the flow */
	if (!ci_flow_is_valid(flow, engine_conf)) {
		CI_DRV_LOG(DEBUG, "invalid flow handle");
		ret = rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Invalid flow handle");
		goto unlock;
	}
	engine_ref = ci_flow_engine_ref_from_idx(engine_conf, flow->engine_idx);
	CI_DRV_LOG(DEBUG, "uninstalling flow (engine '%s')",
			engine_ref.engine->name);

	ret = ci_flow_uninstall(engine_ref, flow, error);

	if (ret != 0) {
		if (error != NULL)
			CI_DRV_LOG(DEBUG, "uninstall failed: %s", error->message);
		else
			CI_DRV_LOG(DEBUG, "uninstall failed");
		goto unlock;
	}

	/* remove the flow from the list and free it */
	TAILQ_REMOVE(&engine_conf->flows, flow, node);
	ci_flow_free(engine_ref, flow);
unlock:
	rte_rwlock_write_unlock(&engine_conf->config_lock);

	return ret;
}

/* default implementation of rte_flow_flush using flow engines */
static inline int
ci_flow_flush(struct ci_flow_engine_conf *engine_conf,
		struct rte_flow_error *error)
{
	struct ci_flow *flow, *tmp;

	CI_DRV_LOG(DEBUG, "removing all flows");

	/* lock the config for writing */
	rte_rwlock_write_lock(&engine_conf->config_lock);

	/* iterate over all flows and uninstall them */
	RTE_TAILQ_FOREACH_SAFE(flow, &engine_conf->flows, node, tmp) {
		struct ci_flow_engine_ref engine_ref;

		/* this shouldn't happen */
		if (!ci_flow_is_valid(flow, engine_conf))
			continue;

		engine_ref = ci_flow_engine_ref_from_idx(engine_conf,
				flow->engine_idx);

		/* ignore failures */
		ci_flow_uninstall(engine_ref, flow, error);

		TAILQ_REMOVE(&engine_conf->flows, flow, node);
		ci_flow_free(engine_ref, flow);
	}

	rte_rwlock_write_unlock(&engine_conf->config_lock);

	return 0;
}

/* default implementation of rte_flow_query using flow engines */
static inline int
ci_flow_query(struct ci_flow_engine_conf *engine_conf,
		struct rte_flow *rte_flow,
		const struct rte_flow_action *action,
		void *data,
		struct rte_flow_error *error)
{
	struct ci_flow *flow = (struct ci_flow *)rte_flow;
	struct ci_flow_engine_ref engine_ref;
	int ret;

	if (action == NULL || data == NULL) {
		CI_DRV_LOG(DEBUG, "action or data is NULL");
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION, NULL,
				"Action or data cannot be NULL");
	}

	/* lock the config for reading */
	rte_rwlock_read_lock(&engine_conf->config_lock);

	/* validate the flow first */
	if (!ci_flow_is_valid(flow, engine_conf)) {
		CI_DRV_LOG(DEBUG, "invalid flow handle");
		ret = rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Invalid flow handle");
		goto unlock;
	}
	/* find the engine that created this flow */
	engine_ref = ci_flow_engine_ref_from_idx(engine_conf, flow->engine_idx);
	/* query the flow if supported */
	if (engine_ref.engine->ops->flow_query != NULL) {
		ret = engine_ref.engine->ops->flow_query(flow, action, data, error);

		if (ret != 0 && error != NULL)
			CI_DRV_LOG(DEBUG, "engine '%s' query failed: %s",
					engine_ref.engine->name, error->message);
		else if (ret != 0)
			CI_DRV_LOG(DEBUG, "engine '%s' query failed",
					engine_ref.engine->name);
	} else {
		CI_DRV_LOG(DEBUG, "engine '%s' does not support querying",
				engine_ref.engine->name);
		ret = rte_flow_error_set(error, ENOTSUP,
			RTE_FLOW_ERROR_TYPE_UNSPECIFIED, NULL,
			"Flow engine does not support querying");
	}
unlock:
	rte_rwlock_read_unlock(&engine_conf->config_lock);

	return ret;
}

/* dump flow rule chunks using memdump - helper for ci_flow_dump */
#define CI_FLOW_DUMP_CHUNK_BYTES 32

static inline void
ci_flow_dump_one(FILE *file, const char *driver, const char *engine,
		const void *data, size_t data_len)
{
	const uint8_t *raw = (const uint8_t *)data;
	const size_t nchunks =
		(data_len + CI_FLOW_DUMP_CHUNK_BYTES - 1) /
		CI_FLOW_DUMP_CHUNK_BYTES;
	char title[64];
	size_t ci;

	fprintf(file, "FLOW DUMP: driver=%s engine=%s\n", driver, engine);
	fprintf(file, "FLOW DUMP: DATA size=%zu chunks=%zu chunk_bytes=%d\n",
		data_len, nchunks, CI_FLOW_DUMP_CHUNK_BYTES);

	for (ci = 0; ci < nchunks; ci++) {
		const size_t off = ci * CI_FLOW_DUMP_CHUNK_BYTES;
		const size_t clen =
			RTE_MIN((size_t)CI_FLOW_DUMP_CHUNK_BYTES,
				data_len - off);
		snprintf(title, sizeof(title), "FLOW DUMP: chunk %03zu/%03zu",
			 ci + 1, nchunks);
		rte_memdump(file, title, raw + off, clen);
	}
}

/* default implementation of rte_flow_dev_dump using flow engines */
static inline int
ci_flow_dump(struct ci_flow_engine_conf *engine_conf,
		struct rte_flow *flow,
		FILE *file,
		struct rte_flow_error *error)
{
	struct ci_flow_engine_ref engine_ref;
	struct ci_flow *cur;
	bool found = false;
	const char *driver_name =
#ifdef RTE_COMPONENT_NAME
			RTE_STR(RTE_COMPONENT_NAME);
#else
			"unknown";
#endif

	rte_rwlock_read_lock(&engine_conf->config_lock);

	TAILQ_FOREACH(cur, &engine_conf->flows, node) {
		const void *data;
		size_t data_len;

		if (flow != NULL && (struct rte_flow *)cur != flow)
			continue;

		/* is this flow valid? */
		if (!ci_flow_is_valid(cur, engine_conf)) {
			CI_DRV_LOG(DEBUG, "invalid flow handle: %p, skipping", cur);
			continue;
		}

		found = true;

		engine_ref = ci_flow_engine_ref_from_idx(engine_conf, cur->engine_idx);

		data = RTE_PTR_ADD(cur, sizeof(struct ci_flow));
		data_len = engine_ref.engine->flow_size - sizeof(struct ci_flow);

		/*
		 * when data_len is 0 the dump loop would not access the data
		 * pointer, but static analysis tools may flag this as a
		 * potential NULL dereference, so skip dump when data_len is 0.
		 */
		if (data_len == 0) {
			CI_DRV_LOG(DEBUG, "flow data length is 0, skipping dump");
			continue;
		}

		ci_flow_dump_one(file, driver_name, engine_ref.engine->name,
				data, data_len);
	}

	rte_rwlock_read_unlock(&engine_conf->config_lock);

	if (flow != NULL && !found) {
		return rte_flow_error_set(error, ENOENT,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"Flow not found");
	}

	return 0;
}

#endif /* _COMMON_INTEL_FLOW_ENGINE_H_ */
