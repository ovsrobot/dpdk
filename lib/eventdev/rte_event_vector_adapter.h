/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Marvell International Ltd.
 * All rights reserved.
 */

#ifndef __RTE_EVENT_VECTOR_ADAPTER_H__
#define __RTE_EVENT_VECTOR_ADAPTER_H__

/**
 * @file rte_event_vector_adapter.h
 *
 * @warning
 * @b EXPERIMENTAL:
 * All functions in this file may be changed or removed without prior notice.
 *
 * Event vector adapter API.
 *
 * An event vector adapter has the following working model:
 *
 *         ┌──────────┐
 *         │  Vector  ├─┐
 *         │ adapter0 │ │
 *         └──────────┘ │
 *         ┌──────────┐ │   ┌──────────┐
 *         │  Vector  ├─┼──►│  Event   │
 *         │ adapter1 │ │   │  Queue0  │
 *         └──────────┘ │   └──────────┘
 *         ┌──────────┐ │
 *         │  Vector  ├─┘
 *         │ adapter2 │
 *         └──────────┘
 *
 *         ┌──────────┐
 *         │  Vector  ├─┐
 *         │ adapter0 │ │   ┌──────────┐
 *         └──────────┘ ├──►│  Event   │
 *         ┌──────────┐ │   │  Queue1  │
 *         │  Vector  ├─┘   └──────────┘
 *         │ adapter1 │
 *         └──────────┘
 *
 * - A vector adapter can be seen as an extension to event queue. It helps in
 *   aggregating ptrs and generating a vector event which is enqueued to the
 *   event queue.
 *
 * - Multiple vector adapters can be created on an event queue, each with its
 *   own unique properties such as event properties, vector size, and timeout.
 *   Note: If the target event queue doesn't support RTE_EVENT_QUEUE_CFG_ALL_TYPES,
 *         then the vector adapter should use the same schedule type as the event
 *         queue.
 *
 * - Each vector adapter aggregates ptrs, generates a vector event and
 *   enqueues it to the event queue with the event properties mentioned in
 *   rte_event_vector_adapter_conf::ev.
 *
 * - After configuring the vector adapter, Application needs to use the
 *   rte_event_vector_adapter_enqueue() function to enqueue ptrs i.e.,
 *   mbufs/ptrs/u64s to the vector adapter.
 *   On reaching the configured vector size or timeout, the vector adapter
 *   enqueues the event vector to the event queue.
 *   Note: Application should use the event_type and sub_event_type properly
 *         identifying the contents of vector event on dequeue.
 *
 * - If the vector adapter advertises the RTE_EVENT_VECTOR_ADAPTER_CAP_SOV_EOV
 *  capability, application can use the RTE_EVENT_VECTOR_ENQ_[S|E]OV flags
 *  to indicate the start and end of a vector event.
 *  * When RTE_EVENT_VECTOR_ENQ_SOV is set, the vector adapter will flush any
 *    aggregation in progress as a vector event and start aggregating a new
 *    vector event with the enqueued ptr.
 *  * When RTE_EVENT_VECTOR_ENQ_EOV is set, the vector adapter will add the
 *    current ptr enqueued to the aggregated event and enqueue the vector event
 *    to the event queue.
 *  * If both flags are set, the vector adapter will flush the current aggregation
 *    as a vector event and enqueue the current ptr as a single event to the event
 *    queue.
 *
 * - If the vector adapter reaches the configured vector size, it will enqueue
 *   the aggregated vector event to the event queue.
 *
 * - If the vector adapter reaches the configured vector timeout, it will flush
 *   the current aggregation as a vector event if the minimum vector size is
 *   reached, if not it will enqueue the ptrs as single events to the event
 *   queue.
 *
 * - If the vector adapter is unable to aggregate the ptrs into a vector event,
 *   it will enqueue the ptrs as single events to the event queue with the event
 *   properties mentioned in rte_event_vector_adapter_conf::ev_fallback.
 *
 * Before using the vector adapter, the application has to create and configure
 * an event device and based on the event device capability it might require
 * creating an additional event port.
 *
 * When the application creates the vector adapter using the
 * ``rte_event_vector_adapter_create()`` function, the event device driver
 * capabilities are checked. If an in-built port is absent, the application
 * uses the default function to create a new event port.
 * For finer control over event port creation, the application should use
 * the ``rte_event_vector_adapter_create_ext()`` function.
 *
 * The application can enqueue one or more ptrs to the vector adapter using the
 * ``rte_event_vector_adapter_enqueue()`` function and control the aggregation
 * using the flags.
 *
 * Vector adapters report stats using the ``rte_event_vector_adapter_stats_get()``
 * function and reset the stats using the ``rte_event_vector_adapter_stats_reset()``.
 *
 * The application can destroy the vector adapter using the
 * ``rte_event_vector_adapter_destroy()`` function.
 *
 */

#include <rte_eventdev.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RTE_EVENT_VECTOR_ADAPTER_CAP_SOV_EOV (1ULL << 0)
/**< Vector adapter supports Start of Vector (SOV) and End of Vector (EOV) flags
 *  in the enqueue flags.
 *
 * @see RTE_EVENT_VECTOR_ENQ_SOV
 * @see RTE_EVENT_VECTOR_ENQ_EOV
 */

#define RTE_EVENT_VECTOR_ENQ_SOV   (1ULL << 0)
/**< Indicates the start of a vector event. When enqueue is called with
 *  RTE_EVENT_VECTOR_ENQ_SOV, the vector adapter will flush any vector
 *  aggregation in progress and start aggregating a new vector event with
 *  the enqueued ptr.
 */
#define RTE_EVENT_VECTOR_ENQ_EOV   (1ULL << 1)
/**< Indicates the end of a vector event. When enqueue is called with
 *  RTE_EVENT_VECTOR_ENQ_EOV, the vector adapter will add the current ptr
 *  to the aggregated event and flush the event vector.
 */
#define RTE_EVENT_VECTOR_ENQ_FLUSH (1ULL << 2)
/**< Flush any in-progress vector aggregation. */

/**
 * Vector adapter configuration structure
 */
struct rte_event_vector_adapter_conf {
	uint8_t event_dev_id;
	/**< Event device identifier */
	uint32_t socket_id;
	/**< Identifier of socket from which to allocate memory for adapter */
	struct rte_event ev;
	/**<
	 *  The values from the following event fields will be used when
	 *  queuing work:
	 *   - queue_id: Targeted event queue ID for vector event.
	 *   - event_priority: Event priority of the vector event in
	 *                     the event queue relative to other events.
	 *   - sched_type: Scheduling type for events from this vector adapter.
	 *   - event_type: Event type for the vector event.
	 *   - sub_event_type: Sub event type for the vector event.
	 *   - flow_id: Flow ID for the vectors enqueued to the event queue by
	 *              the vector adapter.
	 */
	struct rte_event ev_fallback;
	/**<
	 * The values from the following event fields will be used when
	 * aggregation fails and single event is enqueued:
	 *   - event_type: Event type for the single event.
	 *   - sub_event_type: Sub event type for the single event.
	 *   - flow_id: Flow ID for the single event.
	 *
	 * Other fields are taken from rte_event_vector_adapter_conf::ev.
	 */
	uint16_t vector_sz;
	/**<
	 * Indicates the maximum number for enqueued work to combine and form a vector.
	 * Should be within vectorization limits of the adapter.
	 * @see rte_event_vector_adapter_info::min_vector_sz
	 * @see rte_event_vector_adapter_info::max_vector_sz
	 */
	uint64_t vector_timeout_ns;
	/**<
	 * Indicates the maximum number of nanoseconds to wait for receiving
	 * work. Should be within vectorization limits of the adapter.
	 * @see rte_event_vector_adapter_info::min_vector_ns
	 * @see rte_event_vector_adapter_info::max_vector_ns
	 */
	struct rte_mempool *vector_mp;
	/**<
	 * Indicates the mempool that should be used for allocating
	 * rte_event_vector container.
	 * @see rte_event_vector_pool_create
	 */
};

/**
 * Vector adapter vector info structure
 */
struct rte_event_vector_adapter_info {
	uint8_t max_vector_adapters_per_event_queue;
	/**< Maximum number of vector adapters configurable */
	uint16_t min_vector_sz;
	/**< Minimum vector size configurable */
	uint16_t max_vector_sz;
	/**< Maximum vector size configurable */
	uint64_t min_vector_timeout_ns;
	/**< Minimum vector timeout configurable */
	uint64_t max_vector_timeout_ns;
	/**< Maximum vector timeout configurable */
	uint8_t log2_sz;
	/**< True if the size configured should be in log2. */
};

/**
 * Vector adapter statistics structure
 */
struct rte_event_vector_adapter_stats {
	uint64_t vectorized;
	/**< Number of events vectorized */
	uint64_t vectors_timedout;
	/**< Number of timeouts occurred */
	uint64_t vectors_flushed;
	/**< Number of vectors flushed */
	uint64_t alloc_failures;
	/**< Number of vector allocation failures */
};

struct rte_event_vector_adapter;

typedef int (*rte_event_vector_adapter_enqueue_t)(struct rte_event_vector_adapter *adapter,
						  uintptr_t ptrs[], uint16_t num_elem,
						  uint64_t flags);
/**< @internal Enqueue ptrs into the event vector adapter. */

struct __rte_cache_aligned rte_event_vector_adapter {
	rte_event_vector_adapter_enqueue_t enqueue;
	/**< Pointer to driver enqueue function. */
	struct rte_event_vector_adapter_data *data;
	/**< Pointer to the adapter data */
	const struct event_vector_adapter_ops *ops;
	/**< Functions exported by adapter driver */

	uint32_t adapter_id;
	/**< Identifier of the adapter instance. */
	uint8_t used : 1;
	/**< Flag to indicate that this adapter is being used. */
};

/**
 * Callback function type for producer port creation.
 */
typedef int (*rte_event_vector_adapter_port_conf_cb_t)(uint8_t event_dev_id, uint8_t *event_port_id,
						       void *conf_arg);

/**
 * Create an event vector adapter.
 *
 * This function creates an event vector adapter based on the provided
 * configuration. The adapter can be used to combine multiple mbufs/ptrs/u64s
 * into a single vector event, i.e., rte_event_vector, which is then enqueued
 * to the event queue provided.
 * @see rte_event_vector_adapter_conf::ev::event_queue_id.
 *
 * @param conf
 *   Configuration for the event vector adapter.
 * @return
 *   - Pointer to the created event vector adapter on success.
 *   - NULL on failure with rte_errno set to the error code.
 *     Possible rte_errno values include:
 *    - EINVAL: Invalid event device identifier specified in config.
 *    - ENOMEM: Unable to allocate sufficient memory for adapter instances.
 *    - ENOSPC: Maximum number of adapters already created.
 */
struct rte_event_vector_adapter *
rte_event_vector_adapter_create(const struct rte_event_vector_adapter_conf *conf);

/**
 * Create an event vector adapter with the supplied callback.
 *
 * This function can be used to have a more granular control over the event
 * vector adapter creation. If a built-in port is absent, then the function uses
 * the callback provided to create and get the port id to be used as a producer
 * port.
 *
 * @param conf
 *   The event vector adapter configuration structure.
 * @param conf_cb
 *   The port config callback function.
 * @param conf_arg
 *   Opaque pointer to the argument for the callback function.
 * @return
 *   - Pointer to the new allocated event vector adapter on success.
 *   - NULL on error with rte_errno set appropriately.
 *   Possible rte_errno values include:
 *   - ERANGE: vector_timeout_ns is not in supported range.
 *   - ENOMEM: Unable to allocate sufficient memory for adapter instances.
 *   - EINVAL: Invalid event device identifier specified in config.
 *   - ENOSPC: Maximum number of adapters already created.
 */
struct rte_event_vector_adapter *
rte_event_vector_adapter_create_ext(const struct rte_event_vector_adapter_conf *conf,
				    rte_event_vector_adapter_port_conf_cb_t conf_cb,
				    void *conf_arg);

/**
 * Lookup an event vector adapter using its identifier.
 *
 * This function returns the event vector adapter based on the adapter_id.
 * This is useful when the adapter is created in another process and the
 * application wants to use the adapter in the current process.
 *
 * @param adapter_id
 *   Identifier of the event vector adapter to look up.
 * @return
 *   - Pointer to the event vector adapter on success.
 *   - NULL if the adapter is not found.
 */
struct rte_event_vector_adapter *
rte_event_vector_adapter_lookup(uint32_t adapter_id);

/**
 * Destroy an event vector adapter.
 *
 * This function releases the resources associated with the event vector adapter.
 *
 * @param adapter
 *   Pointer to the event vector adapter to be destroyed.
 * @return
 *   - 0 on success.
 *   - Negative value on failure with rte_errno set to the error code.
 */
int
rte_event_vector_adapter_destroy(struct rte_event_vector_adapter *adapter);

/**
 * Get the vector info of an event vector adapter.
 *
 * This function retrieves the vector info of the event vector adapter.
 *
 * @param event_dev_id
 *   Event device identifier.
 * @param info
 *   Pointer to the structure where the vector info will be stored.
 * @return
 *   0 on success, negative value on failure.
 *   - EINVAL if the event device identifier is invalid.
 *   - ENOTSUP if the event device does not support vector adapters.
 */
int
rte_event_vector_adapter_info_get(uint8_t event_dev_id,
				  struct rte_event_vector_adapter_info *info);

/**
 * Get the configuration of an event vector adapter.
 *
 * This function retrieves the configuration of the event vector adapter.
 *
 * @param adapter
 *   Pointer to the event vector adapter.
 * @param conf
 *   Pointer to the structure where the configuration will be stored.
 * @return
 *   0 on success, negative value on failure.
 */
int
rte_event_vector_adapter_conf_get(struct rte_event_vector_adapter *adapter,
				  struct rte_event_vector_adapter_conf *conf);

/**
 * Get the remaining event vector adapters.
 *
 * This function retrieves the number of remaining event vector adapters
 * available for a given event device and event queue.
 *
 * @param event_dev_id
 *   Event device identifier.
 * @param event_queue_id
 *   Event queue identifier.
 * @return
 *   Number of remaining slots available for enqueuing events.
 */
uint8_t
rte_event_vector_adapter_remaining(uint8_t event_dev_id, uint8_t event_queue_id);

/**
 * Get the event vector adapter statistics.
 *
 * This function retrieves the statistics of the event vector adapter.
 *
 * @param adapter
 *   Pointer to the event vector adapter.
 * @param stats
 *   Pointer to the structure where the statistics will be stored.
 * @return
 *   0 on success, negative value on failure.
 */
int
rte_event_vector_adapter_stats_get(struct rte_event_vector_adapter *adapter,
				   struct rte_event_vector_adapter_stats *stats);

/**
 * @brief Reset the event vector adapter statistics.
 *
 * This function resets the statistics of the event vector adapter to their default values.
 *
 * @param adapter
 *   Pointer to the event vector adapter whose statistics are to be reset.
 * @return
 *   0 on success, negative value on failure.
 */
int
rte_event_vector_adapter_stats_reset(struct rte_event_vector_adapter *adapter);

/**
 * Retrieve the service ID of the event vector adapter. If the adapter doesn't
 * use an rte_service function, this function returns -ESRCH.
 *
 * @param adapter
 *   A pointer to an event vector adapter.
 * @param [out] service_id
 *   A pointer to a uint32_t, to be filled in with the service id.
 *
 * @return
 *   - 0: Success
 *   - <0: Error code on failure
 *   - -ESRCH: the adapter does not require a service to operate
 */
int
rte_event_vector_adapter_service_id_get(struct rte_event_vector_adapter *adapter,
					uint32_t *service_id);

/**
 * Enqueue ptrs into the event vector adapter.
 *
 * This function enqueues a specified number of ptrs into the event vector adapter.
 * The ptrs are combined into a single vector event, i.e., rte_event_vector, which
 * is then enqueued to the event queue configured in the adapter.
 *
 * @param adapter
 *   Pointer to the event vector adapter.
 * @param ptrs
 *   Array of ptrs to be enqueued.
 * @param num_elem
 *   Number of ptrs to be enqueued.
 * @param flags
 *   Flags to be used for the enqueue operation.
 * @return
 *   Number of ptrs enqueued on success.
 */
static inline int
rte_event_vector_adapter_enqueue(struct rte_event_vector_adapter *adapter, uintptr_t ptrs[],
				 uint16_t num_elem, uint64_t flags)
{
#ifdef RTE_LIBRTE_EVENTDEV_DEBUG
	if (adapter == NULL) {
		rte_errno = EINVAL;
		return 0;
	}

	if (adapter->used == false) {
		rte_errno = EINVAL;
		return 0;
	}
#endif
	return adapter->enqueue(adapter, ptrs, num_elem, flags);
}

#ifdef __cplusplus
}
#endif

#endif /* __RTE_EVENT_VECTOR_ADAPTER_H__ */
