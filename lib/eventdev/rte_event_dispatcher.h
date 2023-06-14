/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef __RTE_EVENT_DISPATCHER_H__
#define __RTE_EVENT_DISPATCHER_H__

/**
 * @file
 *
 * RTE Event Dispatcher
 *
 * The purpose of the event dispatcher is to help decouple different parts
 * of an application (e.g., modules), sharing the same underlying
 * event device.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_eventdev.h>

/**
 * Function prototype for match callbacks.
 *
 * Match callbacks are used by an application to decide how the
 * event dispatcher distributes events to different parts of the
 * application.
 *
 * The application is not expected to process the event at the point
 * of the match call. Such matters should be deferred to the process
 * callback invocation.
 *
 * The match callback may be used as an opportunity to prefetch data.
 *
 * @param event
 *  Pointer to event
 *
 * @param cb_data
 *  The pointer supplied by the application in
 *  rte_event_dispatcher_register().
 *
 * @return
 *   Returns true in case this events should be delivered (via
 *   the process callback), and false otherwise.
 */
typedef bool
(*rte_event_dispatcher_match_t)(const struct rte_event *event, void *cb_data);

/**
 * Function prototype for process callbacks.
 *
 * The process callbacks are used by the event dispatcher to deliver
 * events for processing.
 *
 * @param event_dev_id
 *  The originating event device id.
 *
 * @param event_port_id
 *  The originating event port.
 *
 * @param events
 *  Pointer to an array of events.
 *
 * @param num
 *  The number of events in the @p events array.
 *
 * @param cb_data
 *  The pointer supplied by the application in
 *  rte_event_dispatcher_register().
 */

typedef void
(*rte_event_dispatcher_process_t)(uint8_t event_dev_id, uint8_t event_port_id,
				  struct rte_event *events, uint16_t num,
				  void *cb_data);

/**
 * Function prototype for finalize callbacks.
 *
 * The finalize callbacks are used by the event dispatcher to notify
 * the application it has delivered all events from a particular batch
 * dequeued from the event device.
 *
 * @param event_dev_id
 *  The originating event device id.
 *
 * @param event_port_id
 *  The originating event port.
 *
 * @param cb_data
 *  The pointer supplied by the application in
 *  rte_event_dispatcher_finalize_register().
 */

typedef void
(*rte_event_dispatcher_finalize_t)(uint8_t event_dev_id, uint8_t event_port_id,
				   void *cb_data);

/**
 * Event dispatcher statistics
 */
struct rte_event_dispatcher_stats {
	uint64_t poll_count;
	/**< Number of event dequeue calls made toward the event device. */
	uint64_t ev_dispatch_count;
	/**< Number of events dispatched to a handler.*/
	uint64_t ev_drop_count;
	/**< Number of events dropped because no handler was found. */
};

/**
 * Create an event dispatcher with the specified id.
 *
 * @param id
 *  An application-specified, unique (across all event dispatcher
 *  instances) identifier.
 *
 * @param event_dev_id
 *  The identifier of the event device from which this event dispatcher
 *  will dequeue events.
 *
 * @return
 *   - 0: Success
 *   - <0: Error code on failure
 */
__rte_experimental
int
rte_event_dispatcher_create(uint8_t id, uint8_t event_dev_id);

/**
 * Free an event dispatcher.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @return
 *  - 0: Success
 *  - <0: Error code on failure
 */
__rte_experimental
int
rte_event_dispatcher_free(uint8_t id);

/**
 * Retrieve the service identifier of an event dispatcher.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param [out] service_id
 *  A pointer to a caller-supplied buffer where the event dispatcher's
 *  service id will be stored.
 *
 * @return
 *  - 0: Success
 *  - <0: Error code on failure.
 */
__rte_experimental
int
rte_event_dispatcher_service_id_get(uint8_t id, uint32_t *service_id);

/**
 * Binds an event device port to a specific lcore on the specified
 * event dispatcher.
 *
 * This function configures the event port id to be used by the event
 * dispatcher service, if run on the specified lcore.
 *
 * Multiple event device ports may be bound to the same lcore. A
 * particular port must not be bound to more than one lcore.
 *
 * If the event dispatcher service is mapped (with
 * rte_service_map_lcore_set()) to a lcore for which no ports are
 * bound, the service function will be a no-operation.
 *
 * This function is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param event_port_id
 *  The event device port identifier.
 *
 * @param batch_size
 *  The batch size to use in rte_event_dequeue_burst(), for the
 *  configured event device port and lcore.
 *
 * @param timeout
 *  The timeout parameter to use in rte_event_dequeue_burst(), for the
 *  configured event device port and lcore.
 *
 * @param lcore_id
 *  The lcore by which this event port will be used.
 *
 * @return
 *  - 0: Success
 *  - -ENOMEM: Unable to allocate sufficient resources.
 *  - -EEXISTS: Event port is already configured.
 *  - -EINVAL: Invalid arguments.
 */
__rte_experimental
int
rte_event_dispatcher_bind_port_to_lcore(uint8_t id, uint8_t event_port_id,
					uint16_t batch_size, uint64_t timeout,
					unsigned int lcore_id);

/**
 * Unbind an event device port from a specific lcore.
 *
 * This function is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param event_port_id
 *  The event device port identifier.
 *
 * @param lcore_id
 *  The lcore which was using this event port.
 *
 * @return
 *  - 0: Success
 *  - -EINVAL: Invalid @c id.
 *  - -ENOENT: Event port id not bound to this @c lcore_id.
 */
__rte_experimental
int
rte_event_dispatcher_unbind_port_from_lcore(uint8_t id, uint8_t event_port_id,
					    unsigned int lcore_id);

/**
 * Register an event handler.
 *
 * The match callback function is used to select if a particular event
 * should be delivered, using the corresponding process callback
 * function.
 *
 * The reason for having two distinct steps is to allow the dispatcher
 * to deliver all events as a batch. This in turn will cause
 * processing of a particular kind of events to happen in a
 * back-to-back manner, improving cache locality.
 *
 * The list of handler callback functions is shared among all lcores,
 * but will only be executed on lcores which has an eventdev port
 * bound to them, and which are running the event dispatcher service.
 *
 * An event is delivered to at most one handler. Events where no
 * handler is found are dropped.
 *
 * The application must not depend on the order of which the match
 * functions are invoked.
 *
 * Ordering of events is not guaranteed to be maintained between
 * different deliver callbacks. For example, suppose there are two
 * callbacks registered, matching different subsets of events arriving
 * on an atomic queue. A batch of events [ev0, ev1, ev2] are dequeued
 * on a particular port, all pertaining to the same flow. The match
 * callback for registration A returns true for ev0 and ev2, and the
 * matching function for registration B for ev1. In that scenario, the
 * event dispatcher may choose to deliver first [ev0, ev2] using A's
 * deliver function, and then [ev1] to B - or vice versa.
 *
 * rte_event_dispatcher_register() is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param match_fun
 *  The match callback function.
 *
 * @param match_cb_data
 *  A pointer to some application-specific opaque data (or NULL),
 *  which is supplied back to the application when match_fun is
 *  called.
 *
 * @param process_fun
 *  The process callback function.
 *
 * @param process_cb_data
 *  A pointer to some application-specific opaque data (or NULL),
 *  which is supplied back to the application when process_fun is
 *  called.
 *
 * @return
 *  - >= 0: The identifier for this registration.
 *  - -ENOMEM: Unable to allocate sufficient resources.
 */
__rte_experimental
int
rte_event_dispatcher_register(uint8_t id,
			      rte_event_dispatcher_match_t match_fun,
			      void *match_cb_data,
			      rte_event_dispatcher_process_t process_fun,
			      void *process_cb_data);

/**
 * Unregister an event handler.
 *
 * This function is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param handler_id
 *  The handler registration id returned by the original
 *  rte_event_dispatcher_register() call.
 *
 * @return
 *  - 0: Success
 *  - -EINVAL: The @c id and/or the @c handler_id parameter was invalid.
 */
__rte_experimental
int
rte_event_dispatcher_unregister(uint8_t id, int handler_id);

/**
 * Register a finalize callback function.
 *
 * An application may optionally install one or more finalize
 * callbacks.
 *
 * All finalize callbacks are invoked by the event dispatcher when a
 * complete batch of events (retrieve using rte_event_dequeue_burst())
 * have been delivered to the application (or have been dropped).
 *
 * The finalize callback is not tied to any particular handler.
 *
 * The finalize callback provides an opportunity for the application
 * to do per-batch processing. One case where this may be useful is if
 * an event output buffer is used, and is shared among several
 * handlers. In such a case, proper output buffer flushing may be
 * assured using a finalize callback.
 *
 * rte_event_dispatcher_finalize_register() is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param finalize_fun
 *  The function called after completing the processing of a
 *  dequeue batch.
 *
 * @param finalize_data
 *  A pointer to some application-specific opaque data (or NULL),
 *  which is supplied back to the application when @c finalize_fun is
 *  called.
 *
 * @return
 *  - >= 0: The identifier for this registration.
 *  - -ENOMEM: Unable to allocate sufficient resources.
 */
__rte_experimental
int
rte_event_dispatcher_finalize_register(uint8_t id,
			    rte_event_dispatcher_finalize_t finalize_fun,
			    void *finalize_data);

/**
 * Unregister a finalize callback.
 *
 * This function is not MT safe.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @param reg_id
 *  The finalize registration id returned by the original
 *  rte_event_dispatcher_finalize_register() call.
 *
 * @return
 *  - 0: Success
 *  - -EINVAL: The @c id and/or the @c reg_id parameter was invalid.
 */
__rte_experimental
int
rte_event_dispatcher_finalize_unregister(uint8_t id, int reg_id);

/**
 * Start an event dispatcher instance.
 *
 * Enables the event dispatcher service.
 *
 * The underlying event device must have been started prior to calling
 * rte_event_dispatcher_start().
 *
 * For the event dispatcher to actually perform work (i.e., dispatch
 * events), its service must have been mapped to one or more service
 * lcores, and its service run state set to '1'. An event dispatcher's
 * service is retrieved using rte_event_dispatcher_service_id_get().
 *
 * Each service lcore to which the event dispatcher is mapped should
 * have at least one event port configured. Such configuration is
 * performed by calling rte_event_dispatcher_bind_port_to_lcore(),
 * prior to starting the event dispatcher.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @return
 *  - 0: Success
 *  - -EINVAL: Invalid @c id.
 */
__rte_experimental
int
rte_event_dispatcher_start(uint8_t id);

/**
 * Stop a running event dispatcher instance.
 *
 * Disables the event dispatcher service.
 *
 * @param id
 *  The event dispatcher identifier.
 *
 * @return
 *  - 0: Success
 *  - -EINVAL: Invalid @c id.
 */
__rte_experimental
int
rte_event_dispatcher_stop(uint8_t id);

/**
 * Retrieve statistics for an event dispatcher instance.
 *
 * This function is MT safe and may be called from any thread
 * (including unregistered non-EAL threads).
 *
 * @param id
 *  The event dispatcher identifier.
 * @param[out] stats
 *   A pointer to a structure to fill with statistics.
 * @return
 *  - 0: Success
 *  - -EINVAL: The @c id parameter was invalid.
 */
__rte_experimental
int
rte_event_dispatcher_stats_get(uint8_t id,
			       struct rte_event_dispatcher_stats *stats);

#ifdef __cplusplus
}
#endif

#endif /* __RTE_EVENT_DISPATCHER__ */
