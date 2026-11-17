/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Pravin Pathak <pravin.pathak.dev@gmail.com>
 */

#include "slb_evdev.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <rte_debug.h>
#include <rte_string_fns.h>

/* The high bits in the xstats id is used to store an additional
 * parameter (beyond the queue or port id already in the xstats
 * interface).
 */
#define SLB_XSTATS_ID_PARAM_BITS (8)
#define SLB_XSTATS_ID_STAT_BITS \
	(sizeof(uint64_t) * CHAR_BIT - SLB_XSTATS_ID_PARAM_BITS)
#define SLB_XSTATS_ID_STAT_MASK ((UINT64_C(1) << SLB_XSTATS_ID_STAT_BITS) - 1)

#define SLB_XSTATS_ID_GET_PARAM(id) \
	((id) >> SLB_XSTATS_ID_STAT_BITS)

#define SLB_XSTATS_ID_GET_STAT(id) \
	((id) & SLB_XSTATS_ID_STAT_MASK)

#define SLB_XSTATS_ID_CREATE(id, param_value) \
	((((uint64_t)(param_value)) << SLB_XSTATS_ID_STAT_BITS) | (id))

typedef uint64_t (*slb_xstats_dev_get_value_fn)(struct slb_evdev *slb);

struct slb_xstat_dev {
	const char *name;
	slb_xstats_dev_get_value_fn get_value_fn;
};

typedef uint64_t (*slb_xstats_port_get_value_fn)(struct slb_evdev *slb,
						 uint8_t port_id,
						 uint8_t queue_id);

struct slb_xstats_port {
	const char *name_fmt;
	slb_xstats_port_get_value_fn get_value_fn;
	bool per_queue;
};

static uint64_t
slb_xstats_dev_credits_on_loan(struct slb_evdev *slb)
{
	return rte_atomic_load_explicit(&slb->credits_on_loan,
					rte_memory_order_relaxed);
}

static struct slb_xstat_dev slb_dev_xstats[] = {
	{ "dev_credits_on_loan", slb_xstats_dev_credits_on_loan }
};

#define SLB_GEN_PORT_ACCESS_FN(_variable) \
	static uint64_t \
	slb_xstats_port_get_ ## _variable(struct slb_evdev *slb, \
					  uint8_t port_id, \
					  uint8_t queue_id __rte_unused) \
	{ \
		return slb->ports[port_id]._variable; \
	}

SLB_GEN_PORT_ACCESS_FN(new_enqueued)
SLB_GEN_PORT_ACCESS_FN(forward_enqueued)
SLB_GEN_PORT_ACCESS_FN(release_enqueued)

static uint64_t
slb_xstats_port_get_queue_enqueued(struct slb_evdev *slb, uint8_t port_id,
				   uint8_t queue_id)
{
	return slb->ports[port_id].queue_enqueued[queue_id];
}

SLB_GEN_PORT_ACCESS_FN(dequeued)

static uint64_t
slb_xstats_port_get_queue_dequeued(struct slb_evdev *slb, uint8_t port_id,
				   uint8_t queue_id)
{
	return slb->ports[port_id].queue_dequeued[queue_id];
}

SLB_GEN_PORT_ACCESS_FN(inflight_credits)
SLB_GEN_PORT_ACCESS_FN(pending_releases)
SLB_GEN_PORT_ACCESS_FN(migrations_in)
SLB_GEN_PORT_ACCESS_FN(migrations_out)

static struct slb_xstats_port slb_port_xstats[] = {
	{ "port_%u_new_enqueued", slb_xstats_port_get_new_enqueued,
	  false },
	{ "port_%u_forward_enqueued", slb_xstats_port_get_forward_enqueued,
	  false },
	{ "port_%u_release_enqueued", slb_xstats_port_get_release_enqueued,
	  false },
	{ "port_%u_queue_%u_enqueued", slb_xstats_port_get_queue_enqueued,
	  true },
	{ "port_%u_dequeued", slb_xstats_port_get_dequeued,
	  false },
	{ "port_%u_queue_%u_dequeued", slb_xstats_port_get_queue_dequeued,
	  true },
	{ "port_%u_inflight_credits", slb_xstats_port_get_inflight_credits,
	  false },
	{ "port_%u_pending_releases", slb_xstats_port_get_pending_releases,
	  false },
	{ "port_%u_migrations_in", slb_xstats_port_get_migrations_in,
	  false },
	{ "port_%u_migrations_out", slb_xstats_port_get_migrations_out,
	  false },
};

typedef void (*slb_xstats_foreach_fn)(const char *xstats_name,
				      enum rte_event_dev_xstats_mode mode,
				      uint8_t queue_port_id,
				      uint64_t xstats_id,
				      void *data);

static void
slb_xstats_dev_foreach(slb_xstats_foreach_fn fn, void *fn_data)
{
	unsigned int i;

	for (i = 0; i < RTE_DIM(slb_dev_xstats); i++)
		fn(slb_dev_xstats[i].name, RTE_EVENT_DEV_XSTATS_DEVICE, 0,
		   i, fn_data);
}

static void
slb_xstats_port_foreach(struct slb_evdev *slb, uint8_t port_id,
			slb_xstats_foreach_fn fn, void *fn_data)
{
	uint8_t queue_id;
	unsigned int stat_idx;

	for (stat_idx = 0, queue_id = 0;
	     stat_idx < RTE_DIM(slb_port_xstats);) {
		struct slb_xstats_port *xstat = &slb_port_xstats[stat_idx];
		char xstats_name[RTE_EVENT_DEV_XSTATS_NAME_SIZE];
		uint64_t xstats_id;

		if (xstat->per_queue) {
			xstats_id = SLB_XSTATS_ID_CREATE(stat_idx, queue_id);
			snprintf(xstats_name, sizeof(xstats_name),
				 slb_port_xstats[stat_idx].name_fmt, port_id,
				 queue_id);
			queue_id++;
		} else {
			xstats_id = stat_idx;
			snprintf(xstats_name, sizeof(xstats_name),
				 slb_port_xstats[stat_idx].name_fmt, port_id);
		}

		fn(xstats_name, RTE_EVENT_DEV_XSTATS_PORT, port_id,
		   xstats_id, fn_data);

		if (!(xstat->per_queue && queue_id < slb->num_queues)) {
			stat_idx++;
			queue_id = 0;
		}
	}
}

struct store_ctx {
	struct rte_event_dev_xstats_name *names;
	uint64_t *ids;
	unsigned int count;
	unsigned int capacity;
};

static void
slb_xstats_store_stat(const char *xstats_name,
		      enum rte_event_dev_xstats_mode mode,
		      uint8_t queue_port_id, uint64_t xstats_id,
		      void *data)
{
	struct store_ctx *ctx = data;

	RTE_SET_USED(mode);
	RTE_SET_USED(queue_port_id);

	if (ctx->count < ctx->capacity) {
		if (ctx->names != NULL)
			strlcpy(ctx->names[ctx->count].name, xstats_name,
				RTE_EVENT_DEV_XSTATS_NAME_SIZE);
		if (ctx->ids != NULL)
			ctx->ids[ctx->count] = xstats_id;
	}

	ctx->count++;
}

int
slb_xstats_get_names(const struct rte_eventdev *dev,
		     enum rte_event_dev_xstats_mode mode,
		     uint8_t queue_port_id,
		     struct rte_event_dev_xstats_name *xstats_names,
		     uint64_t *ids, unsigned int capacity)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	struct store_ctx ctx = {
		.names = xstats_names,
		.ids = ids,
		.capacity = capacity
	};

	switch (mode) {
	case RTE_EVENT_DEV_XSTATS_DEVICE:
		slb_xstats_dev_foreach(slb_xstats_store_stat, &ctx);
		return ctx.count;
	case RTE_EVENT_DEV_XSTATS_PORT:
		if (queue_port_id >= slb->num_ports)
			return -EINVAL;
		slb_xstats_port_foreach(slb, queue_port_id,
					slb_xstats_store_stat, &ctx);
		return ctx.count;
	case RTE_EVENT_DEV_XSTATS_QUEUE:
		return 0;
	default:
		return -EINVAL;
	}
}

static int
slb_xstats_dev_get(const struct rte_eventdev *dev,
		   const uint64_t ids[], uint64_t values[], unsigned int n)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	unsigned int i;

	for (i = 0; i < n; i++) {
		uint64_t id = ids[i];
		struct slb_xstat_dev *xstat;

		if (id >= RTE_DIM(slb_dev_xstats))
			return -EINVAL;

		xstat = &slb_dev_xstats[id];
		values[i] = xstat->get_value_fn(slb);
	}
	return n;
}

static int
slb_xstats_port_get(const struct rte_eventdev *dev, uint8_t port_id,
		    const uint64_t ids[], uint64_t values[], unsigned int n)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	unsigned int i;

	for (i = 0; i < n; i++) {
		uint64_t id = ids[i];
		unsigned int stat_idx = SLB_XSTATS_ID_GET_STAT(id);
		struct slb_xstats_port *xstat;
		uint8_t queue_id = 0;

		if (stat_idx >= RTE_DIM(slb_port_xstats))
			return -EINVAL;

		xstat = &slb_port_xstats[stat_idx];

		if (xstat->per_queue) {
			queue_id = SLB_XSTATS_ID_GET_PARAM(id);
			if (queue_id >= slb->num_queues)
				return -EINVAL;
		}

		values[i] = xstat->get_value_fn(slb, port_id, queue_id);
	}
	return n;
}

int
slb_xstats_get(const struct rte_eventdev *dev,
	       enum rte_event_dev_xstats_mode mode, uint8_t queue_port_id,
	       const uint64_t ids[], uint64_t values[], unsigned int n)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);

	switch (mode) {
	case RTE_EVENT_DEV_XSTATS_DEVICE:
		return slb_xstats_dev_get(dev, ids, values, n);
	case RTE_EVENT_DEV_XSTATS_PORT:
		if (queue_port_id >= slb->num_ports)
			return -EINVAL;
		return slb_xstats_port_get(dev, queue_port_id, ids, values, n);
	case RTE_EVENT_DEV_XSTATS_QUEUE:
		return 0;
	default:
		return -EINVAL;
	}
}

struct find_ctx {
	const struct rte_eventdev *dev;
	const char *name;
	uint64_t *id;
	uint64_t value;
};

static void
slb_xstats_find_stat(const char *xstats_name,
		     enum rte_event_dev_xstats_mode mode,
		     uint8_t queue_port_id, uint64_t xstats_id,
		     void *data)
{
	struct find_ctx *ctx = data;

	if (strcmp(ctx->name, xstats_name) == 0) {
		if (ctx->id != NULL)
			*ctx->id = xstats_id;
		slb_xstats_get(ctx->dev, mode, queue_port_id, &xstats_id,
			       &ctx->value, 1);
	}
}

uint64_t
slb_xstats_get_by_name(const struct rte_eventdev *dev, const char *name,
		       uint64_t *id)
{
	struct slb_evdev *slb = slb_pmd_priv(dev);
	struct find_ctx ctx = {
		.dev = dev,
		.name = name,
		.id = id,
		.value = -EINVAL
	};
	uint16_t port_id;

	if (id != NULL)
		*id = (uint64_t)-1;

	if (name == NULL)
		return -EINVAL;

	slb_xstats_dev_foreach(slb_xstats_find_stat, &ctx);

	for (port_id = 0; port_id < slb->num_ports; port_id++)
		slb_xstats_port_foreach(slb, port_id, slb_xstats_find_stat,
					&ctx);

	return ctx.value;
}
