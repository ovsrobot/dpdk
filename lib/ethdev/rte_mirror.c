/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2025 Stephen Hemminger <stephen@networkplumber.org>
 */

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <rte_alarm.h>
#include <rte_bitops.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_spinlock.h>
#include <rte_stdatomic.h>
#include <eal_export.h>

#include "rte_ethdev.h"
#include "rte_mirror.h"
#include "ethdev_driver.h"
#include "ethdev_private.h"
#include "ethdev_trace.h"

/* Upper bound of packet bursts redirected */
#define RTE_MIRROR_BURST_SIZE 64

#ifndef RTE_EXEC_ENV_WINDOWS
#include <rte_bpf.h>
#endif

/**
 * Structure used to hold information mirror port mirrors for a
 * queue on Rx and Tx.
 */
struct rte_eth_mirror {
	RTE_ATOMIC(struct rte_eth_mirror *) next;
	struct rte_mempool *mp;
	struct rte_bpf *bpf;
	uint32_t snaplen;
	uint32_t flags;
	uint16_t target;
	struct rte_eth_mirror_stats stats;
};

/* spinlock for setting up mirror ports */
static rte_spinlock_t mirror_port_lock = RTE_SPINLOCK_INITIALIZER;

/* dynamically assigned offload flag to indicate ingress vs egress */
static uint64_t mirror_origin_flag;
static int mirror_origin_offset = -1;
static uint64_t mirror_ingress_flag;
static uint64_t mirror_egress_flag;

static uint64_t mbuf_timestamp_dynflag;
static int mbuf_timestamp_offset = -1;

/* register dynamic mbuf fields, done on first mirror creation */
static int
ethdev_dyn_mirror_register(void)
{
	const struct rte_mbuf_dynfield field_desc = {
		.name = RTE_MBUF_DYNFIELD_MIRROR_ORIGIN,
		.size = sizeof(rte_mbuf_origin_t),
		.align = sizeof(rte_mbuf_origin_t),
	};
	struct rte_mbuf_dynflag flag_desc = {
		.name = RTE_MBUF_DYNFLAG_MIRROR_ORIGIN,
	};
	int offset;

	if (rte_mbuf_dyn_tx_timestamp_register(&mbuf_timestamp_offset,
					       &mbuf_timestamp_dynflag) < 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "Failed to register timestamp flag");
		return -1;
	}

	offset = rte_mbuf_dynfield_register(&field_desc);
	if (offset < 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "Failed to register mbuf origin field");
		return -1;
	}
	mirror_origin_offset = offset;

	offset = rte_mbuf_dynflag_register(&flag_desc);
	if (offset < 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "Failed to register mbuf origin flag");
		return -1;
	}
	mirror_origin_flag = RTE_BIT64(offset);

	strlcpy(flag_desc.name, RTE_MBUF_DYNFLAG_MIRROR_INGRESS, sizeof(flag_desc.name));
	offset = rte_mbuf_dynflag_register(&flag_desc);
	if (offset < 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "Failed to register mbuf ingress flag");
		return -1;
	}
	mirror_ingress_flag = RTE_BIT64(offset);

	strlcpy(flag_desc.name, RTE_MBUF_DYNFLAG_MIRROR_EGRESS,
		sizeof(flag_desc.name));
	offset = rte_mbuf_dynflag_register(&flag_desc);
	if (offset < 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "Failed to register mbuf egress flag");
		return -1;
	}
	mirror_egress_flag = RTE_BIT64(offset);

	return 0;
}

/* Add a new mirror entry to the list. */
static int
ethdev_insert_mirror(RTE_ATOMIC(struct rte_eth_mirror *) *top,
		   const struct rte_eth_mirror_conf *conf)
{
	struct rte_eth_mirror *mirror;
	ssize_t filter_len = 0;

	/* Don't allow multiple mirrors from same source to target */
	while ((mirror = *top) != NULL) {
		if (mirror->target == conf->target) {
			RTE_ETHDEV_LOG_LINE(ERR,
				    "Mirror to port %u already exists", conf->target);
			return -EEXIST;
		}
	}

	if (conf->filter) {
#ifdef RTE_LIB_BPF
		filter_len = rte_bpf_buf_size(conf->filter);
		if (filter_len < 0) {
			RTE_ETHDEV_LOG_LINE(ERR, "Invalid BPF filter: %s",
					    rte_strerror(rte_errno));
			return -EINVAL;
		}
#else
		RTE_ETHDEV_LOG_LINE(ERR, "BPF filter not supported");
		return -ENOTSUP;
#endif
	}

	/*
	 * Allocate space for both fast path mirror structure
	 * and filter bpf code (if any).
	 */
	mirror = rte_zmalloc(NULL, sizeof(*mirror) + filter_len, 0);
	if (mirror == NULL)
		return -ENOMEM;

	mirror->mp = conf->mp;
	mirror->target = conf->target;
	mirror->flags = conf->flags;

	if (conf->snaplen == 0) /* specifying 0 implies the full packet */
		mirror->snaplen = UINT32_MAX;
	else
		mirror->snaplen = conf->snaplen;

#ifdef RTE_LIB_BPF
	if (filter_len > 0) {
		/* reserved space for BPF is after mirror structure */
		void *buf = (uint8_t *)mirror + sizeof(*mirror);

		/*
		 * Copy filter internal representation into space
		 * allocated in huge pages to allow access from any process.
		 */
		mirror->bpf = rte_bpf_buf_load(conf->filter, buf, filter_len);
		if (mirror->bpf == NULL) {
			RTE_ETHDEV_LOG_LINE(ERR, "Failed to load BPF filter: %s",
					    rte_strerror(rte_errno));
			rte_free(mirror);
			return -EINVAL;
		}

	}
#endif

	mirror->next = *top;

	rte_atomic_store_explicit(top, mirror, rte_memory_order_relaxed);
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_eth_add_mirror, 25.11)
int
rte_eth_add_mirror(uint16_t port_id, const struct rte_eth_mirror_conf *conf)
{
#ifndef RTE_ETHDEV_MIRROR
	return -ENOTSUP;
#endif

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);

	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	struct rte_eth_dev_info dev_info;

	if (conf == NULL) {
		RTE_ETHDEV_LOG_LINE(ERR, "Missing configuration information");
		return -EINVAL;
	}

	if (conf->mp == NULL) {
		RTE_ETHDEV_LOG_LINE(ERR, "not a valid mempool");
		return -EINVAL;
	}

	if (conf->flags & ~(RTE_ETH_MIRROR_DIRECTION_MASK | RTE_ETH_MIRROR_FLAG_MASK)) {
		RTE_ETHDEV_LOG_LINE(ERR, "unsupported flags");
		return -EINVAL;
	}

	if ((conf->flags & RTE_ETH_MIRROR_DIRECTION_MASK) == 0) {
		RTE_ETHDEV_LOG_LINE(ERR, "missing direction ingress or egress");
		return -EINVAL;
	}

	/* Checks that target exists */
	int ret = rte_eth_dev_info_get(conf->target, &dev_info);
	if (ret != 0)
		return ret;

	/* Loopback mirror could create packet storm */
	if (conf->target == port_id) {
		RTE_ETHDEV_LOG_LINE(ERR, "Cannot mirror port to self");
		return -EINVAL;
	}

	/*
	 * Multiple directions and multiple queues can be mirrored to a single port.
	 * This will cause multiple threads to be transmitting on the same queue.
	 * Therefore device needs to support lockfree transmit.
	 */
	if (!(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MT_LOCKFREE)) {
		RTE_ETHDEV_LOG_LINE(ERR, "Mirror needs lockfree transmit");
		return -ENOTSUP;
	}

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		/* Register dynamic fields once */
		if (mirror_origin_offset < 0) {
			ret = ethdev_dyn_mirror_register();
			if (ret < 0)
				return ret;
		}

		rte_spinlock_lock(&mirror_port_lock);
		ret = 0;

		if (conf->flags & RTE_ETH_MIRROR_DIRECTION_INGRESS)
			ret = ethdev_insert_mirror(&dev->rx_mirror, conf);
		if (ret == 0 && (conf->flags & RTE_ETH_MIRROR_DIRECTION_EGRESS))
			ret = ethdev_insert_mirror(&dev->tx_mirror, conf);
		rte_spinlock_unlock(&mirror_port_lock);
	} else {
		/* in secondary, proxy to primary */
		ret = ethdev_request(port_id, ETH_REQ_ADD_MIRROR, conf, sizeof(*conf));
		if (ret != 0)
			return ret;
	}

	rte_eth_trace_add_mirror(port_id, conf, ret);
	return ret;
}

static struct rte_eth_mirror *
ethdev_find_mirror(RTE_ATOMIC(struct rte_eth_mirror *) *head, uint16_t target_id)
{

	for (;;) {
		struct rte_eth_mirror *mirror
			= rte_atomic_load_explicit(head, rte_memory_order_relaxed);
		if (mirror == NULL)
			return NULL;	/* reached end of list */

		if (mirror->target == target_id)
			return mirror;

		head = &mirror->next;
	}
}

static bool
ethdev_delete_mirror(RTE_ATOMIC(struct rte_eth_mirror *) *top, uint16_t target_id)
{
	struct rte_eth_mirror *mirror;

	mirror = ethdev_find_mirror(top, target_id);
	if (mirror == NULL)
		return false;

	/* unlink from list */
	rte_atomic_store_explicit(top, mirror->next, rte_memory_order_relaxed);

	/*
	 * Defer freeing the mirror until after one second to allow for active threads
	 * that are using it. Assumes no PMD takes more than one second to transmit a burst.
	 * Alternative would be RCU, but RCU in DPDK is optional and requires application changes.
	 */
	rte_eal_alarm_set(US_PER_S, rte_free, mirror);
	return true;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_eth_remove_mirror, 25.11)
int
rte_eth_remove_mirror(uint16_t port_id, uint16_t target_id)
{
#ifndef RTE_ETHDEV_MIRROR
	return -ENOTSUP;
#endif
	int ret = 0;

	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	RTE_ETH_VALID_PORTID_OR_ERR_RET(target_id, -ENODEV);

	struct rte_eth_dev *dev = &rte_eth_devices[port_id];

	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		bool found;

		rte_spinlock_lock(&mirror_port_lock);
		found = ethdev_delete_mirror(&dev->rx_mirror, target_id);
		found |= ethdev_delete_mirror(&dev->tx_mirror, target_id);
		rte_spinlock_unlock(&mirror_port_lock);
		if (!found)
			ret = -ENOENT; /* no mirror present */
	} else {
		ret = ethdev_request(port_id, ETH_REQ_REMOVE_MIRROR,
				     &target_id, sizeof(target_id));
	}

	rte_eth_trace_remove_mirror(port_id, target_id, ret);
	return ret;
}

static inline void
eth_dev_mirror(uint16_t port_id, uint16_t queue_id, uint8_t direction,
	       struct rte_mbuf **pkts, uint16_t nb_pkts,
	       struct rte_eth_mirror *mirror)
{
	struct rte_mbuf *tosend[RTE_MIRROR_BURST_SIZE];
	unsigned int count = 0;

#ifdef RTE_LIB_BPF
	uint64_t rcs[RTE_MIRROR_BURST_SIZE];
	if (mirror->bpf)
		rte_bpf_exec_burst(mirror->bpf, (void **)pkts, rcs, nb_pkts);
#endif

	for (unsigned int i = 0; i < nb_pkts; i++) {
#ifdef RTE_LIB_BPF
		/*
		 * This uses same BPF return value convention as socket filter
		 * and pcap_offline_filter. If program returns zero
		 * then packet doesn't match the filter (will be ignored).
		 */
		if (mirror->bpf && rcs[i] == 0) {
			++mirror->stats.filtered;
			continue;
		}
#endif

		struct rte_mbuf *m = pkts[i];
		struct rte_mbuf *mc = rte_pktmbuf_copy(m, mirror->mp, 0, mirror->snaplen);
		if (unlikely(mc == NULL)) {
			++mirror->stats.nombuf;
			continue;
		}

		/* Put info about origin of the packet */
		if (mirror->flags & RTE_ETH_MIRROR_ORIGIN_FLAG) {
			struct rte_mbuf_origin *origin
				= RTE_MBUF_DYNFIELD(mc, mirror_origin_offset, rte_mbuf_origin_t *);
			origin->original_len = m->pkt_len;
			origin->port_id = port_id;
			origin->queue_id = queue_id;
			mc->ol_flags |= mirror_origin_flag;
		}

		/* Insert timestamp into packet */
		if (mirror->flags & RTE_ETH_MIRROR_TIMESTAMP_FLAG) {
			*RTE_MBUF_DYNFIELD(m, mbuf_timestamp_offset, rte_mbuf_timestamp_t *)
				= rte_get_tsc_cycles();
			mc->ol_flags |= mbuf_timestamp_dynflag;
		}

		mc->ol_flags &= ~(mirror_ingress_flag | mirror_egress_flag);
		if (direction & RTE_ETH_MIRROR_DIRECTION_INGRESS)
			mc->ol_flags |= mirror_ingress_flag;
		else if (direction & RTE_ETH_MIRROR_DIRECTION_EGRESS)
			mc->ol_flags |= mirror_egress_flag;

		tosend[count++] = mc;
	}

	uint16_t nsent = rte_eth_tx_burst(mirror->target, 0, tosend, count);
	mirror->stats.packets += nsent;

	if (unlikely(nsent < count)) {
		uint16_t drop = count - nsent;

		mirror->stats.full += drop;
		rte_pktmbuf_free_bulk(pkts + nsent, drop);
	}
}

/* This function is really internal but used from inline */
RTE_EXPORT_SYMBOL(rte_eth_mirror_burst)
void
rte_eth_mirror_burst(uint16_t port_id, uint16_t queue_id, uint8_t direction,
		     struct rte_mbuf **pkts, uint16_t nb_pkts,
		     struct rte_eth_mirror *mirror)
{

	while (mirror != NULL) {
		for (uint16_t i = 0; i < nb_pkts; i += RTE_MIRROR_BURST_SIZE) {
			uint16_t burst = RTE_MIN(nb_pkts - i, RTE_MIRROR_BURST_SIZE);

			eth_dev_mirror(port_id, queue_id, direction,
				       pkts + i, burst, mirror);
		}

		mirror = rte_atomic_load_explicit(&mirror->next, rte_memory_order_relaxed);
	}
}

static int
ethdev_mirror_stats_get(RTE_ATOMIC(struct rte_eth_mirror *) *head, uint16_t target_id,
			struct rte_eth_mirror_stats *stats)
{
	const struct rte_eth_mirror *mirror;

	mirror = ethdev_find_mirror(head, target_id);
	if (mirror == NULL)
		return -1;

	stats->packets += mirror->stats.packets;
	stats->nombuf += mirror->stats.nombuf;
	stats->full += mirror->stats.full;
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_eth_mirror_stats_get, 25.11)
int
rte_eth_mirror_stats_get(uint16_t port_id, uint16_t target_id,
			 struct rte_eth_mirror_stats *stats)
{
	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	RTE_ETH_VALID_PORTID_OR_ERR_RET(target_id, -ENODEV);

	if (stats == NULL) {
		RTE_ETHDEV_LOG_LINE(ERR, "Mirror port stats is NULL");
		return -EINVAL;
	}

	memset(stats, 0, sizeof(*stats));

	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int rx_ret = ethdev_mirror_stats_get(&dev->rx_mirror, target_id, stats);
	int tx_ret = ethdev_mirror_stats_get(&dev->tx_mirror, target_id, stats);

	/* if rx or tx mirror is valid return 0 */
	return (tx_ret == 0 || rx_ret == 0) ? 0 : -ENOENT;
}

static int
ethdev_mirror_stats_reset(RTE_ATOMIC(struct rte_eth_mirror *) *head, uint16_t target_id)
{
	struct rte_eth_mirror *mirror;

	mirror = ethdev_find_mirror(head, target_id);
	if (mirror == NULL)
		return -1;

	memset(&mirror->stats, 0, sizeof(struct rte_eth_mirror_stats));
	return 0;
}

RTE_EXPORT_EXPERIMENTAL_SYMBOL(rte_eth_mirror_stats_reset, 25.11)
int
rte_eth_mirror_stats_reset(uint16_t port_id, uint16_t target_id)
{
	RTE_ETH_VALID_PORTID_OR_ERR_RET(port_id, -ENODEV);
	RTE_ETH_VALID_PORTID_OR_ERR_RET(target_id, -ENODEV);

	struct rte_eth_dev *dev = &rte_eth_devices[port_id];
	int rx_ret = ethdev_mirror_stats_reset(&dev->rx_mirror, target_id);
	int tx_ret = ethdev_mirror_stats_reset(&dev->tx_mirror, target_id);

	/* if rx or tx mirror is valid return 0 */
	return (tx_ret == 0 || rx_ret == 0) ? 0 : -ENOENT;

}
