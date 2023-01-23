/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_ETHDEV_TRACE_FP_H_
#define _RTE_ETHDEV_TRACE_FP_H_

/**
 * @file
 *
 * API for ethdev trace support
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_trace_point.h>

#include "rte_ethdev.h"

RTE_TRACE_POINT_FP(
	rte_eth_trace_call_rx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **rx_pkts, uint16_t nb_rx,
		uint16_t nb_pkts),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(rx_pkts);
	rte_trace_point_emit_u16(nb_rx);
	rte_trace_point_emit_u16(nb_pkts);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_call_tx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **tx_pkts, uint16_t nb_pkts),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(tx_pkts);
	rte_trace_point_emit_u16(nb_pkts);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_find_next,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_find_next_of,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_find_next_sibling,
	RTE_TRACE_POINT_ARGS(uint16_t port_id_start, uint16_t ref_port_id),
	rte_trace_point_emit_u16(port_id_start);
	rte_trace_point_emit_u16(ref_port_id);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_is_valid_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int is_valid),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(is_valid);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_find_next_owned_by,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const uint64_t owner_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_owner_get,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		struct rte_eth_dev_owner *owner),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_sec_ctx,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, void *ctx),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ctx);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_count_avail,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_count_total,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_name_by_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, char *name),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_port_by_name,
	RTE_TRACE_POINT_ARGS(const char *name, uint16_t port_id),
	rte_trace_point_emit_string(name);
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_is_removed,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_hairpin_get_peer_ports,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t *peer_ports,
		size_t len, uint32_t direction, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(peer_ports);
	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u32(direction);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_buffer_drop_callback,
	RTE_TRACE_POINT_ARGS(struct rte_mbuf **pkts, uint16_t unsent),
	rte_trace_point_emit_ptr(pkts);
	rte_trace_point_emit_u16(unsent);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_buffer_count_callback,
	RTE_TRACE_POINT_ARGS(struct rte_mbuf **pkts, uint16_t unsent,
		uint64_t count),
	rte_trace_point_emit_ptr(pkts);
	rte_trace_point_emit_u16(unsent);
	rte_trace_point_emit_u64(count);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_buffer_init,
	RTE_TRACE_POINT_ARGS(struct rte_eth_dev_tx_buffer *buffer, uint16_t size,
		int ret),
	rte_trace_point_emit_ptr(buffer);
	rte_trace_point_emit_u16(size);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_done_cleanup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id, uint32_t free_cnt,
		int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u32(free_cnt);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_promiscuous_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int promiscuous),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(promiscuous);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_allmulticast_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int all_multicast),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(all_multicast);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_link_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_link *link),
	uint16_t link_duplex = link->link_duplex;
	uint16_t link_autoneg = link->link_autoneg;
	uint16_t link_status = link->link_status;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u16(link_duplex);
	rte_trace_point_emit_u16(link_autoneg);
	rte_trace_point_emit_u16(link_status);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_link_get_nowait,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_link *link),
	uint16_t link_duplex = link->link_duplex;
	uint16_t link_autoneg = link->link_autoneg;
	uint16_t link_status = link->link_status;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u16(link_duplex);
	rte_trace_point_emit_u16(link_autoneg);
	rte_trace_point_emit_u16(link_status);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_link_to_str,
	RTE_TRACE_POINT_ARGS(size_t len, const struct rte_eth_link *link),
	uint16_t link_duplex = link->link_duplex;
	uint16_t link_autoneg = link->link_autoneg;
	uint16_t link_status = link->link_status;

	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u32(link->link_speed);
	rte_trace_point_emit_u16(link_duplex);
	rte_trace_point_emit_u16(link_autoneg);
	rte_trace_point_emit_u16(link_status);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_stats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_stats *stats, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(stats);
	rte_trace_point_emit_u64(stats->rx_nombuf);
	rte_trace_point_emit_u64(stats->ipackets);
	rte_trace_point_emit_u64(stats->opackets);
	rte_trace_point_emit_u64(stats->ibytes);
	rte_trace_point_emit_u64(stats->obytes);
	rte_trace_point_emit_u64(stats->imissed);
	rte_trace_point_emit_u64(stats->ierrors);
	rte_trace_point_emit_u64(stats->oerrors);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_stats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_get_id_by_name,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *xstat_name,
		uint64_t id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstat_name);
	rte_trace_point_emit_u64(id);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_get_names_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_xstat_name *xstats_names, uint64_t ids),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstats_names->name);
	rte_trace_point_emit_u64(ids);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_get_names,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_xstat_name *xstats_names,
		unsigned int size, int cnt_used_entries),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstats_names->name);
	rte_trace_point_emit_u32(size);
	rte_trace_point_emit_int(cnt_used_entries);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_get_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const uint64_t *ids,
		uint64_t *values, unsigned int size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ids);
	rte_trace_point_emit_ptr(values);
	rte_trace_point_emit_u32(size);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_xstat xstats,
		int i),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(xstats.id);
	rte_trace_point_emit_u64(xstats.value);
	rte_trace_point_emit_u32(i);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_xstats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_TRACE_FP_H_ */
