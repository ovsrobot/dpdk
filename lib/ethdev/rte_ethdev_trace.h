/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_ETHDEV_TRACE_H_
#define _RTE_ETHDEV_TRACE_H_

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

RTE_TRACE_POINT(
	rte_ethdev_trace_configure,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t nb_rx_q,
		uint16_t nb_tx_q, const struct rte_eth_conf *dev_conf, int rc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(nb_rx_q);
	rte_trace_point_emit_u16(nb_tx_q);
	rte_trace_point_emit_u32(dev_conf->link_speeds);
	rte_trace_point_emit_u32(dev_conf->rxmode.mq_mode);
	rte_trace_point_emit_u32(dev_conf->rxmode.mtu);
	rte_trace_point_emit_u64(dev_conf->rxmode.offloads);
	rte_trace_point_emit_u32(dev_conf->txmode.mq_mode);
	rte_trace_point_emit_u64(dev_conf->txmode.offloads);
	rte_trace_point_emit_u32(dev_conf->lpbk_mode);
	rte_trace_point_emit_int(rc);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rxq_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, void *mp,
		const struct rte_eth_rxconf *rx_conf, int rc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_ptr(mp);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.pthresh);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.hthresh);
	rte_trace_point_emit_u8(rx_conf->rx_thresh.wthresh);
	rte_trace_point_emit_u8(rx_conf->rx_drop_en);
	rte_trace_point_emit_u8(rx_conf->rx_deferred_start);
	rte_trace_point_emit_u64(rx_conf->offloads);
	rte_trace_point_emit_int(rc);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_txq_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, const struct rte_eth_txconf *tx_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.pthresh);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.hthresh);
	rte_trace_point_emit_u8(tx_conf->tx_thresh.wthresh);
	rte_trace_point_emit_u8(tx_conf->tx_deferred_start);
	rte_trace_point_emit_u16(tx_conf->tx_free_thresh);
	rte_trace_point_emit_u64(tx_conf->offloads);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_close,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_init,
	RTE_TRACE_POINT_ARGS(const char *devargs),
	rte_trace_point_emit_string(devargs);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_next,
	RTE_TRACE_POINT_ARGS(struct rte_dev_iterator *iter, uint16_t id),
	rte_trace_point_emit_ptr(iter);
	rte_trace_point_emit_string(iter->bus_str);
	rte_trace_point_emit_string(iter->cls_str);
	rte_trace_point_emit_u16(id);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_cleanup,
	RTE_TRACE_POINT_ARGS(struct rte_dev_iterator *iter),
	rte_trace_point_emit_ptr(iter);
	rte_trace_point_emit_string(iter->bus_str);
	rte_trace_point_emit_string(iter->cls_str);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_new,
	RTE_TRACE_POINT_ARGS(uint64_t owner_id),
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_set,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		const struct rte_eth_dev_owner *owner, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_unset,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		const uint64_t owner_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_delete,
	RTE_TRACE_POINT_ARGS(const uint64_t owner_id, int ret),
	rte_trace_point_emit_u64(owner_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_socket_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int socket_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(socket_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_speed_bitflag,
	RTE_TRACE_POINT_ARGS(uint32_t speed, int duplex),
	rte_trace_point_emit_u32(speed);
	rte_trace_point_emit_int(duplex);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_capability_name,
	RTE_TRACE_POINT_ARGS(uint64_t capability, const char *name),
	rte_trace_point_emit_u64(capability);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_up,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_down,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, const struct rte_eth_hairpin_conf *conf,
		int ret),
	uint32_t peer_count = conf->peer_count;
	uint32_t tx_explicit = conf->tx_explicit;
	uint32_t manual_bind = conf->manual_bind;
	uint32_t use_locked_device_memory = conf->use_locked_device_memory;
	uint32_t use_rte_memory = conf->use_rte_memory;
	uint32_t force_memory = conf->force_memory;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_ptr(conf);
	rte_trace_point_emit_u32(peer_count);
	rte_trace_point_emit_u32(tx_explicit);
	rte_trace_point_emit_u32(manual_bind);
	rte_trace_point_emit_u32(use_locked_device_memory);
	rte_trace_point_emit_u32(use_rte_memory);
	rte_trace_point_emit_u32(force_memory);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, const struct rte_eth_hairpin_conf *conf,
		int ret),
	uint32_t peer_count = conf->peer_count;
	uint32_t tx_explicit = conf->tx_explicit;
	uint32_t manual_bind = conf->manual_bind;
	uint32_t use_locked_device_memory = conf->use_locked_device_memory;
	uint32_t use_rte_memory = conf->use_rte_memory;
	uint32_t force_memory = conf->force_memory;

	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_ptr(conf);
	rte_trace_point_emit_u32(peer_count);
	rte_trace_point_emit_u32(tx_explicit);
	rte_trace_point_emit_u32(manual_bind);
	rte_trace_point_emit_u32(use_locked_device_memory);
	rte_trace_point_emit_u32(use_rte_memory);
	rte_trace_point_emit_u32(force_memory);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_bind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port, int ret),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_unbind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port, int ret),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_set_err_callback,
	RTE_TRACE_POINT_ARGS(struct rte_eth_dev_tx_buffer *buffer),
	rte_trace_point_emit_ptr(buffer);
	rte_trace_point_emit_ptr(buffer->error_callback);
	rte_trace_point_emit_ptr(buffer->error_userdata);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int diag, int promiscuous),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(diag);
	rte_trace_point_emit_int(promiscuous);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int diag, int promiscuous),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(diag);
	rte_trace_point_emit_int(promiscuous);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int diag, int all_multicast),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(diag);
	rte_trace_point_emit_int(all_multicast);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int diag, int all_multicast),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(diag);
	rte_trace_point_emit_int(all_multicast);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_speed_to_str,
	RTE_TRACE_POINT_ARGS(uint32_t link_speed),
	rte_trace_point_emit_u32(link_speed);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_rx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint8_t stat_idx, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_tx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint8_t stat_idx, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_fw_version_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, char *fw_version, size_t fw_size,
		int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(fw_version);
	rte_trace_point_emit_size_t(fw_size);
	rte_trace_point_emit_int(ret);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_TRACE_H_ */
