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
	rte_eth_trace_add_first_rx_callback,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		rte_rx_callback_fn fn, void *user_param),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(fn);
	rte_trace_point_emit_ptr(user_param);
)

RTE_TRACE_POINT(
	rte_eth_trace_add_rx_callback,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		rte_rx_callback_fn fn, void *user_param),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(fn);
	rte_trace_point_emit_ptr(user_param);
)

RTE_TRACE_POINT(
	rte_eth_trace_add_tx_callback,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		rte_tx_callback_fn fn, void *user_param),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(fn);
	rte_trace_point_emit_ptr(user_param);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_allmulticast_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_call_rx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **rx_pkts, uint16_t nb_rx,
		uint16_t nb_pkts, void *opaque),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(rx_pkts);
	rte_trace_point_emit_u16(nb_rx);
	rte_trace_point_emit_u16(nb_pkts);
	rte_trace_point_emit_ptr(opaque);
)

RTE_TRACE_POINT(
	rte_eth_trace_call_tx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_mbuf **tx_pkts, uint16_t nb_pkts,
		void *opaque),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(tx_pkts);
	rte_trace_point_emit_u16(nb_pkts);
	rte_trace_point_emit_ptr(opaque);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_mtu,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t mtu, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(mtu);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_adjust_nb_rx_tx_desc,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t nb_rx_desc,
			     uint16_t nb_tx_desc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_u16(nb_tx_desc);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_callback_register,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, enum rte_eth_event_type event,
			     rte_eth_dev_cb_fn cb_fn, void *cb_arg),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(event);
	rte_trace_point_emit_ptr(cb_fn);
	rte_trace_point_emit_ptr(cb_arg);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_callback_unregister,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, enum rte_eth_event_type event,
			     rte_eth_dev_cb_fn cb_fn, void *cb_arg),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(event);
	rte_trace_point_emit_ptr(cb_fn);
	rte_trace_point_emit_ptr(cb_arg);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_default_mac_addr_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *addr),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(addr);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_flow_ctrl_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_fc_conf *fc_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(fc_conf);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_flow_ctrl_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_fc_conf *fc_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(fc_conf->high_water);
	rte_trace_point_emit_u32(fc_conf->low_water);
	rte_trace_point_emit_u16(fc_conf->pause_time);
	rte_trace_point_emit_u16(fc_conf->send_xon);
	rte_trace_point_emit_int(fc_conf->mode);
	rte_trace_point_emit_u8(fc_conf->mac_ctrl_frame_fwd);
	rte_trace_point_emit_u8(fc_conf->autoneg);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_fw_version_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, char *fw_version, size_t fw_size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(fw_version);
	rte_trace_point_emit_size_t(fw_size);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_dcb_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_dcb_info *dcb_info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(dcb_info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_eeprom,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_dev_eeprom_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_eeprom_length,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_mtu,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t mtu),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(mtu);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_count_avail,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_count_total,
	RTE_TRACE_POINT_ARGS(uint16_t count),
	rte_trace_point_emit_u16(count);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_name_by_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, char *name),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_port_by_name,
	RTE_TRACE_POINT_ARGS(const char *name, uint16_t port_id),
	rte_trace_point_emit_string(name);
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_reg_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_dev_reg_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_sec_ctx,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_supported_ptypes,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t ptype_mask,
		uint32_t *ptypes, int num),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(ptype_mask);
	rte_trace_point_emit_ptr(ptypes);
	rte_trace_point_emit_int(num);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_vlan_offload,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_dev_info *dev_info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(dev_info->driver_name);
	rte_trace_point_emit_u32(dev_info->if_index);
	rte_trace_point_emit_u16(dev_info->min_mtu);
	rte_trace_point_emit_u16(dev_info->max_mtu);
	rte_trace_point_emit_u32(dev_info->min_rx_bufsize);
	rte_trace_point_emit_u32(dev_info->max_rx_pktlen);
	rte_trace_point_emit_u64(dev_info->rx_offload_capa);
	rte_trace_point_emit_u64(dev_info->tx_offload_capa);
	rte_trace_point_emit_u64(dev_info->rx_queue_offload_capa);
	rte_trace_point_emit_u64(dev_info->tx_queue_offload_capa);
	rte_trace_point_emit_u16(dev_info->reta_size);
	rte_trace_point_emit_u8(dev_info->hash_key_size);
	rte_trace_point_emit_u16(dev_info->nb_rx_queues);
	rte_trace_point_emit_u16(dev_info->nb_tx_queues);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_is_removed,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_is_valid_port,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_mac_addr_add,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *addr,
		uint32_t pool),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_u32(pool);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_mac_addr_remove,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *addr),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(addr);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_pool_ops_supported,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *pool),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(pool);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_priority_flow_ctrl_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_pfc_conf *pfc_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(pfc_conf->fc.high_water);
	rte_trace_point_emit_u32(pfc_conf->fc.low_water);
	rte_trace_point_emit_u16(pfc_conf->fc.pause_time);
	rte_trace_point_emit_u16(pfc_conf->fc.send_xon);
	rte_trace_point_emit_int(pfc_conf->fc.mode);
	rte_trace_point_emit_u8(pfc_conf->fc.mac_ctrl_frame_fwd);
	rte_trace_point_emit_u8(pfc_conf->fc.autoneg);
	rte_trace_point_emit_u8(pfc_conf->priority);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rss_hash_conf_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_rss_conf *rss_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(rss_conf);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rss_hash_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_rss_conf *rss_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(rss_conf->rss_key);
	rte_trace_point_emit_u8(rss_conf->rss_key_len);
	rte_trace_point_emit_u64(rss_conf->rss_hf);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rss_reta_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(reta_conf);
	rte_trace_point_emit_u16(reta_size);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rss_reta_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_rss_reta_entry64 *reta_conf, uint16_t reta_size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(reta_conf->mask);
	rte_trace_point_emit_u16(reta_size);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_intr_ctl,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int epfd, int op, void *data),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(epfd);
	rte_trace_point_emit_int(op);
	rte_trace_point_emit_ptr(data);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_intr_ctl_q,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id, int epfd,
		int op, void *data),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_int(epfd);
	rte_trace_point_emit_int(op);
	rte_trace_point_emit_ptr(data);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_intr_ctl_q_get_fd,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id, int fd),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_int(fd);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_intr_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_intr_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_rx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_eeprom,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_dev_eeprom_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info->data);
	rte_trace_point_emit_u32(info->offset);
	rte_trace_point_emit_u32(info->length);
	rte_trace_point_emit_u32(info->magic);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_down,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_link_up,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_mc_addr_list,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_ether_addr *mc_addr_set,
		uint32_t nb_mc_addr),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(mc_addr_set);
	rte_trace_point_emit_u32(nb_mc_addr);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_ptypes,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t ptype_mask,
		uint32_t *set_ptypes, unsigned int num),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(ptype_mask);
	rte_trace_point_emit_ptr(set_ptypes);
	rte_trace_point_emit_u32(num);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_rx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint8_t stat_idx),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_tx_queue_stats_mapping,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint8_t stat_idx),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u8(stat_idx);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_vlan_ether_type,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, enum rte_vlan_type vlan_type,
		uint16_t tag_type),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(vlan_type);
	rte_trace_point_emit_u16(tag_type);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_vlan_offload,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int offload_mask),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(offload_mask);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_vlan_pvid,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t pvid, int on),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(pvid);
	rte_trace_point_emit_int(on);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_set_vlan_strip_on_queue,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		int on),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_int(on);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_socket_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_offload_name,
	RTE_TRACE_POINT_ARGS(uint64_t offload, const char *name),
	rte_trace_point_emit_u64(offload);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_start,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_tx_queue_stop,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_uc_all_hash_table_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint8_t on),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u8(on);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_uc_hash_table_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *addr,
		uint8_t on),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_u8(on);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_udp_tunnel_port_add,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_udp_tunnel *tunnel_udp),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tunnel_udp->udp_port);
	rte_trace_point_emit_u8(tunnel_udp->prot_type);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_udp_tunnel_port_delete,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_udp_tunnel *tunnel_udp),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tunnel_udp->udp_port);
	rte_trace_point_emit_u8(tunnel_udp->prot_type);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_vlan_filter,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t vlan_id, int on),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(vlan_id);
	rte_trace_point_emit_int(on);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_of,
	RTE_TRACE_POINT_ARGS(uint16_t port_id_start,
		const struct rte_device *parent),
	rte_trace_point_emit_u16(port_id_start);
	rte_trace_point_emit_ptr(parent);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_owned_by,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const uint64_t owner_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_find_next_sibling,
	RTE_TRACE_POINT_ARGS(uint16_t port_id_start, uint16_t ref_port_id),
	rte_trace_point_emit_u16(port_id_start);
	rte_trace_point_emit_u16(ref_port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_cleanup,
	RTE_TRACE_POINT_ARGS(struct rte_dev_iterator *iter),
	rte_trace_point_emit_ptr(iter);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_init,
	RTE_TRACE_POINT_ARGS(struct rte_dev_iterator *iter, const char *devargs),
	rte_trace_point_emit_ptr(iter);
	rte_trace_point_emit_ptr(devargs);
)

RTE_TRACE_POINT(
	rte_eth_trace_iterator_next,
	RTE_TRACE_POINT_ARGS(struct rte_dev_iterator *iter),
	rte_trace_point_emit_ptr(iter);
)

RTE_TRACE_POINT(
	rte_eth_trace_led_off,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_led_on,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_link *link),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_get_nowait,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_link *link),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(link->link_speed);
)

RTE_TRACE_POINT(
	rte_eth_trace_macaddr_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *mac_addr),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(mac_addr);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_promiscuous_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_remove_rx_callback,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		const struct rte_eth_rxtx_callback *user_cb),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(user_cb);
)

RTE_TRACE_POINT(
	rte_eth_trace_remove_tx_callback,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		const struct rte_eth_rxtx_callback *user_cb),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(user_cb);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_burst_mode_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_burst_mode *mode),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(mode);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_rxq_info *qinfo),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(qinfo->mp);
	rte_trace_point_emit_u8(qinfo->scattered_rx);
	rte_trace_point_emit_u8(qinfo->queue_state);
	rte_trace_point_emit_u16(qinfo->nb_desc);
	rte_trace_point_emit_u16(qinfo->rx_buf_size);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_u32(socket_id);
	rte_trace_point_emit_ptr(rx_conf);
	rte_trace_point_emit_ptr(mb_pool);
)

RTE_TRACE_POINT(
	rte_eth_trace_set_queue_rate_limit,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_idx,
		uint16_t tx_rate),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_idx);
	rte_trace_point_emit_u16(tx_rate);
)

RTE_TRACE_POINT(
	rte_eth_trace_speed_bitflag,
	RTE_TRACE_POINT_ARGS(uint32_t speed, int duplex),
	rte_trace_point_emit_u32(speed);
	rte_trace_point_emit_int(duplex);
)

RTE_TRACE_POINT(
	rte_eth_trace_stats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_stats *stats),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(stats);
)

RTE_TRACE_POINT(
	rte_eth_trace_stats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_adjust_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int64_t delta),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_i64(delta);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_disable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_enable,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_read_rx_timestamp,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct timespec *timestamp, uint32_t flags),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(timestamp);
	rte_trace_point_emit_u32(flags);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_read_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct timespec *time),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(time);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_read_tx_timestamp,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct timespec *timestamp),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(timestamp);
)

RTE_TRACE_POINT(
	rte_eth_trace_timesync_write_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const struct timespec *time),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(time);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_count_callback,
	RTE_TRACE_POINT_ARGS(struct rte_mbuf **pkts, uint16_t unsent,
		uint64_t count),
	rte_trace_point_emit_ptr(pkts);
	rte_trace_point_emit_u16(unsent);
	rte_trace_point_emit_u64(count);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_drop_callback,
	RTE_TRACE_POINT_ARGS(struct rte_mbuf **pkts, uint16_t unsent),
	rte_trace_point_emit_ptr(pkts);
	rte_trace_point_emit_u16(unsent);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_init,
	RTE_TRACE_POINT_ARGS(struct rte_eth_dev_tx_buffer *buffer, uint16_t size),
	rte_trace_point_emit_ptr(buffer);
	rte_trace_point_emit_u16(size);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_buffer_set_err_callback,
	RTE_TRACE_POINT_ARGS(struct rte_eth_dev_tx_buffer *buffer,
		buffer_tx_error_fn callback, void *userdata),
	rte_trace_point_emit_ptr(buffer);
	rte_trace_point_emit_ptr(callback);
	rte_trace_point_emit_ptr(userdata);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_burst_mode_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_burst_mode *mode),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(mode);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_done_cleanup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id, uint32_t free_cnt),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u32(free_cnt);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_txq_info *qinfo),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u16(qinfo->nb_desc);
	rte_trace_point_emit_u8(qinfo->queue_state);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_u32(socket_id);
	rte_trace_point_emit_ptr(tx_conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_xstat xstats,
		int i),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(xstats.id);
	rte_trace_point_emit_u64(xstats.value);
	rte_trace_point_emit_u32(i);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const uint64_t *ids,
		uint64_t *values, unsigned int size),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ids);
	rte_trace_point_emit_ptr(values);
	rte_trace_point_emit_u32(size);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_id_by_name,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const char *xstat_name,
		uint64_t *id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstat_name);
	rte_trace_point_emit_ptr(id);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_names,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_xstat_name *xstats_names,
		unsigned int size, int cnt_used_entries),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstats_names->name);
	rte_trace_point_emit_u32(size);
	rte_trace_point_emit_int(cnt_used_entries);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_get_names_by_id,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_xstat_name *xstats_names, uint64_t ids),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_string(xstats_names->name);
	rte_trace_point_emit_u64(ids);
)

RTE_TRACE_POINT(
	rte_eth_trace_xstats_reset,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_delete,
	RTE_TRACE_POINT_ARGS(const uint64_t owner_id, int ret),
	rte_trace_point_emit_u64(owner_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_get,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		struct rte_eth_dev_owner *owner),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_new,
	RTE_TRACE_POINT_ARGS(uint64_t owner_id),
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_set,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		const struct rte_eth_dev_owner *owner),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner->id);
	rte_trace_point_emit_string(owner->name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_owner_unset,
	RTE_TRACE_POINT_ARGS(const uint16_t port_id,
		const uint64_t owner_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u64(owner_id);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_module_eeprom,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_dev_eeprom_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_get_module_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_dev_module_info *modinfo),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(modinfo);
)

RTE_TRACE_POINT(
	rte_eth_trace_read_clock,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint64_t *clk),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(clk);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_hairpin_capability_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_hairpin_cap *cap),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(cap);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, const struct rte_eth_hairpin_conf *conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(rx_queue_id);
	rte_trace_point_emit_u16(nb_rx_desc);
	rte_trace_point_emit_ptr(conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_tx_hairpin_queue_setup,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, const struct rte_eth_hairpin_conf *conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(tx_queue_id);
	rte_trace_point_emit_u16(nb_tx_desc);
	rte_trace_point_emit_ptr(conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_bind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_get_peer_ports,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t *peer_ports,
		size_t len, uint32_t direction),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(peer_ports);
	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u32(direction);
)

RTE_TRACE_POINT(
	rte_eth_trace_hairpin_unbind,
	RTE_TRACE_POINT_ARGS(uint16_t tx_port, uint16_t rx_port),
	rte_trace_point_emit_u16(tx_port);
	rte_trace_point_emit_u16(rx_port);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_speed_to_str,
	RTE_TRACE_POINT_ARGS(uint32_t link_speed),
	rte_trace_point_emit_u32(link_speed);
)

RTE_TRACE_POINT(
	rte_eth_trace_link_to_str,
	RTE_TRACE_POINT_ARGS(char *str, size_t len,
		const struct rte_eth_link *eth_link),
	rte_trace_point_emit_ptr(str);
	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_ptr(eth_link);
)

RTE_TRACE_POINT(
	rte_eth_trace_fec_get_capability,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_fec_capa *speed_fec_capa,
		unsigned int num),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(speed_fec_capa);
	rte_trace_point_emit_u32(num);
)

RTE_TRACE_POINT(
	rte_eth_trace_fec_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t *fec_capa),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(fec_capa);
)

RTE_TRACE_POINT(
	rte_eth_trace_fec_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t fec_capa),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(fec_capa);
)

RTE_TRACE_POINT(
	rte_eth_trace_get_monitor_addr,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_power_monitor_cond *pmc),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(pmc);
)

RTE_TRACE_POINT(
	rte_eth_trace_representor_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_representor_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_capability_name,
	RTE_TRACE_POINT_ARGS(uint64_t capability, const char *name),
	rte_trace_point_emit_u64(capability);
	rte_trace_point_emit_string(name);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_conf_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_conf *dev_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(dev_conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_macaddrs_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *ma,
		unsigned int num),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(ma);
	rte_trace_point_emit_u32(num);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_metadata_negotiate,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint64_t *features),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(features);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_priority_flow_ctrl_queue_configure,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_pfc_queue_conf *pfc_queue_conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(pfc_queue_conf);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_priority_flow_ctrl_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_pfc_queue_info *pfc_queue_info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(pfc_queue_info);
)

RTE_TRACE_POINT(
	rte_ethdev_trace_priv_dump,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_ip_reassembly_capability_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_ip_reassembly_params *capa),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(capa);
)

RTE_TRACE_POINT(
	rte_eth_trace_ip_reassembly_conf_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_ip_reassembly_params *conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_ip_reassembly_conf_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_ip_reassembly_params *conf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(conf);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_avail_thresh_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
)

RTE_TRACE_POINT(
	rte_eth_trace_rx_avail_thresh_set,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		uint8_t avail_thresh),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u8(avail_thresh);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_TRACE_H_ */
