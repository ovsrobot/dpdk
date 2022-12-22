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
#include "rte_mtr.h"
#include "rte_tm.h"

RTE_TRACE_POINT_FP(
	rte_eth_trace_call_rx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		uint16_t nb_rx, uint16_t nb_pkts),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u16(nb_rx);
	rte_trace_point_emit_u16(nb_pkts);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_call_tx_callbacks,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		uint16_t nb_pkts),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
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

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_supported_ptypes,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int supported_num,
		int num, uint32_t ptypes),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(supported_num);
	rte_trace_point_emit_int(num);
	rte_trace_point_emit_u32(ptypes);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_macaddrs_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, unsigned int num),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(num);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_macaddr_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_ether_addr *mac_addr),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(mac_addr);
	rte_trace_point_emit_char_array(mac_addr->addr_bytes, RTE_ETHER_ADDR_LEN);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_mtu,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t mtu),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(mtu);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_vlan_offload,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_flow_ctrl_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_fc_conf *fc_conf,
		int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(fc_conf);
	rte_trace_point_emit_u32(fc_conf->high_water);
	rte_trace_point_emit_u32(fc_conf->low_water);
	rte_trace_point_emit_u16(fc_conf->pause_time);
	rte_trace_point_emit_u16(fc_conf->send_xon);
	rte_trace_point_emit_int(fc_conf->mode);
	rte_trace_point_emit_u8(fc_conf->mac_ctrl_frame_fwd);
	rte_trace_point_emit_u8(fc_conf->autoneg);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_priority_flow_ctrl_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_pfc_queue_info *pfc_queue_info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(pfc_queue_info);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_rss_reta_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_rss_reta_entry64 *reta_conf,
		uint16_t reta_size, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(reta_conf);
	rte_trace_point_emit_u16(reta_size);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_rss_hash_conf_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_rss_conf *rss_conf,
		int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(rss_conf->rss_key);
	rte_trace_point_emit_u8(rss_conf->rss_key_len);
	rte_trace_point_emit_u64(rss_conf->rss_hf);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_fec_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t *fec_capa, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(fec_capa);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_rx_intr_ctl_q_get_fd,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id, int fd),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_int(fd);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_rx_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_rxq_info *qinfo),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(qinfo->mp);
	rte_trace_point_emit_u8(qinfo->conf.rx_drop_en);
	rte_trace_point_emit_u64(qinfo->conf.offloads);
	rte_trace_point_emit_u8(qinfo->scattered_rx);
	rte_trace_point_emit_u8(qinfo->queue_state);
	rte_trace_point_emit_u16(qinfo->nb_desc);
	rte_trace_point_emit_u16(qinfo->rx_buf_size);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_queue_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_txq_info *qinfo),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_u16(qinfo->nb_desc);
	rte_trace_point_emit_u8(qinfo->queue_state);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_rx_burst_mode_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_burst_mode *mode, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(mode);
	rte_trace_point_emit_u64(mode->flags);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_tx_burst_mode_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_eth_burst_mode *mode, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(mode);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_get_monitor_addr,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t queue_id,
		struct rte_power_monitor_cond *pmc, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u16(queue_id);
	rte_trace_point_emit_ptr(pmc);
	rte_trace_point_emit_ptr(pmc->addr);
	rte_trace_point_emit_u8(pmc->size);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_timesync_read_rx_timestamp,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct timespec *timestamp,
		uint32_t flags, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(timestamp);
	rte_trace_point_emit_u64(timestamp->tv_sec);
	rte_trace_point_emit_u64(timestamp->tv_nsec);
	rte_trace_point_emit_u32(flags);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_timesync_read_tx_timestamp,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct timespec *timestamp, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(timestamp);
	rte_trace_point_emit_u64(timestamp->tv_sec);
	rte_trace_point_emit_u64(timestamp->tv_nsec);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_timesync_read_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct timespec *time, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(time);
	rte_trace_point_emit_u64(time->tv_sec);
	rte_trace_point_emit_u64(time->tv_nsec);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_timesync_adjust_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int64_t delta, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_i64(delta);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_timesync_write_time,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, const struct timespec *time, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(time);
	rte_trace_point_emit_u64(time->tv_sec);
	rte_trace_point_emit_u64(time->tv_nsec);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_read_clock,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint64_t *clk, int ret),
	uint64_t clk_v = *clk;
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(clk);
	rte_trace_point_emit_u64(clk_v);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_reg_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_dev_reg_info *info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
	rte_trace_point_emit_ptr(info->data);
	rte_trace_point_emit_u32(info->offset);
	rte_trace_point_emit_u32(info->length);
	rte_trace_point_emit_u32(info->width);
	rte_trace_point_emit_u32(info->version);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_eeprom_length,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_eeprom,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_dev_eeprom_info *info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
	rte_trace_point_emit_ptr(info->data);
	rte_trace_point_emit_u32(info->offset);
	rte_trace_point_emit_u32(info->length);
	rte_trace_point_emit_u32(info->magic);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_module_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_dev_module_info *modinfo, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(modinfo);
	rte_trace_point_emit_u32(modinfo->type);
	rte_trace_point_emit_u32(modinfo->eeprom_len);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_module_eeprom,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_dev_eeprom_info *info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_get_dcb_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_eth_dcb_info *dcb_info,
		int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(dcb_info);
	rte_trace_point_emit_u8(dcb_info->nb_tcs);
	rte_trace_point_emit_char_array(dcb_info->prio_tc,
		RTE_ETH_DCB_NUM_USER_PRIORITIES);
	rte_trace_point_emit_char_array(dcb_info->tc_bws, RTE_ETH_DCB_NUM_TCS);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_ethdev_trace_adjust_nb_rx_tx_desc,
	RTE_TRACE_POINT_ARGS(uint16_t port_id),
	rte_trace_point_emit_u16(port_id);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_representor_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_representor_info *info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_ip_reassembly_conf_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_ip_reassembly_params *conf, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(conf);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_buffer_split_get_supported_hdr_ptypes,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int supported_num, uint32_t ptypes),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(supported_num);
	rte_trace_point_emit_u32(ptypes);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_cman_info_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_eth_cman_info *info, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(info);
	rte_trace_point_emit_u64(info->modes_supported);
	rte_trace_point_emit_u64(info->objs_supported);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_eth_trace_cman_config_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_eth_cman_config *config, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(config);
	rte_trace_point_emit_int(config->obj);
	rte_trace_point_emit_int(config->mode);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, struct rte_flow *flow,
		const struct rte_flow_action *action, void *data, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(flow);
	rte_trace_point_emit_ptr(action);
	rte_trace_point_emit_int(action->type);
	rte_trace_point_emit_ptr(data);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_isolate,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int set, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(set);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_get_restore_info,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_mbuf *m,
		struct rte_flow_restore_info *info),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(m);
	rte_trace_point_emit_ptr(info);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_get_aged_flows,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, void **contexts,
		uint32_t nb_contexts, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(contexts);
	rte_trace_point_emit_u32(nb_contexts);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_get_q_aged_flows,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t queue_id, void **contexts,
		uint32_t nb_contexts, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(queue_id);
	rte_trace_point_emit_ptr(contexts);
	rte_trace_point_emit_u32(nb_contexts);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_action_handle_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		struct rte_flow_action_handle *handle,
		const void *update, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(handle);
	rte_trace_point_emit_ptr(update);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_action_handle_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		const struct rte_flow_action_handle *handle,
		void *data, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(handle);
	rte_trace_point_emit_ptr(data);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_pick_transfer_proxy,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint16_t *proxy_port_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_ptr(proxy_port_id);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_async_action_handle_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t queue_id,
		const struct rte_flow_op_attr *op_attr,
		struct rte_flow_action_handle *action_handle,
		const void *update, void *user_data, int ret),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(queue_id);
	rte_trace_point_emit_ptr(op_attr);
	rte_trace_point_emit_ptr(action_handle);
	rte_trace_point_emit_ptr(update);
	rte_trace_point_emit_ptr(user_data);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT_FP(
	rte_flow_trace_async_action_handle_query,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t queue_id,
		const struct rte_flow_op_attr *op_attr,
		const struct rte_flow_action_handle *action_handle,
		void *data, void *user_data),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(queue_id);
	rte_trace_point_emit_ptr(op_attr);
	rte_trace_point_emit_ptr(action_handle);
	rte_trace_point_emit_ptr(data);
	rte_trace_point_emit_ptr(user_data);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_profile_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id,
		uint32_t meter_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(meter_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_policy_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t policy_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(policy_id);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_profile_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		uint32_t meter_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_u32(meter_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_policy_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		uint32_t meter_policy_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_u32(meter_policy_id);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_dscp_table_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		enum rte_color *dscp_table),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_ptr(dscp_table);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_meter_vlan_table_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		enum rte_color *vlan_table),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_ptr(vlan_table);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_color_in_protocol_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_color_in_protocol_priority_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		enum rte_mtr_color_in_protocol proto),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_int(proto);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_stats_read,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		struct rte_mtr_stats *stats, uint64_t *stats_mask,
		int clear),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_ptr(stats);
	rte_trace_point_emit_ptr(stats_mask);
	rte_trace_point_emit_int(clear);
)

RTE_TRACE_POINT_FP(
	rte_mtr_trace_stats_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t mtr_id,
		uint64_t stats_mask),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(mtr_id);
	rte_trace_point_emit_u64(stats_mask);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_get_number_of_leaf_nodes,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t n_leaf_nodes),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(n_leaf_nodes);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_type_get,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		int *is_leaf),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_ptr(is_leaf);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_shared_wred_context_add_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t shared_wred_context_id,
		uint32_t wred_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(shared_wred_context_id);
	rte_trace_point_emit_u32(wred_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_shared_shaper_add_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t shared_shaper_id,
		uint32_t shaper_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(shared_shaper_id);
	rte_trace_point_emit_u32(shaper_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_parent_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint32_t parent_node_id, uint32_t priority,
		uint32_t weight),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u32(parent_node_id);
	rte_trace_point_emit_u32(priority);
	rte_trace_point_emit_u32(weight);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_shaper_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint32_t shaper_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u32(shaper_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_shared_shaper_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint32_t shared_shaper_id, int add),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u32(shared_shaper_id);
	rte_trace_point_emit_int(add);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_shared_wred_context_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint32_t shared_wred_context_id, int add),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u32(shared_wred_context_id);
	rte_trace_point_emit_int(add);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_stats_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint64_t stats_mask),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u64(stats_mask);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_wfq_weight_mode_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		int *wfq_weight_mode, uint32_t n_sp_priorities),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_ptr(wfq_weight_mode);
	rte_trace_point_emit_u32(n_sp_priorities);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_wred_context_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		uint32_t wred_profile_id),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_u32(wred_profile_id);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_cman_update,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		enum rte_tm_cman_mode cman),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_int(cman);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_node_stats_read,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, uint32_t node_id,
		struct rte_tm_node_stats *stats,
		uint64_t *stats_mask, int clear),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_u32(node_id);
	rte_trace_point_emit_ptr(stats);
	rte_trace_point_emit_ptr(stats_mask);
	rte_trace_point_emit_int(clear);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_mark_vlan_dei,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int mark_green,
		int mark_yellow, int mark_red),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(mark_green);
	rte_trace_point_emit_int(mark_yellow);
	rte_trace_point_emit_int(mark_red);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_mark_ip_ecn,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int mark_green,
		int mark_yellow, int mark_red),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(mark_green);
	rte_trace_point_emit_int(mark_yellow);
	rte_trace_point_emit_int(mark_red);
)

RTE_TRACE_POINT_FP(
	rte_tm_trace_mark_ip_dscp,
	RTE_TRACE_POINT_ARGS(uint16_t port_id, int mark_green,
		int mark_yellow, int mark_red),
	rte_trace_point_emit_u16(port_id);
	rte_trace_point_emit_int(mark_green);
	rte_trace_point_emit_int(mark_yellow);
	rte_trace_point_emit_int(mark_red);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ETHDEV_TRACE_FP_H_ */
