/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 HiSilicon Limited
 */

#ifndef RTE_DMADEV_TRACE_H
#define RTE_DMADEV_TRACE_H

/**
 * @file
 *
 * API for dmadev trace support.
 */

#include <rte_trace_point.h>

#include "rte_dmadev.h"

#ifdef __cplusplus
extern "C" {
#endif

RTE_TRACE_POINT(
	rte_dma_trace_info_get,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, struct rte_dma_info *dev_info),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_string(dev_info->dev_name);
	rte_trace_point_emit_u64(dev_info->dev_capa);
	rte_trace_point_emit_u16(dev_info->max_vchans);
	rte_trace_point_emit_u16(dev_info->max_desc);
	rte_trace_point_emit_u16(dev_info->min_desc);
	rte_trace_point_emit_u16(dev_info->max_sges);
	rte_trace_point_emit_i16(dev_info->numa_node);
	rte_trace_point_emit_u16(dev_info->nb_vchans);
)

RTE_TRACE_POINT(
	rte_dma_trace_configure,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, const struct rte_dma_conf *dev_conf,
			     int ret),
	int enable_silent = (int)dev_conf->enable_silent;
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_u16(dev_conf->nb_vchans);
	rte_trace_point_emit_int(enable_silent);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_start,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_stop,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_close,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_vchan_setup,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, uint16_t vchan,
			     const struct rte_dma_vchan_conf *conf, int ret),
	int src_port_type = conf->src_port.port_type;
	int dst_port_type = conf->dst_port.port_type;
	int direction = conf->direction;
	uint64_t src_pcie_cfg;
	uint64_t dst_pcie_cfg;
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_u16(vchan);
	rte_trace_point_emit_int(direction);
	rte_trace_point_emit_u16(conf->nb_desc);
	rte_trace_point_emit_int(src_port_type);
	memcpy(&src_pcie_cfg, &conf->src_port.pcie, sizeof(uint64_t));
	rte_trace_point_emit_u64(src_pcie_cfg);
	memcpy(&dst_pcie_cfg, &conf->dst_port.pcie, sizeof(uint64_t));
	rte_trace_point_emit_int(dst_port_type);
	rte_trace_point_emit_u64(dst_pcie_cfg);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_stats_get,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, uint16_t vchan,
			     struct rte_dma_stats *stats, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_u16(vchan);
	rte_trace_point_emit_u64(stats->submitted);
	rte_trace_point_emit_u64(stats->completed);
	rte_trace_point_emit_u64(stats->errors);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_stats_reset,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, uint16_t vchan, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_u16(vchan);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_vchan_status,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, uint16_t vchan,
			     enum rte_dma_vchan_status *status, int ret),
	int vchan_status = *status;
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_u16(vchan);
	rte_trace_point_emit_int(vchan_status);
	rte_trace_point_emit_int(ret);
)

RTE_TRACE_POINT(
	rte_dma_trace_dump,
	RTE_TRACE_POINT_ARGS(int16_t dev_id, FILE *f, int ret),
	rte_trace_point_emit_i16(dev_id);
	rte_trace_point_emit_ptr(f);
	rte_trace_point_emit_int(ret);
)

#ifdef __cplusplus
}
#endif

#endif /* RTE_DMADEV_TRACE_H */
