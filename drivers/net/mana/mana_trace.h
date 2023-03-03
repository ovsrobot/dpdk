/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Microsoft Corporation
 */

#ifndef _MANA_TRACE_H_
#define _MANA_TRACE_H_

#include <rte_trace_point.h>

RTE_TRACE_POINT_FP(
	mana_trace_mr_chunk,
	RTE_TRACE_POINT_ARGS(uintptr_t start, uint32_t len),
	rte_trace_point_emit_ptr(start);
	rte_trace_point_emit_u32(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_mr_ibv,
	RTE_TRACE_POINT_ARGS(uint32_t lkey, uintptr_t addr, size_t len),
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_mr_search,
	RTE_TRACE_POINT_ARGS(uintptr_t addr, uint16_t len),
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_u16(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_mr_found,
	RTE_TRACE_POINT_ARGS(uint32_t lkey, uintptr_t addr, size_t len),
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_local_cache_insert,
	RTE_TRACE_POINT_ARGS(uint32_t lkey, uintptr_t addr, size_t len),
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_btree_miss,
	RTE_TRACE_POINT_ARGS(uintptr_t addr, size_t len, uint16_t idx),
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
	rte_trace_point_emit_u16(idx);
);

RTE_TRACE_POINT_FP(
	mana_trace_btree_found,
	RTE_TRACE_POINT_ARGS(uint32_t lkey, uintptr_t addr, size_t len),
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_btree_shift,
	RTE_TRACE_POINT_ARGS(uint16_t shift, uint16_t idx),
	rte_trace_point_emit_u16(shift);
	rte_trace_point_emit_u16(idx);
);

RTE_TRACE_POINT_FP(
	mana_trace_btree_inserted,
	RTE_TRACE_POINT_ARGS(uintptr_t table, uint16_t idx, uintptr_t addr, size_t len),
	rte_trace_point_emit_ptr(table);
	rte_trace_point_emit_u16(idx);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_wqe_pointer,
	RTE_TRACE_POINT_ARGS(uint32_t head, uint32_t size, uint32_t offset),
	rte_trace_point_emit_u32(head);
	rte_trace_point_emit_u32(size);
	rte_trace_point_emit_u32(offset);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_write_dma_oob,
	RTE_TRACE_POINT_ARGS(uintptr_t buf, uint32_t num_sgl, uint32_t inline_oob_size_dw, uint32_t client_data_unit, uintptr_t inline_oob_data, uint32_t inline_oob_size_b),
	rte_trace_point_emit_ptr(buf);
	rte_trace_point_emit_u32(num_sgl);
	rte_trace_point_emit_u32(inline_oob_size_dw);
	rte_trace_point_emit_u32(client_data_unit);
	rte_trace_point_emit_ptr(inline_oob_data);
	rte_trace_point_emit_u32(inline_oob_size_b);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_write_sgl,
	RTE_TRACE_POINT_ARGS(uint32_t num_sge, uintptr_t addr, uint32_t size, uint32_t lkey, uint32_t list_size, uint32_t flags),
	rte_trace_point_emit_u32(num_sge);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_u32(size);
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_u32(list_size);
	rte_trace_point_emit_u32(flags);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_queue_busy,
	RTE_TRACE_POINT_ARGS(uint32_t wqe_size, uint32_t queue_size, uint32_t head, uint32_t tail),
	rte_trace_point_emit_u32(wqe_size);
	rte_trace_point_emit_u32(queue_size);
	rte_trace_point_emit_u32(head);
	rte_trace_point_emit_u32(tail);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_queued,
	RTE_TRACE_POINT_ARGS(uint32_t client_oob_size, uint32_t sgl_data_size, uint32_t wqe_size),
	rte_trace_point_emit_u32(client_oob_size);
	rte_trace_point_emit_u32(sgl_data_size);
	rte_trace_point_emit_u32(wqe_size);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_ring_doorbell,
	RTE_TRACE_POINT_ARGS(uintptr_t page, uintptr_t addr, uint32_t queue_id, uint32_t queue_type, uint32_t tail, uint8_t arm),
	rte_trace_point_emit_ptr(page);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_u32(queue_id);
	rte_trace_point_emit_u32(queue_type);
	rte_trace_point_emit_u32(tail);
	rte_trace_point_emit_u8(arm);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_poll_cq,
	RTE_TRACE_POINT_ARGS(uint32_t cqe_owner_bits, uint32_t old_owner_bits),
	rte_trace_point_emit_u32(cqe_owner_bits);
	rte_trace_point_emit_u32(old_owner_bits);
);

RTE_TRACE_POINT_FP(
	mana_trace_gdma_polled_cq,
	RTE_TRACE_POINT_ARGS(uint32_t new_owner_bits, uint32_t old_owner_bits, uint32_t cqe_owner_bits, uint32_t work_queue_number, uint32_t send_work_queue, uint32_t cq_head),
	rte_trace_point_emit_u32(new_owner_bits);
	rte_trace_point_emit_u32(old_owner_bits);
	rte_trace_point_emit_u32(cqe_owner_bits);
	rte_trace_point_emit_u32(work_queue_number);
	rte_trace_point_emit_u32(send_work_queue);
	rte_trace_point_emit_u32(cq_head);
);

RTE_TRACE_POINT_FP(
	mana_trace_tx_error,
	RTE_TRACE_POINT_ARGS(uint32_t cqe_type, uint32_t vendor_err),
	rte_trace_point_emit_u32(cqe_type);
	rte_trace_point_emit_u32(vendor_err);
);

RTE_TRACE_POINT_FP(
	mana_trace_tx_packet,
	RTE_TRACE_POINT_ARGS(uint16_t pkt_idx, uintptr_t buf, uint32_t nb_segs, uint32_t pkt_len, uint32_t format, uint32_t outer_ipv4, uint32_t outer_ipv6, uint32_t ip_checksum, uint32_t tcp_checksum, uint32_t udp_checksum, uint32_t transport_header_offset),
	rte_trace_point_emit_u16(pkt_idx);
	rte_trace_point_emit_ptr(buf);
	rte_trace_point_emit_u32(nb_segs);
	rte_trace_point_emit_u32(pkt_len);
	rte_trace_point_emit_u32(format);
	rte_trace_point_emit_u32(outer_ipv4);
	rte_trace_point_emit_u32(outer_ipv6);
	rte_trace_point_emit_u32(ip_checksum);
	rte_trace_point_emit_u32(tcp_checksum);
	rte_trace_point_emit_u32(udp_checksum);
	rte_trace_point_emit_u32(transport_header_offset);
);

RTE_TRACE_POINT_FP(
	mana_trace_rx_queue_mismatch,
	RTE_TRACE_POINT_ARGS(uint32_t work_queue_number, uint32_t rq_id),
	rte_trace_point_emit_u32(work_queue_number);
	rte_trace_point_emit_u32(rq_id);
);

RTE_TRACE_POINT_FP(
	mana_trace_rx_truncated,
	RTE_TRACE_POINT_ARGS(void),
);

RTE_TRACE_POINT_FP(
	mana_trace_rx_coalesced,
	RTE_TRACE_POINT_ARGS(void),
);

RTE_TRACE_POINT_FP(
	mana_trace_rx_unknown_cqe,
	RTE_TRACE_POINT_ARGS(uint32_t cqe_type),
	rte_trace_point_emit_u32(cqe_type);
);

RTE_TRACE_POINT_FP(
	mana_trace_rx_cqe,
	RTE_TRACE_POINT_ARGS(void),
);

RTE_TRACE_POINT_FP(
	mana_trace_arm_cq,
	RTE_TRACE_POINT_ARGS(uint32_t cq_id, uint32_t head, uint8_t arm),
	rte_trace_point_emit_u32(cq_id);
	rte_trace_point_emit_u32(head);
	rte_trace_point_emit_u8(arm);
);

RTE_TRACE_POINT_FP(
	mana_trace_handle_secondary_mr,
	RTE_TRACE_POINT_ARGS(uint32_t lkey, uintptr_t addr, size_t len),
	rte_trace_point_emit_u32(lkey);
	rte_trace_point_emit_ptr(addr);
	rte_trace_point_emit_size_t(len);
);
#endif
