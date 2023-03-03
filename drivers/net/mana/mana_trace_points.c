/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2022 Microsoft Corporation
 */

#include <rte_trace_point_register.h>
#include "mana_trace.h"

RTE_TRACE_POINT_REGISTER(mana_trace_mr_chunk, mana.mr.chunk)
RTE_TRACE_POINT_REGISTER(mana_trace_mr_ibv, mana.mr.ibv)
RTE_TRACE_POINT_REGISTER(mana_trace_mr_search, mana.mr.search)
RTE_TRACE_POINT_REGISTER(mana_trace_mr_found, mana.mr.found)
RTE_TRACE_POINT_REGISTER(mana_trace_local_cache_insert, mana.cache.local.insert)
RTE_TRACE_POINT_REGISTER(mana_trace_btree_miss, mana.btree.miss)
RTE_TRACE_POINT_REGISTER(mana_trace_btree_found, mana.btree.found)
RTE_TRACE_POINT_REGISTER(mana_trace_btree_shift, mana.btree.shift)
RTE_TRACE_POINT_REGISTER(mana_trace_btree_inserted, mana.btree.inserted)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_wqe_pointer, mana.gdma.wqe.pointer)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_write_dma_oob, mana.gdma.write.dma.oob)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_write_sgl, mana.gdma.write.sgl)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_queue_busy, mana.gdma.queue.busy)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_queued, mana.gdma.queued)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_ring_doorbell, mana.gdma.ring.doorbell)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_poll_cq, mana.gdma.cq.poll)
RTE_TRACE_POINT_REGISTER(mana_trace_gdma_polled_cq, mana.gdma.cq.polled)
RTE_TRACE_POINT_REGISTER(mana_trace_tx_error, mana.tx.error)
RTE_TRACE_POINT_REGISTER(mana_trace_tx_packet, mana.tx.packet)
RTE_TRACE_POINT_REGISTER(mana_trace_rx_queue_mismatch, mana.rx.queue.mismatch)
RTE_TRACE_POINT_REGISTER(mana_trace_rx_truncated, mana.rx.truncated)
RTE_TRACE_POINT_REGISTER(mana_trace_rx_coalesced, mana.rx.coalesced)
RTE_TRACE_POINT_REGISTER(mana_trace_rx_unknown_cqe, mana.rx.unknown_cqe)
RTE_TRACE_POINT_REGISTER(mana_trace_rx_cqe, mana.rx.cqe)
RTE_TRACE_POINT_REGISTER(mana_trace_arm_cq, mana.arm.cq)
RTE_TRACE_POINT_REGISTER(mana_trace_handle_secondary_mr, mana.secondary.mr)
